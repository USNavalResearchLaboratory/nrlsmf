#include "smfVersion.h"

#include "smf.h"

#include "protoApp.h"
#include "protoSocket.h"
#include "protoPipe.h"
#include "protoCap.h"
#include "protoPktETH.h"
#include "protoPktIP.h"

#ifndef WIN32
// Note: WIN32 ProtoDetour support is TBD
#include "protoDetour.h"
#endif // !WIN32

#include <stdlib.h>  // for atoi()
#include <stdio.h>   // for stdout/stderr printouts
#include <string.h>
#include <ctype.h>  // for "isspace()"

#include "smfDupTree.h"

class SmfApp : public ProtoApp
{
    public:
        SmfApp();
        ~SmfApp();

        // Overrides from ProtoApp or NsProtoSimAgent base
        bool OnStartup(int argc, const char*const* argv);
        bool ProcessCommands(int argc, const char*const* argv);
        void OnShutdown();

    private:
        static const char* DEFAULT_INSTANCE_NAME; 
        static const char* DEFAULT_SMF_SERVER; 
        
        enum {IF_INDEX_MAX = Smf::Interface::INDEX_MAX};
    
        enum CmdType {CMD_INVALID, CMD_ARG, CMD_NOARG};
        static const char* const CMD_LIST[];
        static CmdType GetCmdType(const char* string);
        bool OnCommand(const char* cmd, const char* val);        
        static void Usage();
        
        // Forwarding "modes" for a given interface list
        enum Mode {PUSH, MERGE, RELAY};
        bool ParseInterfaceList(Mode            mode, 
                                const char*     ifaceList, 
                                Smf::RelayType  relayType,
                                bool            resequence = false);
        
        void OnPktCapture(ProtoChannel&              theChannel,
	                      ProtoChannel::Notification notifyType);
        
        void OnControlMsg(ProtoSocket&       thePipe, 
                          ProtoSocket::Event theEvent);
        
        void ProcessPacket(ProtoPktIP& ipPkt, ProtoAddress& srcMacAddr, int srcIfIndex);
        
        // Member variables
        Smf             smf;                                   // General-purpose "SMF" class
        
        ProtoRouteMgr*  rt_mgr;
        
        bool            priority_boost;
        bool            ipv6_enabled;
        bool            resequence;
        bool            firewall_capture;
        bool            firewall_forward;
        
        ProtoCap*       cap_list[Smf::Interface::INDEX_MAX+1]; // List of packet capture instances
                                                               // (one per network interface)
#ifdef _PROTO_DETOUR   
        void OnPktIntercept(ProtoChannel&               theChannel,
                            ProtoChannel::Notification  theNotification);   
        bool SetupIPv4Detour(int hookFlags);
        ProtoDetour*    detour_ipv4;  // for intercept of IPv4 packets
        int             detour_ipv4_flags;
#ifdef HAVE_IPV6
        bool SetupIPv6Detour(int hookFlags);
        ProtoDetour*    detour_ipv6;  // for intercept of IPv6 packets
        int             detour_ipv6_flags;
#endif // HAVE_IPV6
        // The "detour_list" is used for "firewallForward" operation
        // (One "inject only" "detour" per outbound interface, using 
        // "ProtoDetour::SetMulticastInterface()" to make it work
        ProtoDetour*    detour_list[Smf::Interface::INDEX_MAX+1];    
        
#endif // _PROTO_DETOUR        
        
#ifdef MNE_SUPPORT 
        bool MneIsBlocking(const char* macAddr) const;
        char            mne_block_list[Smf::SELECTOR_LIST_LEN_MAX];  
        unsigned int    mne_block_list_len;
#endif // MNE_SUPPORT  
        
        ProtoPipe       control_pipe;   // pipe _from_ controller to me
        char            control_pipe_name[128];
        ProtoPipe       server_pipe;    // pipe _to_ controller (e.g., nrlolsr)
        
        unsigned int    serr_count;        

          
}; // end class SmfApp

// This macro creates our ProtoApp derived application instance 
PROTO_INSTANTIATE_APP(SmfApp) 

const char* SmfApp::DEFAULT_INSTANCE_NAME = "nrlsmf";
const char* SmfApp::DEFAULT_SMF_SERVER = "nrlolsr";
        
SmfApp::SmfApp()
 : smf(GetTimerMgr()), rt_mgr(NULL), priority_boost(true),
   ipv6_enabled(false), resequence(false),
   firewall_capture(false),
#ifdef _PROTO_DETOUR
   detour_ipv4(NULL), detour_ipv4_flags(0),
#ifdef HAVE_IPV6
   detour_ipv6(NULL), detour_ipv6_flags(0),
#endif // HAVE_IPV6          
#endif // _PROTO_DETOUR 
   control_pipe(ProtoPipe::MESSAGE), 
   server_pipe(ProtoPipe::MESSAGE), 
#ifdef MNE_SUPPORT        
   mne_block_list_len(0),
#endif // MNE_SUPPORT  
   serr_count(0)
{
    control_pipe.SetNotifier(&GetSocketNotifier());
    control_pipe.SetListener(this, &SmfApp::OnControlMsg);
}

SmfApp::~SmfApp()
{
    OnShutdown();
}

void SmfApp::Usage()
{
    fprintf(stderr, "Usage: smf [version][ipv6][firewallForward {on|off}][firewallCapture {on|off}\n"
                    "           [cf <ifaceList>][smpr <ifaceList>][ecds <ifaceList>]\n"
                    "           [push <srcIface>,<dstIfaceList>] [rpush <srcIface>,<dstIfaceList>]\n"
                    "           [merge <ifaceList>][rmerge <ifaceList>]\n"
                    "           [forward {on|off}][relay {on|off}]\n"
                    "           [instance <instanceName>][smfServer <serverName>]\n"
                    "           [resequence {on|off}][boost {on|off}]\n"
                    "           [debug <debugLevel>][log <debugLogFile>]\n\n"
                    "   (Note \"firewall\" options must be specified _before_ iface config commands!\n");
}
        
const char* const SmfApp::CMD_LIST[] =
{
    "-version",     // show version and exit
    "-help",        // print help info an exit
    "-ipv6",        // enable IPv6 support (must be first on command-line)
    "+push",        // <srcIface,dstIfaceList> : forward packets from srcIFace to all dstIface's listed
    "+rpush",       // <srcIface,dstIfaceList> : reseq/forward packets from srcIFace to all dstIface's listed
    "+rpush",       // <srcIface,dstIfaceList> : reseq/forward packets from srcIFace to all dstIface's listed
    "+merge",       // <ifaceList> forward among all iface's listed
    "+rmerge",      // <ifaceList> : reseq/forward among all iface's listed
    "+cf",          // <ifaceList> : CF relay among all iface's listed
    "+smpr",        // <ifaceList> : S_MPR relay among all iface's listed        
    "+ecds",        // <ifaceList> : E_CDS relay among all iface's listed  
    "+forward",     // {on | off}  : forwarding enable/disable (default = "on") 
    "+relay",       // {on | off}  : act as relay node (default = "on")
    "+defaultForward",  // (same as relay)
    "+resequence",  // {on | off}  : resequence outbound multicast packets   
    //"+firewall",    // {on | off} : use firewall instead of ProtoCap to capture & forward packets  
    "+firewallCapture", // {on | off} : use firewall instead of ProtoCap to capture packets 
    "+firewallForward", // {on | off} : use firewall instead of ProtoCap to forward packets
    "+instance",    // <instanceName> : sets our instance (control_pipe) name
    "+boost",       // {on | off} : boost process priority (default = "on")
    "+smfServer",   // <serverName> : instructs smf to "register" itself to the given server (pipe only)
    "+debug",       // <debugLevel> : set debug level
    "+log",         // <logFile> : debug log file,
    NULL
};
    

SmfApp::CmdType SmfApp::GetCmdType(const char* cmd)
{
    if (!cmd) return CMD_INVALID;
    unsigned int len = strlen(cmd);
    bool matched = false;
    CmdType type = CMD_INVALID;
    const char* const* nextCmd = CMD_LIST;
    while (*nextCmd)
    {
        if (!strncmp(cmd, *nextCmd+1, len))
        {
            if (matched)
            {
                // ambiguous command (command should match only once)
                return CMD_INVALID;
            }
            else
            {
                matched = true;   
                if ('+' == *nextCmd[0])
                    type = CMD_ARG;
                else
                    type = CMD_NOARG;
                if (len == strlen(*nextCmd+1)) 
                    return type;  // exact match occurred
            }
        }
        nextCmd++;
    }
    return type; 
};  // end SmfApp::GetCmdType()

bool SmfApp::OnStartup(int argc, const char*const* argv)
{
    if (!smf.Init())
    {
        DMSG(0, "SmfApp::OnStartup() error: smf core initialization failed\n");
        return false; 
    }
    
    // Retrieve and store _all_ local IP addresses for all interfaces
    ASSERT(NULL == rt_mgr);
    if (NULL == (rt_mgr = ProtoRouteMgr::Create()))
    {
        DMSG(0, "SmfApp::OnStartup(): ProtoRouteMgr::Create() error: %s\n", GetErrorString());
        return false;        
    }
    if (!rt_mgr->Open())
    {
        DMSG(0, "SmfApp::OnStartup(): error: unable to open ProtoRouteMgr\n");
        delete rt_mgr;
        rt_mgr = NULL;
        return false;
    }
    int ifIndexArray[IF_INDEX_MAX + 1];
    int ifCount = ProtoSocket::GetInterfaceIndices(ifIndexArray, IF_INDEX_MAX+1);
    if (ifCount < 0)
    {
        DMSG(0, "SmfApp::OnStartup(): error: unable to retrieve list of network interface indices\n");
        return false;
    }
    else if (0 == ifCount)
    {
        DMSG(0, "SmfApp::OnStartup(): warning: no network interface indices were found.\n");
    }
    else if (ifCount > IF_INDEX_MAX + 1)
    {
        DMSG(0, "SmfApp::OnStartup(): warning: found network interfaces indices exceeding maximum count.\n");
        ifCount = IF_INDEX_MAX + 1;
    }
    // Check that all found ifIndices are in bounds and 
    // add any IP addrs assigned to this iface to our list
    ProtoAddress::List& addrList = smf.AccessOwnAddressList();
    for (unsigned int i = 0; i < ifCount; i++)
    {
        int ifIndex = ifIndexArray[i];
        if (ifIndex > IF_INDEX_MAX)
        {
            DMSG(0, "SmfApp::OnStartup(): error: found network interface index greate than Smf::IF_INDEX_MAX\n");
            return false;
        }
        // Add the MAC (ETH) addr for this iface to our SMF local addr list
        char ifName[256];
        ifName[255] = '\0';
        if (!ProtoSocket::GetInterfaceName(ifIndex, ifName, 255))
        {
            DMSG(0, "SmfApp::OnStartup() error: unable to get ifName for iface:%s (index:%d)\n", ifIndex);
            return false;
        }
        
        ProtoAddress ifAddr;
        if (!ProtoSocket::GetInterfaceAddress(ifName, ProtoAddress::ETH, ifAddr))
        {
            DMSG(2, "SmfApp::OnStartup() warning: unable to get ETH addr for iface:%s (index:%d)\n", ifName, ifIndex);
        }
        else if (!smf.AddOwnAddress(ifAddr, ifIndex))
        {
            DMSG(0, "SmfApp::OnStartup() error: unable to add ETH addr to own addr list.\n");
            return false;
        }
        // Iterate over and add IP addresses for this interface to our SMF local addr list
        if (!rt_mgr->GetInterfaceAddressList(ifIndex, ProtoAddress::IPv4, addrList))
        {
            DMSG(0, "SmfApp::OnStartup() error: couldn't retrieve IPv4 address for iface index: %d\n", ifIndex);
            return false;
        }
        if (!rt_mgr->GetInterfaceAddressList(ifIndex, ProtoAddress::IPv6, addrList))
        {
            DMSG(0, "SmfApp::OnStartup() error: couldn't retrieve IPv6 address for iface index: %d\n", ifIndex);
            return false;
        }
    }
    
    memset(cap_list, 0, (IF_INDEX_MAX + 1)*sizeof(ProtoCap*));
    smf.SetRelayEnabled(true);
    smf.SetRelaySelected(true);
    if (!ProcessCommands(argc, argv))
    {
        DMSG(0, "smfApp::OnStartup() error: bad command line.\n");
        OnShutdown();
        return false;
    }
    
    // Check to see if any ifaces were configured
    // (or if outbound resequencing is set up)
    if (!resequence)
    {
        int i;
        for (i = 0; i <= IF_INDEX_MAX; i++)
        {
            if (NULL != cap_list[i]) break;
#ifdef _PROTO_DETOUR
            if (NULL != detour_list[i]) break;
#endif // _PROTO_DETOUR
        }  
        if (i > IF_INDEX_MAX)
        {
            // No resequencing or iface I/O configured?
            OnShutdown();
            return false;
        }
    }
    
    // Let's "check" our startup configuration for any possible problems
    if (firewall_capture && !firewall_forward)
        DMSG(0, "SmfApp::OnStartup() warning: \"firewallCapture on\" _requires_ \"firewallForward on\" "
                "for proper operation!\n");
    
    // Open control pipe for remote control if not opened in command-line
    if (!control_pipe.IsOpen())
    {
        // Note this prevents multiple instantiations trying 
        // to use the same default instance name
        if (!OnCommand("instance", DEFAULT_INSTANCE_NAME))
        {
            DMSG(0, "smfApp::OnStartup() error: Couldn't open default control pipe\n");   
            return false;  
        }   
    }
    // Tell an "smfServer" that we're open for business (if not already done)
    if (!server_pipe.IsOpen())
    {
        if (!OnCommand("smfServer", DEFAULT_SMF_SERVER))
        {
            DMSG(0, "smfApp::OnStartup() warning: unable to contact \"nrlolsr\".\n");   
        }   
    }
    
    dispatcher.SetPriorityBoost(priority_boost);
    
    // List "own" addresses (MAC & IP src addrs) for fun    
    ProtoAddress::List::Iterator it(smf.AccessOwnAddressList());
    ProtoAddress nextAddr;
    while (it.GetNextAddress(nextAddr))
        DMSG(0, "interface addr:%s %s\n", nextAddr.GetHostString(),
                nextAddr.IsLinkLocal() ? "(link local)" : "");
        
}  // end SmfApp::OnStartup()

void SmfApp::OnShutdown()
{
    if (control_pipe.IsOpen()) control_pipe.Close();
    if (server_pipe.IsOpen()) server_pipe.Close();
    
#ifdef _PROTO_DETOUR        
    if (NULL != detour_ipv4)
    {
        detour_ipv4->Close();
        delete detour_ipv4;
        detour_ipv4 = NULL;
    }
#ifdef HAVE_IPV6
    if (NULL != detour_ipv6)
    {
        detour_ipv6->Close();
        delete detour_ipv6;
        detour_ipv6 = NULL;
    }
#endif // HAVE_IPV6
#endif // _PROTO_DETOUR
    
    // Go through cap_list and shutdown ProtoCaps and be rid of them
    for (unsigned int i = 0; i <  (IF_INDEX_MAX + 1); i++)
    {
        if (NULL != cap_list[i])
        {
            cap_list[i]->Close();
            delete cap_list[i];
            cap_list[i] = NULL;
        }
    } 
    if (NULL != rt_mgr)
    {
        rt_mgr->Close();
        delete rt_mgr;
        rt_mgr = NULL;
    }
}  // end SmfApp::OnShutdown()

bool SmfApp::ProcessCommands(int argc, const char*const* argv)
{
    // Dispatch command-line commands to our OnCommand() method
    int i = 1;
    while ( i < argc)
    {
        // Is it a class SmfApp command?
        switch (GetCmdType(argv[i]))
        {
            case CMD_INVALID:
            {
                DMSG(0, "SmfApp::ProcessCommands() Invalid command:%s\n", 
                        argv[i]);
                Usage();
                return false;
            }
            case CMD_NOARG:
                if (!OnCommand(argv[i], NULL))
                {
                    DMSG(0, "SmfApp::ProcessCommands() ProcessCommand(%s) error\n", 
                            argv[i]);
                    return false;
                }
                i++;
                break;
            case CMD_ARG:
                if (!OnCommand(argv[i], argv[i+1]))
                {
                    DMSG(0, "SmfApp::ProcessCommands() ProcessCommand(%s, %s) error\n", 
                            argv[i], argv[i+1]);
                    return false;
                }
                i += 2;
                break;
        }
    }
    return true;  
}  // end SmfApp::ProcessCommands()

bool SmfApp::OnCommand(const char* cmd, const char* val)
{
    CmdType type = GetCmdType(cmd);
    if(CMD_INVALID == type)
    {
        DMSG(0, "SmfApp::OnCommand(%s) error: invalid command.\n", cmd);
        return false;   
    }
    unsigned int len = strlen(cmd);
    if ((CMD_ARG == type) && !val)
    {
        DMSG(0, "SmfApp::OnCommand(%s) error: missing argument.\n", cmd);
        return false;
    }
    else if (!strncmp("version", cmd, len) || !strncmp("help", cmd, len))
    {
	    fprintf(stderr, "smf version: %s\n", _SMF_VERSION);
        return true;
    }
    else if (!strncmp("ipv6", cmd, len))
    {
        ipv6_enabled = true;
#ifdef _PROTO_DETOUR
	    if (!OnCommand("resequence", resequence ? "on" : "off"))
        {
           DMSG(0, "SmfApp::OnCommand(ipv6) error setting up IPv6 detour for resequencing\n"); 
           return false;
        }        
#endif // _PROTO_DETOUR
    }
    else if (!strncmp("push", cmd, len))
    {
        // syntax: "push <srcIface,dstIface1,dstIface2,...>"
        if (!ParseInterfaceList(PUSH, val, Smf::CF, false))
        {
            DMSG(0, "SmfApp::OnCommand(push) error parsing interface list\n");
            return false;
        }
    }  
    else if (!strncmp("rpush", cmd, len))
    {
        // syntax: "rpush <srcIface,dstIface1,dstIface2,...>"
        if (!ParseInterfaceList(PUSH, val, Smf::CF, true))
        {
            DMSG(0, "SmfApp::OnCommand(rpush) error parsing interface list\n");
            return false;
        }
    }  
    else if (!strncmp("merge", cmd, len))
    {
        // syntax: "merge <iface1,iface2,iface3,...>"
        if (!ParseInterfaceList(MERGE, val, Smf::CF, false))
        {
            DMSG(0, "SmfApp::OnCommand(merge) error parsing interface list\n");
            return false;
        }
    }  
    else if (!strncmp("rmerge", cmd, len))
    {
        // syntax: "rmerge <iface1,iface2,iface3,...>"
        if (!ParseInterfaceList(MERGE, val, Smf::CF, true))
        {
            DMSG(0, "SmfApp::OnCommand(rmerge) error parsing interface list\n");
            return false;
        }
    } 
    else if (!strncmp("cf", cmd, len))
    {
        // syntax: "cf <iface1,iface2,iface3,...>"
        if (!ParseInterfaceList(RELAY, val, Smf::CF))
        {
            DMSG(0, "SmfApp::OnCommand(cf) error parsing interface list\n");
            return false;
        }
    }      
    else if (!strncmp("smpr", cmd, len))
    {
        // syntax: "smpr <iface1,iface2,iface3,...>"
        if (!ParseInterfaceList(RELAY, val, Smf::S_MPR))
        {
            DMSG(0, "SmfApp::OnCommand(smpr) error parsing interface list\n");
            return false;
        }
    }         
    else if (!strncmp("ecds", cmd, len))
    {
        // syntax: "ecds <iface1,iface2,iface3,...>"
        if (!ParseInterfaceList(RELAY, val, Smf::E_CDS))
        {
            DMSG(0, "SmfApp::OnCommand(ecds) error parsing interface list\n");
            return false;
        }
    }             
    else if (!strncmp("forward", cmd, len))
    {
        // syntax: "forward {on | off}"
        if (!strcmp("on", val))
        {
            smf.SetRelayEnabled(true);
        }
        else if (!strcmp("off", val))
        {
            smf.SetRelayEnabled(false);
        }
        else
        {
            DMSG(0, "SmfApp::OnCommand(forward) invalid argument: %s\n", val);
            return false;
        }
    }                
    else if (!strncmp("relay", cmd, len) || !strncmp("defaultForward", cmd, len))
    {
        // syntax: "relay {on | off}"
        if (!strcmp("on", val))
        {
            smf.SetRelaySelected(true);
        }
        else if (!strcmp("off", val))
        {
            smf.SetRelaySelected(false);
        }
        else
        {
            DMSG(0, "SmfApp::OnCommand(relay) invalid argument: %s\n", val);
            return false;
        }
    }                
#ifdef _PROTO_DETOUR         
    else if (!strncmp("resequence", cmd, len))
    {
        if (!strcmp("on", val))
        {
            int hookFlags = detour_ipv4_flags | ProtoDetour::OUTPUT; // intercept outbound packets
            if (!SetupIPv4Detour(hookFlags))
            {
                DMSG(0, "SmfApp::OnCommand(resequence) error opening IPv4 detour\n");
                return false;
            }
#ifdef HAVE_IPV6
            hookFlags = detour_ipv6_flags | ProtoDetour::OUTPUT;
            if (ipv6_enabled && !SetupIPv6Detour(hookFlags))
            {
                DMSG(0,  "SmfApp::OnCommand(resequence) error opening IPv6 detour\n"); 
                return false; 
            }
#endif // HAVE_IPV6
            resequence = true;
        }
        else if (!strcmp("off", val))
        {
            int hookFlags = detour_ipv4_flags & ~ProtoDetour::OUTPUT; // stop intercept outbound packets
            if (!SetupIPv4Detour(hookFlags))
            {
                DMSG(0, "SmfApp::OnCommand(resequence) error opening IPv4 detour\n");
                return false;
            }
#ifdef HAVE_IPV6
            hookFlags = detour_ipv6_flags & ~ProtoDetour::OUTPUT;
            if (ipv6_enabled && !SetupIPv4Detour(hookFlags))
            {
                DMSG(0,  "SmfApp::OnCommand(resequence) error opening IPv6 detour\n"); 
                return false; 
            }
#endif // HAVE_IPV6
            resequence = false;
        }
        else
        {
            DMSG(0, "SmfApp::OnCommand(resequence) invalid argument: %s\n", val);
            return false;
        }
    }  
    else if (!strncmp("firewallCapture", cmd, len))
    {
        // (TBD) "remap cap" when this is toggled (need to make sure input notify is done)
        if (!strcmp("on", val))
        {
            // Setup ProtoDetour to intercept INBOUND packets
            int hookFlags = detour_ipv4_flags | ProtoDetour::INPUT; // intercept inbound packets
            if (!SetupIPv4Detour(hookFlags))
            {
                DMSG(0, "SmfApp::OnCommand(firewallCapture) error opening IPv4 detour\n");
                return false;
            }
#ifdef HAVE_IPV6
            hookFlags = detour_ipv6_flags | ProtoDetour::INPUT;
            if (ipv6_enabled && !SetupIPv6Detour(hookFlags))
            {
                DMSG(0,  "SmfApp::OnCommand(firewallCapture) error opening IPv6 detour\n"); 
                return false; 
            }
#endif // HAVE_IPV6
            firewall_capture = true;
            // Disable ProtoCap input notifications and delete if "firewall_forward" is enabled
        }
        else if (!strcmp("off", val))
        {
            // Re-enable ProtoCap input notifications, creating ProtoCaps as needed
            // Setup ProtoDetours to ignore INBOUND packets.
            int hookFlags = detour_ipv4_flags & ~ProtoDetour::INPUT; // stop intercept outbound packets
            if (!SetupIPv4Detour(hookFlags))
            {
                DMSG(0, "SmfApp::OnCommand(firewallCapture) error opening IPv4 detour\n");
                return false;
            }
#ifdef HAVE_IPV6
            hookFlags = detour_ipv6_flags & ~ProtoDetour::INPUT;
            if (ipv6_enabled && !SetupIPv4Detour(hookFlags))
            {
                DMSG(0,  "SmfApp::OnCommand(firewallCapture) error opening IPv6 detour\n"); 
                return false; 
            }
#endif // HAVE_IPV6
            firewall_capture = false;
        }
        else
        {
            DMSG(0, "SmfApp::OnCommand(firewallCapture) invalid argument: %s\n", val);
            return false;
        }
    }
    else if (!strncmp("firewallForward", cmd, len))
    {
        // (TBD) "remap cap" when this is toggled
        if (!strcmp("on", val))
        {
            firewall_forward = true;
        }
        else if (!strcmp("off", val))
        {
            firewall_forward = false;
        }
        else
        {
            DMSG(0, "SmfApp::OnCommand(firewallForward) invalid argument: %s\n", val);
            return false;
        }
    }
    else if (!strncmp("firewall", cmd, len))
    {
        // (TBD) "remap cap" when this is toggled
        if (!strcmp("on", val))
        {
            bool result = OnCommand("firewallCapture", "on");
            if (result) result = OnCommand("firewallForward", "on");
            return result;
        }
        else if (!strcmp("off", val))
        {
            bool result = OnCommand("firewallCapture", "off");
            if (result) result = OnCommand("firewallForward", "off");
            return result;
        }
        else
        {
            DMSG(0, "SmfApp::OnCommand(firewall) invalid argument: %s\n", val);
            return false;
        }
    }
#endif // _PROTO_DETOUR
    else if (!strncmp("instance", cmd, len))
    {
        if (control_pipe.IsOpen()) control_pipe.Close();
        if (!control_pipe.Listen(val))
        {
            DMSG(0, "SmfApp::OnCommand(instance) error opening control pipe\n");
            if ('\0' != control_pipe_name[0])
                control_pipe.Listen(control_pipe_name);
            return false;
        }   
        strncpy(control_pipe_name, val, 127);
        control_pipe_name[127] = '\0';
        if (server_pipe.IsOpen())
        {
            char buffer[256];
            sprintf(buffer, "smfClientStart %s", control_pipe_name);
            unsigned int numBytes = strlen(buffer)+1;
            if (!server_pipe.Send(buffer, numBytes))
            {
                DMSG(0, "SmfApp::OnCommand(instance) error sending hello to smf server\n");
                return false;  
            }
        }
    }   
    else if (!strncmp("boost", cmd, len))
    {
        if (!strcmp("on", val))
        {
            priority_boost = true;
        }
        else if (!strcmp("off", val))
        {
            priority_boost = false;
        }
        else
        {
            DMSG(0, "SmfApp::OnCommand(boost) error: invalid argument\n");
            return false;
        }
    }
    else if (!strncmp("smfServer", cmd, len))
    {
        if (server_pipe.IsOpen()) server_pipe.Close();
        if (!control_pipe.IsOpen())
        {
            const char* instanceName = ('\0' != control_pipe_name[0]) ? control_pipe_name : DEFAULT_INSTANCE_NAME;
            if (!OnCommand("instance", instanceName))
            {
                DMSG(0, "SmfApp::OnCommand(smfServer) error establishing instance name: %s\n", instanceName);
                return false;
            }
        }
        if (server_pipe.Connect(val))
        {
            if ('\0' != control_pipe_name[0])
            {
                char buffer[256];
                sprintf(buffer, "smfClientStart %s", control_pipe_name);
                unsigned int numBytes = strlen(buffer)+1;
                if (!server_pipe.Send(buffer, numBytes))
                {
                    DMSG(0, "SmfApp::OnCommand(smfServer) error sending hello to smf server\n");
                    return false;  
                }  
            }     
        }      
        else
        {
            DMSG(0, "SmfApp::OnCommand(smfServer) error connecting to smf server\n");
            return false;   
        }  
    }   
    else if (!strncmp("debug", cmd, len))
    {
        SetDebugLevel(atoi(val));  // set protolib debug level
    }    
    else if (!strncmp("log", cmd, len))
    {
        if (!OpenDebugLog(val))  // set protolib debug log file
        {
            DMSG(0, "SmfApp::OnCommand(log) error opening file:\n", GetErrorString());
            return false;
        }
    }
    else
    {
        fprintf(stderr, "SmfApp::OnCommand(%s) error: command not yet supported,\n", cmd);
        return false;
    }
    return true;
}  // end SmfApp::OnCommand()

// "mode = PUSH, MERGE, SMPR, ECDS, NSMPR, etc 

bool SmfApp::ParseInterfaceList(Mode            mode, 
                                const char*     ifaceList, 
                                Smf::RelayType  relayType,
                                bool            resequence)
{
    ProtoAddress::List& addrList = smf.AccessOwnAddressList();
    unsigned int ifCount = 0;
    int ifArray[IF_INDEX_MAX + 1];
    while((NULL != ifaceList) && (*ifaceList != '\0'))
    {
        const char* ptr = strchr(ifaceList, ',');
        // Get ifName length and set ptr to next ifName (if applicable)
        size_t len = (NULL != ptr) ? (ptr++ - ifaceList) : strlen(ifaceList);
        if (len <= 0)
        {
            ifaceList = ptr;  // point past comma to next char and try again
            continue;
        }
        ASSERT(len < 255);
        char ifName[256];
        ifName[255] = '\0';
        strncpy(ifName, ifaceList, len);
        ifName[len] = '\0';
        int ifIndex = ProtoSocket::GetInterfaceIndex(ifName);
        if (ifIndex < 0)
        {
            DMSG(0, "SmfApp::ParseInterfaceList() error: invalid iface name \"%s\"\n", ifName);
            return false;
        }
        else if (ifIndex > IF_INDEX_MAX)
        {
            DMSG(0, "SmfApp::ParseInterfaceList() error: iface index:%d exceeds allowed range\n", ifIndex);
            return false;
        }
        // Get "real" ifName for given ifIndex 
        if (!ProtoSocket::GetInterfaceName(ifIndex, ifName, 255))
        {
            DMSG(0, "SmfApp::ParseInterfaceList() error: invalid interface \"%s\"\n", ifName);
            return false;
        }

        // Do we already have a "ProtoCap" or "ProtoDetour" (as appropriate) for this ifaceIndex?
        if (firewall_forward)
        {
            if (NULL == detour_list[ifIndex])
            {
                // Create and open new ProtoDetour for this iface 
                if (NULL == (detour_list[ifIndex] = ProtoDetour::Create()))
                {
                    DMSG(0, "SmfApp::ParseInterfaceList(): ProtoDetour::Create() error: %s\n", GetErrorString());
                    return false;
                }
                detour_list[ifIndex]->SetListener(this, &SmfApp::OnPktIntercept);
                detour_list[ifIndex]->SetNotifier(static_cast<ProtoChannel::Notifier*>(&dispatcher));
                // Open in "inject-only" mode
                if (!detour_list[ifIndex]->Open(ProtoDetour::INJECT))
                {
                    DMSG(0, "SmfApp::ParseInterfaceList(): ProtoDetour::Open(INJECT) error: %s\n", GetErrorString());
                    return false;
                }
                if (!detour_list[ifIndex]->SetMulticastInterface(ifName))
                {
                    DMSG(0, "SmfApp::ParseInterfaceList(): ProtoDetour::SetMulticastInterface(%s) failure: %s\n", ifName, GetErrorString());
                    return false;
                }
            }
        }
        if ((NULL == cap_list[ifIndex]) && !(firewall_forward && firewall_capture))
        {
            // Create and open new ProtoCap for this iface 
            if (NULL == (cap_list[ifIndex] = ProtoCap::Create()))
            {
                DMSG(0, "SmfApp::ParseInterfaceList(): ProtoCap::Create() error: %s\n", GetErrorString());
                return false;
            }
            cap_list[ifIndex]->SetUserData((void*)ifIndex);
            cap_list[ifIndex]->SetListener(this, &SmfApp::OnPktCapture);
            cap_list[ifIndex]->SetNotifier(static_cast<ProtoChannel::Notifier*>(&dispatcher));
            if (!cap_list[ifIndex]->Open(ifName))
            {
                DMSG(0, "SmfApp::ParseInterfaceList(): ProtoCap::Open(%s) error: %s\n", ifName, GetErrorString());
                return false;
            }
            cap_list[ifIndex]->StopInputNotification();  // will be re-enabled as needed
        }  // end if (NULL == cap_list[ifIndex])
        
        Smf::Interface* iface = smf.GetInterface(ifIndex);
        if (NULL == iface)
        {
            if (NULL == (iface = smf.AddInterface(ifIndex)))
            {
                DMSG(0, "SmfApp::ParseInterfaceList(): new Smf::Interface error: %s\n", GetErrorString());
                return false;
            } 
            // Add the MAC (ETH) addr for this iface to our SMF local addr list
            ProtoAddress ifAddr;
            if (!ProtoSocket::GetInterfaceAddress(ifName, ProtoAddress::ETH, ifAddr))
            {
                DMSG(0, "SmfApp::ParseInterfaceList() error: unable to get ETH addr for iface:%s\n", ifName);
                return false;
            }
            if (!smf.AddOwnAddress(ifAddr))
            {
                DMSG(0, "SmfApp::ParseInterfaceList() error: unable to add ETH addr to local addr list.\n");
                return false;
            }
            if (NULL == rt_mgr)
            {
                if (NULL == (rt_mgr = ProtoRouteMgr::Create()))
                {
                    DMSG(0, "SmfApp::ParseInterfaceList(): ProtoRouteMgr::Create() error: %s\n", GetErrorString());
                    return false;        
                }
                if (!rt_mgr->Open())
                {
                    DMSG(0, "SmfApp::ParseInterfaceList() error: unable to open ProtoRouteMgr\n");
                    delete rt_mgr;
                    rt_mgr = NULL;
                    return false;
                }
            }
            // Iterate over and add IP addresses for this interface to our SMF local addr list
            if (!rt_mgr->GetInterfaceAddressList(ifIndex, ProtoAddress::IPv4, addrList))
            {
                DMSG(0, "SmfApp::ParseInterfaceList() error: couldn't retrieve IPv4 address for iface: %s\n", ifName);
                return false;
            }
            if (!rt_mgr->GetInterfaceAddressList(ifIndex, ProtoAddress::IPv6, addrList))
            {
                DMSG(0, "SmfApp::ParseInterfaceList() error: couldn't retrieve IPv6 address for iface: %s\n", ifName);
                return false;
            }
        }
        // Cache ifIndex's of listed ifaces
        ifArray[ifCount] = ifIndex;
        ifCount++;        // increment ifCount
        ifaceList = ptr;  // point to next potential iface and continue parsing "val" string
    }  // end while((NULL != ifaceList) && (*ifaceList != '\0'))
    
    // The following is a syntactical check after parsing the textual iface list
    // Make sure more than one valid iface was given for PUSH/MERGE commands
    switch (mode)
    {
        case PUSH:
        case MERGE:
            if (ifCount < 2)
            {
                DMSG(0, "SmfApp::ParseInterfaceList(push/merge) error: insufficient number of ifaces listed\n");
                return false;
            }
            break;
        case RELAY:
            if (ifCount < 1)
            {
                DMSG(0, "SmfApp::ParseInterfaceList() error: insufficient number of ifaces listed\n");
                return false;
            }
            break;
    }
    
    // Note we cached the ifIndexes of the "ifCount" listed ifaces in "ifArray"
    // Now we need to iterate over the "ifArray" and set up input notification for
    // any source interfaces and create appropriate "assocations" to dstIfaces
    for (unsigned int i = 0 ; i < ifCount; i++)
    {
        int ifIndex = ifArray[i];
        Smf::Interface* iface = smf.GetInterface(ifIndex);
        ASSERT(NULL != iface);
        switch (mode)
        {
            case PUSH:
                // First listed iface is our "srcIface" for "PUSH" commands
                if (0 == i)
                {
                    if (resequence)
                    {
                        // Make sure this interface does _not_ have a MANET iface
                        // association (i.e. self association) if we will be 
                        // resequencing rom this iface!
                        Smf::Interface::AssociateIterator it(*iface);
                        Smf::Interface::Associate* assoc;
                        while (NULL != (assoc = it.GetNextAssociate()))
                        {
                            if (assoc->GetInterfaceIndex() == ifIndex)
                            {
                                DMSG(0, "SmfApp::ParseInterfaceList() error: bad 'rpush' configuration from MANET srcIface\n");
                                return false;
                            }
                        }    
                    }                    
                    if (!firewall_capture)
                        cap_list[ifIndex]->StartInputNotification();  // (TBD) error check?
                    iface->SetResequence(resequence);
                }
                else 
                {
                    Smf::Interface* srcIface = smf.GetInterface(ifArray[0]);
                    // No input notifications for outbound-only (no associates) ifaces 
                    if ((iface != srcIface) && !iface->HasAssociates() && !firewall_forward)
                        cap_list[ifIndex]->StopInputNotification();
                    // Add this dstIface as an associate of the "srcIface" 
                    // (first check for conflicting association!)
                    if (NULL != srcIface->FindAssociate(ifIndex))
                    {
                        DMSG(0, "SmfApp::ParseInterfaceList() error: push iface indices %d->%d config conflicts with previous command\n",
                                srcIface->GetIndex(), ifIndex);
                        return false;
                    }
                    // Use Classical Flooding (CF) algorithm for "push" from srcIface->dstIfaces
                    if (!srcIface->AddAssociate(*iface, Smf::CF))
                    {
                        DMSG(0, "SmfApp::ParseInterfaceList(): new Smf::Interface::Associate error: %s\n", GetErrorString());
                        return false;
                    }     
                }
                break;
            case MERGE:
                if (resequence)
                {
                    // Make sure this interface does _not_ have a MANET iface
                    // association (i.e. self association) if we will be 
                    // resequencing rom this iface!
                    Smf::Interface::AssociateIterator it(*iface);
                    Smf::Interface::Associate* assoc;
                    while (NULL != (assoc = it.GetNextAssociate()))
                    {
                        if (assoc->GetInterfaceIndex() == ifIndex)
                        {
                            DMSG(0, "SmfApp::ParseInterfaceList() error: bad 'rmerge' configuration from MANET srcIface\n");
                            return false;
                        }
                    }    
                } 
                // All ifaces are srcIfaces for "MERGE" commands
                if (!firewall_capture)
                    cap_list[ifIndex]->StartInputNotification();  // (TBD) error check?
                iface->SetResequence(resequence);
                // Make this iface an "associate" of all other listed ifaces
                for (unsigned int j = 0 ; j < ifCount; j++)
                {
                    if (i != j)
                    {
                        int dstIfIndex = ifArray[j];
                        // First check for possible conflicting association!
                        if (NULL != iface->FindAssociate(dstIfIndex))
                        {
                            DMSG(0, "SmfApp::ParseInterfaceList() error: merge iface indices %d->%d config conflicts with previous command\n",
                                    ifIndex, dstIfIndex);
                            return false;
                        }
                        Smf::Interface* dstIface = smf.GetInterface(ifArray[j]);
                        ASSERT(NULL != dstIface);
                        // Use Classical Flooding (CF) algorithm for "merge" from each iface->dstIfaces
                        if (!iface->AddAssociate(*dstIface, Smf::CF))
                        {
                            DMSG(0, "SmfApp::ParseInterfaceList(): new Smf::Interface::Associate error: %s\n", GetErrorString());
                            return false;
                        }    
                    }
                }
                break;
            case RELAY:
                // Make sure this iface hasn't been previously set as a rpush or rmerge srcIface
                if (iface->GetResequence())
                {
                    DMSG(0, "SmfApp::ParseInterfaceList() error: MANET iface config conflicts with previous rpush or rmerge config!\n");
                    return false;
                }
                // All ifaces are srcIfaces for "RELAY" commands
                if (!firewall_capture)
                    cap_list[ifIndex]->StartInputNotification();  // (TBD) error check?
                
                ASSERT(!resequence);
                iface->SetResequence(resequence);  
                // Make this iface an "associate" of itself and all other listed ifaces
                for (unsigned int j = 0 ; j < ifCount; j++)
                {
                    int dstIfIndex = ifArray[j];
                    // First check for possible conflicting association!
                    if (NULL != iface->FindAssociate(dstIfIndex))
                    {
                        DMSG(0, "SmfApp::ParseInterfaceList() error: merge iface indices %d->%d config conflicts with previous command\n",
                                ifIndex, dstIfIndex);
                        return false;
                    }
                    Smf::Interface* dstIface = smf.GetInterface(ifArray[j]);
                    ASSERT(NULL != dstIface);
                    // Use Classical Flooding (CF) algorithm for "merge" from each iface->dstIfaces
                    if (!iface->AddAssociate(*dstIface, relayType))
                    {
                        DMSG(0, "SmfApp::ParseInterfaceList(): new Smf::Interface::Associate error: %s\n", GetErrorString());
                        return false;
                    } 
                }
                break;
        }  // end switch (mode)
    }  // end for (unsigned int i = 0 ; i < ifCount; i++)
    if (NULL != rt_mgr)
    {
        rt_mgr->Close();
        delete rt_mgr;
        rt_mgr = NULL;
    }
    return (0 != ifCount);
}  // end SmfApp::ParseInterfaceList()

void SmfApp::OnControlMsg(ProtoSocket& thePipe, ProtoSocket::Event theEvent)
{
    if (ProtoSocket::RECV == theEvent)
    {
        char buffer[8192];
        unsigned int len = 8191;
        if (thePipe.Recv(buffer, len))
        {
            buffer[len] = '\0';
            // Parse received message from controller and populate
            // our forwarding table
            if (len)
	            DMSG(4,"SmfApp::OnControlMsg() recv'd %d byte message from controller \"%s\" "
                       "is what it looks like in string form\n", len, buffer);
	        char* cmd = buffer;
            char* arg = NULL;
            for (unsigned int i = 0; i < len; i++)
            {
                if ('\0' == buffer[i])
                {
                    break;
                }
                else if (isspace(buffer[i]))
                {
                    buffer[i] = '\0';
                    arg = buffer+i+1;
                    break;
                }
            }
            unsigned int cmdLen = strlen(cmd);
            unsigned int argLen = len - (arg - cmd);
            // Check for a pipe only command first
            if (!strncmp(cmd, "smfServerStart", cmdLen))
            {
                if (server_pipe.IsOpen()) server_pipe.Close();
                if (!server_pipe.Connect(arg))
                    DMSG(0, "SmfApp::OnControlMsg(smfServerStart) error connecting to smf server\n");
            }
            else if (!strncmp(cmd, "forwardMac", cmdLen))
            {
                // The "arg" points to the current set of MPR selector MAC addresses
                // Overwrite our current selector list
                if (argLen > Smf::SELECTOR_LIST_LEN_MAX)
                {
                    DMSG(0, "SmfApp::OnControlMsg(forwardMac) error: selector list too long!\n");
                    // (TBD) record this error indication permanently
                    argLen = Smf::SELECTOR_LIST_LEN_MAX;
                }
                smf.SetSelectorList(arg, argLen);
            }  
            else if (!strncmp(cmd, "selectorMac", cmdLen) || !strncmp(cmd, "symetricMac", cmdLen))
            {
                // The "arg" points to the current set of symetric neighbor MAC addresses
                // Overwrite our current symmetric list
                if (argLen > Smf::SELECTOR_LIST_LEN_MAX)
                {
                    DMSG(0, "SmfApp::OnControlMsg(symetricMac) error: symmetric list too long!\n");
                    // (TBD) record this error indication permanently
                    argLen = Smf::SELECTOR_LIST_LEN_MAX;
                }
                smf.SetNeighborList(arg, argLen);
            }  
#ifdef MNE_SUPPORT
            else if (!strncmp(cmd, "mneMacBlock", cmdLen) || !strncmp(cmd, "mneBlock", cmdLen))
            {
                // The "arg" points to the current set of MPR mneBlock MAC addresses
                // Overwrite our current mneBlock list
                if (argLen > Smf::SELECTOR_LIST_LEN_MAX)
                {
                    DMSG(0, "SmfApp::OnControlMsg(mneBlock) error: mac list too long!\n");
                    // (TBD) record this error indication permanently
                    argLen = Smf::SELECTOR_LIST_LEN_MAX;
                }
                memcpy(mne_block_list, arg, argLen);
                mne_block_list_len = argLen;
            }  
#endif // MNE_SUPPORT
            else
            {
                // Maybe it's a regular command
                if (!OnCommand(cmd, arg))
                    DMSG(0, "SmfApp::OnControlMsg() invalid command: \"%s\"\n", cmd);
            }
        }
    }
}  // end SmfApp::OnControlMsg()

#ifdef MNE_SUPPORT
bool SmfApp::MneIsBlocking(const char* macAddr) const
{
    const size_t MAC_ADDR_LEN = 6;
    const char *ptr = mne_block_list;
    const char* endPtr = mne_block_list + mne_block_list_len;
    while (ptr < endPtr)
    {
        if (!memcmp(macAddr, ptr, MAC_ADDR_LEN))
            return true;   
        ptr += MAC_ADDR_LEN;
    }
    return false;
}  // end SmfApp::MneIsBlocking()
#endif // MNE_SUPPORT

static char replayBuffer[2048];
static unsigned int replayLength = 0;

void SmfApp::OnPktCapture(ProtoChannel&              theChannel,
	                      ProtoChannel::Notification notifyType)
{
    //We only care about NOTIFY_INPUT events (all we should get anyway)
    if (ProtoChannel::NOTIFY_INPUT != notifyType) return;
    while(1) 
    {
        ProtoCap::Direction direction;
        // Note: We offset the buffer by 2 bytes since Ethernet header is 14 bytes
        //       (i.e. not a multiple of 4 (sizeof(UINT32))
        //       This gives us a properly aligned buffer for 32-bit aligned IP packets
        const int BUFFER_MAX = 2048;
        UINT32  alignedBuffer[BUFFER_MAX/sizeof(UINT32)];
        UINT16* ethBuffer = ((UINT16*)alignedBuffer) + 1; // offset by 2-bytes so IP content is aligned
        UINT32* ipBuffer = alignedBuffer + 4; // offset by ETHER header size + 2 bytes
        unsigned int numBytes = (sizeof(UINT32) * (BUFFER_MAX/sizeof(UINT32))) - 2;
	    
        ProtoCap& cap = static_cast<ProtoCap&>(theChannel);
        
        if (!cap.Recv((char*)ethBuffer, numBytes, &direction))
        {
    	    DMSG(0, "SmfApp::OnPktCapture() ProtoCap::Recv() error\n");
    	    break;
        }
	    if (numBytes == 0) break;  // no more packets to receive
        
       // Map ProtoPktETH instance into buffer and init for processing
        ProtoPktETH ethPkt((UINT32*)ethBuffer, BUFFER_MAX - 2);
        if (!ethPkt.InitFromBuffer(numBytes))
        {
            DMSG(0, "SmfApp::OnPktCapture() error: bad Ether frame\n");
            continue;
        }
        // Only process IP packets (skip others)
        UINT16 ethType = ethPkt.GetType();
        if ((ethType != 0x0800) && (ethType != 0x86dd)) continue;
        // Map ProtoPktIP instance into buffer and init for processing.
        
        // (TBD) deal with fact that ProtoCap::Recv() seems to give us a little more
        // (at least on MacOS)
        // than the ETH header + PAYLOAD  (ETH trailer? or something else?)
        
        ProtoPktIP ipPkt(ipBuffer, BUFFER_MAX - 16);
        if (!ipPkt.InitFromBuffer(ethPkt.GetPayloadLength()))
        {
            DMSG(0, "SmfApp::OnPktCapture() error: bad IP packet\n");
            continue;
        }
        ProtoAddress srcMacAddr;
        ethPkt.GetSrcAddr(srcMacAddr);
        
#ifdef MNE_SUPPORT
    // In "MNE" environment, ignore packets from blocked MAC sources
        if ((0 != mne_block_list_len) &&
            (MneIsBlocking(srcMacAddr.GetRawHostAddress())))
                continue;  // ignore packets blocked by MNE
#endif // MNE_SUPPORT
        // Finally, process packet for possible forwarding given ipPkt, srcMacAddr, and srcIfIndex      
        int srcIfIndex = (int)cap.GetUserData();
        int dstIfArray[Smf::Interface::INDEX_MAX + 1];
        int dstCount = smf.ProcessPacket(ipPkt, srcMacAddr, srcIfIndex, dstIfArray, IF_INDEX_MAX + 1);
        //DMSG(0, "SmfApp::ProcessPacket() processing result:%d...\n", dstCount);
        for (int i = 0; i < dstCount; i++)
        {
            int dstIfIndex = dstIfArray[i];
            Smf::Interface* dstIface = smf.GetInterface(dstIfIndex);
            ASSERT(NULL != dstIface);

            if (firewall_forward)
            {
                ProtoDetour* dstDetour = detour_list[dstIfIndex];
                ASSERT(NULL != dstDetour);
                // Only the IP portion of the capture frame is injected 
                if (!dstDetour->Inject((const char*)ipPkt.GetBuffer(), ipPkt.GetLength()))
                {
                    DMSG(0, "SmfApp::OnPktCapture() error firewall forwarding packet\n");
                    serr_count++;  // (TBD) set or increment "smf" send error count instead?
                }
            }
            else
            {
                ProtoCap* dstCap = cap_list[dstIfIndex];
                // Note that the MAC header is needed here
                if (!dstCap->Forward((char*)ethBuffer, ProtoPktETH::HDR_LEN + ipPkt.GetLength()))
                {
                    DMSG(0, "SmfApp::OnPktCapture() error forwarding packet\n");
                    serr_count++;  // (TBD) set or increment "smf" send error count instead?
                }
                
                if (0 == replayLength)
                {
                    replayLength = ProtoPktETH::HDR_LEN + ipPkt.GetLength();
                    memcpy(replayBuffer, (char*)ethBuffer, replayLength); 
                }
                else
                {
                    //dstCap->Send(replayBuffer, replayLength); 
                }
                
            }
        }
    }
}  // end SmfApp::OnPktCapture()


#ifdef _PROTO_DETOUR

void SmfApp::OnPktIntercept(ProtoChannel&               theChannel, 
                            ProtoChannel::Notification  theNotification)
{
    if (ProtoChannel::NOTIFY_INPUT == theNotification)
    {
        ProtoDetour& detour = static_cast<ProtoDetour&>(theChannel);
        UINT32 buffer[65536/sizeof(UINT32)];
        // Our pkt seq routines assume a MAC header is there for the moment
        unsigned int numBytes = 65535; 
        ProtoDetour::Direction direction;
        ProtoAddress srcMacAddr;
        int ifIndex;
        if (detour.Recv((char*)buffer, numBytes, &direction, &srcMacAddr, &ifIndex))
        {
            if (0 != numBytes)
            {
                ProtoPktIP ipPkt(buffer, 65535);
                ProtoAddress srcAddr, dstAddr;
                switch (direction)
                {
                    case ProtoDetour::OUTBOUND:
                    {
                        if (!resequence) 
                        {
                            DMSG(0, "SmfApp::OnPktIntercept() warning: intercepted OUTBOUND packet, but resequence disabled?!\n");
                            break;
                        }
                        // For OUTBOUND packets, modify ID field (IPv4)
                        // or add DPD option (IPv6) for 
                        // locally-generated, globally-scoped
                        // multicast packets
                        if (!ipPkt.InitFromBuffer(numBytes))
                        {
                            DMSG(0, "SmfApp::OnPktIntercept() bad IP packet size\n");
                            break;
                        }
                        unsigned char version = ipPkt.GetVersion();
                        if (4 == version)
                        {
                            ProtoPktIPv4 ip4Pkt(ipPkt);
                            ip4Pkt.GetDstAddr(dstAddr);
                            if (!dstAddr.IsMulticast()) // resequence only multicast packets
                            {
                                DMSG(8, "SmfApp::OnPktIntercept() skipping non-multicast IPv4 pkt\n");
                                break;
                            }
                            if (dstAddr.IsLinkLocal()) // don't resequence if link-local dst
                            {
                                DMSG(8, "SmfApp::OnPktIntercept() skipping link-local multicast IPv4 pkt\n");
                                break;
                            }
                            ip4Pkt.GetSrcAddr(srcAddr);
                            if (srcAddr.IsLinkLocal())  // don't resequence if link-local src
                            {
                                DMSG(8, "SmfApp::OnPktIntercept() skipping link-local sourced IPv4 pkt\n");
                                break;
                            }
                            if (!smf.IsOwnAddress(srcAddr)) // resequence only locally-generated packets
                            {
                                DMSG(8, "SmfApp::OnPktIntercept() skipping non-locally-generated IPv4 pkt\n");
                                break;
                            }
                            // Resequence ID field using "local" sequence s
                            ip4Pkt.SetID(smf.IncrementIPv4LocalSequence(&dstAddr), true);  
                        }
                        else if (6 == version)
                        {
                            ProtoPktIPv6 ip6Pkt(ipPkt);
                            if (ip6Pkt.GetHopLimit() <= 1)
                            {
                                // Don't add DPD to packets w/ hopLimit <= 1
                                break;
                            }
                            ip6Pkt.GetDstAddr(dstAddr);
                            if (!dstAddr.IsMulticast()) // resequence only multicast packets
                            {
                                DMSG(8, "SmfApp::OnPktIntercept() skipping non-multicast IPv6 pkt\n");
                                break;
                            }
                            if (dstAddr.IsLinkLocal()) // don't resequence if link-local dst
                            {
                                DMSG(8, "SmfApp::OnPktIntercept() skipping link-local multicast IPv6 pkt\n");
                                break;
                            }
                            ip6Pkt.GetSrcAddr(srcAddr);
                            if (srcAddr.IsLinkLocal())  // don't resequence if link-local src
                            {
                                DMSG(8, "SmfApp::OnPktIntercept() skipping link-local sourced IPv6 pkt\n");
                                break;
                            }
                            if (!smf.IsOwnAddress(srcAddr)) // resequence only locally-generated packets
                            {
                                DMSG(8, "SmfApp::OnPktIntercept() skipping non-locally-generated IPv6 pkt\n");
                                break;
                            }
                            UINT32 pktId;
                            unsigned int pktIdSize;
                            if (Smf::DPD_NONE == Smf::GetIPv6PktID(ip6Pkt, pktId, pktIdSize))
                            {
                                if (!Smf::InsertOptionDPD(ip6Pkt, smf.IncrementIPv6LocalSequence(&dstAddr)))
                                {
                                    DMSG(0, "SmfApp::OnPktIntercept(): error marking IPv6 pkt for DPD ...\n");
                                    break;
                                }
                                // Update "numBytes" to reflect modified packet size
                                numBytes = ip6Pkt.GetLength();
                            }   
                            else
                            {
                                DMSG(0, "SmfApp::OnPktIntercept() warning: intercepted OUTBOUND IPv6 pkt w/ DPD opt in place?!\n");
                            }    
                        }
                        else
                        {
                            DMSG(0, "SmfApp::OnPktIntercept() bad IP packet version\n");
                        }
                        break;
                    }  // end case ProtoDetour:OUTBOUND
                    case ProtoDetour::INBOUND:
                    {
                        if (!firewall_capture) 
                        {
                            DMSG(0, "SmfApp::OnPktIntercept() warning: intercepted INBOUND packet, but firewall_capture disabled?!\n");
                            break;
                        }
                        if (!ipPkt.InitFromBuffer(numBytes))
                        {
                            DMSG(0, "SmfApp::OnPktIntercept() bad IP packet size\n");
                            break;
                        }
                        // Finally, process packet for possible forwarding given ipPkt, srcMacAddr, and srcIfIndex        
                        int dstIfArray[Smf::Interface::INDEX_MAX + 1];
                        int dstCount = smf.ProcessPacket(ipPkt, srcMacAddr, ifIndex, dstIfArray, IF_INDEX_MAX + 1);
                        numBytes = ipPkt.GetLength();  // note size _may_ have been modified if DPD option was added
                        for (int i = 0; i < dstCount; i++)
                        {
                            int dstIfIndex = dstIfArray[i];
                            Smf::Interface* dstIface = smf.GetInterface(dstIfIndex);
                            ASSERT(NULL != dstIface);

                            if (firewall_forward)
                            {
                                ProtoDetour* dstDetour = detour_list[dstIfIndex];
                                // Only the IP portion of the capture frame is injected 
                                if (!dstDetour->Inject((const char*)ipPkt.GetBuffer(), ipPkt.GetLength()))
                                {
                                    DMSG(0, "SmfApp::OnPktCapture() error firewall forwarding packet\n");
                                    serr_count++;  // (TBD) set or increment "smf" send error count instead?
                                }
                            }
                            else
                            {
                                ProtoCap* dstCap = cap_list[dstIfIndex];
                                // (TBD) a MAC header is needed here, so we will need to build one!
                                DMSG(0, "SmfApp::OnPktCapture() error: Ethernet frame forwarding of packets "
                                        "captured via firewall is not yet supported! (sorry.)\n");
                                break;
                                /*if (!dstCap->Forward((char*)ethBuffer, ProtoPktETH::HDR_LEN + ipPkt.GetLength()))
                                {
                                    DMSG(0, "SmfApp::OnPktCapture() error forwarding packet\n");
                                    serr_count++;  // (TBD) set or increment "smf" send error count instead?
                                }*/
                            }
                        }
                        break;
                    }
                        
                    default:
                        DMSG(0, "SmfApp::OnPktCapture() warning: ambiguous packet capture 'direction'\n");
                        break;
                }
                detour.Allow((char*)buffer, numBytes);
            }
        }
    }
}  // end SmfApp::OnPktIntercept()


bool SmfApp::SetupIPv4Detour(int hookFlags)
{
    if (hookFlags == detour_ipv4_flags) return true;
    if (NULL == detour_ipv4)
    {
        if (NULL == (detour_ipv4 = ProtoDetour::Create()))
        {
            DMSG(0, "SmfApp::OpenIPv4Detour() new ProtoDetour error: %s\n",
                    GetErrorString());
            return false;
        }
        detour_ipv4->SetNotifier(static_cast<ProtoChannel::Notifier*>(&dispatcher));
        detour_ipv4->SetListener(this, &SmfApp::OnPktIntercept);
    }
    else
    {
        detour_ipv4->Close();
    }
    detour_ipv4_flags = 0;
    ProtoAddress srcFilter;
    ProtoAddress dstFilter;
    unsigned int dstFilterMask;
    srcFilter.Reset(ProtoAddress::IPv4);  // unspecified address
    dstFilter.ResolveFromString("224.0.0.0");
    dstFilterMask = 4;
    if (!detour_ipv4->Open(hookFlags, srcFilter, 0, dstFilter, dstFilterMask))
    {
        DMSG(0, "SmfApp::OpenIPv4Detour() error opening IPv4 detour\n");
        return false;
    }
    detour_ipv4_flags = hookFlags;
    return true;
}  // end SmfApp::SetupIPv4Detour()

#ifdef HAVE_IPV6
bool SmfApp::SetupIPv6Detour(int hookFlags)
{
    if (hookFlags == detour_ipv6_flags) return true;
    if (NULL == detour_ipv6)
    {
        if (NULL == (detour_ipv6 = ProtoDetour::Create()))
        {
            DMSG(0, "SmfApp::OpenIPv4Detour() new ProtoDetour error: %s\n",
                    GetErrorString());
            return false;
        }
        detour_ipv6->SetNotifier(static_cast<ProtoChannel::Notifier*>(&dispatcher));
        detour_ipv6->SetListener(this, &SmfApp::OnPktIntercept);
    }
    else
    {
        detour_ipv6->Close();
    }
    detour_ipv6_flags = 0;
    ProtoAddress srcFilter;
    ProtoAddress dstFilter;
    unsigned int dstFilterMask;
    srcFilter.Reset(ProtoAddress::IPv6);  // unspecified address
    // (TBD) we don't really need to fix link local mcast, right?
    dstFilter.ResolveFromString("ff00::");
    dstFilterMask = 8;
    if (!detour_ipv6->Open(hookFlags, srcFilter, 0, dstFilter, dstFilterMask))
    {
        DMSG(0, "SmfApp::OpenIPv6Detour() error opening IPv6 detour\n");
        return false;
    }
    detour_ipv6_flags = hookFlags;
    return true;;
}  // end SmfApp::SetupIPv6Detour()
#endif  // HAVE_IPV6
#endif // _PROTO_DETOUR
