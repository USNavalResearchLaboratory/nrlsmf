#include "smfVersion.h"

#include "smf.h"
#include "smfHash.h"

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
        
        //enum {IF_INDEX_MAX = Smf::Interface::INDEX_MAX};
        enum {IF_COUNT_MAX = 256};
        
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
        
        
        static const unsigned int BUFFER_MAX;
        
        void OnPktCapture(ProtoChannel&              theChannel,
	                      ProtoChannel::Notification notifyType);
        
        void HandleInboundPacket(UINT32* alignedBuffer, unsigned int numBytes, unsigned int srcIfIndex);
        
        void ProcessPacket(ProtoPktIP& ipPkt, ProtoAddress& srcMacAddr, unsigned int srcIfIndex);
        
        bool ForwardFrame(unsigned int dstCount, unsigned int* dstIfIndices, char* frameBuffer, unsigned int frameLength);
        bool ForwardFrameToTap(unsigned int srcIfIndex, unsigned int dstCount, unsigned int* dstIfIndices, char* frameBuffer, unsigned int frameLength);
        
        void OnControlMsg(ProtoSocket&       thePipe, 
                          ProtoSocket::Event theEvent);
        
        
        // This class contains pointers to classes that provide
        // any I/O (input/output) mechanism for an interface 
        class InterfaceMechanism
        {
            public:
                InterfaceMechanism();
                ~InterfaceMechanism();
                
                void SetProtoCap(ProtoCap* protoCap)
                    {proto_cap = protoCap;}
                ProtoCap* GetProtoCap() const
                    {return proto_cap;}
#ifdef _PROTO_DETOUR             
                void SetProtoDetour(ProtoDetour* protoDetour)
                    {proto_detour = protoDetour;}
                ProtoDetour* GetProtoDetour() const
                    {return proto_detour;}
#endif // _PROTO_DETOUR

            private:
                ProtoCap*       proto_cap;
#ifdef _PROTO_DETOUR
                ProtoDetour*    proto_detour;
#endif // _PROTO_DETOUR            
        };  // end class SmfApp::InterfaceMechanism
        
        // Member variables
        Smf             smf;                                   // General-purpose "SMF" class
        
        ProtoRouteMgr*  rt_mgr;
        
        bool            priority_boost;
        bool            ipv6_enabled;
        bool            resequence;
        int             ttl_set;
        bool            firewall_capture;
        bool            firewall_forward;
        
#ifdef _PROTO_DETOUR   
        void OnPktIntercept(ProtoChannel&               theChannel,
                            ProtoChannel::Notification  theNotification); 
        bool ForwardPacket(unsigned int dstCount, unsigned int* dstIfIndices, char* pktBuffer, unsigned int pktLength);
        bool SetupIPv4Detour(int hookFlags);
        ProtoDetour*    detour_ipv4;  // for intercept of IPv4 packets
        int             detour_ipv4_flags;
#ifdef HAVE_IPV6
        bool SetupIPv6Detour(int hookFlags);
        ProtoDetour*    detour_ipv6;  // for intercept of IPv6 packets
        int             detour_ipv6_flags;
#endif  // HAVE_IPV6
#endif  // _PROTO_DETOUR        
        
#ifdef MNE_SUPPORT 
        bool MneIsBlocking(const char* macAddr) const;
        char            mne_block_list[Smf::SELECTOR_LIST_LEN_MAX];  
        unsigned int    mne_block_list_len;
#endif // MNE_SUPPORT  
        
        ProtoPipe       control_pipe;   // pipe _from_ controller to me
        char            control_pipe_name[128];
        ProtoPipe       server_pipe;    // pipe _to_ controller (e.g., nrlolsr)
        
        ProtoPipe       tap_pipe;
        bool            tap_active;
        
        unsigned int    serr_count;        

          
}; // end class SmfApp


const unsigned int SmfApp::BUFFER_MAX = 4096 + (256 *sizeof(UINT32));

SmfApp::InterfaceMechanism::InterfaceMechanism()
 : proto_cap(NULL)
#ifdef _PROTO_DETOUR
   ,proto_detour(NULL)
#endif // _PROTO_DETOUR
{
}

SmfApp::InterfaceMechanism::~InterfaceMechanism()
{
    if (NULL != proto_cap)
    {
        proto_cap->Close();
        delete proto_cap;
        proto_cap = NULL;
    }
#ifdef _PROTO_DETOUR
    if (NULL != proto_detour)
    {
        proto_detour->Close();
        delete proto_detour;
        proto_detour = NULL;
    }
#endif // _PROTO_DETOUR    
}


// This macro creates our ProtoApp derived application instance 
PROTO_INSTANTIATE_APP(SmfApp) 

const char* SmfApp::DEFAULT_INSTANCE_NAME = "nrlsmf";
const char* SmfApp::DEFAULT_SMF_SERVER = "nrlolsr";
        
SmfApp::SmfApp()
 : smf(GetTimerMgr()), rt_mgr(NULL), priority_boost(true),
   ipv6_enabled(false), resequence(false), ttl_set(-1),
   firewall_capture(false),
#ifdef _PROTO_DETOUR
   detour_ipv4(NULL), detour_ipv4_flags(0),
#ifdef HAVE_IPV6
   detour_ipv6(NULL), detour_ipv6_flags(0),
#endif // HAVE_IPV6          
#endif // _PROTO_DETOUR 
   control_pipe(ProtoPipe::MESSAGE), 
   server_pipe(ProtoPipe::MESSAGE), 
   tap_pipe(ProtoPipe::MESSAGE), tap_active(false),
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
                    "           [forward {on|off}][relay {on|off}][delayoff <value>]\n"
                    "           [ihash <algorithm>][hash <algorithm>]\n"
                    "           [idpd {on | off}][window {on | off}]\n"
                    "           [instance <instanceName>][smfServer <serverName>]\n"
                    "           [resequence {on|off}][ttl <value>][boost {on|off}]\n"
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
	"+defaultForward", // {on | off}  : same as "relay" (for backwards compatibility)
    "+delayoff",    // {<double> : number of microseconds delay before executing a relay off command (default = 0)
    "+ihash",       // <algorithm> to set ihash_only hash algorithm
    "+hash",        // <algorithm> to set H-DPD hash algorithm
    "+idpd",        // {on | off} to do I-DPD when possible
    "+window",      // {on | off} do window-based I-DPD of sequenced packets
    "+resequence",  // {on | off}  : resequence outbound multicast packets
    "+ttl",         // <value> : set TTL of outbound packets   
    //"+firewall",    // {on | off} : use firewall instead of ProtoCap to capture & forward packets  
    "+firewallCapture", // {on | off} : use firewall instead of ProtoCap to capture packets 
    "+firewallForward", // {on | off} : use firewall instead of ProtoCap to forward packets
    "+instance",    // <instanceName> : sets our instance (control_pipe) name
    "+boost",       // {on | off} : boost process priority (default = "on")
    "+smfServer",   // <serverName> : instructs smf to "register" itself to the given server (pipe only)"+smfTap"
    "+tap",         // <tapName> : instructs smf to divert forwarded packets to process ProtoPipe named <tapName>
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
        PLOG(PL_FATAL, "SmfApp::OnStartup() error: smf core initialization failed\n");
        return false; 
    }
    
    // Retrieve and store _all_ local IP addresses for all interfaces
    ASSERT(NULL == rt_mgr);
    if (NULL == (rt_mgr = ProtoRouteMgr::Create()))
    {
        PLOG(PL_FATAL, "SmfApp::OnStartup(): ProtoRouteMgr::Create() error: %s\n", GetErrorString());
        return false;        
    }
    if (!rt_mgr->Open())
    {
        PLOG(PL_FATAL, "SmfApp::OnStartup(): error: unable to open ProtoRouteMgr\n");
        delete rt_mgr;
        rt_mgr = NULL;
        return false;
    }
    unsigned int ifIndexArray[IF_COUNT_MAX];
    unsigned int ifCount = ProtoSocket::GetInterfaceIndices(ifIndexArray, IF_COUNT_MAX);
    if (0 == ifCount)
    {
        PLOG(PL_FATAL, "SmfApp::OnStartup(): error: unable to retrieve list of network interface indices\n");
        return false;
    }
    else if (0 == ifCount)
    {
        PLOG(PL_WARN, "SmfApp::OnStartup(): warning: no network interface indices were found.\n");
    }
    else if (ifCount > IF_COUNT_MAX)
    {
        PLOG(PL_WARN, "SmfApp::OnStartup(): warning: found network interfaces indices exceeding maximum count.\n");
        ifCount = IF_COUNT_MAX;
    }
    // Add any IP addrs assigned to this iface to our list
    ProtoAddressList& addrList = smf.AccessOwnAddressList();
    for (unsigned int i = 0; i < ifCount; i++)
    {
        unsigned int ifIndex = ifIndexArray[i];
        // Add the MAC (ETH) addr for this iface to our SMF local addr list
        char ifName[256];
        ifName[255] = '\0';
        if (!ProtoSocket::GetInterfaceName(ifIndex, ifName, 255))
        {
            PLOG(PL_FATAL, "SmfApp::OnStartup() error: unable to get ifName for iface:%s (index:%u)\n", ifIndex);
            return false;
        }
        
        ProtoAddress ifAddr;
        if (!ProtoSocket::GetInterfaceAddress(ifName, ProtoAddress::ETH, ifAddr))
        {
            PLOG(PL_WARN, "SmfApp::OnStartup() warning: unable to get ETH addr for iface:%s (index:%u)\n", ifName, ifIndex);
        }
        else if (!smf.AddOwnAddress(ifAddr, ifIndex))
        {
            PLOG(PL_FATAL, "SmfApp::OnStartup() error: unable to add ETH addr to own addr list.\n");
            return false;
        }
        // Iterate over and add IP addresses for this interface to our SMF local addr list
        if (!rt_mgr->GetInterfaceAddressList(ifIndex, ProtoAddress::IPv4, addrList))
        {
            PLOG(PL_FATAL, "SmfApp::OnStartup() error: couldn't retrieve IPv4 address for iface index:%u\n", ifIndex);
            //return false;
        }
        if (!rt_mgr->GetInterfaceAddressList(ifIndex, ProtoAddress::IPv6, addrList))
        {
            PLOG(PL_FATAL, "SmfApp::OnStartup() error: couldn't retrieve IPv6 address for iface index:%u\n", ifIndex);
            //return false;
        }
        if (addrList.IsEmpty())
        {
            PLOG(PL_WARN, "SmfApp::OnStartup() error:no IP addresses found for iface: %s\n", ifName);
            return false;
        }
    }
    smf.SetRelayEnabled(true);
    smf.SetRelaySelected(true);
    if (!ProcessCommands(argc, argv))
    {
        
        PLOG(PL_FATAL, "smfApp::OnStartup() error: bad command line.\n");
        OnShutdown();
        return false;
    }
    
    // Check to see if any ifaces were configured
    // (or if outbound resequencing is set up)
    if (!resequence && (ttl_set < 0))
    {
        
        bool isEmpty = true;
        Smf::InterfaceList::Iterator iterator(smf.AccessInterfaceList());
        Smf::Interface* iface;
        while (NULL != (iface = iterator.GetNextItem()))
        {
            const InterfaceMechanism* mech = reinterpret_cast<const InterfaceMechanism*>(iface->GetUserData());
            if (NULL != mech)
            {
                isEmpty = false;
                break;
            }
        }
        if (isEmpty)
        {
            // No resequencing or iface I/O configured?
            OnShutdown();
            return false;
        }
    }
    
    // Let's "check" our startup configuration for any possible problems
    
    // Open control pipe for remote control if not opened in command-line
    if (!control_pipe.IsOpen())
    {
        // Note this prevents multiple instantiations trying 
        // to use the same default instance name
        if (!OnCommand("instance", DEFAULT_INSTANCE_NAME))
        {
            PLOG(PL_FATAL, "smfApp::OnStartup() error: Couldn't open default control pipe\n");   
            return false;  
        }   
    }
    // Tell an "smfServer" that we're open for business (if not already done)
    if (!server_pipe.IsOpen())
    {
        if (!OnCommand("smfServer", DEFAULT_SMF_SERVER))
        {
            PLOG(PL_WARN, "smfApp::OnStartup() warning: unable to contact \"nrlolsr\".\n");   
        }   
    }
    
    dispatcher.SetPriorityBoost(priority_boost);
    
    // List "own" addresses (MAC & IP src addrs) for fun 
    /*   
    ProtoAddressList::Iterator it(smf.AccessOwnAddressList());
    ProtoAddress nextAddr;
    while (it.GetNextAddress(nextAddr))
        PLOG(PL_INFO, "interface addr:%s %s\n", nextAddr.GetHostString(),
                nextAddr.IsLinkLocal() ? "(link local)" : "");
    */  
	return true;
}  // end SmfApp::OnStartup()

void SmfApp::OnShutdown()
{
    if (control_pipe.IsOpen()) control_pipe.Close();
    if (server_pipe.IsOpen()) server_pipe.Close();
    
    Smf::InterfaceList::Iterator iterator(smf.AccessInterfaceList());
    Smf::Interface* iface;
    while (NULL != (iface = iterator.GetNextItem()))
    {
        InterfaceMechanism* mech = reinterpret_cast<InterfaceMechanism*>(iface->GetUserData());
        if (NULL != mech)
        {
            ProtoCap* cap = mech->GetProtoCap();
            if (NULL != cap)
            {
                mech->SetProtoCap(NULL);
                cap->Close();
                delete cap;
            }
#ifdef _PROTO_DETOUR              
            ProtoDetour* detour = mech->GetProtoDetour();
            if (NULL != detour)
            {
                mech->SetProtoDetour(NULL);
                detour->Close();
                delete detour;
            }
#endif // _PROTO_DETOUR
            iface->SetUserData(NULL);
            delete mech;
        }
    }    
    
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
                PLOG(PL_FATAL, "SmfApp::ProcessCommands() Invalid command:%s\n", 
                        argv[i]);
                Usage();
                return false;
            }
            case CMD_NOARG:
                if (!OnCommand(argv[i], NULL))
                {
                    PLOG(PL_FATAL, "SmfApp::ProcessCommands() ProcessCommand(%s) error\n", 
                            argv[i]);
                    return false;
                }
                i++;
                break;
            case CMD_ARG:
                if (!OnCommand(argv[i], argv[i+1]))
                {
                    PLOG(PL_FATAL, "SmfApp::ProcessCommands() ProcessCommand(%s, %s) error\n", 
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
        PLOG(PL_ERROR, "SmfApp::OnCommand(%s) error: invalid command.\n", cmd);
        return false;   
    }
    unsigned int len = strlen(cmd);
    if ((CMD_ARG == type) && !val)
    {
        PLOG(PL_ERROR, "SmfApp::OnCommand(%s) error: missing argument.\n", cmd);
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
        bool resequenceSaved = resequence;
	    if (!OnCommand("resequence", (resequence || (ttl_set > 0)) ? "on" : "off"))
        {
           PLOG(PL_ERROR, "SmfApp::OnCommand(ipv6) error setting up IPv6 detour for resequencing\n"); 
           return false;
        }      
        resequence = resequenceSaved;  
#endif // _PROTO_DETOUR
    }
    else if (!strncmp("push", cmd, len))
    {
        // syntax: "push <srcIface,dstIface1,dstIface2,...>"
        if (!ParseInterfaceList(PUSH, val, Smf::CF, false))
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(push) error parsing interface list\n");
            return false;
        }
    }  
    else if (!strncmp("rpush", cmd, len))
    {
        // syntax: "rpush <srcIface,dstIface1,dstIface2,...>"
        if (!ParseInterfaceList(PUSH, val, Smf::CF, true))
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(rpush) error parsing interface list\n");
            return false;
        }
    }  
    else if (!strncmp("merge", cmd, len))
    {
        // syntax: "merge <iface1,iface2,iface3,...>"
        if (!ParseInterfaceList(MERGE, val, Smf::CF, false))
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(merge) error parsing interface list\n");
            return false;
        }
    }  
    else if (!strncmp("rmerge", cmd, len))
    {
        // syntax: "rmerge <iface1,iface2,iface3,...>"
        if (!ParseInterfaceList(MERGE, val, Smf::CF, true))
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(rmerge) error parsing interface list\n");
            return false;
        }
    } 
    else if (!strncmp("cf", cmd, len))
    {
        // syntax: "cf <iface1,iface2,iface3,...>"
        if (!ParseInterfaceList(RELAY, val, Smf::CF))
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(cf) error parsing interface list\n");
            return false;
        }
    }      
    else if (!strncmp("smpr", cmd, len))
    {
        // syntax: "smpr <iface1,iface2,iface3,...>"
        if (!ParseInterfaceList(RELAY, val, Smf::S_MPR))
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(smpr) error parsing interface list\n");
            return false;
        }
    }         
    else if (!strncmp("ecds", cmd, len))
    {
        // syntax: "ecds <iface1,iface2,iface3,...>"
        if (!ParseInterfaceList(RELAY, val, Smf::E_CDS))
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(ecds) error parsing interface list\n");
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
            PLOG(PL_ERROR, "SmfApp::OnCommand(forward) invalid argument: %s\n", val);
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
            PLOG(PL_ERROR, "SmfApp::OnCommand(relay) invalid argument: %s\n", val);
            return false;
        }
    }
    else if (!strncmp("delayoff", cmd, len))
    {
        // syntax: "delayoff <value>"
        smf.SetDelayTime(atof(val));
    } 
    else if (!strncmp("hash", cmd, len))
    {
        SmfHash::Type hashType = SmfHash::GetTypeByName(val);
        if (SmfHash::INVALID == hashType)
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(hash) invalid argument: %s\n", val);
            return false;
        }
        if (!smf.SetHashAlgorithm(hashType, false))
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(hash) error: unable to set hash algorithm\n");
            return false;
        }
    }
    else if (!strncmp("ihash", cmd, len))
    {
        SmfHash::Type hashType = SmfHash::GetTypeByName(val);
        if (SmfHash::INVALID == hashType)
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(ihash) invalid argument: %s\n", val);
            return false;
        }
        if (!smf.SetHashAlgorithm(hashType, true))
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(ihash) error: unable to set hash algorithm\n");
            return false;
        }       
    }
    else if (!strncmp("idpd", cmd, len))
    {
        if (!strcmp("on", val))
        {
            smf.SetIdpd(true);
        }
        else if (!strcmp("off", val))
        {
            smf.SetIdpd(false);
        }
        else
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(idpd) invalid argument: %s\n", val);
            return false;
        }
    }
    else if (!strncmp("window", cmd, len))
    {
        if (!strcmp("on", val))
        {
            smf.SetUseWindow(true);
        }
        else if (!strcmp("off", val))
        {
            smf.SetUseWindow(false);
        }
        else
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(window) invalid argument: %s\n", val);
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
                PLOG(PL_ERROR, "SmfApp::OnCommand(resequence) error opening IPv4 detour\n");
                return false;
            }
#ifdef HAVE_IPV6
            hookFlags = detour_ipv6_flags | ProtoDetour::OUTPUT;
            if (ipv6_enabled && !SetupIPv6Detour(hookFlags))
            {
                PLOG(PL_ERROR,  "SmfApp::OnCommand(resequence) error opening IPv6 detour\n"); 
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
                PLOG(PL_ERROR, "SmfApp::OnCommand(resequence) error opening IPv4 detour\n");
                return false;
            }
#ifdef HAVE_IPV6
            hookFlags = detour_ipv6_flags & ~ProtoDetour::OUTPUT;
            if (ipv6_enabled && !SetupIPv4Detour(hookFlags))
            {
                PLOG(PL_ERROR,  "SmfApp::OnCommand(resequence) error opening IPv6 detour\n"); 
                return false; 
            }
#endif // HAVE_IPV6
            resequence = false;
        }
        else
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(resequence) invalid argument: %s\n", val);
            return false;
        }
    }  
    else if (!strncmp("ttl", cmd, len))
    {
        ttl_set = atoi(val);
        // We use the "resequence" command to enable/disable the OUTPUT detour
        // (where outbound packet TTL is set) as needed.
        bool resequenceSaved = resequence;
	    if (!OnCommand("resequence", (resequence || (ttl_set > 0)) ? "on" : "off"))
        {
           PLOG(PL_ERROR, "SmfApp::OnCommand(ipv6) error setting up IPv6 detour for resequencing\n"); 
           return false;
        }      
        resequence = resequenceSaved;  
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
                PLOG(PL_ERROR, "SmfApp::OnCommand(firewallCapture) error opening IPv4 detour\n");
                return false;
            }
#ifdef HAVE_IPV6
            hookFlags = detour_ipv6_flags | ProtoDetour::INPUT;
            if (ipv6_enabled && !SetupIPv6Detour(hookFlags))
            {
                PLOG(PL_ERROR,  "SmfApp::OnCommand(firewallCapture) error opening IPv6 detour\n"); 
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
                PLOG(PL_ERROR, "SmfApp::OnCommand(firewallCapture) error opening IPv4 detour\n");
                return false;
            }
#ifdef HAVE_IPV6
            hookFlags = detour_ipv6_flags & ~ProtoDetour::INPUT;
            if (ipv6_enabled && !SetupIPv4Detour(hookFlags))
            {
                PLOG(PL_ERROR,  "SmfApp::OnCommand(firewallCapture) error opening IPv6 detour\n"); 
                return false; 
            }
#endif // HAVE_IPV6
            firewall_capture = false;
        }
        else
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(firewallCapture) invalid argument: %s\n", val);
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
            PLOG(PL_ERROR, "SmfApp::OnCommand(firewallForward) invalid argument: %s\n", val);
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
            PLOG(PL_ERROR, "SmfApp::OnCommand(firewall) invalid argument: %s\n", val);
            return false;
        }
    }
#endif // _PROTO_DETOUR
    else if (!strncmp("instance", cmd, len))
    {
        if (control_pipe.IsOpen()) control_pipe.Close();
        if (!control_pipe.Listen(val))
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(instance) error opening control pipe\n");
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
                PLOG(PL_ERROR, "SmfApp::OnCommand(instance) error sending hello to smf server\n");
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
            PLOG(PL_ERROR, "SmfApp::OnCommand(boost) error: invalid argument\n");
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
                PLOG(PL_ERROR, "SmfApp::OnCommand(smfServer) error establishing instance name: %s\n", instanceName);
                return false;
            }
        }
        if (server_pipe.Connect(val))
        {
            // Tell the "controller" (server) our control pipe name, if applicable
            if ('\0' != control_pipe_name[0])
            {
                char buffer[256];
                sprintf(buffer, "smfClientStart %s", control_pipe_name);
                unsigned int numBytes = strlen(buffer)+1;
                if (!server_pipe.Send(buffer, numBytes))
                {
                    PLOG(PL_ERROR, "SmfApp::OnCommand(smfServer) error sending hello to smf server\n");
                    return false;  
                }  
            }     
        }      
        else
        {
            PLOG(PL_WARN, "SmfApp::OnCommand(smfServer) warning: unable to connect to smfServer \"%s\"\n", val);
            return true;   
        }  
    }   
    else if (!strncmp("tap", cmd, len))
    {
        if (tap_pipe.IsOpen()) tap_pipe.Close();
        if (!strcmp(val, "off"))
        {
            tap_active = false;
            return true;
        }
        else if (tap_pipe.Connect(val))
        {
            // Tell the remote "tap" process our control pipe name, if applicable
            if ('\0' != control_pipe_name[0])
            {
                char buffer[256];
                sprintf(buffer, "smfClientStart %s", control_pipe_name);
                unsigned int numBytes = strlen(buffer)+1;
                if (!tap_pipe.Send(buffer, numBytes))
                {
                    PLOG(PL_ERROR, "SmfApp::OnCommand(tap) error sending 'smfClientStart' to 'tap' process \"%s\"\n", val);
                    return false;  
                }  
            }  
            tap_active = true;
        }
        else
        {
            PLOG(PL_WARN, "SmfApp::OnCommand(tap) warning: unable to connect to 'tap' process \"%s\"\n", val);
            tap_active = false;
            return true; 
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
            PLOG(PL_ERROR, "SmfApp::OnCommand(log) error opening file:\n", GetErrorString());
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
    ProtoAddressList& addrList = smf.AccessOwnAddressList();
    unsigned int ifCount = 0;
    unsigned int ifArray[IF_COUNT_MAX];
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
        unsigned int ifIndex = ProtoSocket::GetInterfaceIndex(ifName);
        if (0 == ifIndex)
        {
            PLOG(PL_ERROR, "SmfApp::ParseInterfaceList() error: invalid iface name \"%s\"\n", ifName);
            return false;
        }
        // Get "real" ifName for given ifIndex 
        if (!ProtoSocket::GetInterfaceName(ifIndex, ifName, 255))
        {
            PLOG(PL_ERROR, "SmfApp::ParseInterfaceList() error: invalid interface \"%s\"\n", ifName);
            return false;
        }

        Smf::Interface* iface = smf.GetInterface(ifIndex);
        if (NULL == iface)
        {
            if (NULL == (iface = smf.AddInterface(ifIndex)))
            {
                PLOG(PL_ERROR, "SmfApp::ParseInterfaceList(): new Smf::Interface error: %s\n", GetErrorString());
                return false;
            } 
            // Add the MAC (ETH) addr for this iface to our SMF local addr list
            ProtoAddress ifAddr;
            if (!ProtoSocket::GetInterfaceAddress(ifName, ProtoAddress::ETH, ifAddr))
            {
                PLOG(PL_ERROR, "SmfApp::ParseInterfaceList() error: unable to get ETH addr for iface:%s\n", ifName);
                return false;
            }
            if (!smf.AddOwnAddress(ifAddr))
            {
                PLOG(PL_ERROR, "SmfApp::ParseInterfaceList() error: unable to add ETH addr to local addr list.\n");
                return false;
            }
            if (NULL == rt_mgr)
            {
                if (NULL == (rt_mgr = ProtoRouteMgr::Create()))
                {
                    PLOG(PL_ERROR, "SmfApp::ParseInterfaceList(): ProtoRouteMgr::Create() error: %s\n", GetErrorString());
                    return false;        
                }
                if (!rt_mgr->Open())
                {
                    PLOG(PL_ERROR, "SmfApp::ParseInterfaceList() error: unable to open ProtoRouteMgr\n");
                    delete rt_mgr;
                    rt_mgr = NULL;
                    return false;
                }
            }
            rt_mgr->GetInterfaceAddressList(ifIndex, ProtoAddress::IPv4, addrList);
            // Iterate over and add IP addresses for this interface to our SMF local addr list
            if (!rt_mgr->GetInterfaceAddressList(ifIndex, ProtoAddress::IPv4, addrList))
            {
                PLOG(PL_WARN, "SmfApp::ParseInterfaceList() error: couldn't retrieve IPv4 address for iface: %s\n", ifName);
                //return false;
            }
            if (!rt_mgr->GetInterfaceAddressList(ifIndex, ProtoAddress::IPv6, addrList))
            {
                PLOG(PL_WARN, "SmfApp::ParseInterfaceList() error: couldn't retrieve IPv6 address for iface: %s\n", ifName);
                //return false;
            }
            if (addrList.IsEmpty())
            {
                PLOG(PL_WARN, "SmfApp::ParseInterfaceList() error:no IP addresses found for iface: %s\n", ifName);
                return false;
            }
        }  // end if (NULL == iface)
        // Do we already have a "ProtoCap" and/or "ProtoDetour" (as appropriate) for this ifaceIndex?
        InterfaceMechanism* mech = reinterpret_cast<InterfaceMechanism*>(iface->GetUserData());
        if (NULL == mech)
        {
            if (NULL == (mech = new InterfaceMechanism()))
            {
                PLOG(PL_ERROR, "SmfApp::ParseInterfaceList(): new InterfaceMechanism error: %s\n", GetErrorString());
                return false;
            }
            iface->SetUserData(mech);
        }
        // We always open a ProtoCap for each interface to ensure that it is in 
        // promiscuous mode to get packets.  Later, we enable ProtoCap input
        // notification for input interfaces (and remove ProtoCaps for 
        // "firewall_forward" interfaces that are not used for input)
        ProtoCap* cap = mech->GetProtoCap();
        if (NULL == cap)
        {
            if (NULL == (cap = ProtoCap::Create()))
            {
                PLOG(PL_ERROR, "SmfApp::ParseInterfaceList(): ProtoCap::Create() error: %s\n", GetErrorString());
                return false;
            }
            cap->SetListener(this, &SmfApp::OnPktCapture);
            cap->SetNotifier(static_cast<ProtoChannel::Notifier*>(&dispatcher));
            if (!cap->Open(ifName))
            {
                PLOG(PL_ERROR, "SmfApp::ParseInterfaceList(): ProtoCap::Open(%s) error: %s\n", ifName, GetErrorString());
                delete cap;
                return false;
            }
            cap->StopInputNotification();  // will be re-enabled as needed
            mech->SetProtoCap(cap);
        }  // end if (NULL == cap)
        
        if (firewall_forward)
        {	
#ifdef _PROTO_DETOUR
            ProtoDetour* detour = mech->GetProtoDetour();
            if (NULL == detour)
            {
                // Create and open new ProtoDetour for this iface 
                if (NULL == (detour = ProtoDetour::Create()))
                {
                    PLOG(PL_ERROR, "SmfApp::ParseInterfaceList(): ProtoDetour::Create() error: %s\n", GetErrorString());
                    return false;
                }
                detour->SetListener(this, &SmfApp::OnPktIntercept);
                detour->SetNotifier(static_cast<ProtoChannel::Notifier*>(&dispatcher));
                // Open in "inject-only" mode
                if (!detour->Open(ProtoDetour::INJECT))
                {
                    PLOG(PL_ERROR, "SmfApp::ParseInterfaceList(): ProtoDetour::Open(INJECT) error: %s\n", GetErrorString());
                    delete detour;
                    return false;
                }
                if (!detour->SetMulticastInterface(ifName))
                {
                    PLOG(PL_ERROR, "SmfApp::ParseInterfaceList(): ProtoDetour::SetMulticastInterface(%s) failure: %s\n", ifName, GetErrorString());
                    delete detour;
                    return false;
                }
                mech->SetProtoDetour(detour);
            }
#endif // _PROTO_DETOUR
        }
        if (ifCount < IF_COUNT_MAX)
        {
            ifArray[ifCount++] = ifIndex;
        }
        else
        {
            PLOG(PL_ERROR, "SmfApp::ParseInterfaceList() error: IF_COUNT_MAX exceeded!\n");
            return false;
        }  
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
                PLOG(PL_ERROR, "SmfApp::ParseInterfaceList(push/merge) error: insufficient number of ifaces listed\n");
                return false;
            }
            break;
        case RELAY:
            if (ifCount < 1)
            {
                PLOG(PL_ERROR, "SmfApp::ParseInterfaceList() error: insufficient number of ifaces listed\n");
                return false;
            }
            break;
    }
    
    // Now we need to iterate over the listed interfaces and set up input notification for
    // any source interfaces and create appropriate "assocations" to dstIfaces
    for (unsigned int i = 0; i < ifCount; i++)
    {
        unsigned int ifIndex = ifArray[i];
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
                        Smf::Interface::AssociateList::Iterator it(*iface);
                        Smf::Interface::Associate* assoc;
                        while (NULL != (assoc = it.GetNextItem()))
                        {
                            if (assoc->GetInterfaceIndex() == ifIndex)
                            {
                                PLOG(PL_ERROR, "SmfApp::ParseInterfaceList() error: bad 'rpush' configuration from MANET srcIface\n");
                                return false;
                            }
                        }    
                    }                    
                    iface->SetResequence(resequence);
                }
                else 
                {
                    Smf::Interface* srcIface = smf.GetInterface(ifArray[0]);
                    // Add this dstIface as an associate of the "srcIface" 
                    Smf::Interface::Associate* assoc = srcIface->FindAssociate(ifIndex);
                    if (NULL != assoc)
                    {
                        if (Smf::CF != assoc->GetRelayType())
                        {
                            // This association has already been set with different relay rule
                            PLOG(PL_ERROR, "SmfApp::ParseInterfaceList() warning: push iface indices %d->%d config overrides previous command\n",
                                srcIface->GetIndex(), ifIndex);
                            assoc->SetRelayType(Smf::CF);
                        }
                        return false;
                    }
                    else if (!srcIface->AddAssociate(*iface, Smf::CF)) // Use Classical Flooding (CF) algorithm for "push" from srcIface->dstIfaces
                    {
                        PLOG(PL_ERROR, "SmfApp::ParseInterfaceList(): new Smf::Interface::Associate error: %s\n", GetErrorString());
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
                    Smf::Interface::AssociateList::Iterator it(*iface);
                    Smf::Interface::Associate* assoc;
                    while (NULL != (assoc = it.GetNextItem()))
                    {
                        if (assoc->GetInterfaceIndex() == ifIndex)
                        {
                            PLOG(PL_ERROR, "SmfApp::ParseInterfaceList() error: bad 'rmerge' configuration from MANET srcIface\n");
                            return false;
                        }
                    }    
                } 
                iface->SetResequence(resequence);
                // Make this iface an "associate" of all other listed ifaces
                for (unsigned int j = 0 ; j < ifCount; j++)
                {
                    if (i != j)
                    {
                        int dstIfIndex = ifArray[j];
                        Smf::Interface::Associate* assoc = iface->FindAssociate(dstIfIndex);
                        if (NULL != assoc)
                        {
                            if (Smf::CF != assoc->GetRelayType())
                            {
                                // This association has already been set with different relay rule
                                PLOG(PL_ERROR, "SmfApp::ParseInterfaceList() warning: merge iface indices %d->%d config overrides previous command\n",
                                        ifIndex, dstIfIndex);
                                assoc->SetRelayType(Smf::CF);
                            }
                        }
                        else
                        {
                            Smf::Interface* dstIface = smf.GetInterface(ifArray[j]);
                            ASSERT(NULL != dstIface);
                            // Use Classical Flooding (CF) algorithm for "merge" from each iface->dstIfaces
                            if (!iface->AddAssociate(*dstIface, Smf::CF))
                            {
                                PLOG(PL_ERROR, "SmfApp::ParseInterfaceList(): new Smf::Interface::Associate error: %s\n", GetErrorString());
                                return false;
                            }
                        }    
                    }
                }
                break;
            case RELAY:
                // Make sure this iface hasn't been previously set as a rpush or rmerge srcIface
                if (iface->GetResequence())
                {
                    PLOG(PL_ERROR, "SmfApp::ParseInterfaceList() error: MANET iface config conflicts with previous rpush or rmerge config!\n");
                    return false;
                }
                ASSERT(!resequence);
                iface->SetResequence(resequence);  
                // Make this iface an "associate" of itself and all other listed ifaces
                for (unsigned int j = 0 ; j < ifCount; j++)
                {
                    int dstIfIndex = ifArray[j];
                    Smf::Interface::Associate* assoc = iface->FindAssociate(dstIfIndex);
                    if (NULL != assoc)
                    {
                        if (assoc->GetRelayType() != relayType)
                        {
                            // This association has already been set with different relay rule
                            PLOG(PL_WARN, "SmfApp::ParseInterfaceList() warning: manet relay iface indices %d->%d config overrides previous command\n",
                                    ifIndex, dstIfIndex);
                            assoc->SetRelayType(relayType);
                        }
                    }
                    else
                    {
                        Smf::Interface* dstIface = smf.GetInterface(ifArray[j]);
                        ASSERT(NULL != dstIface);
                        // Use Classical Flooding (CF) algorithm for "merge" from each iface->dstIfaces
                        if (!iface->AddAssociate(*dstIface, relayType))
                        {
                            PLOG(PL_ERROR, "SmfApp::ParseInterfaceList(): new Smf::Interface::Associate error: %s\n", GetErrorString());
                            return false;
                        } 
                    }
                }
                break;
        }  // end switch (mode)
    }  // end for (unsigned int i = 0 ; i < ifCount; i++)
    
    // This loop iterates through the listed interfaces and updates
    // their ProtoCap status depending on if the interface is using
    // the ProtoCap for packet capture and/or forwarding.  Even if the
    // ProtoCap isn't used for capture, a ProtoCap may be needed
    // to force the interface into promiscuous mode so that 
    // "firewallCapture" has a chance to get packets of interest.
    for (unsigned int i = 0; i < ifCount; i++)
    {
        unsigned int ifIndex = ifArray[i];
        Smf::Interface* iface = smf.GetInterface(ifIndex);
        ASSERT(NULL != iface);
        if (iface->HasAssociates()) // it's an input interface
        {
            if (!firewall_capture)
            {
                InterfaceMechanism* mech = reinterpret_cast<InterfaceMechanism*>(iface->GetUserData());
                ProtoCap* cap = mech->GetProtoCap();
                ASSERT(NULL != cap);
                cap->StartInputNotification();  // (TBD) error check?
            }
        }
        else if (firewall_forward)
        {
            // output-only, firewall_forward interface
            // (no ProtoCap needed at all)
            InterfaceMechanism* mech = reinterpret_cast<InterfaceMechanism*>(iface->GetUserData());
            ProtoCap* cap = mech->GetProtoCap();
            ASSERT(NULL != cap);
            cap->Close();
            delete cap;
            mech->SetProtoCap(NULL);
            ASSERT(NULL != mech->GetProtoDetour());
        }
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
	            PLOG(PL_INFO,"SmfApp::OnControlMsg() recv'd %d byte message from controller \"%s\" "
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
            // Check for a pipe only commands first
            if (!strncmp(cmd, "smfPkt", cmdLen))
            {
                PLOG(PL_TRACE, "SmfApp::OnControlMsg() recv'd \"smfPkt\" message ...\n");
                // Extract "dstIfIndices" list from message header
                unsigned int indexCount = (unsigned int)buffer[7];
                if (indexCount <= 1)
                {
                    PLOG(PL_WARN, "SmfApp::OnControlMsg(smfPkt) warning: received smfPkt with ZERO dstCount\n");
                    return;
                }
                ASSERT(indexCount <= IF_COUNT_MAX);
                UINT8* indexPtr = (UINT8*)(buffer + 8);
                // Note "indexPtr[0]" is srcIfIndex ...
                unsigned int dstIfIndices[IF_COUNT_MAX];
                for (unsigned int i = 1; i < indexCount; i++)
                    dstIfIndices[i - 1] = (unsigned int)indexPtr[i];
                unsigned int dstCount = indexCount - 1;
                unsigned int msgHdrLen = 7 + 1 + indexCount;
#ifdef _PROTO_DETOUR
                if (firewall_forward)
                {
                    if (!ForwardPacket(dstCount, dstIfIndices, buffer+msgHdrLen+ProtoPktETH::HDR_LEN, len-msgHdrLen-ProtoPktETH::HDR_LEN))
                        PLOG(PL_ERROR, "SmfApp::OnControlMsg(smfPkt) error: unable to firewall forward packet\n");
                }
                else          
#endif
                {
                    if (!ForwardFrame(dstCount, dstIfIndices, buffer+msgHdrLen, len-msgHdrLen))
                        PLOG(PL_ERROR, "SmfApp::OnControlMsg(smfPkt) error: unable to forward packet\n");
                }
            }
            else if (!strncmp(cmd, "smfServerStart", cmdLen))
            {
                if (server_pipe.IsOpen()) server_pipe.Close();
                if (!server_pipe.Connect(arg))
                    PLOG(PL_ERROR, "SmfApp::OnControlMsg(smfServerStart) error connecting to smf server\n");
            }
            else if (!strncmp(cmd, "selectorMac", cmdLen))
            {
                // The "arg" points to the current set of MPR selector MAC addresses
                // Overwrite our current selector list
                if (argLen > Smf::SELECTOR_LIST_LEN_MAX)
                {
                    PLOG(PL_ERROR, "SmfApp::OnControlMsg(selectorMac) error: selector list too long!\n");
                    // (TBD) record this error indication permanently
                    argLen = Smf::SELECTOR_LIST_LEN_MAX;
                }
                smf.SetSelectorList(arg, argLen);
            }  
            else if (!strncmp(cmd, "neighborMac", cmdLen) || !strncmp(cmd, "symetricMac", cmdLen))
            {
                // The "arg" points to the current set of symetric neighbor MAC addresses
                // Overwrite our current symmetric list
                if (argLen > Smf::SELECTOR_LIST_LEN_MAX)
                {
                    PLOG(PL_ERROR, "SmfApp::OnControlMsg(neighborMac) error: symmetric list too long!\n");
                    // (TBD) record this error indication permanently
                    argLen = Smf::SELECTOR_LIST_LEN_MAX;
                }
                smf.SetNeighborList(arg, argLen);
            }  
#ifdef MNE_SUPPORT
            else if (!strncmp(cmd, "mneBlockMac", cmdLen))
            {
                // The "arg" points to the current set of MPR mneBlock MAC addresses
                // Overwrite our current mneBlock list
                if (argLen > Smf::SELECTOR_LIST_LEN_MAX)
                {
                    PLOG(PL_ERROR, "SmfApp::OnControlMsg(mneBlockMac) error: mac list too long!\n");
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
                    PLOG(PL_ERROR, "SmfApp::OnControlMsg() invalid command: \"%s\"\n", cmd);
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

void SmfApp::OnPktCapture(ProtoChannel&              theChannel,
	                      ProtoChannel::Notification notifyType)
{
    // We only care about NOTIFY_INPUT events (all we should get anyway)
    switch (notifyType)
    {
        case ProtoChannel::NOTIFY_INPUT:
        {
            break;
        }
        case ProtoChannel::NOTIFY_OUTPUT:
        {
            // TBD - dequeue a packet and forward
            ProtoCap& cap = static_cast<ProtoCap&>(theChannel);
            cap.StopOutputNotification();
            TRACE("SmfApp::OnPktCapture() output ready notification!\n");
            return;
        }
        default:
        {
            return;
        }
    }
    ProtoCap& cap = static_cast<ProtoCap&>(theChannel);
    unsigned int srcIfIndex = cap.GetInterfaceIndex();
    
    // Note: We offset the buffer by 2 bytes since Ethernet header is 14 bytes
    //       (i.e. not a multiple of 4 (sizeof(UINT32))
    //       This gives us a properly aligned buffer for 32-bit aligned IP packets
    //      (The 256*sizeof(UINT32) bytes are for potential "smfPkt" message header use)
    UINT32  alignedBuffer[BUFFER_MAX/sizeof(UINT32)];
    UINT16* ethBuffer = ((UINT16*)(alignedBuffer+256)) + 1; // offset by 2-bytes so IP content is 32-bit aligned
    const unsigned int ETHER_BYTES_MAX = (BUFFER_MAX - 256*sizeof(UINT32) - 2);
    UINT32* ipBuffer = (alignedBuffer + 256) + 4; // offset by ETHER header size + 2 bytes
    const unsigned int IP_BYTES_MAX = (ETHER_BYTES_MAX - 14);
    while(1) 
    {
        // Read in and handle all inbound captured packets
        unsigned int numBytes = ETHER_BYTES_MAX;
	    ProtoCap::Direction direction;
        if (!cap.Recv((char*)ethBuffer, numBytes, &direction))
        {
    	    PLOG(PL_ERROR, "SmfApp::OnPktCapture() ProtoCap::Recv() error\n");
    	    break;
        }
	    if (numBytes == 0) break;  // no more packets to receive
        if (ProtoCap::INBOUND != direction) continue;  // only handle inbound packets
        
        HandleInboundPacket(alignedBuffer, numBytes, srcIfIndex);
        
    }  // end while(1)  (reading ProtoTap device loop)
}  // end SmfApp::OnPktCapture()

static unsigned int successCount = 0;

// Forward IP packet encapsulated in ETH frame using "ProtoCap" (i.e. pcap or similar) device
bool SmfApp::ForwardFrame(unsigned int dstCount, unsigned int* dstIfIndices, char* frameBuffer, unsigned int frameLength)
{
    bool result = false;
    for (unsigned int i = 0; i < dstCount; i++)
    {
        int dstIfIndex = dstIfIndices[i];
        Smf::Interface* dstIface = smf.GetInterface(dstIfIndex);
        InterfaceMechanism* mech = reinterpret_cast<InterfaceMechanism*>(dstIface->GetUserData());
        ProtoCap* dstCap = mech->GetProtoCap();
        ASSERT(NULL != dstCap);
        // Note that the MAC header is needed here (srcMacAddr portion is modified!)
        if (dstCap->OutputNotification())
        {
            
            // dstIface->EnqueueFrame(frameBuffer, frameLength, pkt_pool);
            
            // We're still waiting for the output to be available
            // TBD - enqueue the packet
            PLOG(PL_ERROR, "SmfApp::ForwardFrame() error: can't yet send frame via iface index: %d\n", dstIfIndex);
            serr_count++;  // (TBD) set or increment "smf" send error count instead?
        }
        else if (!dstCap->Forward(frameBuffer, frameLength))
        {
            PLOG(PL_ERROR, "SmfApp::ForwardFrame() error: unable to send frame via iface index: %d (scount:%u)\n", dstIfIndex, successCount);
            serr_count++;  // (TBD) set or increment "smf" send error count instead?
            successCount = 0;
            dstCap->StartOutputNotification();
        }
        else
        {
            successCount++;
            result = true;  // forwarded on at least one iface
        }
    }
    return result;
}  // end SmfApp::ForwardFrame()

// Forward IP packet encapsulated in ETH frame using "ProtoCap" (i.e. pcap or similar) device
bool SmfApp::ForwardFrameToTap(unsigned int srcIfIndex, unsigned int dstCount, unsigned int* dstIfIndices, char* frameBuffer, unsigned int frameLength)
{
    // "smfPkt" header size = 7 bytes for "smfPkt " plus 1 byte of "indexCount" plus
    // one byte of "srcIfaceIndex" plus <dstCount> bytes of dstIfIndices 
    // 1) Build an "smfPkt" message header to send message to "tap" process
    unsigned int msgHdrLen = 7 + 1 + 1 + dstCount;
    char* msgBuffer = frameBuffer - msgHdrLen;
    sprintf(msgBuffer, "smfPkt ");
    msgBuffer[7] = (UINT8)(dstCount + 1);
    msgBuffer[8] = (UINT8)srcIfIndex;
    for (unsigned int i = 0; i < dstCount; i++)
        msgBuffer[i + 9] = (UINT8)dstIfIndices[i];
    // 2) Send the message to the "tap" process
    unsigned int numBytes = frameLength + msgHdrLen;
    return tap_pipe.Send(msgBuffer, numBytes);
}  // end SmfApp::ForwardFrameToTap()


void SmfApp::HandleInboundPacket(UINT32* alignedBuffer, unsigned int numBytes, unsigned int srcIfIndex)
{
    // NOTE:  The "alignedBuffer" has 256*4 + 2 bytes of extra space at head for an "smfPkt" header to be
    //        be prepended by "ForwardToTap()" if needed.  The "ethBuffer" is a UINT16 pointer offset
    //        by 2 from the "alignedBuffer" so the Ethernet IP packet payload is properly aligned
    //        (The pointers and max sizes here take all of this into account)
    
    UINT16* ethBuffer = ((UINT16*)(alignedBuffer+256)) + 1; // offset by 2-bytes so IP content is 32-bit aligned
    const unsigned int ETHER_BYTES_MAX = (BUFFER_MAX - 256*sizeof(UINT32) - 2);
    UINT32* ipBuffer = (alignedBuffer + 256) + 4; // offset by ETHER header size + 2 bytes
    const unsigned int IP_BYTES_MAX = (ETHER_BYTES_MAX - 14);
    
    // Map ProtoPktETH instance into buffer and init for processing
    ProtoPktETH ethPkt((UINT32*)ethBuffer, ETHER_BYTES_MAX);
    if (!ethPkt.InitFromBuffer(numBytes))
    {
        PLOG(PL_ERROR, "SmfApp::HandleInboundPacket() error: bad Ether frame\n");
        return;
    }
    // Only process IP packets (skip others)
    ProtoPktETH::Type ethType = (ProtoPktETH::Type)ethPkt.GetType();
    if ((ethType != ProtoPktETH::IP) && (ethType != ProtoPktETH::IPv6)) return;
    ProtoPktIP ipPkt(ipBuffer, IP_BYTES_MAX);
    if (!ipPkt.InitFromBuffer(ethPkt.GetPayloadLength()))
    {
        PLOG(PL_ERROR, "SmfApp::HandleInboundPacket() error: bad IP packet\n");
        return;
    }
    ProtoAddress srcMacAddr;
    ethPkt.GetSrcAddr(srcMacAddr);
        
#ifdef MNE_SUPPORT
    // In "MNE" environment, ignore packets from blocked MAC sources
    if ((0 != mne_block_list_len) &&
        (MneIsBlocking(srcMacAddr.GetRawHostAddress())))
            return;  // ignore packets blocked by MNE
#endif // MNE_SUPPORT
    
    unsigned int dstIfIndices[IF_COUNT_MAX];
    int dstCount = smf.ProcessPacket(ipPkt, srcMacAddr, srcIfIndex, dstIfIndices, IF_COUNT_MAX);
    if (dstCount > 0)
    {
        // If the "tap" (diversion to another process) has been activated, pass the packet that
        // would have been forwarded this process.  That process may filter the packet and use 
        // the "smfInject" command to return the packet to "nrlsmf" for final forwarding.
        if (tap_active)
        {
            // To save on byte copying, we left space at the beginning of our "alignedBuffer"
            // for the "smfPkt" message header in case it is needed.
            if (!ForwardFrameToTap(srcIfIndex, dstCount, dstIfIndices, (char*)ethBuffer, ipPkt.GetLength() + ProtoPktETH::HDR_LEN))
            {
                PLOG(PL_ERROR, "SmfApp::HandleInboundPacket() error: unable to forward packet to \"tap\" process\n");
            }
        } 
#ifdef _PROTO_DETOUR
        else if (firewall_forward)
        {
            if (!ForwardPacket(dstCount, dstIfIndices, (char*)ipPkt.GetBuffer(), ipPkt.GetLength()))
            {
                PLOG(PL_ERROR, "SmfApp::HandleInboundPacket() error: unable to forward packet via ProtoDetour\n");
            } 
        }
#endif // _PROTO_DETOUR
        else
        {
            if (!ForwardFrame(dstCount, dstIfIndices, (char*)ethBuffer, ProtoPktETH::HDR_LEN + ipPkt.GetLength()))
            {
                PLOG(PL_ERROR, "SmfApp::HandleInboundPacket() error: unable to forward packet via ProtoCap device\n");
            }
        }
    }  // end if (dstCount > 0)
    
}  // end SmfApp::HandleInboundPacket()

#ifdef _PROTO_DETOUR

// Forward IP packet by injecting through "firewall" or IP raw socket device (ProtoDetour)
// (NOTE: This is used ONLY when the "firewallForward" option is used!!!)
bool SmfApp::ForwardPacket(unsigned int dstCount, unsigned int* dstIfIndices, char* pktBuffer, unsigned int pktLength)
{
    bool result = false;
    for (int i = 0; i < dstCount; i++)
    {
        int dstIfIndex = dstIfIndices[i];
        Smf::Interface* dstIface = smf.GetInterface(dstIfIndex);
        InterfaceMechanism* mech = reinterpret_cast<InterfaceMechanism*>(dstIface->GetUserData());
        ProtoDetour* dstDetour = mech->GetProtoDetour();
        ASSERT(NULL != dstDetour);
        // Only the IP portion of the capture frame is injected 
        if (!dstDetour->Inject(pktBuffer, pktLength))
        {
            PLOG(PL_ERROR, "SmfApp::ForwardPacket() error: unable to send packet via iface index: %d\n", dstIfIndex);
            serr_count++;  // (TBD) set or increment "smf" send error count instead?
        }
        else
        {
            result = true;  // forwarded on at least one iface
        }
    }
    return result;  
}  // end SmfApp::ForwardPacket()


void SmfApp::OnPktIntercept(ProtoChannel&               theChannel, 
                            ProtoChannel::Notification  theNotification)
{
    if (ProtoChannel::NOTIFY_INPUT == theNotification)
    {
        ProtoDetour& detour = static_cast<ProtoDetour&>(theChannel);
        ProtoDetour::Direction direction;
        
        // Note: We offset the buffer by 2 bytes since Ethernet header is 14 bytes
        //       (i.e. not a multiple of 4 (sizeof(UINT32))
        //       This gives us a properly aligned buffer for 32-bit aligned IP packets
        //      (The extra 256*sizeof(UINT32) bytes are for potential "smfPkt" message header use)
        UINT32  alignedBuffer[BUFFER_MAX/sizeof(UINT32)];
        UINT16* ethBuffer = ((UINT16*)(alignedBuffer+256)) + 1; // offset by 2-bytes so IP content is 32-bit aligned
        const unsigned int ETHER_BYTES_MAX = (BUFFER_MAX - 256*sizeof(UINT32) - 2);
        UINT32* ipBuffer = (alignedBuffer + 256) + 4; // offset by ETHER header size + 2 bytes
        const unsigned int IP_BYTES_MAX = (ETHER_BYTES_MAX - 14);
        
        unsigned int numBytes = IP_BYTES_MAX;
	    ProtoAddress srcMacAddr;
        unsigned int ifIndex;
        // TBD - should this be a "while" loop for efficiency?
        if (detour.Recv((char*)ipBuffer, numBytes, &direction, &srcMacAddr, &ifIndex))
        {
            if (0 != numBytes)
            {
                ProtoPktIP ipPkt(ipBuffer, IP_BYTES_MAX);
                ProtoAddress srcAddr, dstAddr;
                switch (direction)
                {
                    case ProtoDetour::OUTBOUND:
                    {
                        if (!resequence && (ttl_set < 0)) 
                        {
                            PLOG(PL_WARN, "SmfApp::OnPktIntercept() warning: intercepted OUTBOUND packet, but resequence disabled?!\n");
                            break;
                        }
                        // For OUTBOUND packets, modify ID field (IPv4)
                        // or add DPD option (IPv6) for 
                        // locally-generated, globally-scoped
                        // multicast packets
                        if (!ipPkt.InitFromBuffer(numBytes))
                        {
                            PLOG(PL_WARN, "SmfApp::OnPktIntercept() warning: bad IP packet size\n");
                            break;
                        }
                        unsigned char version = ipPkt.GetVersion();
                        if (4 == version)
                        {
                            ProtoPktIPv4 ip4Pkt(ipPkt);
                            ip4Pkt.GetDstAddr(dstAddr);
                            if (!dstAddr.IsMulticast()) // resequence only multicast packets
                            {
                                PLOG(PL_TRACE, "SmfApp::OnPktIntercept() skipping non-multicast IPv4 pkt\n");
                                break;
                            }
                            if (dstAddr.IsLinkLocal()) // don't resequence if link-local dst
                            {
                                PLOG(PL_TRACE, "SmfApp::OnPktIntercept() skipping link-local multicast IPv4 pkt\n");
                                break;
                            }
                            ip4Pkt.GetSrcAddr(srcAddr);
                            if (srcAddr.IsLinkLocal())  // don't resequence if link-local src
                            {
                                PLOG(PL_TRACE, "SmfApp::OnPktIntercept() skipping link-local sourced IPv4 pkt\n");
                                break;
                            }
                            if (!smf.IsOwnAddress(srcAddr)) // resequence only locally-generated packets
                            {
                                PLOG(PL_TRACE, "SmfApp::OnPktIntercept() skipping non-locally-generated IPv4 pkt\n");
                                break;
                            }
                            // Resequence IPv4 ID field using "local" sequence no. on a "per dstAddr" basis
                            // (TBD) increment on a proto:srcAddr:dstAddr basis (srcAddr could be implicit?)
                            if (resequence)
                                ip4Pkt.SetID(smf.IncrementIPv4LocalSequence(&dstAddr), true);  
                            if (ttl_set >= 0)
                                ip4Pkt.SetTTL((UINT8)ttl_set, true);
                        }
                        else if (6 == version)
                        {
                            ProtoPktIPv6 ip6Pkt(ipPkt);
                            ip6Pkt.GetDstAddr(dstAddr);
                            if (!dstAddr.IsMulticast()) // resequence only multicast packets
                            {
                                PLOG(PL_TRACE, "SmfApp::OnPktIntercept() skipping non-multicast IPv6 pkt\n");
                                break;
                            }
                            if (dstAddr.IsLinkLocal()) // don't resequence if link-local dst
                            {
                                PLOG(PL_TRACE, "SmfApp::OnPktIntercept() skipping link-local multicast IPv6 pkt\n");
                                break;
                            }
                            ip6Pkt.GetSrcAddr(srcAddr);
                            if (srcAddr.IsLinkLocal())  // don't resequence if link-local src
                            {
                                PLOG(PL_TRACE, "SmfApp::OnPktIntercept() skipping link-local sourced IPv6 pkt\n");
                                break;
                            }
                            if (!smf.IsOwnAddress(srcAddr)) // resequence only locally-generated packets
                            {
                                PLOG(PL_TRACE, "SmfApp::OnPktIntercept() skipping non-locally-generated IPv6 pkt\n");
                                break;
                            }
                            
                            if (ttl_set >= 0)
                                ip6Pkt.SetHopLimit((UINT8)ttl_set);
                            
                            if (ip6Pkt.GetHopLimit() <= 1)
                            {
                                // Don't add DPD to packets w/ hopLimit <= 1
                                break;
                            }
                            
                            char flowId[64];
                            unsigned int flowIdSize = 8*64;
                            char pktId[64];
                            unsigned int pktIdSize = 8*64;
                            
                            if (!smf.ResequenceIPv6(ip6Pkt, flowId, &flowIdSize, pktId, &pktIdSize))
                            {
                                PLOG(PL_WARN, "SmfApp::OnPktIntercept() warning: unable to properly resequence outbound IPv6 pkt\n");
                            }
                            // Update "numBytes" to reflect possibly modified packet size
                            // (Note: packet size may have been modified even if
                            //  Smf::ResequenceIPv6() returned false
                            numBytes = ip6Pkt.GetLength();
                        }
                        else
                        {
                            PLOG(PL_WARN, "SmfApp::OnPktIntercept() warning: bad IP packet version\n");
                        }
                        break;
                    }  // end case ProtoDetour:OUTBOUND
                    case ProtoDetour::INBOUND:
                    {
                        if (!firewall_capture) 
                        {
                            PLOG(PL_WARN, "SmfApp::OnPktIntercept() warning: intercepted INBOUND packet, but firewall_capture disabled?!\n");
                            break;
                        }
                        if (!ipPkt.InitFromBuffer(numBytes))
                        {
                            PLOG(PL_WARN, "SmfApp::OnPktIntercept() warning: bad IP packet size\n");
                            break;
                        }
                        // Build Ethernet MAC header for possible TAP or ProtoCap forwarding
                        // (TBD - maybe we will avoid this in the future if all of our downstream
                        //        packet handling is just uses IP packet and a little meta data (src ifIndex and macAddr, etc)
                        ProtoPktETH ethPkt((UINT32*)ethBuffer, ETHER_BYTES_MAX);
                        ProtoAddress dstIpAddr;
                        ProtoPktETH::Type protocolType = ProtoPktETH::IP;
                        switch (ipPkt.GetVersion())
                        {
                            case 4:
                            {
                                ProtoPktIPv4 ip4Pkt(ipPkt);
                                ip4Pkt.GetDstAddr(dstIpAddr);
                                break;
                            }
                            case 6:
                            {
                                protocolType = ProtoPktETH::IPv6;
                                ProtoPktIPv6 ip6Pkt(ipPkt);
                                ip6Pkt.GetDstAddr(dstIpAddr);
                                break;
                            }
                            default:
                            {
                                // Should never get here
                                ASSERT(0);
                                break;
                            }
                        }
                        ethPkt.SetSrcAddr(srcMacAddr);
                        ProtoAddress dstMacAddr;
                        dstMacAddr.GetEthernetMulticastAddress(dstIpAddr);
                        ethPkt.SetDstAddr(dstMacAddr);
                        ethPkt.SetType(protocolType);  
                        ethPkt.SetPayloadLength(numBytes);
                        HandleInboundPacket(alignedBuffer, ethPkt.GetLength(), ifIndex);
                        break;
                    }  // end case ProtoDetour:INBOUND   
                    default:
                        PLOG(PL_WARN, "SmfApp::OnPktIntercept() warning: ambiguous packet capture 'direction'\n");
                        break;
                }
                detour.Allow((char*)ipBuffer, numBytes);
                
                
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
            PLOG(PL_ERROR, "SmfApp::OpenIPv4Detour() new ProtoDetour error: %s\n", GetErrorString());
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
        PLOG(PL_ERROR, "SmfApp::OpenIPv4Detour() error opening IPv4 detour\n");
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
            PLOG(PL_ERROR, "SmfApp::OpenIPv4Detour() new ProtoDetour error: %s\n", GetErrorString());
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
        PLOG(PL_ERROR, "SmfApp::OpenIPv6Detour() error opening IPv6 detour\n");
        return false;
    }
    detour_ipv6_flags = hookFlags;
    return true;;
}  // end SmfApp::SetupIPv6Detour()
#endif  // HAVE_IPV6
#endif // _PROTO_DETOUR
