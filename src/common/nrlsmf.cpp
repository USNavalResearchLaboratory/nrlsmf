#include "smfVersion.h"

#include "smf.h"
#include "smfHash.h"
#include "smfConfig.h"
#include "smfDupTree.h"

// maximum allowed packet size including MAC, IP, etc. headers
#define FRAME_SIZE_MAX 4096

#if defined(ELASTIC_MCAST) || defined(ADAPTIVE_ROUTING)
#include "mcastFib.h"
#ifdef ADAPTIVE_ROUTING
#include "smartController.h"
#include "smartForwarder.h"
#endif // ADAPTIVE_ROUTING
#endif // ELASTIC_MCAST

#include "protoApp.h"
#include "protoSocket.h"
#include "protoPipe.h"
#include "protoCap.h"
#include "protoVif.h"
#include "protoPktETH.h"
#include "protoPktIP.h"
#include "protoPktIGMP.h"
#include "protoNet.h"
#include "protoRouteTable.h"
#include "protoRouteMgr.h"
#include "protoString.h"

#if !defined(WIN32) && !defined(ANDROID) && !defined(ELASTIC_MCAST)
// Note: WIN32 and ANDROID ProtoDetour support is TBD
#include "protoDetour.h"
#endif // !WIN32 && !ANDROID

#ifdef WIN32
#include <IPTypes.h> // for MAX_ADAPTER_NAME_LENGTH
#endif

#include <stdlib.h>  // for atoi()
#include <stdio.h>   // for stdout/stderr printouts
#include <string.h>
#include <ctype.h>  // for "isspace()"

#include <string.h>
#include <stdio.h>

class SmfApp : public ProtoApp
#ifdef ELASTIC_MCAST
    , public ElasticMulticastForwarder::OutputMechanism
#endif // ELASTIC_MCAST
#ifdef ADAPTIVE_ROUTING
    , public SmartForwarder::OutputMechanism
#endif // ADAPTIVE_ROUTING
{
    public:
        SmfApp();
        ~SmfApp();

        // Overrides from ProtoApp or NsProtoSimAgent base
        bool OnStartup(int argc, const char*const* argv);
        bool ProcessCommands(int argc, const char*const* argv);
        void OnShutdown();

        // This is used by ElasticMulticastForwarder to send EM_ACKs, etc
        bool SendFrame(unsigned int ifaceIndex, char* buffer, unsigned int length);

    private:
        void MonitorEventHandler(ProtoChannel&               theChannel,
                                 ProtoChannel::Notification  theNotification);

        static const char* DEFAULT_INSTANCE_NAME;
        static const char* DEFAULT_SMF_SERVER;

        enum {IF_COUNT_MAX = 256};

        enum CmdType {CMD_INVALID, CMD_ARG, CMD_NOARG};
        static const char* const CMD_LIST[];
        static CmdType GetCmdType(const char* string);
        bool OnCommand(const char* cmd, const char* val);
        static void Usage();

        bool LoadConfig(const char* configPath);
        bool ProcessGroupConfig(ProtoJson::Object& groupConfig);
        bool ProcessInterfaceConfig(ProtoJson::Object& ifaceConfig);
        bool SaveConfig(const char* configPath);

        bool EnableEncapsulation(const char* ifaceList);

        bool ParseRouteList(const char* routeList);

        class InterfaceMatcher;

        void ParseDSCPList(const char* strDSCPList, int cmd);

        Smf::InterfaceGroup* GetInterfaceGroup(const char*         groupName,
                                               Smf::Mode           mode,
                                               Smf::RelayType      relayType,
                                               bool                rseq,
                                               bool                tunnel = false,
                                               InterfaceMatcher*   matcher = NULL,
                                               bool                isTemplate = false);

        bool ParseInterfaceList(const char*         ifaceGroupName,
                                Smf::Mode           mode,
                                const char*         ifaceList,
                                Smf::RelayType      relayType,
                                bool                rseq,
                                bool                tunnel  = false,
                                InterfaceMatcher*   matcher = NULL);

        bool ParseInterfaceName(Smf::InterfaceGroup&    ifaceGroup,
                                const char*             ifaceName,
                                bool                    isSourceIface);

        Smf::Interface* GetInterface(const char* ifaceName, unsigned int ifIndex = 0);

        bool AddInterfaceToGroup(Smf::InterfaceGroup& ifaceGroup, Smf::Interface& iface, bool isSourceIface);

        bool MatchInterface(InterfaceMatcher&       ifaceMatcher,
                            const char*             ifName,
                            unsigned int            ifIndex);

        bool MatchExistingInterfaces(InterfaceMatcher& ifaceMatcher);

        bool UpdateGroupAssociations(Smf::InterfaceGroup& ifaceGroup);

        bool RemoveInterfaces(const char* ifaceList);

        bool RemoveInterface(Smf::InterfaceGroup* ifaceGroup, const char* ifaceName);

        void RemoveMatchers(const char* groupName);
    
        unsigned int OpenDevice(const char* vifName, const char* ifaceName, const char* addrList, 
                                bool shadow = false, bool blockIGMP = false);
        Smf::Interface* AddDevice(const char* vifName, const char* ifaceName, bool stealAddrs);
        Smf::Interface* CreateDevice(const char* vifName);
        unsigned int AddCidElement(const char* deviceName, const char* ifaceName, int flags, unsigned int vifIndex);
        bool RemoveCidElement(const char* deviceName, const char* ifaceName);
        bool TransferAddresses(unsigned int vifIndex, unsigned int ifaceIndex);
        bool AssignAddresses(const char* ifaceName, unsigned int ifaceIndex, const char* addrList);
        
        
#if defined (BLOCK_ICMP) && defined(LINUX)
        static bool BlockICMP(const char* ifaceName, bool enable);
#endif  // BLOCK_ICMP && LINUX

        static const unsigned int BUFFER_MAX;

        void OnPktCapture(ProtoChannel&              theChannel,
	                      ProtoChannel::Notification notifyType);

        void OnPktOutput(ProtoChannel&              theChannel,
	                     ProtoChannel::Notification notifyType);

        bool HandleInboundPacket(UINT32* alignedBuffer, unsigned int numBytes, ProtoCap& srcCap);

        void HandleIGMP(ProtoPktIGMP igmpMsg, Smf::Interface& iface, bool inbound);

        static bool IsPriorityFrame(UINT32* frameBuffer, unsigned int frameLength);

        bool ForwardFrame(unsigned int dstCount, unsigned int* dstIfIndices, char* frameBuffer, unsigned int frameLength);
        bool SendFrame(Smf::Interface& iface, char* frameBuffer, unsigned int frameLength);
        bool ForwardFrameToTap(unsigned int srcIfIndex, unsigned int dstCount, unsigned int* dstIfIndices, char* frameBuffer, unsigned int frameLength);

        void OnControlMsg(ProtoSocket&       thePipe,
                          ProtoSocket::Event theEvent);

        bool OnIgmpQueryTimeout(ProtoTimer& theTimer);

        void DisplayGroups();

        // "Composite Interface Device" element
        class CidElement : public ProtoList::Item
        {
            public:
                enum Flag
                {
                    CID_RX = 0x01,
                    CID_TX = 0x02
                };
                CidElement(ProtoCap& protoCap, int flags = CID_TX | CID_RX);
                ~CidElement();
                
                ProtoCap& GetProtoCap()
                    {return proto_cap;}
                    
                unsigned int GetInterfaceIndex() const
                    {return proto_cap.GetInterfaceIndex();}

                bool FlagIsSet(Flag flag) const
                    {return (0 != (flag & cid_flags));}
                    
                void SetFlag(Flag flag)
                    {cid_flags |= flag;}    
                    
                void SetFlags(int flags) 
                    {cid_flags = flags;}
                    
                void ClearFlag(Flag flag)
                    {cid_flags &= ~flag;}

            private:
                ProtoCap&       proto_cap;
                int             cid_flags;
        };  // end class SmfApp::CidElement

        class CidElementList : public ProtoListTemplate<CidElement> {};

        // This class contains pointers to classes that provide
        // any I/O (input/output) mechanism for an nrlsmf interface
        class InterfaceMechanism : public Smf::Interface::Extension
        {
            public:
                InterfaceMechanism(Smf::Interface& iface, SmfPacket::Pool& pktPool);
                ~InterfaceMechanism();
                
                Smf::Interface& GetInterface() {return smf_iface;}

                void CloseDevice();
                void Close();
                
                void SetProtoVif(ProtoVif* protoVif)
                    {proto_vif = protoVif;}
                ProtoVif* GetProtoVif() const
                    {return proto_vif;}
                    
                // If "is_shadowing", a smf vif "device" uses the underlying
                // interface addressing (MAC and IP) for its transmissions
                void SetShadowing(bool state)
                    {is_shadowing = state;}
                bool IsShadowing() const
                    {return is_shadowing;}
                
                // Controls blocking of outbound IGMP messages
                // (Only applies to nrlsmf "device" interfaces running elastic mcast)
                void SetBlockIGMP(bool state)
                    {block_igmp = state;}
                bool BlockIGMP() const
                    {return block_igmp;}

                // Adds a "rx-only" Composite Interface Device element
                bool AddCidElement(ProtoCap& protoCap, int flags);// = CidElement::CID_RX);
                
                void RemoveCidElement(unsigned int capIndex);
                
                CidElement* GetPrincipalElement() {return cid_list.GetHead();}
                
#ifdef _PROTO_DETOUR
                void SetProtoDetour(ProtoDetour* protoDetour)
                    {proto_detour = protoDetour;}
                ProtoDetour* GetProtoDetour() const
                    {return proto_detour;}
#endif // _PROTO_DETOUR

                enum TxStatus {TX_OK, TX_BLOCK,TX_ERROR};
                TxStatus SendFrame(char* frame, unsigned int frameLen);


                void ResetTxIterator() {tx_iterator.Reset();}
                CidElement* GetNextTxElement(bool autoReset);

                // If SetTxRateLimit() returns true, its tx_timer must be activated by caller
                bool SetTxRateLimit(double bytesPerSecond);
                double GetTxRateLimit() const
                    {return tx_rate_limit;}
                ProtoTimer& GetTxTimer()
                    {return tx_timer;}
                    
                void StartInputNotification();
                bool OutputNotification()
                    {return output_notification;} // status based on "mirror" or "round-robin" 
                void SetOutputNotification(bool status)
                    {output_notification = status;}
                
                bool OnTxTimeout(ProtoTimer& theTimer);
                unsigned int GetSendErrorCount() const {return serr_count;}

            private:
                Smf::Interface&             smf_iface;
                SmfPacket::Pool&            pkt_pool;
                ProtoVif*                   proto_vif;
                bool                        is_shadowing;
                bool                        block_igmp;
                CidElementList              cid_list;
                unsigned int                cid_list_length;
                bool                        cid_mirror;  // if true, transmit packets on all CidElements, else round-robin
                CidElementList::Iterator    tx_iterator;  // for CidElement round-robin transmission
                bool                        output_notification;
#ifdef _PROTO_DETOUR
                ProtoDetour*                proto_detour;
#endif // _PROTO_DETOUR

                // Used to enforce output rate limit, if applicable (TBD - support per-CidElement rate control?)
                double                      tx_rate_limit;  // in _bytes_ per second (-1.0 means no limit)
                ProtoTimer                  tx_timer;
                unsigned int                serr_count;

        };  // end class SmfApp::InterfaceMechanism

        // This is called to change set default tx rate limit for newly added interfaces
        // (the normal default is -1.0 which means unlimited rate)
        void SetTxRateLimit(double bytesPerSecond)
            {default_tx_rate_limit = bytesPerSecond;}

        class InterfaceMatcher : public ProtoSortedTree::Item
        {
            public:
                InterfaceMatcher(const char* ifacePrefix, Smf::InterfaceGroup& ifaceGroup);
                ~InterfaceMatcher();

                const char* GetPrefix() const
                    {return iface_prefix;}

                void SetSourceMatcher(bool srcMatcher)
                    {src_matcher = srcMatcher;}
                bool IsSourceMatcher() const
                    {return src_matcher;}
                const char* GetGroupName() const
                    {return iface_group.GetName();}


                Smf::Mode GetForwardingMode() const
                    {return iface_group.GetForwardingMode();}
                Smf::RelayType GetRelayType() const
                    {return iface_group.GetRelayType();}
                bool GetResequence() const
                    {return iface_group.GetResequence();}

                bool IsTunnel() const
                    {return iface_group.IsTunnel();}
                bool GetElasticMulticast() const
                    {return iface_group.GetElasticMulticast();}
                bool GetElasticUnicast() const
                    {return iface_group.GetElasticUnicast();}
                 bool GetAdaptiveRouting() const
                    {return adaptive_routing;}
				void SetAdaptiveRouting(bool adaptive)
                    {adaptive_routing = true;}
            private:
                const char* GetKey() const
                    {return iface_prefix;}
                unsigned int GetKeysize() const
                    {return iface_prefix_bits;}
                char                    iface_prefix[Smf::IF_NAME_MAX+1];
                unsigned int            iface_prefix_bits;
                bool                    adaptive_routing;
                Smf::InterfaceGroup&    iface_group;
                bool            src_matcher;
        };  // end class SmfApp::InterfaceMatcher

        class InterfaceMatcherList : public ProtoSortedTreeTemplate<InterfaceMatcher> {};

        SmfPacket* GetPacket(); // from pool or allocate new

        // Member variables
        Smf                     smf;            // General-purpose "SMF" class
        bool                    need_help;

        bool                    priority_boost;
        bool                    ipv6_enabled;
        bool                    resequence;
        int                     ttl_set;
        double                  default_tx_rate_limit;   // default tx_rate_limit (bytes / second) for new interfaces
        int                     smf_queue_limit; // default queue limit, if non-zero, using Smf::Interface queues
        SmfPacket::Pool         pkt_pool;
        ProtoRouteTable         route_table;     // to support routing supplicant encapsulation

#ifdef _PROTO_DETOUR
        bool                    firewall_capture;
        bool                    firewall_forward;

        void OnPktIntercept(ProtoChannel&               theChannel,
                            ProtoChannel::Notification  theNotification);
        bool ForwardPacket(unsigned int dstCount, unsigned int* dstIfIndices, char* pktBuffer, unsigned int pktLength);
        bool SetupIPv4Detour(int hookFlags);
        bool SetupIPv4UnicastDetour(int hookFlags, const char *unicastPrefix, int dscp);
        ProtoDetour*            detour_ipv4;  // for intercept of IPv4 packets
        int                     detour_ipv4_flags;
        ProtoDetour*            detour_ipv4_unicast;  // for intercept of IPv4 unicast packets
        int                     detour_ipv4_unicast_flags;
#ifdef HAVE_IPV6
        bool SetupIPv6Detour(int hookFlags);
        ProtoDetour*            detour_ipv6;  // for intercept of IPv6 packets
        int                     detour_ipv6_flags;
#endif  // HAVE_IPV6
#endif  // _PROTO_DETOUR

#ifdef MNE_SUPPORT
        bool MneIsBlocking(const char* macAddr) const;
        char                    mne_block_list[Smf::SELECTOR_LIST_LEN_MAX];
        unsigned int            mne_block_list_len;
#endif // MNE_SUPPORT

#ifdef ELASTIC_MCAST
        ElasticMulticastController  mcast_controller;
        ProtoTimer                  igmp_query_timer;
#endif // ELASTIC_MCAST
#ifdef ADAPTIVE_ROUTING
        SmartController             smart_controller;
#endif
        bool                        elastic_mcast;    // set to "true" when Elastic Multicast is active
        bool                        adaptive_routing;

        SmfConfig                   smf_config;
        bool                        filter_duplicates;

        // TBD - establish a second InterfaceMatcherList for interfaces that go "down" (and may come back up)?
        InterfaceMatcherList        iface_matcher_list;
        ProtoNet::Monitor*          iface_monitor;

        ProtoPipe                   control_pipe;   // pipe _from_ controller to me
        char                        control_pipe_name[128];
        ProtoPipe                   server_pipe;    // pipe _to_ controller (e.g., nrlolsr)

        ProtoPipe                   tap_pipe;
        bool                        tap_active;

#ifdef WIN32
		char			            if_friendly_name[MAX_ADAPTER_NAME_LENGTH];
#endif
        char                        config_path[PATH_MAX + 1];  

}; // end class SmfApp

const unsigned int SmfApp::BUFFER_MAX = FRAME_SIZE_MAX + 2 + (256 *sizeof(UINT32));

SmfApp::InterfaceMechanism::InterfaceMechanism(Smf::Interface& iface, SmfPacket::Pool& pktPool)
 : smf_iface(iface), pkt_pool(pktPool), proto_vif(NULL), is_shadowing(false), block_igmp(false),
   cid_list_length(0), cid_mirror(true), tx_iterator(cid_list), output_notification(false),
#ifdef _PROTO_DETOUR
   proto_detour(NULL),
#endif // _PROTO_DETOUR
   tx_rate_limit(-1.0), serr_count(0)
{
    tx_timer.SetRepeat(-1);
}

SmfApp::InterfaceMechanism::~InterfaceMechanism()
{
    Close();
}

void SmfApp::InterfaceMechanism::CloseDevice()
{
    // Keeps the ProtoDetour (to be deprecated) open
    if (NULL != proto_vif)
    {
        proto_vif->Close();
        delete proto_vif;
        proto_vif = NULL;
    }   
    // This will empty the list, deleting its contents, 
    // calling the item destructors (thus closing ProtoCaps
    cid_list.Destroy();
    cid_list_length = 0;
}  // end SmfApp::InterfaceMechanism::CloseDevice()

void SmfApp::InterfaceMechanism::Close()
{
    // TBD - move this stuff to a ::Close() method?
    PLOG(PL_DEBUG, "SmfApp::InterfaceMechanism::Close() was called\n");
    CloseDevice();
    
#ifdef _PROTO_DETOUR
    if (NULL != proto_detour)
    {
        proto_detour->Close();
        delete proto_detour;
        proto_detour = NULL;
    }
#endif // _PROTO_DETOUR
}  // end SmfApp::InterfaceMechanism::Close()


// if return value is true, the application should activate tx_timer
bool SmfApp::InterfaceMechanism::SetTxRateLimit(double bytesPerSecond)
{
    if (0.0 == tx_rate_limit)
    {
        ASSERT(!tx_timer.IsActive());
        if (0.0 != bytesPerSecond)
        {
            // Adopt new non-zero rate and awaken
            tx_rate_limit = bytesPerSecond;
            // If output notification is pending, that will awaken us instead
            bool blockOnAny = false;  // "false" means block only if _all_
            bool unblock = blockOnAny ? true : false;
            CidElementList::Iterator ciderator(cid_list);
            CidElement* nextElement;
            while (NULL != (nextElement = reinterpret_cast<CidElement*>(ciderator.GetNextItem())))
            {
                if (!nextElement->FlagIsSet(CidElement::CID_TX)) continue;
                if (blockOnAny)
                {
                    if (nextElement->GetProtoCap().OutputNotification())
                    {
                        unblock = false;
                        break;
                    }
                }
                else  // blockOnAll
                {
                    if (!nextElement->GetProtoCap().OutputNotification())
                    {
                        unblock = true;
                        break;
                    }
                }
            }  // end while (ciderator.GetNextItem())
            if (unblock)
            {
                tx_timer.SetInterval(0.0);
                // return true to cue caller to activate tx_timer
                return true;
            }
        }
    }
    else if (tx_timer.IsActive())
    {
        if (0.0 == bytesPerSecond)
        {
            // Stop the txTimer
            tx_timer.Deactivate();
        }
        else
        {
            // We need to reschedule for new rate, scaling first
            ASSERT(tx_rate_limit > 0.0);
            double scaledInterval = (tx_rate_limit/bytesPerSecond) * tx_timer.GetTimeRemaining();
            tx_timer.SetInterval(scaledInterval);
            tx_timer.Reschedule();
        }
        tx_rate_limit = bytesPerSecond;
    }
    else
    {
        tx_rate_limit = bytesPerSecond;
    }
    return false;
}  // end SmfApp::InterfaceMechanism::SetTxRateLimit()

bool SmfApp::InterfaceMechanism::AddCidElement(ProtoCap& protoCap, int flags)
{
    // Check to see if protoCap or its associated iface index already added.
    CidElement* elem;
    CidElementList::Iterator ciderator(cid_list);
    unsigned int capIndex = protoCap.GetInterfaceIndex();
    while (NULL != (elem = ciderator.GetNextItem()))
    {
        if (capIndex == elem->GetInterfaceIndex())
        {
            // Already in list, so just update flags
            PLOG(PL_DETAIL, "SmfApp::InterfaceMechanism::AddCidElement() updating flags for existing ifaceIndex: %u\n", capIndex);
            elem->SetFlags(flags);  // TBD - update notifications as needed?
            return true;
        }
    }
    elem = new CidElement(protoCap, flags);
    if (NULL == elem)
    {
        PLOG(PL_ERROR, "SmfApp::InterfaceMechanism::AddCidElement() new CidElement error: %s\n", GetErrorString());
        return false;
    }
    cid_list.Append(*elem);
    cid_list_length += 1;
    return true;
}  // end SmfApp::InterfaceMechanism::AddCidElement()

void SmfApp::InterfaceMechanism::RemoveCidElement(unsigned int capIndex)
{
    CidElementList::Iterator ciderator(cid_list);
    CidElement* elem;
    while (NULL != (elem = ciderator.GetNextItem()))
    {
        if (capIndex == elem->GetInterfaceIndex())
        {
            cid_list.Remove(*elem);
            cid_list_length--;
            delete elem; // closes ProtoCap, etc
        }
    }
    PLOG(PL_WARN, "SmfApp::InterfaceMechanism::RemoveCidElement() warning: invalid interface index %u for this InterfaceMechanism!\n", capIndex);
}  // end SmfApp::InterfaceMechanism::RemoveCidElement()

void SmfApp::InterfaceMechanism::StartInputNotification()
{
    CidElement* elem;
    CidElementList::Iterator ciderator(cid_list);
    while (NULL != (elem = ciderator.GetNextItem()))
    {
        if (elem->FlagIsSet(CidElement::CID_RX))
            elem->GetProtoCap().StartInputNotification();  // (TBD) error check?
    }
}  // end SmfApp::InterfaceMechanism::StartInputNotification()

SmfApp::CidElement* SmfApp::InterfaceMechanism::GetNextTxElement(bool autoReset)
{
    // also detects when loop without any tx elements found
    CidElement* startElem = tx_iterator.GetNextItem();
    if (NULL == startElem)
    {
        if (autoReset)
        {
            tx_iterator.Reset();
            startElem = tx_iterator.GetNextItem();
        }
        if (NULL == startElem) return NULL;  // empty list
    }
    CidElement* elem = startElem;
    while (!elem->FlagIsSet(CidElement::CID_TX))
    {
        elem = tx_iterator.GetNextItem();
        if (NULL == elem)
        {
            if (!autoReset) return NULL; // no more tx elements found
            tx_iterator.Reset();
            elem = tx_iterator.GetNextItem();
        }
        if (elem == startElem) return NULL; // no tx elements in list
    } 
    return elem;
}  // end  SmfApp::InterfaceMechanism::GetNetTxElement()

SmfApp::InterfaceMechanism::TxStatus SmfApp::InterfaceMechanism::SendFrame(char* frame, unsigned int frameLength)
{
    bool success = false;
    unsigned int numBytes = frameLength;
    if (1 == cid_list_length)
    {
        // It's a "regular" cap interface or vif bound to single cap interface
        CidElement* elem = cid_list.GetHead();
        if (!elem->FlagIsSet(CidElement::CID_TX))
        {
            success = false;
            numBytes = 0;  // will end up setting TX_BLOCK for this interface until a CID_TX element is available
        }
        else if ((NULL != proto_vif) && !is_shadowing)
        {
            // Send frame using vif MAC addr as source address for frame
            success = elem->GetProtoCap().ForwardFrom(frame, numBytes, proto_vif->GetHardwareAddress());
        }
        else
        {
            // Forward using the "cap" MAC addr as the source addr
            success = elem->GetProtoCap().Forward(frame, numBytes);
        }
    }
    else
    {
        // Multi-element composite interface device (cid), so use "mirror" or "round-robin" transmit strategy
        // where "mirror" sends the frame duplicatively on all tx interfaces and non-mirror is round-robin
        // Blocking rules: Current for both "round-robin" and "mirror', all tx-enabled cid elements associated
        // with a vif device interface must be blocked to block the vif.
        if (cid_mirror)
        {
            // Mirror frame to all tx-enable sub-elements
            ResetTxIterator();
            CidElement* elem = GetNextTxElement(false);
            while (NULL != elem)
            {
                numBytes = frameLength;
                bool mirrorSuccess;
                if (is_shadowing)
                    mirrorSuccess = elem->GetProtoCap().Forward(frame, numBytes);
                else
                    mirrorSuccess = elem->GetProtoCap().ForwardFrom(frame, numBytes, proto_vif->GetHardwareAddress());
                if (0 == numBytes) mirrorSuccess = false;
                success |= mirrorSuccess;  // 'success' will be true if _any_ interface works
                elem = GetNextTxElement(false);
            }
        }
        else
        {
            // Implement round-robin frame transmission to sub-element interfaces using 'tx_iterator'
            CidElement* startElem = GetNextTxElement(true);
            if (NULL == startElem)
            {
                PLOG(PL_ERROR, "SmfApp::SendFrame() error: no tx-enabled cid elements available?!\n");
                // Stop reading packets from vif (adding tx-enabled CID will reactivate vif
                proto_vif->StopInputNotification();
                return TX_ERROR;
            }
            CidElement* elem = startElem;
            while (true)
            {
                numBytes = frameLength;
                if (is_shadowing)
                    success = elem->GetProtoCap().Forward(frame, numBytes);
                else
                    success = elem->GetProtoCap().ForwardFrom(frame, numBytes, proto_vif->GetHardwareAddress());
                if (0 == numBytes) success = false;
                if (success) break;
                elem = GetNextTxElement(true);
                if (elem == startElem)
                {
                    tx_iterator.SetCursor(elem);
                    break;
                }
            }
        }  // end if/else mirror/round-robin
    } // end if/else single-element / multi-element
    
    if (success)
    {
        return TX_OK;
    }
    else if (0 != numBytes)
    {
         // It was due to EAGAIN / EWOULDBLOCK, so use async i/o notification to wait
        ResetTxIterator();
        CidElement* elem;
        while (NULL != (elem = GetNextTxElement(false)))
        {
            // For now for both mirror and round-robin, any interface can "wake up" the vif for output
            // Note if no elements with CID_TX, then output notification will be started when a CID
            // is added as CID_TX or changed to CID_TX status
            if (elem->FlagIsSet(CidElement::CID_TX))
            {
                elem->GetProtoCap().StartOutputNotification();
                output_notification = true;
            }
        }
        return TX_BLOCK;
    }
    else
    {
        return TX_ERROR;
    }
}  // end  SmfApp::InterfaceMechanism::SendFrame()

bool SmfApp::InterfaceMechanism::OnTxTimeout(ProtoTimer& theTimer)
{
    // TBD - we may want to have a strategy here that pulls a packet from the "vif" if there are
    // no priority packets in our queue to give potential priority packets a better chance
    if (GetTxRateLimit() < 0.0)
    {
        // The tx timer was used to wait because of cap send error
        // that was _not_ EAGAIN or EWOULDBLOCK
        // So we just reactivate transmission for this interface 
        // with an output notification
        theTimer.Deactivate();
        CidElement* elem = cid_list.GetHead();
        // This will result in call to SmfApp::OnPktCapture()
        elem->GetProtoCap().OnNotify(ProtoChannel::NOTIFY_OUTPUT);
        return false;
    }
    ASSERT(0.0 != GetTxRateLimit());
    // 1) Are there enqueued packets that need to be sent
    SmfPacket* frame = smf_iface.PeekNextPacket();
    if (NULL != frame)
    {
        // if so, send and resched timeout
        InterfaceMechanism::TxStatus txStatus = SendFrame((char*)frame->AccessBuffer(), frame->GetLength());
        if (InterfaceMechanism::TX_OK == txStatus)
        {
            frame = smf_iface.DequeuePacket();
            double txInterval = ((double)frame->GetLength()) / GetTxRateLimit();
            theTimer.SetInterval(txInterval);
            if (NULL != proto_vif)
            {
                // Try to pull a frame from vif to replace the one we just sent
                unsigned int numBytes = SmfPacket::PKT_SIZE_MAX;
                if (proto_vif->Read((char*)frame->AccessBuffer(), numBytes))
                {
                    if (0 != numBytes)
                    {
                        frame->SetLength(numBytes);
                        bool priority = IsPriorityFrame(frame->AccessBuffer(), numBytes);
                        smf_iface.EnqueuePacket(*frame, priority, &pkt_pool);
                        if (smf_iface.QueueIsFull() && proto_vif->InputNotification())
                        {
                            proto_vif->StopInputNotification();
                        }
                        return true;
                    }
                }
                // Wake vif up if needed to refill queue
                if (!proto_vif->InputNotification())
                {
                    proto_vif->StartInputNotification();
                }
            }
            pkt_pool.Put(*frame);
            return true;
        }
        else if (InterfaceMechanism::TX_ERROR == txStatus)
        {
           // We had a send error, possibly due to ENOBUFS, so we need to wait before
            // trying to send since ENOBUFS doesn't block select() or write(), etc
            // Use tx timer to wait 1 msec and try again
            serr_count++;
            double waitInterval = 1.0e-03; // 1 msec default wait
            double txRateLimit = GetTxRateLimit();
            if (txRateLimit > 0.0) waitInterval = ((double)frame->GetLength()) / txRateLimit;
            theTimer.SetInterval(waitInterval);
            // Note attempted frame is left in our interface packet queue for retry
            return true;
        }
        // else was blocked and async i/o output notification was started
        // and frame is left in our interface packet queue
    }
    else if (NULL != proto_vif)
    {
        // Try to pull a packet from vif to keep real-time schedule
        const int BUFFER_MAX = FRAME_SIZE_MAX + 2;
        UINT32 alignedBuffer[BUFFER_MAX/sizeof(UINT32)];
        // offset by 2-bytes so IP content is 32-bit aligned
        UINT16* ethBuffer = ((UINT16*)alignedBuffer) + 1;
        unsigned int numBytes = BUFFER_MAX - 2;
        if (proto_vif->Read((char*)ethBuffer, numBytes))
        {
            if (0 != numBytes)
            {
                unsigned int frameLength = numBytes;
                // This is just a check
                ProtoPktETH ethPkt((UINT32*)ethBuffer, BUFFER_MAX - 2);
                if (!ethPkt.InitFromBuffer(numBytes))
                {
                    PLOG(PL_ERROR, "SmfApp::InterfaceMechanism::OnTxTimeout() error: bad output Ether frame\n");
                    // Set a zero timeout interval for immediate retry
                    theTimer.SetInterval(0.0);
                    return true;
                }

                // Got a frame, so send it and resched timeout
                // TBD - mcast mirror?
                InterfaceMechanism::TxStatus txStatus = SendFrame((char*)ethBuffer, numBytes);
                if (InterfaceMechanism::TX_OK == txStatus)
                {
                    double txInterval = ((double)frameLength) / GetTxRateLimit();
                    theTimer.SetInterval(txInterval);
                    return true;
                }
                else
                {
                    if (smf_iface.IsQueuing())
                    {
                        // Enqueue packet for later service by pcap output notification
                        // TBD - write received packets directly to an SmfPacket buffer to avoid copying done here
                        SmfPacket* pkt = pkt_pool.GetPacket();
                        if (NULL != pkt)
                        {
                            memcpy(pkt->AccessBuffer(), (char*)ethBuffer, frameLength);
                            pkt->SetLength(frameLength);
                            bool priority = IsPriorityFrame(pkt->AccessBuffer(), pkt->GetLength());
                            if (smf_iface.EnqueuePacket(*pkt, priority, &pkt_pool))
                            {
                                if (smf_iface.QueueIsFull() && proto_vif->InputNotification())
                                {
                                    proto_vif->StopInputNotification();
                                }
                            }
                            else
                            {
                                PLOG(PL_WARN, "SmfApp::InterfaceMechanism::OnTxTimeout() warning: interface queue is full\n");
                                pkt_pool.Put(*pkt);
                                serr_count++;  // TBD - make this a drop_count per interface
                            }
                        }
                    }
                    else
                    {
                        serr_count++;  // couldn't send or queue
                    }
                    if (InterfaceMechanism::TX_ERROR == txStatus)
                    {
                        // We had a send error, possibly due to ENOBUFS, so we need to wait before
                        // trying to send since ENOBUFS doesn't block select() or write(), etc
                        // Use tx timer to wait
                        serr_count++;
                        double waitInterval = 1.0e-03; // 1 msec default wait
                        double txRateLimit = GetTxRateLimit();
                        waitInterval = ((double)numBytes) / txRateLimit;
                        theTimer.SetInterval(waitInterval);
                        return true;
                    }
                    // else output notification was started for TX_BLOCK status
                }  // end if/else (frameSent)
            }  // end if (0 != numBytes)
        }  // end if (vif->Read())

        // No packet was ready,
        if (!smf_iface.IsQueuing())
        {
            ASSERT(!proto_vif->InputNotification());
            proto_vif->StartInputNotification();
        }
        // else no change in queue status, so leave vif alone
    }  // end if (NULL != frame) else (NULL != vif)

    // No frame sent, so deactivate tx_timer.
    theTimer.Deactivate();
    return false;
}  // end SmfApp::InterfaceMechanism::OnTxTimeout()



SmfApp::CidElement::CidElement(ProtoCap& protoCap, int flags)
  : proto_cap(protoCap), cid_flags(flags)
{
}

SmfApp::CidElement::~CidElement()
{
    proto_cap.Close();
    delete &proto_cap;
}

SmfApp::InterfaceMatcher::InterfaceMatcher(const char* ifacePrefix, Smf::InterfaceGroup& ifaceGroup)
 : iface_group(ifaceGroup), src_matcher(false)
{
    strncpy(iface_prefix, ifacePrefix, Smf::IF_NAME_MAX);
    iface_prefix[Smf::IF_NAME_MAX] = '\0';
    iface_prefix_bits = strlen(iface_prefix) << 3;
}

SmfApp::InterfaceMatcher::~InterfaceMatcher()
{
}

// This macro creates our ProtoApp derived application instance
PROTO_INSTANTIATE_APP(SmfApp)

const char* SmfApp::DEFAULT_INSTANCE_NAME = "nrlsmf";
const char* SmfApp::DEFAULT_SMF_SERVER = "nrlolsr";

SmfApp::SmfApp()
 : smf(GetTimerMgr()), need_help(false), priority_boost(true), ipv6_enabled(false),
   resequence(false), ttl_set(-1),
   default_tx_rate_limit(-1.0), smf_queue_limit(0),
#ifdef _PROTO_DETOUR
   firewall_capture(false), firewall_forward(false),
   detour_ipv4(NULL), detour_ipv4_flags(0),
   detour_ipv4_unicast(NULL), detour_ipv4_unicast_flags(0),
#ifdef HAVE_IPV6
   detour_ipv6(NULL), detour_ipv6_flags(0),
#endif // HAVE_IPV6
#endif // _PROTO_DETOUR
#ifdef MNE_SUPPORT
   mne_block_list_len(0),
#endif // MNE_SUPPORT
#ifdef ELASTIC_MCAST
   mcast_controller(GetTimerMgr()),
#endif // ELASTIC_MCAST
#ifdef ADAPTIVE_ROUTING
   smart_controller(GetTimerMgr()),
#endif  // ADAPTIVE_ROUTING
   elastic_mcast(false),
   adaptive_routing(false),
   filter_duplicates(true),
   iface_monitor(NULL), 
   control_pipe(ProtoPipe::MESSAGE),
   server_pipe(ProtoPipe::MESSAGE), 
   tap_pipe(ProtoPipe::MESSAGE), tap_active(false)
{
    control_pipe.SetNotifier(&GetSocketNotifier());
    control_pipe.SetListener(this, &SmfApp::OnControlMsg);
#ifdef WIN32
	if_friendly_name[0] = '\0';
#endif //WINew
#ifdef ELASTIC_MCAST
    mcast_controller.SetForwarder(&smf);
    smf.SetController(&mcast_controller);
    smf.SetOutputMechanism(this);
    igmp_query_timer.SetListener(this, &SmfApp::OnIgmpQueryTimeout);
#endif // ELASTIC_MCAST
#ifdef ADAPTIVE_ROUTING
    smart_controller.SetForwarder(&smf);
    smf.SetController(&smart_controller);
    smf.SetOutputMechanism(this);
#endif // ADAPTIVE_ROUTING
        
    config_path[0] = config_path[PATH_MAX] = '\0';
}

SmfApp::~SmfApp()
{
    OnShutdown();
}

void SmfApp::Usage()
{
    fprintf(stderr, "Usage: nrlsmf [version][ipv6][firewallForward {on|off}][firewallCapture {on|off}\n"
                    "              [add [<group>,]{cf|smpr|ecds|push|rpush|merge|rmerge},<ifaceList>]\n"
                    "              [remove {<group> | [<group>,]<ifaceList>}][elastic <group>][adaptive <group>]\n"
                    "              [cf <ifaceList>][smpr <ifaceList>][ecds <ifaceList>]\n"
                    "              [push <srcIface>,<dstIfaceList>] [rpush <srcIface>,<dstIfaceList>]\n"
                    "              [merge <ifaceList>][rmerge <ifaceList>]\n"
                    "              [forward {on|off}][relay {on|off}][delayoff <value>]\n"
                    "              [device <vifName>,<ifaceName>[/{t|r}][,<addr>[/<maskLen>][,<addr2>[/<maskLen>]...]]]\n"
                    "              [rate [<iface>,]<bits/sec>][queue [<iface>,]<limit>][filterDups {on | off}]\n"
                    "              [layered <ifaceList>][reliable <ifaceList>][advertise]\n"
                    "              [unicast {<group> | <unicastPrefix> | off}][encapsulate <ifaceList>]\n"
                    "              [dscpCapture <dscpValue>,<dscpValueList>]\n"
                    "              [dscpRelease <dscpValue>,<dscpValueList>]\n"
                    "              [ihash <algorithm>][hash <algorithm>]\n"
                    "              [idpd {on | off}][window {on | off}]\n"
                    "              [instance <instanceName>][smfServer <serverName>]\n"
                    "              [resequence {on|off}][ttl <value>][boost {on|off}]\n"
                    "              [debug <debugLevel>][log <debugLogFile>]\n"
                    "              [cid <vifName>,<iface>[/{t|r|d}][, <iface2>[/{t|r|d}],...]\n"
                    "   (Note \"firewall\" options must be specified _before_ iface config commands!\n");
}

const char* const SmfApp::CMD_LIST[] =
{
    "-version",     // show version and exit
    "-help",        // print help info an exit
    "-ipv6",        // enable IPv6 support (must be first on command-line)
    "+add",         // [<group>,]{cf|smpr|ecds},<ifaceList> : add interface(s) to flooding group with relay algorithm type given
    "+remove",      // {<group>|[<group>,]<ifaceList>] : remove entire interface group, or the interface(s) from the specified or all group(s)
    "+push",        // <srcIface,dstIfaceList> : forward packets from srcIFace to all dstIface's listed
    "+rpush",       // <srcIface,dstIfaceList> : reseq/forward packets from srcIFace to all dstIface's listed
    "+rpush",       // <srcIface,dstIfaceList> : reseq/forward packets from srcIFace to all dstIface's listed
    "+merge",       // <ifaceList> forward _among_ all iface's listed
    "+rmerge",      // <ifaceList> : reseq/forward _among_ all iface's listed
    "+tunnel",      // <ifaceList> forward _among_ all iface's listed with no TTL decrement
    "+cf",          // <ifaceList> : CF relay among all iface's listed
    "+smpr",        // <ifaceList> : S_MPR relay among all iface's listed
    "+ecds",        // <ifaceList> : E_CDS relay among all iface's listed
    "+forward",     // {on | off}  : forwarding enable/disable (default = "on")
    "+relay",       // {on | off}  : act as relay node (default = "on")
    "+elastic",     // <ifaceGroup> : enable Elastic Multicast for specific interface group
    "+reliable",    // <ifaceList> : experimental reliable hop-by-hop forwarding option (adds UMP option to IPv4 packets)
    "+utos",        // <trafficClass> : set IP traffic class to be ignored by reliable forwarding
    "-advertise",   //  Sets elastic multicast operation to advertise flows instead of token-bucket limited forwarding
    "+allow",       // {<filterSpec> | all}: set filter for flows that nrlsmf elastic mcast is allowed to forward.
    "+deny",        // {<filterSpec> | all}: set filter for flows that nrlsmf elastic mcast should ignore
    "+adaptive",    // <ifaceGroup>: enable Smart Routing for specific interface group
    "+unicast",     // {unicastPrefix | off}  : allow unicast forwarding for a given prefix, or off (default = "off")
    "+filterDups",  // {on | off} : filter received duplicates for "device" operation (default = "on")
    "+encapsulate", // <ifaceList> - use IPIP encapsulation for outbound unicast packets on listed smf "device" interfaces
    "+route",       // <dstAddr>,<nextHopAddr>  (used for debugging encapsulation only)
    "+dscpCapture", // {value,dscpValueList}  : set the DSCP values(s) for unicast capture.
    "+dscpRelease", // {value,dscpValueList}  : unset DSCP values(s) for unicast capture.
    "+defaultForward", // {on | off}  : same as "relay" (for backwards compatibility)
    "+delayoff",    // {<double> : number of microseconds delay before executing a relay off command (default = 0)
    "+ihash",       // <algorithm> to set ihash_only hash algorithm
    "+hash",        // <algorithm> to set H-DPD hash algorithm
    "+idpd",        // {on | off} to do I-DPD when possible
    "+window",      // {on | off} do window-based I-DPD of sequenced packets
    "+resequence",  // {on | off}  : resequence outbound multicast packets
    "+ttl",         // <value> : set TTL of outbound packets
    "+device",      // <vifName>,<ifaceName>[/{t|r|d}][,<addr1>[,addr2, ...]] to create virtual interface 'device' associated with one or more physical interfaces
    "+cid",         // <vifName>,<iface1>[/{t|r|d}][,<iface2>[/{t|r|d}][,<iface3>[/{t|r|d}],...]] to add/delete elements to composite interface device
    "+rate",        // [<ifaceName>,]<bitsPerSecond> : impose forwarding/transmit rate limit
    "+queue",       // perform SMF packet queuing ...
    "+layered",     // <ifaceList> : mark interface(s) as "layered", where it has its own underlying multicast distribution mechanism
    //"+firewall",  // {on | off} : use firewall instead of ProtoCap to capture _and_ forward packets
    "+firewallCapture", // {on | off} : use firewall instead of ProtoCap to capture packets
    "+firewallForward", // {on | off} : use firewall instead of ProtoCap to forward packets
    "+instance",    // <instanceName> : sets our instance (control_pipe) name
    "+load",        // <configFile>  : load nrlsmf JSON configuration file
    "+boost",       // {on | off} : boost process priority (default = "on")
    "+smfServer",   // <serverName> : instructs smf to "register" itself to the given server (pipe only)"+smfTap"
    "+tap",         // <tapName> : instructs smf to divert forwarded packets to process ProtoPipe named <tapName>
    "+debug",       // <debugLevel> : set debug level
    "+log",         // <logFile> : debug log file,
    "+save",        // <configFile> : save JSON configurstion file upon exit
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
}  // end SmfApp::GetCmdType()

bool SmfApp::OnStartup(int argc, const char*const* argv)
{
    if (!smf.Init())
    {
        PLOG(PL_FATAL, "SmfApp::OnStartup() error: smf core initialization failed\n");
        return false;
    }

    unsigned int ifIndexArray[IF_COUNT_MAX];
    unsigned int ifCount = ProtoNet::GetInterfaceIndices(ifIndexArray, IF_COUNT_MAX);
    if (0 == ifCount)
    {
        PLOG(PL_WARN, "SmfApp::OnStartup(): warning: no network interface indices were found.\n");
    }
    else if (ifCount > IF_COUNT_MAX)
    {
        PLOG(PL_WARN, "SmfApp::OnStartup(): warning: found network interfaces indices exceeding maximum count.\n");
        ifCount = IF_COUNT_MAX;
    }
    // Add any MAC or IP addrs assigned to this host to our list
    for (unsigned int i = 0; i < ifCount; i++)
    {
        ProtoAddressList addrList;
        unsigned int ifIndex = ifIndexArray[i];
        // Add the MAC (ETH) addr for this iface to our SMF local addr list
        char ifName[Smf::IF_NAME_MAX+1];
        ifName[Smf::IF_NAME_MAX] = '\0';
        if (!ProtoNet::GetInterfaceName(ifIndex, ifName, Smf::IF_NAME_MAX))
        {
            PLOG(PL_FATAL, "SmfApp::OnStartup() error: unable to get ifName for iface:%s (index:%u)\n", ifIndex);
            return false;
        }

        ProtoAddress ifAddr;
        if (!ProtoNet::GetInterfaceAddress(ifName, ProtoAddress::ETH, ifAddr))
        {
            PLOG(PL_WARN, "SmfApp::OnStartup() warning: unable to get ETH addr for iface:%s (index:%u)\n", ifName, ifIndex);
        }
        else if (!smf.AddOwnAddress(ifAddr, ifIndex))
        {
            PLOG(PL_FATAL, "SmfApp::OnStartup() error: unable to add ETH addr to own addr list.\n");
            return false;
        }
        // Iterate over and add IP addresses for this interface to our SMF local addr list
        if (!ProtoNet::GetInterfaceAddressList(ifIndex, ProtoAddress::IPv4, addrList))
        {
            PLOG(PL_FATAL, "SmfApp::OnStartup() error: couldn't retrieve IPv4 address for iface index:%u\n", ifIndex);
            //return false;
        }
        if (!ProtoNet::GetInterfaceAddressList(ifIndex, ProtoAddress::IPv6, addrList))
        {
            PLOG(PL_FATAL, "SmfApp::OnStartup() error: couldn't retrieve IPv6 address for iface index:%u\n", ifIndex);
            //return false;
        }
        if (addrList.IsEmpty())
        {
            PLOG(PL_WARN, "SmfApp::OnStartup() error:no IP addresses found for iface: %s\n", ifName);
            //return false;
        }
        ProtoAddressList::Iterator adderator(addrList);
        ProtoAddress addr;
        while (adderator.GetNextAddress(addr))
        {
            smf.AddOwnAddress(addr, ifIndex); // TBD - check result
        }
    }

    smf.SetRelayEnabled(true);
    smf.SetRelaySelected(true);
    smf.SetUnicastEnabled(false);
    smf.SetUnicastPrefix("off");
    if (!ProcessCommands(argc, argv))
    {
        if (!need_help)
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
            const InterfaceMechanism* mech = static_cast<const InterfaceMechanism*>(iface->GetExtension());
            if (NULL != mech)
            {
                isEmpty = false;
                break;
            }
        }
        if (isEmpty)
        {
            // No resequencing or iface I/O configured?
            PLOG(PL_WARN, "smfApp::OnStartup() warning: no active forwarding or resequencing in place (runtime configuration will be needed)\n");
            //OnShutdown();
            //return false;
        }
    }
    // Create / startup iface monitor
    iface_monitor = ProtoNet::Monitor::Create();
    if (NULL == iface_monitor)
    {
        PLOG(PL_ERROR, "smfApp::OnStartup() new ProtoNet::Monitor error: %s\n", GetErrorString());
        OnShutdown();
        return false;

    }
    iface_monitor->SetNotifier(static_cast<ProtoChannel::Notifier*>(&dispatcher));
    iface_monitor->SetListener(this, &SmfApp::MonitorEventHandler);
    if (!iface_monitor->Open())
    {
        PLOG(PL_ERROR, "smfApp::OnStartup() error unable to open iface_monitor\n");
        OnShutdown();
        return false;
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
            OnShutdown();
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

#ifdef ELASTIC_MCAST
    // At the moment IGMP Queries are just used _internally_
    // (with "nrlsmf device" virtual interfaces.  This will be
    // expanded to allow and SMF Elastic Multicast router query
    // neighbors for membership replies on configured interfaces.
    // Similar to IGMP wired LAN operation, non-router (i.e. host-only)
    // nodes should only reply to one querying router when multiple routers
    // are detected (generally the router w/ lowest ID or something)
    
    // This code is disabled for the moment
    /*if (elastic_mcast)
    {
        igmp_query_timer.SetInterval(0.0);  // for first timeout
        igmp_query_timer.SetRepeat(-1);
        ActivateTimer(igmp_query_timer);
    }
    */
#endif // ELASTIC_MCAST

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
    if ('\0' != config_path[0])
        SaveConfig(config_path);
    
    if (NULL != iface_monitor)
    {
        if (iface_monitor->IsOpen()) iface_monitor->Close();
        delete iface_monitor;
        iface_monitor = NULL;
    }
    iface_matcher_list.Destroy();
    if (control_pipe.IsOpen()) control_pipe.Close();
    if (server_pipe.IsOpen()) server_pipe.Close();

    Smf::InterfaceList::Iterator iterator(smf.AccessInterfaceList());
    Smf::Interface* iface;
    while (NULL != (iface = iterator.GetNextItem()))
    {
       
        InterfaceMechanism* mech = static_cast<InterfaceMechanism*>(iface->RemoveExtension());
        ProtoVif* vif = (NULL != mech) ? mech->GetProtoVif() : NULL;
        if (NULL != vif)
        {
            // If the associated "proto_cap" has no addresses, assume they were stolen 
            // and reclaim them from the proto_vif (and restore routes)
            ProtoRouteMgr* rtMgr = NULL;
            ProtoRouteTable rtTable;   // used to cache stolen routes from vif for restoration to cap
            // Restore address to _first_ (only one for non-composite devices) CidElement
            CidElement* elem = mech->GetPrincipalElement();
            if (NULL != elem)
            {
                ProtoCap& cap = elem->GetProtoCap();
                unsigned int capIndex = cap.GetInterfaceIndex();
                ProtoAddressList addrList;
                ProtoNet::GetInterfaceAddressList(capIndex, ProtoAddress::IPv4, addrList);
#ifdef HAVE_IPV6
                ProtoNet::GetInterfaceAddressList(capIndex, ProtoAddress::IPv6, addrList);
#endif // HAVE_IPV6
                // Weed out link local addrs
                ProtoAddressList::Iterator it(addrList);
                ProtoAddress addr;
                while (it.GetNextAddress(addr))
                {
                    if (addr.IsLinkLocal()) addrList.Remove(addr);
                }
                if (addrList.IsEmpty())
                {
                    // Before making address changes, cache system routes (then restore after vif close)
                    // (TBD - this code needs to be completed and tested)
                    rtMgr = ProtoRouteMgr::Create();
                    if ((NULL != rtMgr) && rtMgr->Open())
                    {
                        //rtMgr->SaveAllRoutes();
                        ProtoRouteTable tmpTable;
                        rtMgr->GetAllRoutes(ProtoAddress::IPv4, tmpTable);
                        rtMgr->GetAllRoutes(ProtoAddress::IPv6, tmpTable);
                        ProtoRouteTable::Iterator it(tmpTable);
                        ProtoRouteTable::Entry* entry;
                        while (NULL != (entry = it.GetNextEntry()))
                        {
                            if (!entry->GetGateway().IsValid())
                            {
                                unsigned int ifIndex = entry->GetInterfaceIndex();
                                if (iface->GetIndex() == ifIndex)
                                {
                                    rtMgr->DeleteRoute(*entry);
                                    if (entry->IsDefault())
                                    {
                                        rtTable.SetRoute(entry->GetDestination(), entry->GetPrefixSize(), 
                                                         entry->GetGateway(), entry->GetInterfaceIndex(),
                                                         entry->GetMetric());
                                    }          
                                    else
                                    {
                                        tmpTable.RemoveEntry(*entry);
                                        rtTable.InsertEntry(*entry);
                                    }              
                                }
                            }
                        }
                    }
                    else
                    {
                        PLOG(PL_WARN, "SmfApp::InterfaceMechanism::Close() warning: unable to open ProtoRouteMgr()!\n");
                    }
                    // Assume the addresses the tap device has were "stolen" and return them
                    ProtoNet::GetInterfaceAddressList(iface->GetIndex(), ProtoAddress::IPv4, addrList);
#ifdef HAVE_IPV6
                    ProtoNet::GetInterfaceAddressList(iface->GetIndex(), ProtoAddress::IPv6, addrList);
#endif // HAVE_IPV6
                    it.Reset();
                    while (it.GetNextAddress(addr))
                    {
                        if (addr.IsLinkLocal()) continue;
                        unsigned int maskLen = ProtoNet::GetInterfaceAddressMask(iface->GetIndex(), addr);
                        // Remove address from vif
                        if (!ProtoNet::RemoveInterfaceAddress(iface->GetIndex(), addr, maskLen))
                            PLOG(PL_ERROR, "SmfApp::InterfaceMechanism::Close() error removing address %s from vif \"%s\"\n", addr.GetHostString(), vif->GetName());
                        // Assign address to "interface"
                        if (!ProtoNet::AddInterfaceAddress(capIndex, addr, maskLen))
                           PLOG(PL_ERROR, "SmfApp::InterfaceMechanism::Close() error returning address %s to interface index %u\n", addr.GetHostString(), capIndex);
				    }
                }
#if defined(BLOCK_ICMP) && defined(LINUX)
                // TBD - which did this code
                // Restore ICMP message delivery to physical interface
                char capName[Smf::IF_NAME_MAX + 1];
                capName[Smf::IF_NAME_MAX ] = '\0';
                if (!ProtoNet::GetInterfaceName(capIndex, capName, Smf::IF_NAME_MAX))
                    PLOG(PL_ERROR, "SmfApp::InterfaceMechanism::Close() warning: unable to get ifName for iface:%s (index:%u)\n", capIndex);
                else if (!BlockICMP(capName, false))
                    PLOG(PL_ERROR, "SmfApp::InterfaceMechanism::Close() warning: unable to restore ICMP reception to interface %s\n", capName);
#endif // LINUX
                if (NULL != rtMgr)
                {
                    // Restore stolen routes from vif to cap
                    ProtoRouteTable::Iterator it(rtTable);
                    ProtoRouteTable::Entry* entry;
                    while (NULL != (entry = it.GetNextEntry()))
                    {
                        entry->SetInterface(capIndex);
                        rtMgr->SetRoute(*entry);
                    }
                     // Restores cached routes if address reassignments were made
                    //rtMgr->RestoreSavedRoutes();
                    rtMgr->Close();
                    delete rtMgr;
                }
            }  // end if (NULL != elem)
        }  // end (NULL != vif)
        if (NULL != mech)
        {
            mech->Close();
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
    if (NULL != detour_ipv4_unicast)
    {
	    detour_ipv4_unicast->Close();
	    delete detour_ipv4_unicast;
	    detour_ipv4_unicast = NULL;
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
                    if (!need_help) // catches "help" and "version" checks
                        PLOG(PL_FATAL, "SmfApp::ProcessCommands() ProcessCommand(%s) error\n", argv[i]);
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
    else if (!strncmp("version", cmd, len))
    {
        fprintf(stderr, "smf version: %s\n", _SMF_VERSION);
        need_help = true;
        return false;
    }
    else if (!strncmp("help", cmd, len))
    {
	    Usage();
        need_help = true;
        return false;
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
    else if (!strncmp("add", cmd, len))
    {
        // add [<group>,]{cf|smpr|ecds},<ifaceList> : add interface(s) to flooding group with relay algorithm type given
        size_t vlen = strlen(val);
        char* vtext = new char[vlen + 1];
        if (NULL == vtext)
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(add) new string[] error: %s\n", GetErrorString());
            return false;
        }
        strcpy(vtext, val);
        char* groupNamePtr = vtext;
        char* relayTypePtr = strchr(groupNamePtr, ',');
        if (NULL == relayTypePtr)
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(add) error: missing interface list\n");
            delete[] vtext;
            return false;
        }
        *relayTypePtr++ = '\0';
        // Is groupName actually given?
        char* ifaceListPtr;
        Smf::Mode mode = Smf::RELAY;
        bool rseq = false;
        Smf::RelayType relayType = Smf::GetRelayType(groupNamePtr);
        if (Smf::INVALID == relayType)
        {
            mode = Smf::GetForwardingMode(groupNamePtr);
            if (Smf::RELAY != mode)
            {
                // No explicit group name was given; instead was push, rpush, merge, or rmerge
                // (no explicit groupName given, so we use the mode name as group name?)
                if ('r' == groupNamePtr[0]) rseq = true;
                relayType = Smf::CF;
                ifaceListPtr = relayTypePtr;
                // relayTypePtr = "cf"; // not used anyway
            }
            else
            {
                // An actual group name was given
                ifaceListPtr = strchr(relayTypePtr, ',');
                if (NULL == ifaceListPtr)
                {
                    PLOG(PL_ERROR, "SmfApp::OnCommand(add) error: missing interface list\n");
                    delete[] vtext;
                    return false;
                }
                *ifaceListPtr++ = '\0';
                relayType = Smf::GetRelayType(relayTypePtr);
                if (Smf::INVALID == relayType)
                {
                    mode = Smf::GetForwardingMode(relayTypePtr);
                    if (Smf::RELAY != mode)
                    {
                        if ('r' == relayTypePtr[0]) rseq = true;
                        relayType = Smf::CF;
                        // relayTypePtr = "cf";  // not used anyway
                    }
                    else
                    {
                        PLOG(PL_ERROR, "SmfApp::OnCommand(add) error: invalid SMF relay algorithm: %s\n", relayTypePtr);
                        delete[] vtext;
                        return false;
                    }
                }
            }
        }
        else
        {
            // no group name was given
            ifaceListPtr = relayTypePtr;
            relayTypePtr = groupNamePtr;
            //groupNamePtr = NULL;
        }
        // At this point, we have "groupNamePtr", "relayType", and "ifaceListPtr"
        //if (NULL != groupNamePtr)
        //    PLOG(PL_ERROR, "SmfApp::OnCommand(add) error: named interface groups not yet supported\n");
        //groupNamePtr = relayTypePtr;
        bool result = ParseInterfaceList(groupNamePtr, mode, ifaceListPtr, relayType, rseq);
        delete[] vtext;
        if (!result) return false;
    }
    else if (!strncmp("remove", cmd, len))
    {
        // remove {<group> | [<group>,]<ifaceList>}
        // Note for PUSH groups, the first <ifaceList> item
        // must be the PUSH source interface name
        if (!RemoveInterfaces(val))
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(remove) error removing groups or interfaces\n");
            return false;
        }
    }
    else if (!strncmp("unicast", cmd, len))
    {
        // Is the 'val' argument a legit interface group name?
        Smf::InterfaceGroup* ifaceGroup = smf.FindInterfaceGroup(val);
        if (NULL != ifaceGroup)
        {
#ifdef ELASTIC_MCAST
            ifaceGroup->SetElasticUnicast(true);
            // The "elastic unicast" option has been selected
            // Add unicast "memberships" for interface addresses
            Smf::InterfaceGroup::Iterator ifacerator(*ifaceGroup);
            Smf::Interface* iface;
            while (NULL != (iface = ifacerator.GetNextInterface()))
            {
                char ifaceName[64];
                ifaceName[63] = '\0';
                if (!ProtoNet::GetInterfaceName(iface->GetIndex(), ifaceName, 63))
                {
                    PLOG(PL_ERROR, "SmfApp::OnCommand(unicast) error: unable to retrieve interface name\n");
                    return false;
                }
                ProtoAddressList addrList;
                if (!ProtoNet::GetInterfaceAddressList(ifaceName, ProtoAddress::IPv4, addrList))
                {
                    PLOG(PL_ERROR, "SmfApp::OnCommand(unicast) error: unable to retrieve interface address list\n");
                    return false;
                }
                ProtoAddress addr;
                ProtoAddressList::Iterator iterator(addrList);
                while (iterator.GetNextAddress(addr))
                {
                    if (addr.IsLinkLocal()) continue;
                    if (!mcast_controller.AddManagedMembership(iface->GetIndex(), addr))
                    {
                        PLOG(PL_ERROR, "SmfApp::OnCommand(unicast) error: unable to add unicast membership\n");
                        return false;
                    }
                }
            }
            smf.SetUnicastEnabled(true);
#endif // ELASTIC_MCAST
        }
        else
#ifdef _PROTO_DETOUR
        {
            // legacy (will be deprecated) "unicast on|off" command
            // syntax: "unicast {unicastPrefix | off}"
		    int hookUnicastFlags;
            if (!strcmp("off", val))
            {
                // Stop intercept unicast packets
	            // First check whether there are DSCP Capture options
	            char *arrayDSCP = smf.GetUnicastDSCP();
	            bool dscpflag = false;

	            // Create one iptables entry per DSCP value.
	            for(int i = 0; i < 255; i++)
                {
	                if(arrayDSCP[i] > 0)
                    {
		                dscpflag = true;
		                hookUnicastFlags = detour_ipv4_unicast_flags & ~ProtoDetour::INPUT & ~ProtoDetour::OUTPUT;
		                if (!SetupIPv4UnicastDetour(hookUnicastFlags, val, i))
                        {
		                    PLOG(PL_ERROR, "SmfApp::OnCommand(unicast) error opening IPv4 detour\n");
		                    return false;
		                }
	                }
	            }

	            // If no DSCP value was specified, then traffic should be captured regardless of DSCP
	            if(!dscpflag)
                {
	                hookUnicastFlags = detour_ipv4_unicast_flags & ~ProtoDetour::INPUT & ~ProtoDetour::OUTPUT;
	                if (!SetupIPv4UnicastDetour(hookUnicastFlags, val, 0))
                    {
		                PLOG(PL_ERROR, "SmfApp::OnCommand(unicast) error opening IPv4 detour\n");
		                return false;
	                }
	            }
	            smf.SetUnicastEnabled(false);
	            smf.SetUnicastPrefix(val);
            }
            else if (!strcmp("on", val))
            {
	            // intercept unicast packets for the given unicast prefix
	            // First check whether there are DSCP Capture options
	            char *arrayDSCP = smf.GetUnicastDSCP();
	            bool dscpflag = false;

	            // Create one iptables entry per DSCP value.
	            for(int i = 0; i<255; i++)
                {
	                if(arrayDSCP[i] > 0)
                    {
		                dscpflag = true;
		                //PLOG(PL_INFO, "SmfApp::OnCommand(unicast) DSCP: %d\n", i);
		                hookUnicastFlags = detour_ipv4_unicast_flags | ProtoDetour::INPUT | ProtoDetour::OUTPUT;
		                if (!SetupIPv4UnicastDetour(hookUnicastFlags, val, i))
                        {
		                    PLOG(PL_ERROR, "SmfApp::OnCommand(unicast) error opening IPv4 detour\n");
		                    return false;
		                }
	                }
	            }

	            // If no DSCP value was specified, then traffic should be captured regardless of DSCP
	            if (!dscpflag)
                {
	                hookUnicastFlags = detour_ipv4_unicast_flags | ProtoDetour::INPUT | ProtoDetour::OUTPUT;
	                if (!SetupIPv4UnicastDetour(hookUnicastFlags, val, 0))
                    {
		                PLOG(PL_ERROR, "SmfApp::OnCommand(unicast) error opening IPv4 detour\n");
		                return false;
	                }
	            }

	            smf.SetUnicastEnabled(true);
	            smf.SetUnicastPrefix(val);

	            // Enable Firewall Capture for multicast packets
	            if(!firewall_capture)
	               OnCommand("firewallCapture", "on");
            }
            else
            {
                PLOG(PL_ERROR, "SmfApp::OnCommand(unicast) error: invalid interface group name \"%s\"\n", val);
                return false;
            }
        }
#else
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(unicast) error: invalid interface group name \"%s\"\n", val);
            return false;
        }
#endif // if/else _PROTO_DETOUR
    }
    else if (!strncmp("elastic", cmd, len))
    {
        // elastic <groupName>
        Smf::InterfaceGroup* ifaceGroup = smf.FindInterfaceGroup(val);
        if (NULL == ifaceGroup)
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(elastic) error: invalid group name\n");
            return false;
        }
        ifaceGroup->SetElasticMulticast(true);
#ifdef ELASTIC_MCAST
        // Iterate over ifaces in group and add any group memberships to controller
        Smf::InterfaceGroup::Iterator ifacerator(*ifaceGroup);
        Smf::Interface* iface;
        while (NULL != (iface = ifacerator.GetNextInterface()))
        {
            char ifaceName[64];
            ifaceName[63] = '\0';
            if (!ProtoNet::GetInterfaceName(iface->GetIndex(), ifaceName, 63))
            {
                PLOG(PL_ERROR, "SmfApp::OnCommand(elastic) error: unable to retrieve interface name\n");
                return false;
            }
            ProtoAddressList groupList;
            if (!ProtoNet::GetGroupMemberships(ifaceName, ProtoAddress::IPv4, groupList))
            {
                PLOG(PL_ERROR, "SmfApp::OnCommand(elastic) error: unable to retrieve interface %s memberships\n", ifaceName);
                return false;
            }
            ProtoAddress groupAddr;
            ProtoAddressList::Iterator iterator(groupList);
            while (iterator.GetNextAddress(groupAddr))
            {
                if (groupAddr.IsLinkLocal()) continue;
                if (!mcast_controller.AddManagedMembership(iface->GetIndex(), groupAddr))
                {
                    PLOG(PL_ERROR, "SmfApp::OnCommand(elastic) error: unable to add group membership\n");
                    return false;
                }
            }
        }
#endif // ELASTIC_MCAST
        elastic_mcast = true;
    }
    else if (!strncmp("advertise", cmd, len))
    {
#ifdef ELASTIC_MCAST
        // This cues elastic multicast to advertise flows instead of limited forwarding
        // (TBD - allow filters to delineate default forwarding for different traffic.
        //        For example, mission critical data could always be flooded by default)
        smf.SetDefaultForwardingStatus(MulticastFIB::HYBRID);
        mcast_controller.SetDefaultForwardingStatus(MulticastFIB::HYBRID);
#else
        PLOG(PL_ERROR, "SmfApp::OnCommand(advertise) error: 'advertise' option only supported elastic multicast build\n");
#endif
    }
    else if (!strncmp("etx", cmd, len))
    {
#ifdef ELASTIC_MCAST
        ProtoTokenator tk(val, ',');
        const char* ifaceName;
        while (NULL != (ifaceName = tk.GetNextItem()))
        {
            unsigned int ifaceIndex = ProtoNet::GetInterfaceIndex(ifaceName);
            Smf::Interface*iface = smf.GetInterface(ifaceIndex);
            if (NULL == iface)
            {
                PLOG(PL_ERROR, "OnCommand(etx) error: invalid interface \"%s\"\n", ifaceName);
                return false;
            }
            ASSERT(iface->GetIpAddress().IsValid());
            iface->SetETX(true);
        }
#else
        PLOG(PL_ERROR, "SmfApp::OnCommand(etx) error: 'etx' option only supported elastic multicast build\n");
#endif // if/else ELASTIC_MCAST
    }
    else if (!strncmp("reliable", cmd, len))
    {
#ifdef ELASTIC_MCAST
        ProtoTokenator tk(val, ',');
        const char* ifaceName;
        while (NULL != (ifaceName = tk.GetNextItem()))
        {
            unsigned int ifaceIndex = ProtoNet::GetInterfaceIndex(ifaceName);
            Smf::Interface*iface = smf.GetInterface(ifaceIndex);
            if (NULL == iface)
            {
                PLOG(PL_ERROR, "OnCommand(reliable) error: invalid interface \"%s\"\n", ifaceName);
                return false;
            }
            ASSERT(iface->GetIpAddress().IsValid());
            // TBD - provide command-line option and/or config for per-interface cache limit
            if (smf.CreatePacketCache(*iface, 32))
            {
                iface->SetReliable(true);
            }
            else
            {
                PLOG(PL_ERROR, " SmfApp::OnCommand(reliable) error: unable to create packet cache!\n");
                return false;
            }
        }
#else
        PLOG(PL_ERROR, "SmfApp::OnCommand(reliable) error: 'reliable' option only supported elastic multicast build\n");
#endif // if/else ELASTIC_MCAST
    }
#ifdef ELASTIC_MCAST
    else if (!strncmp("utos", cmd, len))
    {
        // sets "unreliable TOS"
        int tos = -1;
        int result = sscanf(val, "%i", &tos);
        if (1 != result)
        {
            unsigned int utos = 256;
            result = sscanf(val, "%x", &utos);
            tos = (int)utos;
        }
        if ((1 != result) || (tos < 0) || (tos > 255))
        {
            fprintf(stderr, "mfApp::OnCommand(utos) error: invalid 'utos' value!\n");
            Usage();
            return -1;
        }
        smf.SetUnreliableTOS((UINT8)tos);
    }
#endif // ELASTIC_MCAST
    else if (!strncmp("adaptive", cmd, len))
    {
        // adaptive <groupName>
        Smf::InterfaceGroup* ifaceGroup = smf.FindInterfaceGroup(val);
        if (NULL == ifaceGroup)
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(adaptive) error: invalid group name\n");
            return false;
        }
        ifaceGroup->SetAdaptiveRouting(true);
#ifdef ADAPTIVE_ROUTING
        // Iterate over ifaces in group and add any group memberships to controller
        Smf::InterfaceGroup::Iterator ifacerator(*ifaceGroup);
        Smf::Interface* iface;
        while (NULL != (iface = ifacerator.GetNextInterface()))
        {
            char ifaceName[64];
            ifaceName[63] = '\0';
            if (!ProtoNet::GetInterfaceName(iface->GetIndex(), ifaceName, 63))
            {
                PLOG(PL_ERROR, "SmfApp::OnCommand(adaptive) error: unable to retrieve interface name\n");
                return false;
            }
            ProtoAddressList groupList;
            if (!ProtoNet::GetGroupMemberships(ifaceName, ProtoAddress::IPv4, groupList))
            {
                PLOG(PL_ERROR, "SmfApp::OnCommand(adaptive) error: unable to retrieve interface %s memberships\n", ifaceName);
                return false;
            }
            ProtoAddress groupAddr;
            ProtoAddressList::Iterator iterator(groupList);
            while (iterator.GetNextAddress(groupAddr))
            {
                if (groupAddr.IsLinkLocal()) continue;
//                if (!smart_controller.AddManagedMembership(iface->GetIndex(), groupAddr))
//                {
//                    PLOG(PL_ERROR, "SmfApp::OnCommand(adaptive) error: unable to add group membership\n");
//                    return false;
//                }
            }
        }
#endif // ADAPTIVE_ROUTING
        adaptive_routing = true;
        smf.SetAdaptiveRouting(true);
    }
#ifdef ELASTIC_MCAST
    else if (!strncmp("allow", cmd, len))
    {
        // syntax: "allow <addr1>[,<addr2>, ...] with "all" as a wildcard address
        bool result = false;
        ProtoTokenator tk(val, ',');
        const char* text;
        while (NULL != (text = tk.GetNextItem()))
        {
            ProtoAddress dstAddr;
            if (0 != strcmp("all", text))
                result = dstAddr.ConvertFromString(text);
            else
                result = true;
            if (!result) break;
            ProtoFlow::Description flowDescription(dstAddr);
            result = mcast_controller.SetPolicy(flowDescription, true);
            if (!result) break;
        }
        if (!result)   
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(allow) invalid argument: %s\n", val);
            return false;
        }     
    }
    else if (!strncmp("deny", cmd, len))
    {
        // syntax: "deny <addr1>[,<addr2>, ...] with "all" as a wildcard address
        bool result = false;
        ProtoTokenator tk(val, ',');
        const char* text;
        while (NULL != (text = tk.GetNextItem()))
        {
            ProtoAddress dstAddr;
            if (0 != strcmp("all", text))
                result = dstAddr.ConvertFromString(text);
            else
                result = true;
            if (!result) break;
            ProtoFlow::Description flowDescription(dstAddr);
            result = mcast_controller.SetPolicy(flowDescription, false);
            if (!result) break;
        }
        if (!result)   
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(allow) invalid argument: %s\n", val);
            return false;
        }     
    }
#endif // ELASTIC_MAST
    else if (!strncmp("filterDups", cmd, len))
    {
        // syntax: "filterDups {on | off}"
        if (!strcmp("on", val))
        {
            filter_duplicates = true;
        }
        else if (!strcmp("off", val))
        {
            filter_duplicates = false;
        }
        else
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(filterDups) invalid argument: %s\n", val);
            return false;
        }
    }
    else if (!strncmp("push", cmd, len))
    {
        // syntax: "push <srcIface,dstIface1,dstIface2,...>"
        if (!ParseInterfaceList("push", Smf::PUSH, val, Smf::CF, false))
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(push) error parsing interface list\n");
            return false;
        }
    }
    else if (!strncmp("rpush", cmd, len))
    {
        // syntax: "rpush <srcIface,dstIface1,dstIface2,...>"
        if (!ParseInterfaceList("push", Smf::PUSH, val, Smf::CF, true))
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(rpush) error parsing interface list\n");
            return false;
        }
    }
    else if (!strncmp("merge", cmd, len))
    {
        // syntax: "merge <iface1,iface2,iface3,...>"
        if (!ParseInterfaceList("merge", Smf::MERGE, val, Smf::CF, false))
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(merge) error parsing interface list\n");
            return false;
        }
    }
    else if (!strncmp("rmerge", cmd, len))
    {
        // syntax: "rmerge <iface1,iface2,iface3,...>"
        if (!ParseInterfaceList("merge", Smf::MERGE, val, Smf::CF, true))
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(rmerge) error parsing interface list\n");
            return false;
        }
    }
    else if (!strncmp("tunnel", cmd, len))
    {
        // A "merge" with no TTL decrement
        // syntax: "tunnel <iface1,iface2,iface3,...>"
        if (!ParseInterfaceList("tunnel", Smf::MERGE, val, Smf::CF, false, true))
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(merge) error parsing interface list\n");
            return false;
        }
    }
    else if (!strncmp("cf", cmd, len))
    {
        // syntax: "cf <iface1,iface2,iface3,...>"
        if (!ParseInterfaceList("cf", Smf::RELAY, val, Smf::CF, false))
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(cf) error parsing interface list\n");
            return false;
        }
    }
    else if (!strncmp("smpr", cmd, len))
    {
        // syntax: "smpr <iface1,iface2,iface3,...>"
        if (!ParseInterfaceList("smpr", Smf::RELAY, val, Smf::S_MPR, false))
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(smpr) error parsing interface list\n");
            return false;
        }
    }
    else if (!strncmp("ecds", cmd, len))
    {
        // syntax: "ecds <iface1,iface2,iface3,...>"
        if (!ParseInterfaceList("ecds", Smf::RELAY, val, Smf::E_CDS, false))
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
            PLOG(PL_ERROR, "SmfApp::OnCommand(relay) error: invalid argument: %s\n", val);
            return false;
        }
    }
    else if (!strncmp("encapsulate", cmd, len))
    {
        if (!EnableEncapsulation(val))
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(encapsulate) error: invalid ifaceList\n");
            return false;
        }
    }
    else if (!strncmp("route", cmd, len))
    {

        if (!ParseRouteList(val))
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(route) error: invalid route command: \"%s\"\n", val);
            return false;
        }
    }
    else if (!strncmp("dscpCapture", cmd, len))
    {
	    // syntax: "dscpCapture {value,dscpValueList}"
        ParseDSCPList(val, SET_DSCP);
	    if(smf.GetUnicastEnabled())
        {
            OnCommand("unicast", "off");
	        OnCommand("unicast", smf.GetUnicastPrefix());
	    }
    }
    else if (!strncmp("dscpRelease", cmd, len))
    {
	    // syntax: "dscpRelease {value,dscpValueList}"
        ParseDSCPList(val, RESET_DSCP);
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

    else if (!strncmp("device", cmd, len))
    {
        // value is in form <vifName>,<ifaceName>[,shadow][,blockIGMP],[,addr1/maskLen,addr2[/maskLen],...
        // copy it so we can parse it
        ProtoTokenator tk(val, ',');
        const char* vifName = tk.GetNextItem(true); // _detaches_ tokenized 'vifName' so needs deletion later
        if (NULL == vifName)
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(device) error: no arguments provided!\n");
            return false;
        }
        const char* ifaceName = tk.GetNextItem(true); // _detaches_ tokenized 'ifaceName' so needs deletion later
        if (NULL == ifaceName)
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(device) error: mission <ifaceName> argument!\n");
            delete[] vifName;
            return false;
        }
        bool shadow = false;
        bool blockIGMP = false;
        const char* addrList;
        while (NULL != (addrList = tk.GetNextPtr()))
        {
            if (0 == strncmp("shadow", addrList, 6))
            {
                shadow = true;
                tk.GetNextItem();  // consume 'shadow' key word
            }
            else if (0 == strncmp("block", addrList, 5))
            {
                blockIGMP = true;
                tk.GetNextItem();  // consume 'blockIGMP' key word
            }
            else
            {
                break;
            }
        }
        unsigned int vifIndex = OpenDevice(vifName, ifaceName, addrList, shadow, blockIGMP);
        delete[] vifName;
        delete[] ifaceName;
        if (0 == vifIndex)
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(device) error: unable to add device \"%s\"!\n", val);
            return false;
        }
    }
    else if (!strncmp("cid", cmd, len))
    {
        // cid <vifName>,<iface1,iface2, ...>
        ProtoTokenator tk(val, ',');
        const char* vifName = tk.GetNextItem(true); // _detaches_ tokenized 'vifName', so we MUST delete it later
        if (NULL == vifName)
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(cid) error: no arguments given!\n");
            Usage();
            return false;
        }
        const char* next;
        unsigned int ifaceCount = 0;  // for error checking
        while (NULL != (next = tk.GetNextItem())) // _detaches_ tokenized 'vifName', so we MUST delete it later
        {
            ifaceCount++;
            ProtoTokenator tk2(next, '/');
            const char* ifaceName = tk2.GetNextItem(true);  // _detaches_ tokenized 'ifaceName', so we MUST delete it later
            const char* ifaceStatus = tk2.GetNextItem();
            int cidFlags;
            if (NULL == ifaceStatus)
            {
                cidFlags = CidElement::CID_TX | CidElement::CID_RX;
            }
            else 
            {
                switch(ifaceStatus[0])
                {
                    case 't':
                        cidFlags = CidElement::CID_TX;
                        break;
                    case 'r':
                        cidFlags = CidElement::CID_RX;
                        break;
                    case 'd':
                    {
                        // remove this interface from the Composite Interface Device (CID)
                        if (!RemoveCidElement(vifName, ifaceName))
                        {
                            PLOG(PL_ERROR, "SmfApp::OnCommand(cid) error: invalid interface status: %s\n", next);
                            delete[] ifaceName;
                            delete[] vifName;
                            return false;
                        }
                        continue;
                    }
                    default:
                        PLOG(PL_ERROR, "SmfApp::OnCommand(cid) error: invalid interface deletion: %s\n", next);
                        delete[] ifaceName;
                        delete[] vifName;
                        return false;
                }
            }
            if (!AddCidElement(vifName, ifaceName, cidFlags, 0))
            {
                PLOG(PL_ERROR, "SmfApp::OnCommand(cid) error: AddCidElement() failure!\n");
                delete[] ifaceName;
                delete[] vifName;
                return false;
            }
            delete[] ifaceName;
        }  // end while (NULL != (next = tk.GetNextItem()))
        delete[] vifName;
        if (0 == ifaceCount)
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(cid) error: no interface list provided!\n");
            Usage();
            return false;
        }
    }
    else if (!strncmp("rate", cmd, len))
    {
        // [<ifaceName>,]<bitsPerSecond>
        Smf::Interface* iface = NULL;
        const char* ratePtr = strchr(val, ',');
        if (NULL != ratePtr)
        {
            char ifaceName[Smf::IF_NAME_MAX + 1];
            size_t nameLen = ratePtr - val;
            if (nameLen > Smf::IF_NAME_MAX) nameLen = Smf::IF_NAME_MAX;
            strncpy(ifaceName, val, nameLen);
            ifaceName[nameLen] = '\0';
            unsigned int ifaceIndex = ProtoNet::GetInterfaceIndex(ifaceName);
            iface = smf.GetInterface(ifaceIndex);
            if (NULL == iface)
            {
                PLOG(PL_ERROR, "OnCommand(rate) error: invalid interface \"%s\"\n", ifaceName);
                return false;
            }
            ratePtr++;  // point past comma delimiter
        }
        else
        {
            ratePtr = val;
        }
        double txRate;
        if (1 != sscanf(ratePtr, "%lf", &txRate))
        {
            PLOG(PL_ERROR, "OnCommand(rate) error: invalid rate value \"%s\"\n", ratePtr);
            return false;
        }
        txRate /= 8.0;  // convert to bytes per second
        if (NULL != iface)
        {
            InterfaceMechanism* mech = static_cast<InterfaceMechanism*>(iface->GetExtension());
            if (mech->SetTxRateLimit(txRate)) ActivateTimer(mech->GetTxTimer());
        }
        else
        {
            // No interface specified, set default rate for added interfaces
            // (TBD - should we make this retroactive for existing interfaces with no limit?)
            SetTxRateLimit(txRate);
        }
    }
    else if (!strncmp("queue", cmd, len))
    {
        // [<iface>,]<limit> zero limit means no queuing, -1 means unlimited queue depth
        Smf::Interface* iface = NULL;
        const char* limitPtr = strchr(val, ',');
        if (NULL != limitPtr)
        {
            size_t namelen = limitPtr - val;
            if (namelen > Smf::IF_NAME_MAX)
                namelen = Smf::IF_NAME_MAX;
            char ifaceName[Smf::IF_NAME_MAX+1];
            strncpy(ifaceName, val, namelen);
            ifaceName[namelen] = '\0';
            unsigned int ifaceIndex = ProtoNet::GetInterfaceIndex(ifaceName);
            iface = smf.GetInterface(ifaceIndex);
            if (NULL == iface)
            {
                PLOG(PL_ERROR, "OnCommand(queue) error: invalid interface \"%s\"\n", ifaceName);
                return false;
            }
            limitPtr++;

        }
        else
        {
            limitPtr = val;
        }
        int qlimit;
        if (1 != sscanf(limitPtr, "%d", &qlimit))
        {
            PLOG(PL_ERROR, "OnCommand(queue) error: invalid queue limit \"%s\"\n", limitPtr);
            return false;
        }
        if (NULL != iface)
        {
            iface->SetQueueLimit(qlimit);
        }
        else
        {
            // Default setting for all new interfaces
            smf_queue_limit = qlimit;
        }
    }
    else if (!strncmp("layered", cmd, len))
    {
        ProtoTokenator tk(val, ',');
        const char* ifaceName;
        while (NULL != (ifaceName = tk.GetNextItem()))
        {
            unsigned int ifaceIndex = ProtoNet::GetInterfaceIndex(ifaceName);
            Smf::Interface*iface = smf.GetInterface(ifaceIndex);
            if (NULL == iface)
            {
                PLOG(PL_ERROR, "OnCommand(layered) error: invalid interface \"%s\"\n", ifaceName);
                return false;
            }
            iface->SetLayered(true);
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
	    //// Cannot disable Firewall Capture if the unicast option is enabled
	    if (smf.GetUnicastEnabled()) {
	        PLOG(PL_ERROR,  "SmfApp::OnCommand(firewallCapture) error: cannot disable Firewall Capture while Unicast is enabled.\n");
                return false;
	    }

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
            snprintf(buffer, 256, "smfClientStart %s", control_pipe_name);
            unsigned int numBytes = strlen(buffer)+1;
            if (!server_pipe.Send(buffer, numBytes))
            {
                PLOG(PL_ERROR, "SmfApp::OnCommand(instance) error sending hello to smf server\n");
                return false;
            }
        }
    }
    else if (!strncmp("load", cmd, len))
    {
        if (!LoadConfig(val))
        {
            PLOG(PL_ERROR, "SmfApp::OnCommand(load) error loading configuration file\n");
            return false;
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
                snprintf(buffer, 256, "smfClientStart %s", control_pipe_name);
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
                snprintf(buffer, 256, "smfClientStart %s", control_pipe_name);
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
    else if (!strncmp("save", cmd, len))
    {
        strncpy(config_path, val, PATH_MAX);
    }
    else
    {
        fprintf(stderr, "SmfApp::OnCommand(%s) error: command not yet supported,\n", cmd);
        return false;
    }
    DisplayGroups();
    return true;
}  // end SmfApp::OnCommand()


bool SmfApp::LoadConfig(const char* configPath)
{
    ProtoJson::Parser parser;
    smf_config.Destroy(); // just in case
    if (!parser.LoadDocument(configPath, &smf_config))
    {
        PLOG(PL_ERROR, "SmfApp::LoadConfig() error parsing configuration file\n");
        return false;
    }

    ProtoJson::Object* configObj = smf_config.AccessConfigurationObject();
    if (NULL == configObj)
    {
        PLOG(PL_ERROR, "SmfApp::LoadConfig() error: empty config?!\n");
        return false;
    }
    // Process any 'device" configs before other commands
    ProtoJson::Object::Iterator iterator(*configObj);
    iterator.Reset(false, "interface");
    ProtoJson::Entry* entry;
    while (NULL != (entry =  iterator.GetNextEntry()))
    {
        ProtoJson::Value* value = entry->AccessValue();
        if ((NULL == value) || (ProtoJson::Item::OBJECT != value->GetType()))
        {
            PLOG(PL_ERROR, "SmfApp::LoadConfig() error: invalid 'device' configuration!\n");
            return false;
        }
        if (!ProcessInterfaceConfig(static_cast<ProtoJson::Object&>(*value)))
        {
            PLOG(PL_ERROR, "SmfApp::LoadConfig() error processing 'device' configuration item\n");
            return false;
        }
    }
    // Process any "group" configuration entries
    iterator.Reset(false, "group");
    while (NULL != (entry =  iterator.GetNextEntry()))
    {
        ProtoJson::Value* value = entry->AccessValue();
        if ((NULL == value) || (ProtoJson::Item::OBJECT != value->GetType()))
        {
            PLOG(PL_ERROR, "SmfApp::LoadConfig() error: invalid 'group' configuration!\n");
            return false;
        }
        if (!ProcessGroupConfig(static_cast<ProtoJson::Object&>(*value)))
        {
            PLOG(PL_ERROR, "SmfApp::LoadConfig() error processing 'group' configuration item\n");
            return false;
        }
    }
    return true;
}  // end SmfApp::LoadConfig()

bool SmfApp::ProcessInterfaceConfig(ProtoJson::Object& ifaceConfig)
{
    const char* ifaceName = ifaceConfig.GetString("name");
    if (NULL == ifaceName)
    {
        PLOG(PL_ERROR, "SmfApp::ProcessInterfaceConfig() error: missing 'name' attribute\n");
        return false;
    }
    
    bool shadow = ifaceConfig.GetBoolean("shadow");         // for vif device interfaces only
    bool blockIGMP = ifaceConfig.GetBoolean("blockIGMP");   // for vif device interfaces only
    
    // Fetch the index to determine if it is an existing interface
    unsigned int ifaceIndex = ProtoNet::GetInterfaceIndex(ifaceName);
    
    ProtoJson::Array* addrArray = ifaceConfig.GetArray("addresses");
    unsigned int addrCount = (NULL != addrArray) ? addrArray->GetLength() : 0;    
    if (0 == ifaceIndex)
    {
        const char* device = ifaceConfig.GetString("device");
        if (NULL == device)
        {
            PLOG(PL_ERROR, "SmfApp::ProcessInterfaceConfig() error: invalid interface \"%s\"\n", ifaceName);
            return false;
        }
        // We pass an empty string (or NULL for steal) here since addresses are added below
        const char* addrListPtr = (0 != addrCount) ? "" : NULL;
        ifaceIndex = OpenDevice(ifaceName, device, addrListPtr, shadow, blockIGMP);
        if (0 == ifaceIndex)
        {
            PLOG(PL_ERROR, "SmfApp::ProcessInterfaceConfig() error: unable to add vif device '%s'\n", device);
            return false;
        }
    }   
    else
    {
        Smf::Interface* iface = GetInterface(ifaceName, ifaceIndex);
        if (NULL == iface)
        {
            PLOG(PL_ERROR, "SmfApp::ProcessInterfaceConfig() error: unable to find interface '%s'\n", ifaceName);
            return false;
        }
    }
    
    // TBD - handle case when vif already exists?
    
    for (unsigned int i = 0; i < addrCount; i++)
    {
        const char* item = addrArray->GetString(i);
        if (NULL == item)
        {
            PLOG(PL_ERROR, "SmfApp::ProcessInterfaceConfig() error:invalid address item at index %u\n", i);
            smf.RemoveInterface(ifaceIndex);
            return false;
        }
        // Look for addr/maskLen (TBD - put this code to process an "addr/mask" item in its own method?
        ProtoTokenator tk2(item, '/');
        const char* addrText = tk2.GetNextItem();
        if (NULL == addrText)
        {
            PLOG(PL_ERROR, "SmfApp::ProcessInterfaceConfig() error: invalid address list item: %s\n", item);
            smf.RemoveInterface(ifaceIndex);
            return false;
        }
        ProtoAddress addr;
        if (!addr.ResolveFromString(addrText))
        {
            PLOG(PL_ERROR, "SmfApp::ProcessInterfaceConfig() error: invalid address \"%s\"\n", addrText);
            smf.RemoveInterface(ifaceIndex);
            return false;
        }
        unsigned int maskLen;
        const char* maskLenText = tk2.GetNextItem();
        if (NULL != maskLenText)
        {
            if (1 != sscanf(maskLenText, "%u", &maskLen))
            {
                PLOG(PL_ERROR, "SmfApp::ProcessInterfaceConfig() error: invalid mask length \"%s\"\n", maskLenText);
                smf.RemoveInterface(ifaceIndex);
                return false;
            }
        }
        else
        {
            maskLen = addr.GetLength() << 3;  // assume full mask len if not specified
        }
        // Assign address to interface
        if (!ProtoNet::AddInterfaceAddress(ifaceName, addr, maskLen))
        {
            PLOG(PL_ERROR, "SmfApp::ProcessInterfaceConfig() error adding configured address %s to vif %s\n", addr.GetHostString(), ifaceName);
            smf.RemoveInterface(ifaceIndex);
            return false;
        }
        smf.AddOwnAddress(addr, ifaceIndex);
    }
    Smf::Interface* iface = smf.GetInterface(ifaceIndex);
    ASSERT(NULL != iface);
    // Save device interface IPv4 addresses for possible IPIP encapsulation use
    ProtoNet::GetInterfaceAddressList(ifaceName, ProtoAddress::IPv4, iface->AccessAddressList());
    iface->UpdateIpAddress();   
    
    // Note "layered" attribute is optional (i.e., default "layered=false" in absence)
    iface->SetLayered(ifaceConfig.GetBoolean("layered"));
    iface->SetReliable(ifaceConfig.GetBoolean("reliable"));
    
    return true;
}  // end SmfApp::ProcessInterfaceConfig()

bool SmfApp::ProcessGroupConfig(ProtoJson::Object& groupConfig)
{
    const char* groupName = groupConfig.GetString("name");
    if (NULL == groupName)
    {
        PLOG(PL_ERROR, "SmfApp::ProcessGroupConfig() error: missing group 'name' attribute\n");
        return false;
    }
    bool reseq = false;
    Smf::Mode forwardingMode = Smf::RELAY;
    const char* relayTypeString = groupConfig.GetString("type");
    if (NULL == relayTypeString)
        relayTypeString = groupConfig.GetString("type");
    if (NULL == relayTypeString)
    {
        PLOG(PL_ERROR, "SmfApp::ProcessGroupConfig() error: missing relay 'type' attribute\n");
        return false;
    }
    Smf::RelayType relayType = Smf::GetRelayType(relayTypeString);
    if (Smf::INVALID == relayType)
    {
        const char* ptr = relayTypeString;
        if ('r' == ptr[0])
        {
            reseq = true;
            ptr++;
        }
        if (0 == strcmp("push", ptr))
        {
            forwardingMode = Smf::PUSH;
            relayType = Smf::CF;
        }
        else if (0 == strcmp("merge", ptr))
        {
            forwardingMode = Smf::MERGE;
            relayType = Smf::CF;
        }
        else
        {
            PLOG(PL_ERROR, "SmfApp::ProcessGroupConfig() error: invalid/unsupported relay 'type'\n");
            return false;
        }
    }
    Smf::InterfaceGroup* ifaceGroup = GetInterfaceGroup(groupName, forwardingMode, relayType, reseq);

    ProtoJson::Array* ifaceArray = groupConfig.GetArray("interfaces");
    if (NULL == ifaceArray)
    {
        PLOG(PL_ERROR, "SmfApp::ProcessGroupConfig() error: missing 'interfaceList' attribute\n");
        return false;
    }
    unsigned int ifaceCount = ifaceArray->GetLength();
    for (unsigned int i = 0; i < ifaceCount; i++)
    {
        const char* ifaceName = ifaceArray->GetString(i);
        if (NULL == ifaceName)
        {
            PLOG(PL_ERROR, "SmfApp::ProcessGroupConfig() error: invalid 'interfaceList' item at index: %u\n", i);
            return false;
        }
        if (!ParseInterfaceName(*ifaceGroup, ifaceName, (0 == i)))
        {
            PLOG(PL_ERROR, "SmfApp::ProcessGroupConfig() error: unable to add interface item \"%s\"\n", ifaceName);
            return false;
        }
    }
    
    // TBD - implement these differently so they don't depend on the command-line interface
    if (groupConfig.GetBoolean("elastic"))
        OnCommand("elastic", groupName);
    if (groupConfig.GetBoolean("unicast"))
        OnCommand("unicast", groupName);
    if (groupConfig.GetBoolean("etx"))
        OnCommand("etx", groupName);
    
    return true;
}  // end SmfApp::ProcessGroupConfig()

bool SmfApp::SaveConfig(const char* configPath)
{
    SmfConfig config;
    // First, save "interface" configurations 
    Smf::InterfaceList::Iterator iterator(smf.AccessInterfaceList());
    Smf::Interface* iface;
    while (NULL != (iface = iterator.GetNextItem()))
    {
        char ifaceName[Smf::IF_NAME_MAX + 1];
        ifaceName[Smf::IF_NAME_MAX] = '\0';
        if (0 == ProtoNet::GetInterfaceName(iface->GetIndex(), ifaceName, Smf::IF_NAME_MAX))
        {
            PLOG(PL_ERROR, "SmfApp::SaveConfig() error: unable to get interface name\n");
            return false;
        }
        // If it's a 'device' (using vif), get underlying physical device name, too
        // and save addresses _explicitly_ assigned (not stolen) to vif device interfaces
        ProtoAddressList* addrList = NULL;
        char deviceName[Smf::IF_NAME_MAX + 1];
        deviceName[Smf::IF_NAME_MAX] = '\0';
        InterfaceMechanism* mech = static_cast<InterfaceMechanism*>(iface->GetExtension());
        ProtoVif* vif = (NULL != mech) ? mech->GetProtoVif() : NULL;
        if (NULL != vif)
        {
            // The "principal" ProtoCap associated with a vif 'device' is the 
            // only one where addresses may have been
            CidElement* elem = mech->GetPrincipalElement();
            if (NULL != elem)
            {
                if (0 == ProtoNet::GetInterfaceName(elem->GetInterfaceIndex(), deviceName, Smf::IF_NAME_MAX))
                {
                    PLOG(PL_ERROR, "SmfApp::SaveConfig() error: unable to get device name\n");
                    return false;
                }
                // Assume if pcap has no addresses, the vif device has 'stolen' addresses
                ProtoAddressList tempList;
                ProtoNet::GetInterfaceAddressList(elem->GetInterfaceIndex(), ProtoAddress::IPv4, tempList);
                if (tempList.IsEmpty())
                    ProtoNet::GetInterfaceAddressList(elem->GetInterfaceIndex(), ProtoAddress::IPv6, tempList);
                // Prune link-local addresses
                ProtoAddressList::Iterator adderator(tempList);
                ProtoAddress addr;
                while (adderator.GetNextAddress(addr))
                {
                    if (addr.IsLinkLocal()) tempList.Remove(addr);
                }
                if (!tempList.IsEmpty())
                    addrList = &iface->AccessAddressList();
            }  // end if (NULL != elem)
        }  // end if (NULL != vif)
        if (!config.AddInterface(ifaceName, addrList, (NULL != vif) ? deviceName : NULL,
                                 iface->IsReliable(), iface->IsLayered(), 
                                 mech->IsShadowing(), mech->BlockIGMP()))
        {
            PLOG(PL_ERROR, "SmfApp::SaveConfig() error: unable to add interface item\n");
            return false;
        }
    }
    // Second, save interface group configs
    Smf::InterfaceGroupList::Iterator grouperator(smf.AccessInterfaceGroupList());
    Smf::InterfaceGroup* group;
    while (NULL != (group = grouperator.GetNextItem()))
    {
        if (!config.AddInterfaceGroup(group->GetName(), group->GetRelayType(), group->AccessInterfaceList(), 
                                      group->IsElastic(), group->GetElasticUnicast(), group->UseETX()))
        {
            PLOG(PL_ERROR, "SmfApp::SaveConfig() error: unable to add interface item\n");
            return false;
        }
    }
    FILE* configFile = fopen(configPath, "w+");
    if (NULL == configFile)
    {
        PLOG(PL_ERROR, "SmfApp::SaveConfig() fopen() error: %s\n", GetErrorString());
        return false;
    }
    config.Print(configFile);
    fclose(configFile);
    return true;
}  // end SmfApp::SaveConfig()


void SmfApp::ParseDSCPList(const char* strDSCPList, int cmd)
{
    // TBD - use ProtoTokenator here
    while((NULL != strDSCPList) && (*strDSCPList != '\0'))
    {
        const char* ptr = strchr(strDSCPList, ',');

        // Get DSCP value length and set ptr to next DSCP value (if applicable)
        size_t len = (NULL != ptr) ? (ptr++ - strDSCPList) : strlen(strDSCPList);
        if (len <= 0)
        {
           strDSCPList = ptr;  // point past comma to next char and try again
           continue;
        }
        ASSERT(len < 4);
        char strDSCP[4];
        strDSCP[3] = '\0';
        strncpy(strDSCP, strDSCPList, len);
        strDSCP[len] = '\0';
	    int dscpval = atoi(strDSCP);
	    if(dscpval >= 256)
	        PLOG(PL_ERROR, "SmfApp::ParseDSCPList(): invalid DSCP value: %d\n", dscpval);
	    if(cmd == SET_DSCP)
	        smf.SetUnicastDSCP(dscpval);
        else
	        smf.UnsetUnicastDSCP(dscpval);
	    strDSCPList = ptr;
    }  // end while (NULL != strDSCPlist) ...)

}  // end SmfApp::ParseDSCPList()


// print current groups to log output
void SmfApp::DisplayGroups()
{
    if (GetDebugLevel() < PL_DEBUG) return;
    PLOG(PL_DEBUG, "CURRENT GROUPS:\n");
    Smf::InterfaceGroupList::Iterator grouperator(smf.AccessInterfaceGroupList());
    Smf::InterfaceGroup* group;
    while (NULL != (group = grouperator.GetNextItem()))
    {
        if (group->IsTemplateGroup())
            PLOG(PL_ALWAYS, "   tmplate group ");
        else
            PLOG(PL_ALWAYS, "   regular group ");
        PLOG(PL_ALWAYS, "\"%s\" ", group->GetName());
        bool comma = false;
        char ifaceName[Smf::IF_NAME_MAX + 1];
        ifaceName[Smf::IF_NAME_MAX] = '\0';
        if ((Smf::PUSH == group->GetForwardingMode()) && (NULL != group->GetPushSource()))
        {
            // print source interface name first for PUSH groups
            ProtoNet::GetInterfaceName(group->GetPushSource()->GetIndex(), ifaceName, Smf::IF_NAME_MAX);
            PLOG(PL_ALWAYS, "%s", ifaceName);
            comma = true;
        }
        Smf::InterfaceGroup::Iterator ifacerator(*group);
        Smf::Interface* iface;
        while (NULL != (iface = ifacerator.GetNextInterface()))
        {
            if ((Smf::PUSH == group->GetForwardingMode()) &&
                (group->GetPushSource() == iface))
                continue;  // already printed
            ProtoNet::GetInterfaceName(iface->GetIndex(), ifaceName, Smf::IF_NAME_MAX);
            PLOG(PL_ALWAYS, "%s%s", comma ? "," : "", ifaceName);
            comma = true;
        }
        PLOG(PL_ALWAYS, "%s\n", group->GetElasticMulticast() ? " (Elastic Multicast)" : "");
        PLOG(PL_ALWAYS, "%s\n", group->GetAdaptiveRouting() ? " (Adaptive Routing)" : "");
    }
    PLOG(PL_ALWAYS, "MATCHERS:\n");
    InterfaceMatcherList::Iterator matcherator(iface_matcher_list);
    InterfaceMatcher* m;
    while (NULL != (m = matcherator.GetNextItem()))
    {
        PLOG(PL_ALWAYS, "   %s -> %s%s\n", m->GetPrefix(), m->GetGroupName(), m->IsSourceMatcher() ? " (src)" : "");
    }
    PLOG(PL_ALWAYS, "\n");

}  // end SmfApp::DisplayGroups()

bool SmfApp::EnableEncapsulation(const char* ifaceList)
{
    // comma-delimited ifaceList in the form <ifaceName>[/<dstMAC>][,<ifaceName2>[/dstMAC2>]] ...
    const size_t ENCAP_NAME_MAX = Smf::IF_NAME_MAX + 12;  // allows for ifaceName and optional MAC addr w/ delimiter
    char ifaceName[ENCAP_NAME_MAX + 1];
    const char* ptr = ifaceList;
    while (NULL != ptr)
    {
        const char* nextPtr = strchr(ptr, ',');
        size_t nameLen;
        if (NULL != nextPtr)
        {
            nameLen = nextPtr - ptr;
            nextPtr++;
        }
        else
        {
            nameLen = strlen(ptr);
        }
        if (nameLen > ENCAP_NAME_MAX) nameLen = ENCAP_NAME_MAX;
        strncpy(ifaceName, ptr, nameLen);
        ifaceName[nameLen] = '\0';
        char* macPtr = strchr(ifaceName, '/');
        if (NULL != macPtr) *macPtr++ = '\0';
        Smf::Interface* iface = GetInterface(ifaceName);
        if (NULL == iface)
        {
            PLOG(PL_ERROR, "SmfApp::EnableEncapsulation() error: invalid interface name \"%s\"\n", ifaceName);
            return false;
        }
        iface->SetEncapsulation(true);
        if (NULL != macPtr)
        {
            ProtoAddress dstMacAddr;
            if (!dstMacAddr.ResolveEthFromString(macPtr))
            {
                PLOG(PL_ERROR, "SmfApp::EnableEncapsulation() error: invalid destination MAC address \"%s\"\n", macPtr);
                return false;
            }
            iface->SetEncapsulationLink(dstMacAddr);
        }
        ptr = nextPtr;
    }
    return true;
}  // end SmfApp::EnableEncapsulation()

bool SmfApp::ParseRouteList(const char* routeList)
{
    // The routeList MUST begin with and "add", "delete", or "clear" command
    char cmd[8];
    const char* ptr = strchr(routeList, ',');
    size_t cmdLen = (NULL != ptr) ? (ptr - routeList) : strlen(routeList);
    if (cmdLen > 7) cmdLen = 7;
    strncpy(cmd, routeList, cmdLen);
    cmd[cmdLen] = '\0';
    for (size_t i = 0; i < cmdLen; i++)
        cmd[i] = tolower(cmd[i]);
    bool addRoute = false;
    if (0 == strncmp("add", cmd, cmdLen))
    {
        addRoute = true;
    }
    else if (0 == strncmp("clear", cmd, cmdLen))
    {
        // Clear all routes
        route_table.Destroy();
        return true;
    }
    else if (0 != strncmp("delete", cmd, cmdLen))
    {
        PLOG(PL_ERROR, "SmfApp::ParseRouteList() error: invalid route command \"%s\"\n", cmd);
        return false;
    }
    // else delete listed route items

    if (NULL == ptr)
    {
        PLOG(PL_ERROR, "SmfApp::ParseRouteList() error: missing <routeList>\n", cmd);
        return false;
    }
    ptr++;
    while (NULL != ptr)
    {
        // Each <routeItem> in the list is semi-colon delimited (w/ comma-delimited fields)
        const char* nextPtr = strchr(ptr, ';');
        size_t itemLen;
        if (NULL != nextPtr)
        {
            itemLen = nextPtr - ptr;
            nextPtr++;
        }
        else
        {
            itemLen = strlen(ptr);
        }
        if (itemLen < 1)
        {
            // Empty item due to terminating ';' or something
            ptr = nextPtr;
            continue;
        }
        char routeItem[256];
        if (itemLen > 255) itemLen = 255;
        strncpy(routeItem, ptr, itemLen);
        routeItem[itemLen] = '\0';
        // routeItem should be in form <dst>[/<maskLen>],<gwAddr>[,<ifIndex>,[<metric>]]  (note <gwAddr> optional for "delete" cmd)
        ProtoAddress dstAddr;
        ProtoAddress gwAddr;
        unsigned int ifIndex = 0;
        int metric = -1;
        char* dstPtr = routeItem;
        char* gwPtr = strchr(dstPtr, ',');
        if (NULL != gwPtr)
        {
            *gwPtr++ = '\0';
            char* indexPtr = strchr(gwPtr, ',');
            if (NULL != indexPtr)
            {
                *indexPtr++ = '\0';
                char* metricPtr = strchr(indexPtr, ',');
                if (NULL != metricPtr)
                {
                    *metricPtr++ = '\0';
                    if (1 != sscanf(metricPtr, "%d", &metric))
                    {
                        PLOG(PL_ERROR, "SmfApp::ParseRouteList() error: invalid metric \"%s\"\n", metricPtr);
                        return false;
                    }
                }
                if (1 != sscanf(indexPtr, "%u", &ifIndex))
                {
                    PLOG(PL_ERROR, "SmfApp::ParseRouteList() error: invalid interface index \"%s\"\n", indexPtr);
                    return false;
                }
            }
            char* tmpPtr = gwPtr;
            while ('\0' != *tmpPtr)
            {
                *tmpPtr = tolower(*tmpPtr);
                tmpPtr++;
            }
            if (0 == strcmp("none", gwPtr))
            {
                if (0 == ifIndex)
                {
                    PLOG(PL_ERROR, "SmfApp::ParseRouteList() error: missing ifIndex!\n");
                    return false;
                }
            }
            else if (!gwAddr.ResolveFromString(gwPtr))
            {
                PLOG(PL_ERROR, "SmfApp::ParseRouteList() error: invalid gateway address \"%s\"\n", gwPtr);
                return false;
            }
        }
        char* maskPtr = strchr(dstPtr, '/');
        if (NULL != maskPtr) *maskPtr++ = '\0';
        if (!dstAddr.ResolveFromString(dstPtr))
        {
            PLOG(PL_ERROR, "SmfApp::ParseRouteList() error: invalid destination address \"%s\"\n", dstPtr);
            return false;
        }
        unsigned int maskLen = 8 * dstAddr.GetLength();
        if (NULL != maskPtr)
        {
            if (1 != sscanf(maskPtr, "%u", &maskLen))
            {
                PLOG(PL_ERROR, "SmfApp::ParseRouteList() error: invalid mask length \"%s\"\n", maskPtr);
                return false;
            }
        }
        if (addRoute)
        {

            if (!route_table.SetRoute(dstAddr, maskLen, gwAddr, ifIndex, metric))
            {
                PLOG(PL_ERROR, "SmfApp::ParseRouteList() error: unable to add route!\n");
                return false;
            }
        }
        else
        {
            if (!route_table.DeleteRoute(dstAddr, maskLen, gwAddr.IsValid() ? &gwAddr : NULL, ifIndex))
            {
                PLOG(PL_ERROR, "SmfApp::ParseRouteList() error: unable to add route!\n");
                return false;
            }
        }

        ptr = nextPtr;
    }
    return true;
}  // end SmfApp::ParseRouteList()


// This method gets (creates as needed) and configures an interface group
Smf::InterfaceGroup* SmfApp::GetInterfaceGroup(const char*         groupName,
                                               Smf::Mode           mode,
                                               Smf::RelayType      relayType,
                                               bool                rseq,
                                               bool                tunnel,
                                               InterfaceMatcher*   matcher,
                                               bool                isTemplate)
{
    Smf::InterfaceGroup* ifaceGroup = smf.FindInterfaceGroup(groupName);
    if (NULL == ifaceGroup)
    {
        PLOG(PL_DEBUG, "SmfApp::GetInterfaceGroup() NEW interface %sgroup \"%s\" ...\n", isTemplate ? "template " : "", groupName);
        ifaceGroup = smf.AddInterfaceGroup(groupName);
        if (NULL == ifaceGroup)
        {
            PLOG(PL_ERROR, "SmfApp::GetInterfaceGroup() new InterfaceGroup error: %s\n", GetErrorString());
            return NULL;
        }
        ifaceGroup->SetTemplateGroup(isTemplate);  // if "true", this will be a template group for wildcard PUSH sources
        ifaceGroup->SetForwardingMode(mode);
        ifaceGroup->SetRelayType(relayType);
        ifaceGroup->SetResequence(rseq);
        ifaceGroup->SetTunnel(tunnel);
        if ((Smf::PUSH == mode) && (NULL != matcher) && (matcher->IsSourceMatcher()))
        {
            // This is a new push source, so we need to add destination interfaces from corresponding template group
            Smf::InterfaceGroup* templateGroup = smf.FindInterfaceGroup(matcher->GetGroupName());

            if (NULL == templateGroup)
            {
                // Need to create (or recreate) template group
                if (NULL == (templateGroup = smf.AddInterfaceGroup(matcher->GetGroupName())))
                {
                    PLOG(PL_ERROR, "SmfApp::GetInterfaceGroup() new template InterfaceGroup error: %s\n", GetErrorString());
                    return NULL;
                }
                templateGroup->SetTemplateGroup(true);
                templateGroup->CopyAttributes(*ifaceGroup);
                PLOG(PL_DEBUG, "SmfApp::GetInterfaceGroup() NEW template interface group \"%s\"\n", matcher->GetGroupName());
            }
            Smf::InterfaceGroup::Iterator ifacerator(*templateGroup);
            Smf::Interface* iface;
            while (NULL != (iface = ifacerator.GetNextInterface()))
            {
                if (!ifaceGroup->AddInterface(*iface))
                {
                    PLOG(PL_ERROR, "SmfApp::GetInterfaceGroup() error: unable to add destination iface to new source group\n");
                    return NULL;
                }
#ifdef PROTO_DEBUG
                // This is for debugging output purposes only
                char dstIfaceName[Smf::IF_NAME_MAX+1];
                dstIfaceName[Smf::IF_NAME_MAX] = '\0';
                if (ProtoNet::GetInterfaceName(iface->GetIndex(), dstIfaceName, Smf::IF_NAME_MAX))
                    PLOG(PL_DEBUG, "SmfApp::GetInterfaceGroup() added destination iface \"%s\" to PUSH group \"%s\"\n", dstIfaceName, ifaceGroup->GetName());
#endif // PROTO_DEBUG
            }
        }
    }
    else
    {
        if ((mode != ifaceGroup->GetForwardingMode()) || (rseq != ifaceGroup->GetResequence()))
        {
            // Not allowed to change forwarding mode or resequence status of existing group
            PLOG(PL_ERROR, "SmfApp::GetInterfaceGroup() error: inconsistent forwarding mode or resequence status for group \"%s\"\n", groupName);
            return NULL;
        }
        if (relayType != ifaceGroup->GetRelayType())  // let it slide, but issue warning (interface associations will be updated)
        {
            PLOG(PL_WARN, "SmfApp::GetInterfaceGroup() warning: changing relay type for group \"%s\"?!\n", groupName);
            ifaceGroup->SetRelayType(relayType);
        }
        if (rseq != ifaceGroup->GetResequence())  // let it slide, but issue warning (interface associations will be updated)
        {
            PLOG(PL_WARN, "SmfApp::GetInterfaceGroup() warning: changing resequence option for group \"%s\"?!\n", groupName);
            ifaceGroup->SetResequence(rseq);
        }
        if (tunnel != ifaceGroup->IsTunnel())  // let it slide, but issue warning (interface associations will be updated)
        {
            PLOG(PL_WARN, "SmfApp::GetInterfaceGroup() warning: changing tunnel mode for group \"%s\"?!\n", groupName);
            ifaceGroup->SetTunnel(tunnel);
        }
    }
    return ifaceGroup;
}  // end SmfApp::GetInterfaceGroup()

// "mode = Smf::PUSH, Smf::MERGE, SMPR, ECDS, NSMPR, etc
bool SmfApp::ParseInterfaceList(const char*         groupName,
                                Smf::Mode           mode,
                                const char*         ifaceList,
                                Smf::RelayType      relayType,
                                bool                rseq,
                                bool                tunnel,
                                InterfaceMatcher*   matcher)
{
    if (NULL == groupName)
    {
        PLOG(PL_ERROR, "SmfApp::ParseInterfaceList() error: NULL group name?!\n");
        ASSERT(0);
        return false;
    }

    // If the forwarding "mode" is PUSH, we need to refactor the group name
    // to the PUSH <srcIface>, so we adjust groupName here if needed (Note if the srcIface is
    // a 'wildcard' interface name (delineated by inclusion of '#' wildcard, then a "dummy"
    // push group is created with a list of interfaces for future push activations (i.e., when
    // a matching <srcIface> goes up)
    char pushGroupName[Smf::IF_GROUP_NAME_MAX+Smf::IF_NAME_MAX+2];
    pushGroupName[Smf::IF_GROUP_NAME_MAX+Smf::IF_NAME_MAX+1] = '\0';
    bool isTemplate = false;  // will be set true if it's a template PUSH group with a 'wildcard' source interface name
    if (Smf::PUSH == mode)
    {
        // PUSH groups are always named <group>:<srcIface> so we can identify multiple
        // ones in the same group.
        // We use the PUSH "srcIface" for group name since no explicit group was given
        size_t glen = strlen(groupName);
        if (glen > Smf::IF_GROUP_NAME_MAX) glen = Smf::IF_GROUP_NAME_MAX;
        strncpy(pushGroupName, groupName, glen);
        pushGroupName[glen++]= ':';
        const char* ptr = strchr(ifaceList, ',');
        size_t ilen = (NULL != ptr) ? ptr - ifaceList : strlen(ifaceList);
        if (ilen > Smf::IF_NAME_MAX) ilen = Smf::IF_NAME_MAX;
        strncpy(pushGroupName + glen, ifaceList, ilen);
        pushGroupName[glen+ilen] = '\0';

        // Is it a "wildcard" source interface name (e.g. "ppp#")
        char* ifaceNamePtr = pushGroupName + glen;
        char* hashPtr = strchr(ifaceNamePtr, '#');
        if (NULL != hashPtr)
        {
            *hashPtr = '\0';
            isTemplate = true;
        }
        groupName = pushGroupName;
    }

    Smf::InterfaceGroup* ifaceGroup = GetInterfaceGroup(groupName, mode, relayType, rseq, tunnel, matcher, isTemplate);
    if (NULL == ifaceGroup)
    {
        PLOG(PL_ERROR, "SmfApp::ParseInterfaceList() error: unable to get/configure interface group\n");
        return false;
    }

    ProtoTokenator tk(ifaceList, ',');
    bool firstIface = true;
    const char* ifaceName;
    while (NULL != (ifaceName = tk.GetNextItem()))
    {
        if (!ParseInterfaceName(*ifaceGroup, ifaceName, firstIface))
        {
            PLOG(PL_ERROR, "SmfApp::ParseInterfaceList() error: unable to add interface item \"%s\"\n", ifaceName);
            return false;
        }
        firstIface = false;
    }
    return true;
}  // end SmfApp::ParseInterfaceList()

bool SmfApp::ParseInterfaceName(Smf::InterfaceGroup& ifaceGroup, const char* ifaceName, bool isSourceIface)
{
    // Is this a 'wildcard' interface?
    const char* hashPtr = strchr(ifaceName, '#');
    if (NULL != hashPtr)
    {
        size_t prefixLen = hashPtr - ifaceName;
        char ifName[Smf::IF_NAME_MAX+1];
        ifName[Smf::IF_NAME_MAX] = '\0';
        strncpy(ifName, ifaceName, prefixLen);
        ifName[prefixLen] = '\0';

        // Create or replace matcher using ifaceGroup information
        InterfaceMatcherList::Iterator matcherator(iface_matcher_list, false, ifName, strlen(ifName) << 3);
        InterfaceMatcher* ifaceMatcher;
        bool sourceMatcher = isSourceIface && (Smf::PUSH == ifaceGroup.GetForwardingMode());
        while (NULL != (ifaceMatcher = matcherator.GetNextItem()))
        {
            // Is this an existing interface matcher
            // i.e., same iface prefix, group name, source match
            // Does the iface prefix _and_ iface group match?
            if ((0 == strcmp(ifaceMatcher->GetPrefix(), ifName)) &&
                (0 == strcmp(ifaceMatcher->GetGroupName(), ifaceGroup.GetName())) &&
                (ifaceMatcher->IsSourceMatcher() == sourceMatcher))
                break; // a matching matcher was found, so we're updating its parameters
        }
        if (NULL == ifaceMatcher)
        {
            // Create a new matcher to map matching interfaces to group
            if (NULL == (ifaceMatcher = new InterfaceMatcher(ifName, ifaceGroup)))
            {
                PLOG(PL_ERROR, "SmfApp::ParseInterfaceName() new InterfaceMatcher error: %s\n", GetErrorString());
                return false;
            }
            ifaceMatcher->SetSourceMatcher(sourceMatcher);
            if (!iface_matcher_list.Insert(*ifaceMatcher))
            {
                PLOG(PL_ERROR, "SmfApp::ParseInterfaceName() error: unable to insert new InterfaceMatcher!\n");
                delete ifaceMatcher;
                return false;
            }
        }

        // If any existing interfaces are a match, place them in the appropriate group(s)
        if (!(MatchExistingInterfaces(*ifaceMatcher)))
        {
            PLOG(PL_ERROR, "SmfApp::ParseInterfaceName() error: unable to add existing interfaces\n");
            return false;
        }

    }
    else
    {
        Smf::Interface* iface = GetInterface(ifaceName);
        if (NULL == iface)
        {
            PLOG(PL_ERROR, "SmfApp::ParseInterfaceName() error: unable to add new Smf::Interface\n");
            return false;
        }
        if (!AddInterfaceToGroup(ifaceGroup, *iface, isSourceIface))
        {
            PLOG(PL_ERROR, "SmfApp::ParseInterfaceName() error: unable to add interface \"%s\" to group \"%s\"\n",
                            ifaceName, ifaceGroup.GetName());
            return false;
        }
        PLOG(PL_DEBUG, "SmfApp::ParseInterfaceName() added SMF %sinterface \"%s\" to %sgroup \"%s\"\n",
                isSourceIface ? "source " : "", ifaceName, ifaceGroup.IsTemplateGroup() ? "template " : "", ifaceGroup.GetName());
    }
    return true;
}  // end SmfApp::ParseInterfaceName()

// This gets a known Smf::Interface by name or creates a new one
// and adds to our set of known interfaces
Smf::Interface* SmfApp::GetInterface(const char* ifName, unsigned int ifIndex)
{
    if (0 == ifIndex)
        ifIndex = ProtoNet::GetInterfaceIndex(ifName);
    if (0 == ifIndex)
    {
        PLOG(PL_ERROR, "SmfApp::GetInterface() error: invalid iface name \"%s\"\n", ifName);
        return NULL;
    }
    Smf::Interface* iface = smf.GetInterface(ifIndex);
    if (NULL != iface) return iface;

    // TBD - Check if the interface is up here???
    if (NULL == iface)
    {
        if (NULL == (iface = smf.AddInterface(ifIndex)))
        {
            PLOG(PL_ERROR, "SmfApp::GetInterface(): new Smf::Interface error: %s\n", GetErrorString());
            return NULL;
        }
        // Set interface to default queuing limit until overridden
        iface->SetQueueLimit(smf_queue_limit);
        // Add the MAC (ETH) addr for this iface to our SMF local addr list
        ProtoAddress ifAddr;
        if (!ProtoSocket::GetInterfaceAddress(ifName, ProtoAddress::ETH, ifAddr))
        {
            PLOG(PL_ERROR, "SmfApp::GetInterface() error: unable to get ETH addr for iface:%s\n", ifName);
            smf.RemoveInterface(ifIndex);
            return NULL;
        }
        if (!smf.AddOwnAddress(ifAddr, ifIndex))
        {
            PLOG(PL_ERROR, "SmfApp::GetInterface() error: unable to add ETH addr to local addr list.\n");
            smf.RemoveInterface(ifIndex);
            return NULL;
        }
        iface->SetInterfaceAddress(ifAddr);
        // Iterate over and add IP addresses for this interface to our SMF local addr list
        ProtoAddressList addrList;
        if (!ProtoNet::GetInterfaceAddressList(ifIndex, ProtoAddress::IPv4, addrList))
            PLOG(PL_WARN, "SmfApp::GetInterface() error: couldn't retrieve IPv4 address for iface: %s\n", ifName);
        // Save device interface IPv4 addresses for possible IPIP encapsulation use
        iface->AccessAddressList().AddList(addrList);
        iface->UpdateIpAddress();
        if (!ProtoNet::GetInterfaceAddressList(ifIndex, ProtoAddress::IPv6, addrList))
            PLOG(PL_WARN, "SmfApp::GetInterface() error: couldn't retrieve IPv6 address for iface: %s\n", ifName);
        if (addrList.IsEmpty())
        {
            PLOG(PL_WARN, "SmfApp::GetInterface() warning: no IP addresses found for iface: %s\n", ifName);
        }
        ProtoAddressList::Iterator iterator(addrList);
        ProtoAddress addr;
        while (iterator.GetNextAddress(addr))
        {
            // TBD - check result here?
            smf.AddOwnAddress(addr, ifIndex);
        }
    }  // end if (NULL == iface)

    // Do we already have a "ProtoCap" and/or "ProtoDetour" (as appropriate) for this ifaceIndex?
    InterfaceMechanism* mech = static_cast<InterfaceMechanism*>(iface->GetExtension());
    if (NULL == mech)
    {
        if (NULL == (mech = new InterfaceMechanism(*iface, pkt_pool)))
        {
            PLOG(PL_ERROR, "SmfApp::GetInterface(): new InterfaceMechanism error: %s\n", GetErrorString());
            smf.RemoveInterface(ifIndex);
            return NULL;
        }
        iface->SetExtension(*mech);
        mech->GetTxTimer().SetListener(mech, &SmfApp::InterfaceMechanism::OnTxTimeout);
        if (mech->SetTxRateLimit(default_tx_rate_limit)) ActivateTimer(mech->GetTxTimer());  // inherit SmfApp default tx_rate_limit
    }
    // We always open a ProtoCap for each interface to ensure that it is in
    // promiscuous mode to get packets.  Later, we enable ProtoCap input
    // notification for input interfaces (and remove ProtoCaps for
    // "firewall_forward" interfaces that are not used for input)
    if (NULL == mech->GetPrincipalElement())
    {
        ProtoCap* cap = ProtoCap::Create();
        if (NULL == cap)
        {
            PLOG(PL_ERROR, "SmfApp::GetInterface(): ProtoCap::Create() error: %s\n", GetErrorString());
            smf.RemoveInterface(ifIndex);
            return NULL;
        }
        cap->SetListener(this, &SmfApp::OnPktCapture);
        cap->SetNotifier(static_cast<ProtoChannel::Notifier*>(&dispatcher));
        if (!cap->Open(ifName))
        {
            PLOG(PL_ERROR, "SmfApp::GetInterface(): ProtoCap::Open(%s) error: %s\n", ifName, GetErrorString());
            delete cap;
            smf.RemoveInterface(ifIndex);
            return NULL;
        }
        cap->StopInputNotification();  // will be re-enabled in UpdateGroupAssociations() as needed
        cap->SetUserData(iface);
        unsigned int flags = CidElement::CID_TX | CidElement::CID_RX;
        mech->AddCidElement(*cap, flags);
    }  // end if (mech->GetElementList().IsEmpty())

#ifdef _PROTO_DETOUR
    if (firewall_forward || smf.GetUnicastEnabled())
    {
        // "firewallForward" detour open as INJECT-only (only underlying raw socket is opened/used)
        ProtoDetour* detour = mech->GetProtoDetour();
        if (NULL == detour)
        {
            // Create and open new ProtoDetour for this iface
            if (NULL == (detour = ProtoDetour::Create()))
            {
                PLOG(PL_ERROR, "SmfApp::GetInterface(): ProtoDetour::Create() error: %s\n", GetErrorString());
                smf.RemoveInterface(ifIndex);
                return NULL;
            }
            detour->SetListener(this, &SmfApp::OnPktIntercept);
            detour->SetNotifier(static_cast<ProtoChannel::Notifier*>(&dispatcher));
            // Open in "inject-only" mode (no firewall rules are set up as we use a RAW socket)
            if (!detour->Open(ProtoDetour::INJECT))
            {
                PLOG(PL_ERROR, "SmfApp::GetInterface(): ProtoDetour::Open(INJECT) error: %s\n", GetErrorString());
                delete detour;
                smf.RemoveInterface(ifIndex);
                return NULL;
            }
            if (!detour->SetMulticastInterface(ifName))
            {
                PLOG(PL_ERROR, "SmfApp::GetInterface(): ProtoDetour::SetMulticastInterface(%s) failure: %s\n", ifName, GetErrorString());
                delete detour;
                smf.RemoveInterface(ifIndex);
                return NULL;
            }
            mech->SetProtoDetour(detour);
            detour->SetUserData(iface);
        }
    }
#endif // _PROTO_DETOUR
    return iface;
}  // SmfApp::GetInterface()


bool SmfApp::AddInterfaceToGroup(Smf::InterfaceGroup& ifaceGroup, Smf::Interface& iface, bool isSourceIface)
{
    // Add interface to ifaceGroup and update group associations
    if (!ifaceGroup.Contains(iface))
    {
        if (!ifaceGroup.AddInterface(iface))
        {
            PLOG(PL_ERROR, "SmfApp::AddInterfaceToGroup() error: unable to add interface to group\n");
            return false;
        }
        if (Smf::PUSH == ifaceGroup.GetForwardingMode() && isSourceIface)
        {
            ifaceGroup.SetPushSource(&iface);
        }
    }
    if (ifaceGroup.IsTemplateGroup())
    {
        ASSERT(Smf::PUSH == ifaceGroup.GetForwardingMode());
        ASSERT(!isSourceIface);
        return true;  // we don't update group associations for PUSH
    }
    else
    {
#ifdef ELASTIC_MCAST
        if (ifaceGroup.GetElasticMulticast())
        {
            // Add this interface's group memberships to mcast_controller
            char ifaceName[64];
            ifaceName[63] = '\0';
            if (!ProtoNet::GetInterfaceName(iface.GetIndex(), ifaceName, 63))
            {
                PLOG(PL_ERROR, "SmfApp::AddInterfaceToGroup(%s) error: unable to retrieve interface name\n", ifaceName);
                return false;
            }
            ProtoAddressList groupList;
            if (!ProtoNet::GetGroupMemberships(ifaceName, ProtoAddress::IPv4, groupList))
            {
                PLOG(PL_ERROR, "SmfApp::AddInterfaceToGroup(%s) error: unable to retrieve interface %s memberships\n", ifaceName);
                return false;
            }
            ProtoAddress groupAddr;
            ProtoAddressList::Iterator iterator(groupList);
            while (iterator.GetNextAddress(groupAddr))
            {
                if (groupAddr.IsLinkLocal()) continue;
                if (!mcast_controller.AddManagedMembership(iface.GetIndex(), groupAddr))
                {
                    PLOG(PL_ERROR, "SmfApp::AddInterfaceToGroup(%s) error: unable to add group membership\n", ifaceName);
                    return false;
                }
            }
        }
#endif // ELASTIC_MCAST
#ifdef ADAPTIVE_ROUTING
        if (ifaceGroup.GetAdaptiveRouting())
        {
            // Add this interface's group memberships to mcast_controller
            char ifaceName[64];
            ifaceName[63] = '\0';
            if (!ProtoNet::GetInterfaceName(iface.GetIndex(), ifaceName, 63))
            {
                PLOG(PL_ERROR, "SmfApp::AddInterfaceToGroup(%s) error: unable to retrieve interface name\n", ifaceName);
                return false;
            }
            ProtoAddressList groupList;
            if (!ProtoNet::GetGroupMemberships(ifaceName, ProtoAddress::IPv4, groupList))
            {
                PLOG(PL_ERROR, "SmfApp::AddInterfaceToGroup(%s) error: unable to retrieve interface %s memberships\n", ifaceName);
                return false;
            }
            ProtoAddress groupAddr;
            ProtoAddressList::Iterator iterator(groupList);
            while (iterator.GetNextAddress(groupAddr))
            {
                if (groupAddr.IsLinkLocal()) continue;
//                if (!mcast_controller.AddManagedMembership(iface.GetIndex(), groupAddr))
//                {
//                    PLOG(PL_ERROR, "SmfApp::AddInterfaceToGroup(%s) error: unable to add group membership\n", ifaceName);
//                    return false;
//                }
            }
        }
#endif // ADAPTIVE_ROUTING
        return UpdateGroupAssociations(ifaceGroup);  // TBD - we could economize this by optionally passing in the "iface" being added
    }
}  // end SmfApp::AddInterfaceToGroup()

bool SmfApp::MatchInterface(InterfaceMatcher& ifaceMatcher, const char* ifName, unsigned int ifIndex)
{
    if (0 == ifIndex)
    {
        if (0 == (ifIndex = ProtoNet::GetInterfaceIndex(ifName)))
        {
            PLOG(PL_ERROR, "SmfApp::MatchInterface() error: invalid interface \"%s\"\n", ifName);
            return false;
        }
    }
    if (Smf::PUSH == ifaceMatcher.GetForwardingMode())
    {
        if (ifaceMatcher.IsSourceMatcher())
        {
            // It's a push source matcher so we need use base group name and iface name to possibly
            // establish a new source push group
            char groupName[Smf::IF_GROUP_NAME_MAX+1];  // for group base name only
            const char* ptr = strchr(ifaceMatcher.GetGroupName(), ':');
            ASSERT(NULL != ptr);
            size_t baseNameLen = ptr - ifaceMatcher.GetGroupName();
            strncpy(groupName, ifaceMatcher.GetGroupName(), baseNameLen);
            groupName[baseNameLen] = '\0';
            // We call ParseInterfaceList() to invoke creation of new PUSH group with given source iface as needed
            if (!ParseInterfaceList(groupName, Smf::PUSH, ifName, Smf::CF, ifaceMatcher.GetResequence(), ifaceMatcher.IsTunnel(), &ifaceMatcher))
            {
                PLOG(PL_ERROR, "SmfApp::MatchInterface() error: unable to create PUSH group \"%s:%s\"\n", groupName, ifName);
                return false;
            }
        }
        else
        {
            // If the interface is a destination match to a template group, we need to
            // add the interface to all groups matching the template group name prefix
            // (including the template group itself).  If it's not, this should work
            // to add destination interface matches to just the intended group
            const char* groupName = ifaceMatcher.GetGroupName();
            Smf::InterfaceGroupList::Iterator grouperator(smf.AccessInterfaceGroupList());
            // Set a iterator prefix to give us the "group::ifacePrefix" prefix subtree
            grouperator.Reset(false, groupName, strlen(groupName) << 3);
            Smf::InterfaceGroup* group;
            while (NULL != (group = grouperator.GetNextItem()))
            {
                if (!ParseInterfaceName(*group, ifName, false))
                {
                    PLOG(PL_ERROR, "SmfApp::MatchInterface() error: unable to add matched interface \"%s\" to PUSH group \"%s\"\n",
                                   ifName, group->GetName());
                }
            }
        }
    }
    else  // it's RELAY group, so just add the interface to the group via ParseInterfaceName()
    {
        // We parse a list of one so a new group is created as needed
        if (!ParseInterfaceList(ifaceMatcher.GetGroupName(), Smf::RELAY, ifName, ifaceMatcher.GetRelayType(), false))
        {
            PLOG(PL_ERROR, "SmfApp::MatchInterface() error: unable to add matched interface \"%s\" to group \"%s\"\n",
                               ifName, ifaceMatcher.GetGroupName());
            return false;
        }
    }
    return true;

}  // end SmfApp::MatchInterface()


bool SmfApp::MatchExistingInterfaces(InterfaceMatcher& ifaceMatcher)
{
    unsigned int ifIndexArray[IF_COUNT_MAX];
    unsigned int ifCount = ProtoNet::GetInterfaceIndices(ifIndexArray, IF_COUNT_MAX);
    if (0 == ifCount)
    {
        PLOG(PL_WARN, "SmfApp::MatchExistingInterfaces() warning: no network interface indices  were found.\n");
    }
    else if (ifCount > IF_COUNT_MAX)
    {
        PLOG(PL_WARN, "SmfApp::MatchExistingInterfaces() warning: found network interfaces indices exceeding maximum count.\n");
        ifCount = IF_COUNT_MAX;
    }
    for (unsigned int i = 0; i < ifCount; i++)
    {
        unsigned int ifIndex  = ifIndexArray[i];
        char ifName[Smf::IF_NAME_MAX + 1];
        ifName[Smf::IF_NAME_MAX] = '\0';
        if (!ProtoNet::GetInterfaceName(ifIndex, ifName, Smf::IF_NAME_MAX))
        {
            PLOG(PL_WARN, "SmfApp::MatchExistingInterfaces() warning: unnable to get interface name for index %u\n", ifIndex);

            continue;
        }
        if (0 != strncmp(ifName, ifaceMatcher.GetPrefix(), strlen(ifaceMatcher.GetPrefix())))
            continue;  // Interface name doesn't match our prefix
        // Is the interface up?
        if (ProtoNet::IFACE_UP != ProtoNet::GetInterfaceStatus(ifIndex))
        {
            PLOG(PL_WARN, "SmfApp::MatchExistingInterfaces() matched interface \"%s\" is down.\n", ifName);
            continue;
        }
        if (!MatchInterface(ifaceMatcher, ifName, ifIndex))
        {
            PLOG(PL_ERROR, "SmfApp::MatchExistingInterfaces() error: unable to add matched interface \"%s\" to group \"%s\"\n",
                            ifName, ifaceMatcher.GetGroupName());
            // Should we bail and return "false" here, or keep trying other interfaces ?!
        }
    }
    return true;
}  // end SmfApp::MatchExistingInterfaces()

// Update group associations _and_  interface mechanism state as needed
bool SmfApp::UpdateGroupAssociations(Smf::InterfaceGroup& ifaceGroup)
{
    // Setup the interface group's interface associations according
    // to the "mode" and relay algorithm type
    bool rseq = ifaceGroup.GetResequence();
    bool tunnel = ifaceGroup.IsTunnel();
    Smf::Interface* srcIface = NULL;
    if (Smf::PUSH == ifaceGroup.GetForwardingMode())
    {
        srcIface = ifaceGroup.GetPushSource();
        if (NULL == srcIface)
        {
            // This is a "template" PUSH group or hasn't yet had its
            // source interface set
            // (so we don't do anything to set its associations)
            return true;
        }
        if (rseq)
        {
            // Make sure this interface does _not_ have a MANET iface
            // association (i.e. self association) if we will be
            // resequencing rom this iface!
            unsigned int srcIndex = srcIface->GetIndex();
            Smf::Interface::AssociateList::Iterator it(*srcIface);
            Smf::Interface::Associate* assoc;
            while (NULL != (assoc = it.GetNextItem()))
            {
                if (assoc->GetInterface().GetIndex() == srcIndex)
                {
                    PLOG(PL_ERROR, "SmfApp::UpdateGroupAssociations() error: bad 'rpush' configuration from MANET srcIface\n");
                    return false;
                }
            }
        }
        srcIface->SetResequence(rseq);
        srcIface->SetTunnel(tunnel);
        // Make sure the group's source interface is OK to be an "rpush" source
    }

    // Iterate through the group's set of interfaces and update associations
    Smf::InterfaceGroup::Iterator ifacerator(ifaceGroup);
    Smf::Interface* iface;
    while (NULL != (iface = ifacerator.GetNextInterface()))
    {
        switch (ifaceGroup.GetForwardingMode())
        {
            case Smf::PUSH:
            {
                if (iface == srcIface) continue;  // don't associate with self if PUSH
                // Set up a classical flooding relay type to all other interfaces in group
                Smf::Interface::Associate* assoc = srcIface->FindAssociate(iface->GetIndex());
                if (NULL != assoc)
                {
                    if (&ifaceGroup != &assoc->GetInterfaceGroup())
                    {
                        PLOG(PL_ERROR, "SmfApp::UpdateGroupAssociations() error: push iface index %d already has a different association with index %d?!\n",
                                       srcIface->GetIndex(), iface->GetIndex());
                        return false;
                    }
                }
                else if (!srcIface->AddAssociate(ifaceGroup, *iface)) // Use Classical Flooding (CF) algorithm for "push" from srcIface->dstIfaces
                {
                    PLOG(PL_ERROR, "SmfApp::UpdateGroupAssociations(): new Smf::Interface::Associate error: %s\n", GetErrorString());
                    return false;
                }
                break;
            }
            case Smf::MERGE:
            {
                if (rseq)
                {
                    // Make sure this interface does _not_ have a MANET iface
                    // association (i.e. self association) if we will be
                    // resequencing from this iface!
                    Smf::Interface::AssociateList::Iterator it(*iface);
                    Smf::Interface::Associate* assoc;
                    while (NULL != (assoc = it.GetNextItem()))
                    {
                        if (assoc->GetInterface().GetIndex() == iface->GetIndex())
                        {
                            PLOG(PL_ERROR, "SmfApp::UpdateGroupAssociations() error: bad 'rmerge' configuration from MANET srcIface\n");
                            return false;
                        }
                    }
                }
                iface->SetResequence(rseq);
                iface->SetTunnel(tunnel);
                // Now set up CF association to all _other_ interfaces in group
                Smf::InterfaceGroup::Iterator dstIfacerator(ifaceGroup);
                Smf::Interface* dstIface;
                while (NULL != (dstIface = dstIfacerator.GetNextInterface()))
                {
                    if (dstIface == iface) continue;  // don't associate with self
                    Smf::Interface::Associate* assoc = iface->FindAssociate(dstIface->GetIndex());
                    if (NULL != assoc)
                    {
                        if (&ifaceGroup != &assoc->GetInterfaceGroup())
                        {
                            PLOG(PL_ERROR, "SmfApp::UpdateGroupAssociations() error: merge iface index %d already has a different association with index %d?!\n",
                                       srcIface->GetIndex(), iface->GetIndex());
                            return false;
                        }
                    }
                    else
                    {
                        // Use Classical Flooding (CF) algorithm for "merge" from each iface->dstIfaces
                        if (!iface->AddAssociate(ifaceGroup, *dstIface))
                        {
                            PLOG(PL_ERROR, "SmfApp::UpdateGroupAssociations(): new Smf::Interface::Associate error: %s\n", GetErrorString());
                            return false;
                        }
                    }
                }
                break;
            }
            case Smf::RELAY:
            {
                // Make sure this iface hasn't been previously set as a rpush or rmerge srcIface
                if (iface->GetResequence() || iface->IsTunnel())
                {
                    PLOG(PL_ERROR, "SmfApp::UpdateGroupAssociations() error: MANET iface config conflicts with previous rpush or rmerge config!\n");
                    return false;  // TBD - issue warning and make this "continue" instead ???
                }
                Smf::InterfaceGroup::Iterator dstIfacerator(ifaceGroup);
                Smf::Interface* dstIface;
                while (NULL != (dstIface = dstIfacerator.GetNextInterface()))
                {
                    Smf::Interface::Associate* assoc = iface->FindAssociate(dstIface->GetIndex());
                    if (NULL != assoc)
                    {
                        if (&ifaceGroup != &assoc->GetInterfaceGroup())
                        {
                            PLOG(PL_ERROR, "SmfApp::UpdateGroupAssociations() error: MANET iface index %d already has a different association with index %d?!\n",
                                       srcIface->GetIndex(), iface->GetIndex());
                            return false;
                        }
                    }
                    else
                    {
                        // Use designated relay algorithm from each iface->dstIfaces
                        if (!iface->AddAssociate(ifaceGroup, *dstIface))
                        {
                            PLOG(PL_ERROR, "SmfApp::UpdateGroupAssociations(): new Smf::Interface::Associate error: %s\n", GetErrorString());
                            return false;
                        }
                    }
                }
                break;
            }
        }  // end switch(ifaceGroup.GetForwardingMode())
    }  // end while(ifacerator.GetNextInterface())


    // This loop iterates through the group's interfaces and updates
    // their ProtoCap status depending on if the interface is using
    // the ProtoCap for packet capture and/or forwarding.  Even if the
    // ProtoCap isn't used for capture, a ProtoCap may be needed
    // to force the interface into promiscuous mode so that
    // "firewallCapture" has a chance to get packets of interest.
    ifacerator.Reset();
    while (NULL != (iface = ifacerator.GetNextInterface()))
    {
        if (iface->HasAssociates()) // it's an input interface
        {
#ifdef _PROTO_DETOUR
            if (!firewall_capture && !smf.GetUnicastEnabled())  // TBD - why unicast exception here ?!
#endif // _PROTO_DETOUR
            {
                InterfaceMechanism* mech = static_cast<InterfaceMechanism*>(iface->GetExtension());
                mech->StartInputNotification();
            }
        }
#ifdef _PROTO_DETOUR
        else if (firewall_forward)
        {
            // output-only, firewall_forward interface
            // (no ProtoCap needed at all)
            InterfaceMechanism* mech = static_cast<InterfaceMechanism*>(iface->GetExtension());
            ASSERT(NULL != mech->GetProtoDetour());
            mech->CloseDevice();// deletes CidElements, closing/deleting ProtoCaps
        }
#endif // _PROTO_DETOUR
    }  // end while (ifacerator.GetNextInterface())
    return true;

}  // end SmfApp::UpdateGroupAssociations()

// Here "ifaceList" is of form <group> or [<group>,]<iface1>,<iface2>, ...
// where <iface1> is the srcIface if it's a PUSH group
bool SmfApp::RemoveInterfaces(const char* ifaceList)
{
    if (NULL == ifaceList) return true;
    // 1) Look at the list format
    const char* ptr = strchr(ifaceList, ',');
    if (NULL == ptr)
    {
        // Only one item in list, so find it and remove it
        Smf::InterfaceGroup* ifaceGroup = smf.FindInterfaceGroup(ifaceList);
        if (NULL == ifaceGroup)
        {
            // Perhaps it's the common prefix for one or more PUSH groups (e.g. "push")
            Smf::InterfaceGroupList::Iterator grouperator(smf.AccessInterfaceGroupList());
            // Set a iterator prefix to give us the "group::ifacePrefix" prefix subtree
            grouperator.Reset(false, ifaceList, strlen(ifaceList) << 3);
            unsigned int count = 0;
            while (NULL != (ifaceGroup = grouperator.GetNextItem()))
            {
                PLOG(PL_DEBUG, "SmfApp::RemoveInterfaces() deleting interface group \"%s\"\n", ifaceGroup->GetName());
                RemoveMatchers(ifaceGroup->GetName());
                smf.DeleteInterfaceGroup(*ifaceGroup);
                count++;
            }
            if (count > 0)
            {
                PLOG(PL_DEBUG, "SmfApp::RemoveInterfaces() removed %u groups matching prefix \"%s\"\n", count, ifaceList);
                return true;
            }
            else
            {
                // Maybe it's an interface name instead (if it's wildcarded, all matches will be removed)
                if (!RemoveInterface(NULL, ifaceList))
                {
                    PLOG(PL_ERROR, "SmfApp::RemoveInterfaces() error: invalid group (or interface) \"%s\"\n", ifaceList);
                    return false;
                }
                else
                {
                    PLOG(PL_DEBUG, "SmfApp::RemoveInterfaces() removed interface(s) \"%s\" from all groups\n", ifaceList);
                    return true;
                }
            }
        }
        PLOG(PL_DEBUG, "SmfApp::RemoveInterfaces() deleting interface group \"%s\"\n", ifaceGroup->GetName());
        RemoveMatchers(ifaceGroup->GetName());
        smf.DeleteInterfaceGroup(*ifaceGroup);
        return true;
    }

    // 2) Extract the group name (or prefix) from first comma-delimited "ifaceList" item
    char groupName[Smf::IF_GROUP_NAME_MAX + Smf::IF_NAME_MAX + 2];
    groupName[Smf::IF_GROUP_NAME_MAX + Smf::IF_NAME_MAX + 1] = '\0';
    size_t glen = ptr - ifaceList;
    if (glen > Smf::IF_GROUP_NAME_MAX)
    {
        PLOG(PL_WARN, "SmfApp::RemoveInterfaces() warning: group name exceeds maximum length allowed\n");
        glen = Smf::IF_GROUP_NAME_MAX;
    }
    strncpy(groupName, ifaceList, glen);
    groupName[glen] = '\0';
    const char* ifaceListPtr = ptr + 1;  // point to next item in list
    bool isTemplateGroup = false;  // Will be set if was PUSH group name with wildcarded source interface name
    // Is this a PUSH group base name
    Smf::InterfaceGroup* ifaceGroup = smf.AccessInterfaceGroupList().FindClosestMatch(groupName, glen << 3);
    if ((NULL != ifaceGroup) &&
        (0 == strncmp(ifaceGroup->GetName(), groupName, glen)) &&
        (Smf::PUSH == ifaceGroup->GetForwardingMode()))
    {
         // It's a prefix match to a push group, so we include the <srcIface>
        //  as part of full group name "group:srcIface"
        ptr = strchr(ifaceListPtr, ',');
        size_t ilen = (NULL != ptr) ? (ptr - ifaceListPtr) : strlen(ifaceListPtr);
        if (ilen > Smf::IF_NAME_MAX)
        {
            PLOG(PL_ERROR, "SmfApp::RemoveInterfaces() error: interface name exceeds maximum length allowed\n");
            return false;
        }
        else if (ilen > 0)
        {
            groupName[glen++] = ':';
            strncpy(groupName + glen, ifaceListPtr, ilen);
            glen += ilen;
            groupName[glen] = '\0';
        }
        // Is it in form of "group:srcIface#" (i.e., remove all matching PUSH groups
        char* hashPtr = (NULL != strchr(groupName, ':')) ? strchr(groupName, '#') : NULL;
        if (NULL != hashPtr)
        {
            // Just use prefix for the group name
            glen = hashPtr - groupName;
            groupName[glen] = '\0';
            isTemplateGroup = true;
        }
        // Since this is a PUSH group, consume first iface item as part of group name
        // (Because if it's the only item, the entire PUSH group is removed)
        ifaceListPtr =  (NULL != ptr) ? (ptr + 1) : NULL;
    }

    // At this point, we have a groupName of "group"  or "group:srcIface"
    // (and "isTemplateGroup" is true if we need to iterate over a set of PUSH groups)
    Smf::InterfaceGroupList::Iterator grouperator(smf.AccessInterfaceGroupList());
    // Set a iterator prefix to give us the "group::ifacePrefix" prefix subtree
    if (isTemplateGroup)
    {
        grouperator.Reset(false, groupName, strlen(groupName) << 3);
        ifaceGroup = grouperator.GetNextItem();
        if (NULL == ifaceGroup)
        {
            PLOG(PL_ERROR, "SmfApp::RemoveInterfaces() error: invalid template PUSH group \"%s\"\n", groupName);
            return false;
        }
    }
    else
    {
        ifaceGroup = smf.FindInterfaceGroup(groupName);
        if (NULL == ifaceGroup) ifaceListPtr = ifaceList;  // assume <group> name was omitted
    }

    do
    {
        // TBD - process ifaceList here (if empty, delete the group)
        if (NULL != ifaceListPtr)
        {
            // process interface group items, deleting them from group
            // (and delete groups that become empty as a result)
            const char* namePtr = ifaceListPtr;
            while ((NULL != namePtr) && ('\0' != *namePtr))
            {
                ptr = strchr(namePtr, ',');
                size_t ilen = (NULL != ptr) ? (ptr - namePtr) : strlen(namePtr);
                char ifaceName[Smf::IF_NAME_MAX+1];
                ifaceName[Smf::IF_NAME_MAX] = '\0';
                strncpy(ifaceName, namePtr, ilen);
                ifaceName[ilen] = '\0';
                if (!RemoveInterface(ifaceGroup, ifaceName))
                    PLOG(PL_WARN, "SmfApp::RemoveInterfaces() warning: invalid interface \"%s\"\n", ifaceName);
                namePtr = (NULL != ptr) ? ptr + 1 : NULL;  // advance to next item in "ifaceList"
            }
        }
        else
        {
            if (NULL == ifaceGroup)
            {
                PLOG(PL_ERROR, "SmfApp::RemoveInterfaces() error: invalid interface group \"%s\"\n", groupName);
                return false;
            }
            //if (ifaceGroup->IsTemplateGroup())
                RemoveMatchers(ifaceGroup->GetName());
            PLOG(PL_DEBUG, "SmfApp::RemoveInterfaces() deleting interface group \"%s\"\n", ifaceGroup->GetName());
            smf.DeleteInterfaceGroup(*ifaceGroup);
        }
        if (isTemplateGroup)
            ifaceGroup = grouperator.GetNextItem();
        else
            ifaceGroup = NULL;

    } while (NULL != ifaceGroup);

    return true;

}  // end SmfApp::RemoveInterfaces()

// If "ifaceGroup" is NULL, the interface is removed from all groups
bool SmfApp::RemoveInterface(Smf::InterfaceGroup* ifaceGroup, const char* ifaceName)
{
    if (NULL != ifaceName)
    {
        unsigned int prefixLen = 0;
        unsigned int ifCount = 1;
        unsigned int ifIndexArray[IF_COUNT_MAX];
        const char* hashPtr = strchr(ifaceName, '#');
        if (NULL != hashPtr)
        {
            prefixLen = hashPtr - ifaceName;
            // Remove any InterfaceMatchers for given group
            InterfaceMatcherList::Iterator matcherator(iface_matcher_list, false, ifaceName, prefixLen << 3);
            InterfaceMatcher* matcher;
            while (NULL != (matcher = matcherator.GetNextItem()))
            {
                Smf::InterfaceGroup* matcherGroup = smf.FindInterfaceGroup(matcher->GetGroupName());
                // Does this matcher map to our group?
                if ((NULL != ifaceGroup) && (ifaceGroup != matcherGroup))
                    continue;  // doesn't match so don't delete matcher

                // If it's a source matcher, delete all matching groups (incl. the template group)
                // (and any destination matchers that map _to_ the template group)
                if (matcher->IsSourceMatcher())
                {
                    ASSERT((NULL == matcherGroup) || matcherGroup->IsTemplateGroup());
                    Smf::InterfaceGroupList::Iterator grouperator(smf.AccessInterfaceGroupList());
                    // Set a iterator prefix to give us the "group::ifacePrefix" prefix subtree
                    const char* groupName = matcher->GetGroupName();
                    grouperator.Reset(false, groupName, strlen(groupName) << 3);
                    Smf::InterfaceGroup* group;
                    while (NULL != (group = grouperator.GetNextItem()))
                    {
                        // Find al matchers that map to this group and
                        // delete since we're about to delete the group.
                        RemoveMatchers(group->GetName());
                        PLOG(PL_DEBUG, "SmfApp::RemoveInterface() deleting PUSH interface group \"%s\"\n", group->GetName());
                        smf.DeleteInterfaceGroup(*group);
                    }
                    ifaceGroup = NULL;  // since it was source matcher, the group was deleted
                    return true;
                }
                else
                {
                    iface_matcher_list.Remove(*matcher);
                    delete matcher;
                }
            }

            ifCount = ProtoNet::GetInterfaceIndices(ifIndexArray, IF_COUNT_MAX);
            if (ifCount > IF_COUNT_MAX)
            {
                PLOG(PL_WARN, "SmfApp::RemoveInterface() warning: system interface count exceeds IF_COUNT_MAX\n");
                ifCount = IF_COUNT_MAX;
            }
        }
        while (ifCount > 0)
        {
            unsigned int ifIndex;
            char ifName[Smf::IF_NAME_MAX+1];
            ifName[Smf::IF_NAME_MAX] = '\0';
            const char* ifNamePtr = ifaceName; // initially point to name passed in
            if (0 != prefixLen)
            {
                ifCount--;
                ifIndex = ifIndexArray[ifCount];
                if (!ProtoNet::GetInterfaceName(ifIndex, ifName, Smf::IF_NAME_MAX))
                {
                    PLOG(PL_WARN, "SmfApp::RemoveInterface() warning: unable to get interface name for index %u\n", ifIndex);
                    continue;
                }
                if (0 != (strncmp(ifaceName, ifName, prefixLen)))
                    continue;  // interface name doesn't match our prefix
                ifNamePtr = ifName;
            }
            else
            {
                ifIndex = ProtoNet::GetInterfaceIndex(ifaceName);
                if (0 == ifIndex)
                {
                    PLOG(PL_ERROR, "SmfApp::RemoveInterface() error: invalid interface name \"%s\"\n", ifaceName);
                    return false;
                }
                ifCount = 0;
            }

            if (NULL != ifaceGroup)
            {
                Smf::Interface* iface = ifaceGroup->FindInterface(ifIndex);
                if (NULL == iface)
                {
                    PLOG(PL_DEBUG, "SmfApp::RemoveInterface() iface \"%s\" not in group \"%s\"\n", ifNamePtr, ifaceGroup->GetName());
                    continue;
                }
                // If it's the srcIface for a Smf::PUSH group, remove entire group
                // (template PUSH groups must be explicitly deleted)  TBD - make sure this is the case!
                if ((iface == ifaceGroup->GetPushSource()) && !ifaceGroup->IsTemplateGroup())
                {
                    PLOG(PL_DEBUG, "SmfApp::RemoveInterface() deleting PUSH interface group \"%s\"\n", ifaceGroup->GetName());
                    smf.DeleteInterfaceGroup(*ifaceGroup);
                    return true;
                }
                ifaceGroup->RemoveInterface(*iface);
                if (!smf.IsInGroup(*iface))
                    smf.DeleteInterface(iface); // It's not in any other groups, so deactivate / delete it
                if (ifaceGroup->IsEmpty())
                {
                    PLOG(PL_DEBUG, "SmfApp::RemoveInterface() deleting empty interface group \"%s\"\n", ifaceGroup->GetName());
                    smf.DeleteInterfaceGroup(*ifaceGroup);
                    return true;
                }
            }
            else
            {
                // Remove / deactivate / delete interface completely
                smf.RemoveInterface(ifIndex);
            }
        }  // end while (ifCount > 0)
    }
    else
    {
        // Just remove/delete group completely
       PLOG(PL_DEBUG, "SmfApp::RemoveInterface() deleting interface group \"%s\"\n", ifaceGroup->GetName());
       smf.DeleteInterfaceGroup(*ifaceGroup);
    }
    return true;
}  // end SmfApp::RemoveInterface()

// Remove all InterfaceMatchers that map to given "groupName"
// (should only be called when a group is explicitly removed
//  by name)
void SmfApp::RemoveMatchers(const char* groupName)
{
    // Find all matchers that map to this group and
    // delete since we're about to delete the group.
    InterfaceMatcherList::Iterator it(iface_matcher_list);
    InterfaceMatcher* m;
    while (NULL != (m = it.GetNextItem()))
    {
        if (0 != strcmp(groupName, m->GetGroupName()))
            continue;  // not a matching matcher (for different group)
        iface_matcher_list.Remove(*m);
        delete m;
    }
}  // end SmfApp::RemoveMatchers()


// This section of routines all for creation a virtual interface ("vif") devices that can be used as
// a logical interface for SMF and other IP networking.  A "device" is associated with one or more
// underlying actual interfaces.  The usual case is to support a single underlying interface
// associated with the "device", but the capability of a "composite interface device" (aka "cid") is
// also supported so the "device" can be a front end for multiple underlying transmit and/or receive
// channels. This is mainly to support experimentation but have other use cases.

// A nrlsmf "device" is a virtual interface (ProtoVif "vif") bound to one or more pcap instances (ProtoCap "cap")
unsigned int SmfApp::OpenDevice(const char* vifName, const char* ifaceNameAndFlags, const char* addrList, bool shadow, bool blockIGMP)
{
    // Add ProtoVif "device", stealing ifaceName addresses if NULL addrString
    Smf::Interface* iface = AddDevice(vifName, ifaceNameAndFlags, (NULL == addrList));
    if (NULL == iface)
    {
        PLOG(PL_ERROR, "SmfApp::OpenDevice() error: unable to add device '%s'\n", vifName);
        return 0;
    }
    unsigned int vifIndex = iface->GetIndex();
    
    if ((NULL != addrList) && !AssignAddresses(vifName, vifIndex, addrList))
    {
        PLOG(PL_ERROR, "SmfApp::OpenDevice(%s) error: failed to assign addresses\n");
        smf.RemoveInterface(iface);
    }
    
    InterfaceMechanism* mech = static_cast<InterfaceMechanism*>(iface->GetExtension());
    
    ProtoTokenator tk(ifaceNameAndFlags, '/');  // get the isolated 'ifaceName' portion of 'ifaceNameAndFlags'
    const char* ifaceName = tk.GetNextItem();
    
    // Save device interface IPv4 addresses for possible IPIP encapsulation use
    if (shadow)
    {
        // Also use underlying interface hardware address as "own address" for vifIndex
        ProtoAddress hwAddr;
        ProtoNet::GetInterfaceAddress(ifaceName, ProtoAddress::ETH, hwAddr);
        smf.AddOwnAddress(hwAddr, vifIndex);
    }
    mech->SetShadowing(shadow);
    mech->SetBlockIGMP(blockIGMP);
    ProtoNet::GetInterfaceAddressList(vifName, ProtoAddress::IPv4, iface->AccessAddressList());
    iface->UpdateIpAddress();
#if defined(BLOCK_ICMP) && defined(LINUX)
    if (!BlockICMP(ifaceName, true))
    {
        PLOG(PL_ERROR, "SmfApp::OpenDevice() warning: unable to block physical device ICMP reception!\n");
    }
#endif  // LINUX
    return vifIndex;
}  // end SmfApp::OpenDevice()

Smf::Interface* SmfApp::AddDevice(const char* vifName, const char* ifaceNameAndFlags, bool stealAddrs)
{
    // 1) Create the ProtoVif device
    Smf::Interface* iface = CreateDevice(vifName);
    if (NULL == iface)
    {
        PLOG(PL_ERROR, "SmfApp::AddDevice() error: unable to create ProtoVif device: \"%s\"\n", vifName);
        return NULL;
    }
    unsigned int vifIndex = iface->GetIndex();
    
    // 2) Add the given "ifaceName" as a CidElement for this virtual device
    //    This will be the underlying interface tethered to the vif although
    //     multiple CidElements can be tethered to a vif device
    
    // Note "ifaceName" here can have syntax "ifaceName[/{t|r|d}]" to specify tx-only (t) or rx-only (r) operation for the given iface
    // (This is with respect to composite interface device (cid) capaability. - the default is tx and rx operation)
    
    ProtoTokenator tk(ifaceNameAndFlags, '/');
    const char* ifaceName = tk.GetNextItem(true); // detaches tokenized string item, so we MUST delete it later
    const char* ifaceStatus = tk.GetNextItem();
    int cidFlags;
    if (NULL == ifaceStatus)
    {
        cidFlags = CidElement::CID_TX | CidElement::CID_RX;
    }
    else 
    {
        switch(ifaceStatus[0])
        {
            case 't':
                cidFlags = CidElement::CID_TX;
                break;
            case 'r':
                cidFlags = CidElement::CID_RX;
                break;
            default:
                PLOG(PL_ERROR, "SmfApp::OpenDevice(%s) error: invalid interface status: %s\n", ifaceNameAndFlags);
                delete[] ifaceName;
                return NULL;
        }
    }
    unsigned int ifaceIndex = AddCidElement(vifName, ifaceName, cidFlags, vifIndex);
    if (0 == ifaceIndex)
    {
        PLOG(PL_ERROR, "SmfApp::AddDevice() error: unable to add interface \"%s\" as element\n", ifaceName);
        smf.RemoveInterface(iface);
        delete[] ifaceName;
        return NULL;
    }
    if (stealAddrs && !TransferAddresses(vifIndex, ifaceIndex))
    {
        PLOG(PL_ERROR, "SmfApp::AddDevice() error: unable to transfer addresses from interface \"%s\"\n", ifaceName);
        smf.RemoveInterface(iface);
        delete[] ifaceName;
        return NULL;
    }
    delete[] ifaceName;
    return iface;
}  // end SmfApp::AddDevice()

Smf::Interface* SmfApp::CreateDevice(const char* vifName)
{
    // Create ProtoVif device for use as an Smf::Interface
    // 1) Make sure the device doesn't already exist and create it and associate InterfaceMechanism
    if (0 != ProtoNet::GetInterfaceIndex(vifName))
    {
        PLOG(PL_ERROR, "SmfApp::CreateDevice() error: interface/device \"%s\" already exists!\n", vifName);
        return NULL;
    }
    ProtoVif* vif = ProtoVif::Create();
    if (NULL == vif)
    {
        PLOG(PL_ERROR, "SmfApp::CreateDevice() new ProtoVif error: %s\n", GetErrorString());
        return NULL;
    }
   
    // At this point, if we delete the "mech", the "vif" will also get closed/deleted
    vif->SetNotifier(static_cast<ProtoChannel::Notifier*>(&dispatcher));
    if (!vif->SetListener(this, &SmfApp::OnPktOutput))
    {
        PLOG(PL_ERROR, "SmfApp::CreateDevice() error: unable to set vif listener: %s\n", GetErrorString());
        delete vif;
        return NULL;
    }
    
    // 2) Open the vif (i.e. this instantiates the virtual interface on the system)
    //    (Note we use the virtual interface index as the index for our Smf::Interface
    ProtoAddress addr;
    if (!vif->Open(vifName, addr, 0))  // note invalid "addr" means no address is yet assigned
    {
        PLOG(PL_ERROR, "SmfApp::CreateDevice() error: unable to open vif \"%s\"\n", vifName);
        delete vif;
        return NULL;
    }
    // We use the vif interface index for our Smf::Interface
    unsigned int vifIndex = ProtoNet::GetInterfaceIndex(vifName);
    if (0 == vifIndex)
    {
        PLOG(PL_ERROR, "SmfApp::CreateDevice() error: unable to get interface index for vif \"%s\"\n", vifName);
        delete vif;
        return NULL;
    }
    // Verify that this is _not_ an already existing "smf" interface
    Smf::Interface* iface = smf.GetInterface(vifIndex);
    if (NULL != iface)
    {
        PLOG(PL_ERROR, "SmfApp::CreateDevice() error: interface \"%s\" (index:%d) already in use!\n", vifName, vifIndex);
        delete vif;
        return NULL;
    }
    // 3) Now directly add the device  as an Smf::Interface
    iface = smf.AddInterface(vifIndex);
    if (NULL == iface)
    {
        PLOG(PL_ERROR, "SmfApp::CreateDevice() error: unable to add SMF interface\n");
        delete vif;
        return NULL;
    }
    
    // Create InterfaceMechanism to associate vif device
    InterfaceMechanism* mech = new InterfaceMechanism(*iface, pkt_pool);
    if (NULL == mech)
    {
        PLOG(PL_ERROR, "SmfApp::CreateDevice() new InterfaceMechanism error: %s\n", GetErrorString());
        delete vif;
        smf.RemoveInterface(iface);
        return NULL;
    }
    vif->SetBlocking(false);
    mech->SetProtoVif(vif);
    mech->GetTxTimer().SetListener(mech, &SmfApp::InterfaceMechanism::OnTxTimeout);
    if (mech->SetTxRateLimit(default_tx_rate_limit)) ActivateTimer(mech->GetTxTimer());  // inherit SmfApp default tx_rate_limit
    iface->SetInterfaceAddress(vif->GetHardwareAddress());
    smf.AddOwnAddress(vif->GetHardwareAddress(), vifIndex);
    iface->SetQueueLimit(smf_queue_limit);  // init to default
    iface->SetExtension(*mech);
    vif->SetUserData(iface);
    return iface;
}  // end SmfApp::CreateDevice()


unsigned int SmfApp::AddCidElement(const char* deviceName, const char* ifaceName, int flags, unsigned int vifIndex)
{
    // Add a CID_RX pcap device to an existing nrlsmf virtual interface "device"
     // First make sure nrlsmf isn't already using this "ifaceName" for something
    unsigned int capIndex = ProtoNet::GetInterfaceIndex(ifaceName);
    if (NULL != smf.GetInterface(capIndex))
    {
        PLOG(PL_ERROR, "SmfApp::AddCidElement() error: interface \"%s\" (index:%d) already in use!\n", ifaceName, capIndex);
        return 0;
    }
    // If not provided, lookup  the vif interface index to retrieve the corresponding Smf::Interface
    if (0 == vifIndex)
        vifIndex = ProtoNet::GetInterfaceIndex(deviceName);
    if (0 == capIndex)
    {
        PLOG(PL_ERROR, "SmfApp::GetCidElementList() error: unable to get interface index for interface \"%s\"\n", ifaceName);
        return 0;
    }
    // Verify that this "deviceName" is an existing nrlsmf interface
    Smf::Interface* iface = smf.GetInterface(vifIndex);
    if (NULL == iface)
    {
        PLOG(PL_ERROR, "SmfApp::AddCidElement() error: invalid nrlsmf interface \"%s\"\n", deviceName);
        return 0;
    }
    // Get its interface mechanism
    InterfaceMechanism* mech = static_cast<InterfaceMechanism*>(iface->GetExtension());
    if ((NULL == mech) || (NULL == mech->GetProtoVif()))
    {
        PLOG(PL_ERROR, "SmfApp::AddCidElement() error: invalid nrlsmf device \"%s\"\n", deviceName);
        return 0;
    }
    ProtoCap* cap = ProtoCap::Create();
    if (NULL == cap)
    {
        PLOG(PL_ERROR, "SmfApp::AddCidElement(): ProtoCap::Create() error: %s\n", GetErrorString());
        return 0;
    }
    cap->SetListener(this, &SmfApp::OnPktCapture);
    cap->SetNotifier(static_cast<ProtoChannel::Notifier*>(&dispatcher));
    if (!cap->Open(ifaceName))
    {
        PLOG(PL_ERROR, "SmfApp::AddCidElement(): ProtoCap::Open(%s) error: %s\n", ifaceName, GetErrorString());
        delete cap;
        return 0;
    }
    cap->StopInputNotification();  // will be re-enabled in UpdateGroupAssociations() as needed
    cap->SetUserData(iface);
    mech->AddCidElement(*cap, flags);
    return capIndex;
}  // end SmfApp::AddCidElement()

bool SmfApp::RemoveCidElement(const char* deviceName, const char* ifaceName)
{
    unsigned int vifIndex = ProtoNet::GetInterfaceIndex(deviceName);
    // Verify that this "deviceName" is an existing nrlsmf interface
    Smf::Interface* iface = smf.GetInterface(vifIndex);
    if (NULL == iface)
    {
        PLOG(PL_ERROR, "SmfApp::RemoveCidElement() error: invalid nrlsmf interface \"%s\"\n", deviceName);
        return false;
    }    
    // Get its interface mechanism
    InterfaceMechanism* mech = static_cast<InterfaceMechanism*>(iface->GetExtension());
    unsigned int capIndex = ProtoNet::GetInterfaceIndex(ifaceName);
    mech->RemoveCidElement(capIndex);
    return true;
}  // end SmfApp::RemoveCidElement()

bool SmfApp::TransferAddresses(unsigned int vifIndex, unsigned ifaceIndex)
{
    // Transfers addresses from ifaceIndex to vifIndex
    ProtoRouteTable rtTable;  // for passing routes from cap device to vif device
    ProtoRouteMgr* rtMgr = ProtoRouteMgr::Create();
    if ((NULL != rtMgr) && rtMgr->Open())
    {
        //rtMgr->SaveAllRoutes();
        ProtoRouteTable tmpTable;
        rtMgr->GetAllRoutes(ProtoAddress::IPv4, tmpTable);
        rtMgr->GetAllRoutes(ProtoAddress::IPv6, tmpTable);
        // TBD- This section of code is incomplete
        ProtoRouteTable::Iterator it(tmpTable);
        ProtoRouteTable::Entry* entry;
        // Save relevant routes for later restoration
        while (NULL != (entry = it.GetNextEntry()))
        {
            if (!entry->GetGateway().IsValid())
            {
                unsigned int ifIndex = entry->GetInterfaceIndex();
                if (ifIndex == ifaceIndex)
                {
                    rtMgr->DeleteRoute(*entry);
                    if (entry->IsDefault())
                    {
                        rtTable.SetRoute(entry->GetDestination(), entry->GetPrefixSize(), 
                                         entry->GetGateway(), ifIndex, entry->GetMetric());
                    }          
                    else
                    {
                        tmpTable.RemoveEntry(*entry);
                        rtTable.InsertEntry(*entry);
                    }              
                }
            }
        }
    }
    else
    {
        PLOG(PL_WARN, "SmfApp::TransferAddresses() warning: unable to open ProtoRouteMgr!\n");
    }
    ProtoAddressList addrList;
    if (!ProtoNet::GetInterfaceAddressList(ifaceIndex, ProtoAddress::IPv4, addrList))
    {
        char ifaceName[Smf::IF_NAME_MAX+1];
        ifaceName[Smf::IF_NAME_MAX] = '\0';
        ProtoNet::GetInterfaceName(ifaceIndex, ifaceName, Smf::IF_NAME_MAX);
        PLOG(PL_WARN, "SmfApp::TransferAddresses() warning: no IPv4 addresses for interface index \"%u\"\n", ifaceName);
    }
#ifdef HAVE_IPV6
    if (!ProtoNet::GetInterfaceAddressList(ifaceIndex, ProtoAddress::IPv6, addrList))
    {
        char ifaceName[Smf::IF_NAME_MAX+1];
        ifaceName[Smf::IF_NAME_MAX] = '\0';
        ProtoNet::GetInterfaceName(ifaceIndex, ifaceName, Smf::IF_NAME_MAX);
        PLOG(PL_WARN, "SmfApp::TransferAddresses() warning: no IPv6 addresses for interface \"%s\"\n", ifaceName);
    }
#endif // HAVE_IPV6

#ifdef WIN32
	// On WIN32 after we move the interface ip address to the vif interface
	// subsequent calls using the original ifAddr ip address will get the
	// vif adapter - save the friendly name to prevent this.
	ProtoAddress interfaceIpAddr;
	ProtoNet::GetInterfaceIpAddress(ifaceIndex, interfaceIpAddr);
	if (!ProtoNet::GetInterfaceFriendlyName(interfaceIpAddr, if_friendly_name, MAX_ADAPTER_NAME_LENGTH))
	{
		PLOG(PL_ERROR, "SmfApp::TransferAddresses() error: unable to get interface friendly name for %s\n",interfaceIpAddr.GetHostString());
		return false;
	}
#endif // WIN32
    // Remove addresses from "ifaceName"  and add to "vifName"
    // (note we need to restore them later)
    ProtoAddressList::Iterator iterator(addrList);
    ProtoAddress addr;
    while (iterator.GetNextAddress(addr))
    {
	    if (addr.IsLinkLocal()) continue;
#ifdef WIN32
		unsigned int maskLen = ProtoNet::GetInterfaceAddressMask(ifaceIndex, addr);
#else
        unsigned int maskLen = ProtoNet::GetInterfaceAddressMask(ifaceIndex, addr);
#endif //WIN32
        // Remove address from "ifaceName"
        // TBD - on failure, restore any addresses removed from the "ifName" ???
#ifdef WIN32
		if (!ProtoNet::RemoveInterfaceAddress(if_friendly_name,addr,maskLen))
#else
        if (!ProtoNet::RemoveInterfaceAddress(ifaceIndex, addr, maskLen))
#endif // WIN32
        {
            char ifaceName[Smf::IF_NAME_MAX+1];
            ifaceName[Smf::IF_NAME_MAX] = '\0';
            ProtoNet::GetInterfaceName(ifaceIndex, ifaceName, Smf::IF_NAME_MAX);
            PLOG(PL_ERROR, "SmfApp::TransferAddresses() error removing address %s from interface %s\n", addr.GetHostString(), ifaceName);
            return false;
        }
        // Assign address to "vifName"
        if (!ProtoNet::AddInterfaceAddress(vifIndex, addr, maskLen))
        {
            char vifName[Smf::IF_NAME_MAX+1];
            vifName[Smf::IF_NAME_MAX] = '\0';
            ProtoNet::GetInterfaceName(ifaceIndex, vifName, Smf::IF_NAME_MAX);
            PLOG(PL_ERROR, "SmfApp::TransferAddresses() error adding address %s to vif %s\n", addr.GetHostString(), vifName);
            return false;
        }
        smf.AddOwnAddress(addr, vifIndex);
    }
    if (NULL != rtMgr)
    {
        // Assign cached route from pcap to vif
        ProtoRouteTable::Iterator it(rtTable);
        ProtoRouteTable::Entry* entry;
        while (NULL != (entry = it.GetNextEntry()))
        {
            entry->SetInterface(vifIndex);
            rtMgr->SetRoute(*entry);
        }
        // Restore cached routes if address reassignments were made now that vif is up and addressed
        // (this restores any routes that were lost due to reassignment of addressed from physical iface to vif)
        //rtMgr->RestoreSavedRoutes();
        rtMgr->Close();
        delete rtMgr;
    }
    return true;
}  // end SmfApp::TransferAddresses()

bool SmfApp::AssignAddresses(const char* ifaceName, unsigned int ifaceIndex, const char* addrList)
{
    ASSERT(NULL != ifaceName);
    // Parse "addrList" and configure vif with listed addrs
    // List is comma-delimited "addr/masklen" items
    ProtoTokenator tk(addrList, ',');
    const char* item;
    while (NULL != (item = tk.GetNextItem()))
    {
        // Look for addr/maskLen
        ProtoTokenator tk2(item, '/');
        const char* addrText = tk2.GetNextItem();
        if (NULL == addrText)
        {
            PLOG(PL_ERROR, "SmfApp::AssignAddresses() error: invalid address list item: %s\n", item);
            return false;
        }
        ProtoAddress addr;
        if (!addr.ResolveFromString(addrText))
        {
            PLOG(PL_ERROR, "SmfApp::AssignAddresses() error: invalid address \"%s\"\n", addrText);
            return false;
        }
        unsigned int maskLen;
        const char* maskLenText = tk2.GetNextItem();
        if (NULL != maskLenText)
        {
            if (1 != sscanf(maskLenText, "%u", &maskLen))
            {
                PLOG(PL_ERROR, "SmfApp::AssignAddresses() error: invalid mask length \"%s\"\n", maskLenText);
                return false;
            }
        }
        else
        {
            maskLen = addr.GetLength() << 3;  // assume full mask len if not specified
        }
        // Assign address to "ifaceName"
        if (!ProtoNet::AddInterfaceAddress(ifaceName, addr, maskLen))
        {
            PLOG(PL_ERROR, "SmfApp::AssignAddresses() error adding configured address %s to vif %s\n", addr.GetHostString(), ifaceName);
            return false;
        }
        smf.AddOwnAddress(addr, ifaceIndex);
    }  // end while (NULL != (item = tk.GetNextItem()))
    return true;
}  // end SmfApp::AssignAddresses()


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
	            PLOG(PL_DEBUG,"SmfApp::OnControlMsg() recv'd %d Byte message from controller \"%s\"\n", len, buffer);
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
                // IPv4 unicast packets need to be sent via firewall forward, too,
		        // unless they have a broadcast MAC address
#ifdef _PROTO_DETOUR
		        bool unicastFirewallForwardFlag = true;
#endif // _PROTO_DETOUR
                unsigned int ethHdrLen = ProtoPktETH::GetHeaderLength(buffer, 8191);
		        UINT8* bufPtr = (UINT8*)(buffer+msgHdrLen+ethHdrLen - 2); // Points to the Ethernet type
		        if((*bufPtr == 0x08 && *(bufPtr+1) == 0x00) && smf.GetUnicastEnabled())
                {
                    // IPv4 Unicast forwarding is enabled
		            const unsigned int ETHER_BYTES_MAX = FRAME_SIZE_MAX;
		            const unsigned int IP_BYTES_MAX = (ETHER_BYTES_MAX - 16);
		            const unsigned int UDP_BYTES_MAX = (IP_BYTES_MAX - 20);
		            bufPtr = (UINT8*)(buffer + msgHdrLen); // Points to the Ethernet header (reserves space for 'tap' msgHdr
		            ProtoPktETH ethPkt(bufPtr, ETHER_BYTES_MAX);
		            if (!ethPkt.InitFromBuffer(len - msgHdrLen))
		            {
		                PLOG(PL_ERROR, "SmfApp::OnControlMsg() error: bad Ether frame\n");
		                return;
		            }
		            ProtoPktETH::Type ethType = (ProtoPktETH::Type)ethPkt.GetType();
		            if (ethType == ProtoPktETH::IP)
                    {
		                bufPtr = (UINT8*)(buffer+msgHdrLen+ethHdrLen); // Points to the IP header
		                ProtoPktIP ipPkt((UINT32*)bufPtr, IP_BYTES_MAX);
		                if (!ipPkt.InitFromBuffer(ethPkt.GetPayloadLength()))
		                {
		  	                PLOG(PL_ERROR, "SmfApp::OnControlMsg() Error: bad IP packet\n");
			                return;
		                }
			            ProtoPktIPv4 ipv4Pkt(ipPkt);
			            if((0 == ipv4Pkt.GetChecksum()) && (0 == ipv4Pkt.GetID()))
                        {
			                // Update checksum for UDP packets if it hasn't been computed already
			                if(ipv4Pkt.GetProtocol() == 17)
                            {
			                    ProtoPktUDP udpPkt(bufPtr, UDP_BYTES_MAX);
			                    if (!udpPkt.InitFromPacket(ipPkt))
			                    {
				                    PLOG(PL_ERROR, "SmfApp::OnControlMsg() Error: bad UDP packet\n");
				                    return;
				                }
				                if(udpPkt.GetChecksum() == 0)
                                {
				                    UINT16 chksum = udpPkt.ComputeChecksum(ipPkt);
				                    udpPkt.SetChecksum(chksum);
				                }
			                }
			                // Increment the packet ID for the new packets generated by outside processes
			                ipv4Pkt.CalculateChecksum(true);
			                ProtoAddress srcIP;
			                ipv4Pkt.GetSrcAddr(srcIP);
			                UINT16 newseq = smf.IncrementIPv4LocalSequence(&srcIP);
			                ipv4Pkt.SetID(newseq, true);
			                //PLOG(PL_INFO, "SEQUENCE: %d IPID: %d\n", newseq, ipv4Pkt.GetID());
			            }
			            bufPtr = (UINT8*)(buffer+msgHdrLen+ethHdrLen + 16); // Points to the IP destination address
			            if((*bufPtr & 0xf0) != 224)
                        {
		                    // This is not a multicast destination address
		                    // Check the destination MAC address
		                    bufPtr = (UINT8*)(buffer+msgHdrLen);  // Points to the Ethernet destination address
		                    int bufCnt = 0;
			                while (bufCnt < 6)
                            {
			                    if(*(bufPtr + bufCnt) != 0x00)
                                {
#ifdef _PROTO_DETOUR
				                    unicastFirewallForwardFlag = false;
#endif  // _PROTO_DETOUR
				                    break;
				                }
				                bufCnt++;
			                }
			            }
		            }
		        }
#ifdef _PROTO_DETOUR
                if (firewall_forward || unicastFirewallForwardFlag)
                {
                    if (!ForwardPacket(dstCount, dstIfIndices, buffer+msgHdrLen+ethHdrLen, len-msgHdrLen-ethHdrLen))
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
	        else if (!strncmp(cmd, "queueStats", cmdLen))
	        {
	    	    // Dump interface queue lengths to server_pipe
                int len = snprintf(buffer, 8192, "smfQueueStats ");
		        Smf::InterfaceList::Iterator iterator(smf.AccessInterfaceList());
		        Smf::Interface* nextIface;
		        char ifaceName[Smf::IF_NAME_MAX+1];
		        ifaceName[Smf::IF_NAME_MAX] = '\0';
                bool firstIface = true;
		        while (NULL != (nextIface = iterator.GetNextItem()))
		        {
	                ProtoNet::GetInterfaceName(nextIface->GetIndex(), ifaceName, Smf::IF_NAME_MAX);
                    snprintf(buffer+len, 8192-len, "%s%s,%u", firstIface ? "" : ";", ifaceName, nextIface->GetQueueLength());
                    firstIface = false;
		        }
                if (server_pipe.IsOpen())
                {
                    unsigned int numBytes = strlen(buffer);
                    server_pipe.Send(buffer, numBytes);  // TBD - error check?
                }
                else
                {
                    fprintf(stdout, "%s\n", buffer);
                }
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

#ifdef ELASTIC_MCAST
bool SmfApp::OnIgmpQueryTimeout(ProtoTimer& theTimer)
{
    // NOTE:  This is _not_ currently used.


    // Send an IGMPv3 QUERY to all nrlsmf devices that have
    // Elastic Multicast associations.  This is used to
    // learn the local host group memberships for the applicable
    // interfaces, even if nrlsmf is started late
    UINT32 alignedBuffer[256/4];  // queries are small
    UINT16* ethBuffer = ((UINT16*)alignedBuffer) + 1;  // offset so IP is 32-bit aligned
    UINT32* ipBuffer = alignedBuffer + 4;  // 2 bytes offset + 14 bytes ETH header

    unsigned int frameMax = 256 - 2;
    ProtoAddress dstMac;  // use broadcast ETH address for now
    dstMac.ResolveEthFromString("ff:ff:ff:ff:ff:ff");
    ProtoPktETH ethPkt((UINT32*)ethBuffer, frameMax);
    //ethPkt.SetSrcAddr(srcMac);  // TBD on a per-interface basis
    ethPkt.SetDstAddr(dstMac);
    ethPkt.SetType(ProtoPktETH::IP);
    ProtoPktIPv4 ipPkt(ipBuffer, frameMax - 14);
    ipPkt.SetID(0);
    ipPkt.SetTTL(1);
    ipPkt.SetProtocol(ProtoPktIP::IGMP);
    // ipPkt.SetSrcAddr(srcIp);  - TBD on a per interface basis
    ProtoAddress dstIp;
    dstIp.ConvertFromString("224.0.0.1");  // "all hosts" IPv4 multicast addr
    ipPkt.SetDstAddr(dstIp);

    ProtoPktIGMP igmpMsg(ipPkt.AccessPayload(), frameMax - 14 - 20);
    igmpMsg.InitIntoBuffer(ProtoPktIGMP::QUERY, 3, ipPkt.AccessPayload(), frameMax - 14 - 20);
    igmpMsg.FinalizeChecksum();
    ipPkt.SetPayloadLength(igmpMsg.GetLength());
    // ipPkt.FinalizeChecksum()  // TBD after per-interface srcIp is set
    ethPkt.SetPayloadLength(ipPkt.GetLength());

    // Then, iterate over elastic multicast interface groups/interfaces
    // and send the query to each (different srcIp for each)
    Smf::InterfaceGroupList::Iterator iterator(smf.AccessInterfaceGroupList());
    Smf::InterfaceGroup* ifaceGroup;
    while (NULL != (ifaceGroup = iterator.GetNextItem()))
    {
        if (!ifaceGroup->GetElasticMulticast()) continue;
        Smf::InterfaceGroup::Iterator ifacerator(*ifaceGroup);
        Smf::Interface* iface;
        while (NULL != (iface = ifacerator.GetNextInterface()))
        {
            InterfaceMechanism* mech = static_cast<InterfaceMechanism*>(iface->GetExtension());
            ProtoVif* vif = (NULL != mech) ? mech->GetProtoVif() : NULL;
            if (NULL != vif)
            {
                PLOG(PL_DEBUG, "SmfApp::OnIgmpQueryTimeout() sending IGMP query to iface index %d\n", iface->GetIndex());
                // Send the IGMP Query to the vif\n");
                ProtoAddress ifaceIp = iface->GetIpAddress();
                // This code finds a compatible  address for the given interface's subnet
                // for us to use to generate internal IGMP queries.
                unsigned int prefixLen = ProtoNet::GetInterfaceAddressMask(iface->GetIndex(), ifaceIp);
                unsigned prefixMax = (ifaceIp.GetLength() << 3) - 2;
                if (prefixLen > prefixMax) prefixLen = prefixMax;
                ProtoAddress srcIp;
                ifaceIp.GetSubnetAddress(prefixLen, srcIp);
                srcIp.Increment();
                if (srcIp.HostIsEqual(ifaceIp)) srcIp.Increment();
                ipPkt.SetSrcAddr(srcIp);
                ipPkt.FinalizeChecksum();
                ethPkt.SetSrcAddr(iface->GetInterfaceAddress());
                if (!vif->Write((char*)ethPkt.GetBuffer(), ethPkt.GetLength()))
                    PLOG(PL_ERROR, "SmfApp::OnIgmpQueryTimeout() error: unable to write IGMP query packet to kernel!\n");
            }
        }
    }
    theTimer.SetInterval(10.0);
    return true;
}  // end SmfApp::OnIgmpQueryTimeout()
#endif // ELASTIC_MCAST

// This is the notification handler called when outbound virtual interface packets are received
// These should be packets generated by the local host or forwarded via non-SMF forwarding
void SmfApp::OnPktOutput(ProtoChannel&              theChannel,
	                     ProtoChannel::Notification notifyType)
{
    //PLOG(PL_DEBUG, "SmfApp::OnPktOutput(): Function called.\n");
    // Read packets from IP stack and output to associated ProtoCap
    ProtoVif& vif = static_cast<ProtoVif&>(theChannel);
    Smf::Interface* iface = reinterpret_cast<Smf::Interface*>((void*)vif.GetUserData());
    // TBD - We could pre-size and align the "ethBuffer" here to allow
    // for possible forwarding IP encapsulation
    const int BUFFER_MAX = FRAME_SIZE_MAX + 2;
    bool packetHandled = false;
    UINT32 alignedBuffer[BUFFER_MAX/sizeof(UINT32)];
    // offset by 2-bytes so IP content is 32-bit aligned
    const unsigned int ENCAPS_OFFSET = 20;  // fixed 20 bytes for IPIP encapsulation
    UINT16* ethBuffer = ((UINT16*)alignedBuffer) + 1 + ENCAPS_OFFSET/2;
    const unsigned int BUFFER_RESERVE = 2 + ENCAPS_OFFSET;  // space reserved for alignment and encapsulation purposes
    unsigned int numBytes = BUFFER_MAX - BUFFER_RESERVE;

    ASSERT(!iface->IsQueuing() || !iface->QueueIsFull());
    while (vif.Read((char*)ethBuffer, numBytes))
    {
        if (0 == numBytes) break;  // no more packets to output
        // This is just a check
        ProtoPktETH ethPkt(ethBuffer, BUFFER_MAX - 2);
        if (!ethPkt.InitFromBuffer(numBytes))
        {
            PLOG(PL_ERROR, "SmfApp::OnPktOutput() error: bad Ether frame\n");
            numBytes = BUFFER_MAX - BUFFER_RESERVE;  // reset "numBytes" for next vif.Read() call
            continue;
        }

        // Some IGMP snooping test code
        bool igmpSnoop = false;
        if (igmpSnoop && (ProtoPktETH::IP == ethPkt.GetType())) // TBD - support IPv6 and MLD
        {
            ProtoPktIPv4 ip4Pkt;
            if (!ip4Pkt.InitFromBuffer(ethPkt.AccessPayload(), ethPkt.GetPayloadMax()))
            {
                PLOG(PL_WARN, "SmfApp::OnPktOutput() warning: invalid IPv4 packet?!\n");
                numBytes = BUFFER_MAX - BUFFER_RESERVE;  // reset "numBytes" for next vif.Read() call
                continue;
            }
            if (ProtoPktIP::IGMP == ip4Pkt.GetProtocol())
            {
                ProtoPktIGMP igmpMsg(ip4Pkt.AccessPayload(), ip4Pkt.GetPayloadLength());
                if (igmpMsg.InitFromBuffer(ip4Pkt.GetPayloadLength()))
                    HandleIGMP(igmpMsg, *iface, false);
                else
                    PLOG(PL_WARN, "SmfApp::OnPktOutput() warning: invalid IGMP message?!\n");
            }
        }

#ifdef ADAPTIVE_ROUTING
        // Intercept outbound packets if this interface is part of the smart-routing / adaptive routing association
        // This is due to the fact that outbound packets need to be given the SRR header, to track the path through the network
        // as well as sending proactive ACK information.
        // If a packet goes through process packet, then we must make sure it's not forwarded by another mechanism, this will result
        // in duplicate packets.
        Smf::Interface::Associate* assoc = iface->FindAssociate(iface->GetIndex());
        if ((NULL != assoc) && (assoc->GetInterfaceGroup().GetAdaptiveRouting()))
        {
            if (ProtoPktETH::IP == ethPkt.GetType())
            {
                ProtoPktIP ipPkt;
                if (ipPkt.InitFromBuffer(ethPkt.GetPayloadLength(), ethPkt.AccessPayload(), ethPkt.GetPayloadMax()))
                {
                    if (4 == ipPkt.GetVersion())
                    {
                        // at this point we've grabbed an ipv4 packet.
                        ProtoPktIPv4 ipv4Pkt(ipPkt);
                        if (ipv4Pkt.GetTOS() >> 2 >= SmartPkt::ADAPTIVE_DSCP_MIN && ipv4Pkt.GetTOS() >> 2 <= SmartPkt::ADAPTIVE_DSCP_MAX)
                        {
                            // Now this is a packet we're interested in.
                            // These packets should not be packets that have already gone through processPacket()
                            unsigned int dstIfIndices[IF_COUNT_MAX];
                            ProtoAddress srcMacAddr;
                            ProtoAddress dstMacAddr;
                            // Grab the source and destination MAC addresses
                            ethPkt.GetSrcAddr(srcMacAddr);
                            ethPkt.GetDstAddr(dstMacAddr);
                            // Call to process packet with outbound = true;
                            // This skips the packet reception part of process packet, adds the SRR header, and forwards.
                            int dstCount = smf.ProcessPacket(ipPkt, srcMacAddr, dstMacAddr, *iface, dstIfIndices, IF_COUNT_MAX,ethPkt, true);
                            // We set this bool to true here to make sure that later attempts to inform code below this was sent
                            packetHandled = true;
                            // If process packet decides to send the packet...
                            if (dstCount > 0)
                            {
                                // If the "tap" (diversion to another process) has been activated, pass the packet that
                                // would have been forwarded this process.  That process may filter the packet and use
                                // the "smfInject" command to return the packet to "nrlsmf" for final forwarding.
                                if (tap_active)
                                {
                                    // To save on byte copying, we left space at the beginning of our "alignedBuffer"
                                    // for the "smfPkt" message header in case it is needed.
                                    unsigned int ethHdrLen = ProtoPktETH::GetHeaderLength(ethBuffer, BUFFER_MAX - 2);
                                    if (!ForwardFrameToTap(iface->GetIndex(), dstCount, dstIfIndices, (char*)ethBuffer, ipPkt.GetLength() + ethHdrLen))
                                    {
                                        PLOG(PL_ERROR, "SmfApp::OnPktOutput() error: unable to forward packet to \"tap\" process\n");
                                    }

                                }
#ifdef _PROTO_DETOUR
                                else if (firewall_forward)
                                {
                                    if (!ForwardPacket(dstCount, dstIfIndices, (char*)ipPkt.GetBuffer(), ipPkt.GetLength()))
                                    {
                                        PLOG(PL_ERROR, "SmfApp::OnPktOutput() error: unable to forward packet via ProtoDetour\n");
                                    }
                                }
#endif // _PROTO_DETOUR
                                else
                                {
                                    if (!ForwardFrame(dstCount, dstIfIndices, (char *)ethPkt.GetBuffer(), ethPkt.GetLength()))
                                    {
                                        PLOG(PL_ERROR, "SmfApp::OnPktOutput() error: unable to forward packet via ProtoCap device\n");
                                    }

                                }
                            }  // end if (dstCount > 0)
                        }
                    }
                }
            }
        }
#endif // ADAPTIVE_ROUTING

#ifdef ELASTIC_MCAST
        // Intercept outbound IGMP messages if this interface is
        // part of an elastic multicast association
        // Look for elastic self-association as an indicator
        // TBD - add an "elastic" attribute to Smf::Interface class??
        Smf::Interface::Associate* assoc = iface->FindAssociate(iface->GetIndex());
        bool elasticMulticast = (NULL != assoc) ? assoc->GetInterfaceGroup().GetElasticMulticast() : false;
        bool elasticUnicast = (NULL != assoc) ? assoc->GetInterfaceGroup().GetElasticUnicast() : false;
        if (elasticMulticast || elasticUnicast)
        {
            ProtoPktIP ipPkt;
            bool isValidIP = (ProtoPktETH::IP == ethPkt.GetType()) && 
                             ipPkt.InitFromBuffer(ethPkt.GetPayloadLength(), ethPkt.AccessPayload(), ethPkt.GetPayloadMax());
            UINT8 trafficClass = 0;
            if (isValidIP)
            {
                bool isUnicast = false;
                if (4 == ipPkt.GetVersion())
                {
                    ProtoPktIPv4 ip4Pkt(ipPkt);
                    ProtoAddress src, dst;
                    ip4Pkt.GetSrcAddr(src);
                    ip4Pkt.GetDstAddr(dst);
                    isUnicast = dst.IsUnicast();
                    trafficClass = ip4Pkt.GetTOS();
                    if (elasticMulticast && (ProtoPktIP::IGMP == ip4Pkt.GetProtocol()))
                    {
                        // This is an outbound IGMP message, so intercept it
                        ProtoAddress srcAddr;
                        ip4Pkt.GetSrcAddr(srcAddr);
                        ProtoPktIGMP igmpMsg(ip4Pkt.AccessPayload(), ip4Pkt.GetPayloadLength());
                        if (igmpMsg.InitFromBuffer(ip4Pkt.GetPayloadLength()))
                        {
                            mcast_controller.HandleIGMP(igmpMsg, srcAddr, iface->GetIndex(), false);
                            InterfaceMechanism* mech = static_cast<InterfaceMechanism*>(iface->GetExtension());
                            if (mech->BlockIGMP())
                            {
                                numBytes = BUFFER_MAX - BUFFER_RESERVE;  // reset "numBytes" for next vif.Read() call
                                continue;
                            }
                        }
                        else
                        {
                            PLOG(PL_WARN, "SmfApp::OnPktOutput() warning: invalid IGMP message?!\n");
                        }
                    }
                }
                else if (6 == ipPkt.GetVersion())
                {
                    ProtoPktIPv6 ip6Pkt(ipPkt);
                    ProtoAddress dst;
                    ip6Pkt.GetDstAddr(dst);
                    isUnicast = dst.IsUnicast();
                    trafficClass = ip6Pkt.GetTrafficClass();
                }   
                if (elasticUnicast && isUnicast)
                {
                    // For elastic unicast, we need to change the ETH 
                    // destination  address since ARP is disabled, etc
                    // TBD - support ARP interception instead? (i.e. do our own ARP cache)
                    // TBD - do this _after_ smf.ProcessPacket() is called???
                    char addrBuffer[6];
			        memset(addrBuffer, 0XFF, 6);
                    ProtoAddress bcastAddr;
			        bcastAddr.SetRawHostAddress(ProtoAddress::ETH, addrBuffer, 6);        
                    ethPkt.SetDstAddr(bcastAddr);
                }
                // Use Smf::ProcessPacket() to decide if packet should be sent instead of default packet transmission behavior
                unsigned int dstIfIndices[IF_COUNT_MAX];
                // Grab the source and destinaiton MAC addresses
                ProtoAddress srcMacAddr;
                ethPkt.GetSrcAddr(srcMacAddr);
                ProtoAddress dstMacAddr;
                ethPkt.GetDstAddr(dstMacAddr);
                int dstCount = smf.ProcessPacket(ipPkt, srcMacAddr, dstMacAddr, *iface, dstIfIndices, IF_COUNT_MAX, ethPkt, true);
                for (int i = 0; i < dstCount; i++)
                {
                    // TBD - perhaps we should have a more efficient way to dereference the dstIface ???
                    // (e.g., instead of dstIfIndices array, pass an array of Smf::Interface pointers)
                    Smf::Interface* dstIface = smf.GetInterface(dstIfIndices[i]);
                    ASSERT(NULL != dstIface);
                    if (dstIface->UseETX() && (4 == ipPkt.GetVersion()))
                    {
                        UINT8 utos = smf.GetUnreliableTOS();
                        bool reliable = dstIface->IsReliable() && ((0 == utos) || (utos != trafficClass));
                        // add (or update) UMP option
                        ProtoPktIPv4 ip4Pkt(ipPkt);
                        UINT16 sequence = dstIface->GetUmpSequence();
                        dstIface->SetUMPOption(ip4Pkt, reliable);
                        ethPkt.SetPayloadLength(ip4Pkt.GetLength());
                        // Cache the packet for possible retransmission if NACKed
                        if (reliable)
                            smf.CachePacket(*dstIface, sequence, (char*)ethPkt.GetBuffer(), ethPkt.GetLength());
                    }
                    if (!SendFrame(*dstIface, (char*)ethPkt.GetBuffer(), ethPkt.GetLength()))
                    {
                        char ifaceName[32], dstIfaceName[32];
                        ifaceName[31] = dstIfaceName[31] = '\0';
                        ProtoNet::GetInterfaceName(iface->GetIndex(), ifaceName, 31);
                        ProtoNet::GetInterfaceName(dstIface->GetIndex(), dstIfaceName, 31);
                        PLOG(PL_WARN, "SmfApp::OnPktOutput(%s) warning: blocked sending frame via iface %s\n", ifaceName, dstIfaceName);
                    }
                }
                packetHandled =  true;  // so code below doesn't also send the packet
            }  // end if (isValidIP)
        }
#endif // ELASTIC_MCAST
        // Note even it ELASTIC_MCAST or ADAPTIVE_ROUTING, non-IP packets need to be sent
        // The IP-IP encapsulation code here should be moved elsewhere 
        //  (e.g., within ForwardFrame() on a per-interface basis
        if (!packetHandled)
        {
            if (iface->IsEncapsulating())
            {
                PLOG(PL_WARN, "SmfApp::OnPktOutput() note : Packet Encapsulation\n");
                // a) Encapsulate IP Unicast only, so we need to get the dstAddr to check
                ProtoAddress dstAddr; // stays "invalid" if not an IP packet
                ProtoPktIP ipPkt;//((UINT32*)ethPkt.GetPayload(), ethPkt.GetPayloadLength());
                ProtoPktETH::Type ethType = ethPkt.GetType();
                if ((ProtoPktETH::IP == ethType) || (ProtoPktETH::IPv6 == ethType))
                {
                    if (ipPkt.InitFromBuffer(ethPkt.GetPayloadLength(), (UINT32*)ethPkt.GetPayload(), ethPkt.GetPayloadMax()))
                        ipPkt.GetDstAddr(dstAddr);
                    else
                        PLOG(PL_WARN, "SmfApp::OnPktOutput() warning: invalid IP packet?!\n");

                }
                // b) Look up next hop for encapsulation
                ProtoAddress nextHopAddr;  // stays "invalid" if not to encapsulate
                if (dstAddr.IsValid() && dstAddr.IsUnicast())
                {
                    unsigned int prefixLen = dstAddr.GetLength() << 3; // addr length in bits
                    unsigned int nextHopIndex;
                    int metric;
                    if (!route_table.GetRoute(dstAddr, prefixLen, nextHopAddr, nextHopIndex, metric))
                        PLOG(PL_WARN, "SmfApp::OnPktOutput() warning: no route for encapsulating packet to %s\n", dstAddr.GetHostString());
                }
                if (ProtoAddress::IPv6 == nextHopAddr.GetType())
                {
                    PLOG(PL_WARN, "SmfApp::OnPktOutput() error: IPv6 encapsulation not yet supported!\n");
                    nextHopAddr.Invalidate();  // TBD - support IPv6 encapsulation
                }
                // c) If valid next hop and not equal to destination, encapsulate
                if (nextHopAddr.IsValid() && !nextHopAddr.HostIsEqual(dstAddr))
                {
                    // Perform the encapsulation.  Current initial proof-of-concept limitations:
                    // 1) IPv4-only RFC 2003 IPIP encapsulation (IPv4 over IPv4)
                    // 2) We don't deal with fragmentation or MTU Discovery issues yet
                    // 3) No ICMP handling
                    // 4) TBD - handle these issues and provide RFC 2003 IPIP encapsulation when needed (incl. IPv6 variant)
                    // RFC 2004 minimal encapsulation (IPv4 only) is <modified IP Header> + <minimal Encapsulation Header> + <IP Payload>
                    UINT16* ethBuffer2 = ethBuffer - ENCAPS_OFFSET / 2;
                    memcpy(ethBuffer2, ethBuffer, 14);  // slide 14 bytes of Ethernet header into "reserved" buffer space
                    ProtoPktETH ethPkt2((UINT32*)ethBuffer2, BUFFER_MAX - BUFFER_RESERVE + ENCAPS_OFFSET);
                    ethPkt2.InitFromBuffer(ethPkt.GetLength());
                    // We use some info from the inner packet we are encapsulating
                    ProtoPktIPv4 ip4Pkt(ipPkt); // we know it's an IPv4 packet

                    // TBD - We should check here if the inner packet we plan to encapsulate is one
                    // that had already been encapsulated but ended up being queued because of flow
                    // control. If that's the case we should not re-encapsulate and refresh the next
                    // hop address instead!

                    // Initialize and build our outer, encapsulating IPv4 packet header
                    ProtoPktIPv4 ip4Pkt2((UINT32*)ethPkt2.GetPayload(), ethPkt2.GetPayloadLength() + ENCAPS_OFFSET);
                    ip4Pkt2.SetTOS(ip4Pkt.GetTOS());
                    ip4Pkt2.SetID(ip4Pkt.GetID()); // TBD - set the IP ID field differently?
                    ip4Pkt2.SetTTL(ip4Pkt.GetTTL());
                    ip4Pkt2.SetProtocol(ProtoPktIP::IPIP);  // IPIP encapsulation (protocol 4)
                    ip4Pkt2.SetSrcAddr(iface->GetIpAddress());
                    ip4Pkt2.SetDstAddr(nextHopAddr);
                    // We don't copy the enclosed packet as a payload since it _should_
                    // already be in the right place due to our ENCAPS_OFFSET.
                    // but we do need to set the payload length and calculate the checksum
                    ip4Pkt2.SetPayloadLength(ip4Pkt.GetLength(), true);
                    ethPkt2.SetPayloadLength(ip4Pkt2.GetLength());

                    // If an explicit encapsulation link dst MAC addr has been set, use it.
                    // Otherwise assume the frame already has the proper next hop MAC addr
                    // (THis should be the case if a system default route is set for the
                    //  egress point for this encapsulating host/router; i.e, a tactical radio)
                    if (iface->GetEncapsulationLink().IsValid())
                        ethPkt2.SetDstAddr(iface->GetEncapsulationLink());

                    // Send our frame with IPIP encapsulated packet ...
                    //PLOG(PL_WARN, "SmfApp::OnPktOutput() note : Call to Send Frame 1!\n");
                    SendFrame(*iface, (char*)ethBuffer2, ethPkt2.GetLength());
                }
                else
                {
                   // PLOG(PL_WARN, "SmfApp::OnPktOutput() note : Call to Send Frame 2!\n");
                    SendFrame(*iface, (char*)ethBuffer, numBytes);
                }
            }  // end if (ip_encapsulate)
            else
            {
                SendFrame(*iface, (char*)ethBuffer, numBytes);
            }
        }  // end if (!packetHandled)
        if (!vif.InputNotification()) break;
        numBytes = BUFFER_MAX - BUFFER_RESERVE;  // reset "numBytes" for next vif.Read() call
    }  // end while (vif.Read())
    //  (Also opportunity to do multicast mirror, etc)
}  // end SmfApp::OnPktOutput()

// This is the notification handler called when pcap packets are received
void SmfApp::OnPktCapture(ProtoChannel&              theChannel,
	                      ProtoChannel::Notification notifyType)
{
    ProtoCap& cap = static_cast<ProtoCap&>(theChannel);
    PLOG(PL_DETAIL, "SmfApp::OnPktCapture() called ...\n");
    if (ProtoChannel::NOTIFY_INPUT == notifyType)
    {

        // Note: We offset the buffer by 2 bytes since Ethernet header is 14 bytes
        //       (i.e. not a multiple of 4 (sizeof(UINT32))
        //       This gives us a properly aligned buffer for 32-bit aligned IP packets
        //      (The 256*sizeof(UINT32) bytes are for potential "smfPkt" message header use)
        UINT32  alignedBuffer[BUFFER_MAX/sizeof(UINT32)];
        UINT16* ethBuffer = ((UINT16*)(alignedBuffer+256)) + 1; // offset by 2-bytes so IP content is 32-bit aligned
        const unsigned int ETHER_BYTES_MAX = (BUFFER_MAX - 256*sizeof(UINT32) - 2);
        for (;;)
        {
            // Read in and handle all inbound captured packets
            unsigned int numBytes = ETHER_BYTES_MAX;
            ProtoCap::Direction direction;
            if (!cap.Recv((char*)ethBuffer, numBytes, &direction))
            {
                PLOG(PL_ERROR, "SmfApp::OnPktCapture() ProtoCap::Recv() error\n");
                break;
            }
            if (0 == numBytes) break;  // no more packets to receive
            if (ProtoCap::INBOUND != direction) continue;  // only handle inbound packets
            PLOG(PL_DETAIL, "SmfApp::OnPktCapture() calling HandleInboundPacket\n");
            HandleInboundPacket(alignedBuffer, numBytes, cap);
        }  // end while(1)  (reading ProtoTap device loop)
    }
    else if (ProtoChannel::NOTIFY_OUTPUT == notifyType)
    {
        // Note this is _not_ a packet capture notification
        cap.StopOutputNotification();
        Smf::Interface* iface = reinterpret_cast<Smf::Interface*>((void*)cap.GetUserData());
        ASSERT(NULL != iface);
        InterfaceMechanism* mech = static_cast<InterfaceMechanism*>(iface->GetExtension());
        mech->SetOutputNotification(false);
        ProtoVif* vif = mech->GetProtoVif();
        ProtoTimer& txTimer = mech->GetTxTimer();
        ASSERT(!txTimer.IsActive());
        if (0.0 == mech->GetTxRateLimit()) return;  // rate is zero, so don't send
        // Send as many pending queued packets as we can ...
        // (Note SendFrame() polls "vif" (if applicable) for more
        while (!iface->QueueIsEmpty())
        {
            SmfPacket* frame = iface->DequeuePacket();
            ASSERT(NULL != frame);
            // Note SendFrame() will re-enqueue frame and
            // restart output notification if blocked
            SendFrame(*iface, (char*)frame->GetBuffer(), frame->GetLength());
            if (mech->OutputNotification() || txTimer.IsActive() || (0.0 == mech->GetTxRateLimit())) break;
        }
        if ((NULL != vif) && !vif->InputNotification())
        {
            if (iface->IsQueuing())
            {
                if (!iface->QueueIsFull())
                {
                    vif->StartInputNotification();
                }
            }
            else if (!mech->OutputNotification() && !txTimer.IsActive() && (0.0 != mech->GetTxRateLimit()))
            {
                vif->StartInputNotification();
            }
        }
     }
}  // end SmfApp::OnPktCapture()

// Forward IP packet encapsulated in ETH frame using "ProtoCap" (i.e. pcap or similar) device
bool SmfApp::ForwardFrame(unsigned int dstCount, unsigned int* dstIfIndices, char* frameBuffer, unsigned int frameLength)
{
    bool result = false;
    for (unsigned int i = 0; i < dstCount; i++)
    {
        // TBD - perhaps we should have a more efficient way to dereference the dstIface ???
        // (e.g., instead of dstIfIndices array, pass an array of Smf::Interface pointers)
        int dstIfIndex = dstIfIndices[i];
        Smf::Interface* dstIface = smf.GetInterface(dstIfIndex);
        ASSERT(NULL != dstIface);
        result |= SendFrame(*dstIface, frameBuffer, frameLength);
    }  // end for (...)
    return result;
}  // end SmfApp::ForwardFrame()

bool SmfApp::IsPriorityFrame(UINT32* frameBuffer, unsigned int frameLength)
{
    ProtoPktETH ethPkt(frameBuffer, frameLength);
    if (!ethPkt.InitFromBuffer(frameLength))
    {
        PLOG(PL_ERROR, "SmfApp::IsPriorityFrame() error: bad ether frame\n");
        return false;
    }
    switch (ethPkt.GetType())
    {
        case ProtoPktETH::IP:
        case ProtoPktETH::IPv6:
            break;
        //case ProtoPktETH::ARP:  TBD - prioritize ARP ???
        default:
            return false;
    }
    ProtoPktIP ipPkt((UINT32*)ethPkt.GetPayload(), ethPkt.GetPayloadLength());
    if (!ipPkt.InitFromBuffer(ethPkt.GetPayloadLength()))
    {
        PLOG(PL_ERROR, "SmfApp::IsPriorityFrame() error: invalid IP packet\n");
        return false;
    }
    ProtoPktIP::Protocol protocol;
    //UINT8 trafficClass;
    switch (ipPkt.GetVersion())
    {
        case 4:
        {
            ProtoPktIPv4 ipv4Pkt(ipPkt);
            protocol = ipv4Pkt.GetProtocol();
            //trafficClass = ipv4Pkt.GetTOS();
            break;
        }
        case 6:
        {
            ProtoPktIPv6 ipv6Pkt(ipPkt);
            protocol = ipv6Pkt.GetNextHeader();
            //trafficClass = ipv6Pkt.GetTrafficClass();
            break;
        }
        default:
            return false;
    }
    switch (protocol)
    {
        case ProtoPktIP::OSPF:
            return true;
        default:
            break;
    }
    return false;
}  // end SmfApp::IsPriorityFrame()

// Send a single frame via a single interface (this method used for ElasticMulticast control plane messaging)
bool SmfApp::SendFrame(unsigned int ifaceIndex, char* frameBuffer, unsigned int frameLength)
{
    Smf::Interface* iface = smf.GetInterface(ifaceIndex);
    ASSERT(NULL != iface);
    return SendFrame(*iface, frameBuffer, frameLength);
}  // end SmfApp::SendFrame()

// Forward IP packet encapsulated in ETH frame using "ProtoCap" (i.e. pcap or similar) device
bool SmfApp::SendFrame(Smf::Interface& iface, char* frameBuffer, unsigned int frameLength)
{
    InterfaceMechanism* mech = static_cast<InterfaceMechanism*>(iface.GetExtension());
    // Iterate over tx-enabled CidElements
    ProtoVif* vif = mech->GetProtoVif();
    if (mech->OutputNotification() || mech->GetTxTimer().IsActive() || (0.0 == mech->GetTxRateLimit()))
    {
        // output pcap device is still blocked due to device or self-imposed rate limit (incl. 0.0)
        // so we enqueue the packet if we can
        if (iface.IsQueuing())
        {
            // Enqueue packet for later service by pcap output notification or tx_timer
            // TBD - write received packets directly to an SmfPacket buffer to avoid copying done here
            SmfPacket* pkt = pkt_pool.GetPacket();
            if (NULL != pkt)
            {
                memcpy(pkt->AccessBuffer(), frameBuffer, frameLength);
                pkt->SetLength(frameLength);
                bool priority = IsPriorityFrame(pkt->AccessBuffer(), pkt->GetLength());
                if (iface.EnqueuePacket(*pkt, priority, &pkt_pool))
                {
                    if (iface.QueueIsFull() && (NULL != vif) && vif->InputNotification())
                    {
                        vif->StopInputNotification();
                    }
                    return true;
                }
                // else iface queue was full
                PLOG(PL_WARN, "SmfApp::SendFrame() warning: interface queue is full\n");
                pkt_pool.Put(*pkt);
            }
        }
    }
    else
    {
        InterfaceMechanism::TxStatus txStatus = mech->SendFrame(frameBuffer, frameLength);
        if (InterfaceMechanism::TX_OK == txStatus)     
        {
            double txRateLimit = mech->GetTxRateLimit();
            if (txRateLimit > 0.0)
            {
                ASSERT(0 != frameLength);
                double txInterval = ((double)frameLength) / txRateLimit;
                mech->GetTxTimer().SetInterval(txInterval);
                ActivateTimer(mech->GetTxTimer());
                if (!iface.IsQueuing() && (NULL != vif) && vif->InputNotification())
                {
                    vif->StopInputNotification();
                }
            }
            iface.IncrementSentCount();
            return true;
        }
        else
        {
            if (InterfaceMechanism::TX_ERROR == txStatus)
            {
                // We had a send error, possibly due to ENOBUFS, so we need to wait before
                // trying to send again since ENOBUFS doesn't block select() or write(), etc
                // Use tx timer to wait
                double waitInterval = 1.0e-03; // 1 msec default wait
                double txRateLimit = mech->GetTxRateLimit();
                if (txRateLimit > 0.0) waitInterval = ((double)frameLength) / txRateLimit;
                mech->GetTxTimer().SetInterval(waitInterval);
                ActivateTimer(mech->GetTxTimer());
                if (!iface.IsQueuing() && (NULL != vif) && vif->InputNotification())
                {
                    vif->StopInputNotification();
                }
            }
            if (iface.IsQueuing())
            {
                // Ennqueue (or re-enqueue) the packet for later service
                // TBD - write received packets directly to an SmfPacket buffer to avoid copying done here
                SmfPacket* pkt = pkt_pool.GetPacket();
                if (NULL != pkt)
                {
                    memcpy(pkt->AccessBuffer(), frameBuffer, frameLength);
                    pkt->SetLength(frameLength);
                    bool priority = IsPriorityFrame(pkt->AccessBuffer(), pkt->GetLength());
                    if (iface.EnqueuePacket(*pkt, priority, &pkt_pool))
                    {
                        if (iface.QueueIsFull() && (NULL != vif) && vif->InputNotification())
                        {
                            vif->StopInputNotification();
                        }
                        return true;
                    }
                    // else iface queue was already full
                    PLOG(PL_WARN, "SmfApp::SendFrame() warning: interface queue is full\n");
                    pkt_pool.Put(*pkt);
                }
            }  // end if (iface.IsQueueing())
        }  // end if/else TX_OK
    }
    // Pkt not sent or queued, so it will be dropped, but stop asking for more from vif if applicable
    // (when cap or tx timer is ready to send more it will awake the vif input notification as needed)
    if ((NULL != vif) && (vif->InputNotification()))
    {
        vif->StopInputNotification();
    }
    return false;
}  // end SmfApp::SendFrame()

// Divert IP packet encapsulated in ETH frame to external process using "ProtoPipe"
bool SmfApp::ForwardFrameToTap(unsigned int srcIfIndex, unsigned int dstCount, unsigned int* dstIfIndices, char* frameBuffer, unsigned int frameLength)
{
    // IMPORTANT: This function assumes some space is reserved in the memory area prior to the "frameBuffer" pointer!!!
    // (This is done to avoid unnecessary data copying)
    // "smfPkt" header size = 7 bytes for "smfPkt " plus 1 byte of "indexCount" plus
    // one byte of "srcIfaceIndex" plus <dstCount> bytes of dstIfIndices
    // 1) Build an "smfPkt" message header to send message to "tap" process
    unsigned int msgHdrLen = 7 + 1 + 1 + dstCount;
    char* msgBuffer = frameBuffer - msgHdrLen;
    snprintf(msgBuffer, 8, "smfPkt ");
    msgBuffer[7] = (UINT8)(dstCount + 1);
    msgBuffer[8] = (UINT8)srcIfIndex;
    for (unsigned int i = 0; i < dstCount; i++)
        msgBuffer[i + 9] = (UINT8)dstIfIndices[i];
    // 2) Send the message to the "tap" process
    unsigned int numBytes = frameLength + msgHdrLen;
    return tap_pipe.Send(msgBuffer, numBytes);
}  // end SmfApp::ForwardFrameToTap()

void SmfApp::HandleIGMP(ProtoPktIGMP igmpMsg, Smf::Interface& iface, bool inbound)
{
    // For the moment, this is just printing info to debug ProtoPketIGMP, etc
    // Eventually, this will be used for Elastic Multicast purposes
    char ifaceName[256];
    ifaceName[255] = '\0';
    ProtoNet::GetInterfaceName(iface.GetIndex(), ifaceName, 255);
    PLOG(PL_DEBUG, "SmfApp::HandleIGMP() %s IGMP message on interface %s ...\n", inbound ? "inbound" : "outbound", ifaceName);
    switch (igmpMsg.GetType())
    {
        case ProtoPktIGMP::REPORT_V3:
        {
            PLOG(PL_DEBUG, "   IGMPv3 report with %d group records ...\n", igmpMsg.GetNumRecords());
            ProtoPktIGMP::GroupRecord groupRecord;
            while (igmpMsg.GetNextGroupRecord(groupRecord))
            {
                ProtoAddress groupAddr;
                groupRecord.GetGroupAddress(groupAddr);
                PLOG(PL_DEBUG, "      type:%d group:%s nsrc:%d\n", groupRecord.GetType(), groupAddr.GetHostString(), groupRecord.GetNumSources());
                unsigned int nsrc = groupRecord.GetNumSources();
                for (unsigned int i = 0; i < nsrc; i++)
                {
                    ProtoAddress srcAddr;
                    groupRecord.GetSourceAddress(i, srcAddr);
                    PLOG(PL_DEBUG, "         (src: %s)\n", srcAddr.GetHostString());
                }
            }
            break;
        }

        default:
        {
            PLOG(PL_DEBUG, "   non-IGMPv3 report message type %d...\n", igmpMsg.GetType());
            ProtoAddress groupAddr;
            igmpMsg.GetGroupAddress(groupAddr);
            PLOG(PL_DEBUG, "   groupAddr = %s\n", groupAddr.GetHostString());
            break;
        }
    }
}  // end SmfApp::HandleIGMP()

// returns "true" if packet is destined for local host.  This will be the case for multicast packets
// and unicast packets destined for the local host.
// TODO: Currently the unicast packets follow the former path through OnPktIntercept() and are NOT processed
// through HandleInboundPacket()
bool SmfApp::HandleInboundPacket(UINT32* alignedBuffer, unsigned int numBytes, ProtoCap& srcCap)
{
    // NOTE:  The "alignedBuffer" has 256*4 + 2 bytes of extra space at head for an "smfPkt" header to be
    //        be prepended by "ForwardToTap()" if needed.  The "ethBuffer" is a UINT16 pointer offset
    //        by 2 from the "alignedBuffer" so the Ethernet IP packet payload is properly aligned
    //        (The pointers and max sizes here take all of this into account)
    UINT16* ethBuffer = ((UINT16*)(alignedBuffer+256)) + 1; // offset by 2-bytes so IP content is 32-bit aligned

    const unsigned int ETHER_BYTES_MAX = (BUFFER_MAX - 256*sizeof(UINT32) - 2);
    // Map ProtoPktETH instance into buffer and init for processing
    ProtoPktETH ethPkt((UINT32*)ethBuffer, ETHER_BYTES_MAX);
    UINT32* ipBuffer = (alignedBuffer + 256) + 4; // offset by ETHER header size + 2 bytes
    const unsigned int IP_BYTES_MAX = (ETHER_BYTES_MAX - 14);
    ProtoPktIP ipPkt(ipBuffer, IP_BYTES_MAX);
    bool result = false;
    ProtoAddress srcMacAddr;
    
        // Here is where the SMF forwarding process is done
    //unsigned int srcIfIndex = srcIface.GetIndex();
    unsigned int dstIfIndices[IF_COUNT_MAX];
    int dstCount = 0;

    if (!ethPkt.InitFromBuffer(numBytes))
    {
        PLOG(PL_ERROR, "SmfApp::HandleInboundPacket() error: bad Ether frame\n");
        return false;
    }
    ethPkt.GetSrcAddr(srcMacAddr);   
    // This check is needed because the ProtoCap may falsely report 
    // outbound packets as inbound when using the SMF "device" construct
    // because the virtual "device" MAC addr is not the same as the
    // physical interface that ProtoCap is reading ???
    
    Smf::Interface* srcIface = reinterpret_cast<Smf::Interface*>((void*)srcCap.GetUserData());
    unsigned int srcIfIndex = srcIface->GetIndex();
    
    if (srcMacAddr.IsEqual(srcIface->GetInterfaceAddress()))
    {
        return false;
    }
    ProtoAddress dstMacAddr;
    ethPkt.GetDstAddr(dstMacAddr);
#ifdef ELASTIC_MCAST
    UINT8 trafficClass = 0;
#endif // ELASTIC_MCAST
    bool isDuplicate = false; // used to check for duplicate receptions for "device" interfaces
    ProtoPktIP::Protocol protocol = ProtoPktIP::RESERVED;  // will be set if IP packet
    ProtoPktETH::Type ethType = (ProtoPktETH::Type)ethPkt.GetType();
    if (ethType == ProtoPktETH::ARP)
    {
        result = true;
    }
    else if ((ProtoPktETH::IP == ethType) || (ProtoPktETH::IPv6 == ethType))
    {
        result = true;
         // Only process IP packets for forwarding
        if (!ipPkt.InitFromBuffer(ethPkt.GetPayloadLength()))
        {
            PLOG(PL_ERROR, "SmfApp::HandleInboundPacket() error: bad IP packet?!\n");
            return false;
        }
        unsigned char version = ipPkt.GetVersion();
        ProtoAddress dstAddr;
        if (4 == version)
        {
            ProtoPktIPv4 ip4Pkt(ipPkt);
            ip4Pkt.GetDstAddr(dstAddr);
            protocol = ip4Pkt.GetProtocol();
#ifdef ELASTIC_MCAST
            trafficClass = ip4Pkt.GetTOS();
#endif // ELASTIC_MCAST
        }
        else if (6 == version)
        {
            ProtoPktIPv6 ip6Pkt(ipPkt);
            ip6Pkt.GetDstAddr(dstAddr);
            protocol = ip6Pkt.GetNextHeader();
#ifdef ELASTIC_MCAST
            trafficClass = ip6Pkt.GetTrafficClass();
#endif // ELASTIC_MCAST
        }
        else
        {
            PLOG(PL_ERROR, "SmfApp::HandleInboundPacket() error: invalid IP version?!\n");
            return false;
        }
        if (!dstAddr.IsMulticast() && !smf.GetUnicastEnabled() && !smf.GetAdaptiveRouting())
        {
            // Don't process unicast unless enabled
            return true;
        }

        // Some IGMP snooping test code (TBD - handle IPv6 too)
        bool igmpSnoop = false;
        if (igmpSnoop && (ProtoPktIP::IGMP == protocol))
        {
            ProtoPktIPv4 ip4Pkt(ipPkt);
            ProtoPktIGMP igmpMsg(ip4Pkt.AccessPayload(), ip4Pkt.GetPayloadLength());
            if (igmpMsg.InitFromBuffer(ip4Pkt.GetPayloadLength()))
                HandleIGMP(igmpMsg, *srcIface, true);
            else
                PLOG(PL_WARN, "SmfApp::HandleInboundPacket() warning: invalid IGMP message?!\n");
        }

        //PLOG(PL_DEBUG, "SmfApp::HandleInboundPacket(): Calling Process Packet \n" );
        dstCount = smf.ProcessPacket(ipPkt, srcMacAddr, dstMacAddr, *srcIface, dstIfIndices, IF_COUNT_MAX, ethPkt, false, &isDuplicate);
        PLOG(PL_DETAIL, "SmfApp::HandleInboundPacket(): Called ProcessPacket, return value  = %d \n", dstCount);
        if (dstCount < 0) result = false;
        if (srcIface->IsEncapsulating() && (4 == ipPkt.GetVersion()))
        {
            // We need to check to see if we need to unpack the packet
            // (currently only IPv4 IPIP encapsulation is used (RFC 2003)
            ProtoPktIPv4 ip4Pkt(ipPkt);
            ProtoAddress dstAddr;
            if (ProtoPktIP::IPIP == ip4Pkt.GetProtocol())
            {
                // TBD - should we also validate that the ip4Pkt source address is one of our
                //        one-hop neighbors or at least someone for which we have a route entry???
                //       (i.e., as a check that this encapsulated packet is from a peer)
                const unsigned int ENCAPS_OFFSET = 20;  // 20 bytes of encapsulating IP header
                ip4Pkt.GetDstAddr(dstAddr);
                if (smf.IsOwnAddress(dstAddr))
                {
                    // It's an IPIP packet for me, so unpack
                    // a) move the ethBuffer pointer (writes over ip4Pkt header)
                    UINT16* ethBuffer2 = ethBuffer + ENCAPS_OFFSET / 2;
                    memcpy(ethBuffer2, ethBuffer, 14);
                    ethBuffer = ethBuffer2;
                    numBytes -= ENCAPS_OFFSET;
                    if (!ethPkt.InitFromBuffer(numBytes, (UINT32*)ethBuffer, numBytes))
                    {
                        PLOG(PL_ERROR, "SmfApp::HandleInboundPacket() error: bad IPIP encapsulation Ether frame\n");
                        return false;
                    }
                    // So we have now "reframed" the Ether frame, effectively stripping away the encapsulation header
                    // and we need to re-init our "ipPkt" for SMF forwarding evaluation
                    if (!ipPkt.InitFromBuffer(ethPkt.GetPayloadLength(), (UINT32*)ethPkt.GetPayload(), ethPkt.GetPayloadLength()))
                    {
                        PLOG(PL_ERROR, "SmfApp::HandleInboundPacket() error: bad encapsulated IP packet\n");
                        return false;
                    }
                }
            }
        }  // end if (srcIFace.IsEncapsulating() ...
    }
    // Check if this is an "SMF Device" interface (i.e., coupled with a vif)
    // If this "srcIface" is part of an "SMF Device" (i.e., is a "vif"), we need to write a copy up to the
    // kernel as a received packet via our virtual interface (vif) mechanism
    // (Note we do this _before_ forwarding, since forwarding modifies the Ethernet frame / IP packet
    InterfaceMechanism* mech = static_cast<InterfaceMechanism*>(srcIface->GetExtension());
    ASSERT(NULL != mech);
    ProtoVif* vif = mech->GetProtoVif();
    if ((NULL != vif) && (dstCount >= 0))  // A non-NULL vif indicates it's an SmfDevice interface
    {
        //PLOG(PL_DEBUG, "SmfApp::HandleInboundPacket(): Non-Null VIF \n" );
        // Is it for me? (check for multicast/broadcast MAC dest or matching MAC address for us
        ProtoAddress dstMacAddr;
        ethPkt.GetDstAddr(dstMacAddr);
        // Note ProtoAddress::IsMulticast() for ETH addrs includes broadcast addr as multicast
        // TBD - we could look at the dst IP addr and opportunistically get packets destined for us?
        bool match = dstMacAddr.IsMulticast() || 
                     dstMacAddr.HostIsEqual(vif->GetHardwareAddress()) ||
                     dstMacAddr.HostIsEqual(srcCap.GetInterfaceAddr());
        if (match)
        {
            // TBD - Do not write duplicate packets up to kernel
            if (!isDuplicate || !filter_duplicates)
            {
                
                // This "hack" blocks ICMP messages from being written up to the virtual
                // interface, because the "device" PCAP interface already sends them up to the kernel,
                // (Even though IP is disabled on that physical interface!)
                // such that duplicate Ping response would be generated if we also write the request
                // up here. (Need to confirm for other ICMP message types, but likely true for all)
                //if (protocol != ProtoPktIP::ICMP)  // TBD - investigate ICMP6 handling
                {
                    if (!vif->Write((char*)ethPkt.GetBuffer(), ethPkt.GetLength()))
                        PLOG(PL_ERROR, "SmfApp::HandleInboundPacket() error: unable to write incoming packet to kernel!\n");
                }
            }
        }
    }
#ifdef ELASTIC_MCAST   
    for (int i = 0; i < dstCount; i++)
    {
        // TBD - perhaps we should have a more efficient way to dereference the dstIface ???
        // (e.g., instead of dstIfIndices array, pass an array of Smf::Interface pointers)
        Smf::Interface* dstIface = smf.GetInterface(dstIfIndices[i]);
        ASSERT(NULL != dstIface);
        if (dstIface->UseETX() &&  (4 == ipPkt.GetVersion()))
        {
            UINT8 utos = smf.GetUnreliableTOS();
            bool reliable = dstIface->IsReliable() && ((0 == utos) || (utos != trafficClass));
            // add (or update) UMP option
            ProtoPktIPv4 ip4Pkt(ipPkt);
            UINT16 sequence = dstIface->GetUmpSequence();
            dstIface->SetUMPOption(ip4Pkt, reliable);
            ethPkt.SetPayloadLength(ip4Pkt.GetLength());
            // Cache the packet for potential retransmission if NACKed
            if (reliable)
                smf.CachePacket(*dstIface, sequence, (char*)ethPkt.GetBuffer(), ethPkt.GetLength());
        }
        if (!SendFrame(*dstIface, (char*)ethPkt.GetBuffer(), ethPkt.GetLength()))
        {
            char ifaceName[32], dstIfaceName[32];
            ifaceName[31] = dstIfaceName[31] = '\0';
            ProtoNet::GetInterfaceName(srcIfIndex, ifaceName, 31);
            ProtoNet::GetInterfaceName(dstIface->GetIndex(), dstIfaceName, 31);
            PLOG(PL_WARN, "SmfApp::HandleInboundPacket(%s) warning: blocked sending frame via iface %s\n", ifaceName, dstIfaceName);
        }
    }
#else
    // This code will be deprecated since "firewall" operation is supplanted by the
    //  "nrlsmf device" option and the "tap" could be handled differently.
    if (dstCount > 0)
    {
        //PLOG(PL_DEBUG, "SmfApp::HandleInboundPacket():Forwarding \n" );
        // If the "tap" (diversion to another process) has been activated, pass the packet that
        // would have been forwarded this process.  That process may filter the packet and use
        // the "smfInject" command to return the packet to "nrlsmf" for final forwarding.
        if (tap_active)
        {
            // To save on byte copying, we left space at the beginning of our "alignedBuffer"
            // for the "smfPkt" message header in case it is needed.
            unsigned int ethHdrLen = ProtoPktETH::GetHeaderLength(ethBuffer, ETHER_BYTES_MAX);
            if (!ForwardFrameToTap(srcIfIndex, dstCount, dstIfIndices, (char*)ethBuffer, ipPkt.GetLength() + ethHdrLen))
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
            if (!ForwardFrame(dstCount, dstIfIndices, (char *)ethPkt.GetBuffer(), ethPkt.GetLength()))
            {
                PLOG(PL_ERROR, "SmfApp::HandleInboundPacket() error: unable to forward packet via ProtoCap device\n");
            }
        }
    }  // end if (dstCount > 0)
#endif  // if/else ELASTIC_MCAST
    return result;
}  // end SmfApp::HandleInboundPacket()

void SmfApp::MonitorEventHandler(ProtoChannel&               theChannel,
                                 ProtoChannel::Notification  theNotification)
{
    if (ProtoChannel::NOTIFY_INPUT == theNotification)
    {
        // Read all available (until NULL_EVENT) events
        while (1)
        {
            ProtoNet::Monitor::Event theEvent;
            if (!iface_monitor->GetNextEvent(theEvent))
            {
				PLOG(PL_ERROR, "NetExample::MonitorEventHandler() error: failure getting network events\n");
                break;
            }
            if (ProtoNet::Monitor::Event::NULL_EVENT == theEvent.GetType()) break;

            switch(theEvent.GetType())
            {
                case ProtoNet::Monitor::Event::IFACE_UP:
                    PLOG(PL_DEBUG, "SmfApp::MonitorEventHandler() IFACE_UP \"%s\" (index:%d)\n",
                                theEvent.GetInterfaceName(), theEvent.GetInterfaceIndex());
                    break;
                case ProtoNet::Monitor::Event::IFACE_DOWN:
                    PLOG(PL_DEBUG, "SmfApp::MonitorEventHandler() IFACE_DOWN \"%s\" (index:%d)\n",
                                theEvent.GetInterfaceName(), theEvent.GetInterfaceIndex());
                    break;
                case ProtoNet::Monitor::Event::IFACE_ADDR_NEW:
                {
                    ProtoAddress addr;
                    PLOG(PL_DEBUG, "SmfApp::MonitorEventHandler() IFACE_ADDR_NEW \"%s\" (index:%d) address:%s\n",
                                theEvent.GetInterfaceName(), theEvent.GetInterfaceIndex(), theEvent.GetAddress().GetHostString());
                    break;
                }
                case ProtoNet::Monitor::Event::IFACE_ADDR_DELETE:
                {
                    ProtoAddress addr;
                    PLOG(PL_DEBUG, "SmfApp::MonitorEventHandler() IFACE_ADDR_DELETE \"%s\" (index:%d) address:%s\n",
                                theEvent.GetInterfaceName(), theEvent.GetInterfaceIndex(), theEvent.GetAddress().GetHostString());
                    break;
                }
                case ProtoNet::Monitor::Event::IFACE_STATE:
                case ProtoNet::Monitor::Event::UNKNOWN_EVENT:
                    // ignore other state changes unknown events
                    break;
                default:
                    PLOG(PL_DEBUG, "SmfApp::MonitorEventHandler() unhandled event type %d\n", theEvent.GetType());
                    break;
            }  // end switch(theEvent.GetType())

            unsigned int ifIndex = theEvent.GetInterfaceIndex();
            const char* ifName = theEvent.GetInterfaceName();

            // Is this an interface we care about?
            // a) Is it one of our interfaces?
            Smf::Interface* iface = smf.GetInterface(ifIndex);
            if (NULL == iface)
            {
                if (ProtoNet::Monitor::Event::IFACE_DOWN == theEvent.GetType())
                    continue;  // "down" interface we aren't handling
                // b) Is it an interface were looking for with one or more InterfaceMatchers
                InterfaceMatcher* ifaceMatcher = iface_matcher_list.FindPrefix(ifName, strlen(ifName) << 3);
                if (NULL != ifaceMatcher)
                {
                    // There's at least one, so iterate over all matches
                    const char* prefix = ifaceMatcher->GetPrefix();
                    InterfaceMatcherList::Iterator matcherator(iface_matcher_list, false, prefix, strlen(prefix) << 3);
                    while (NULL != (ifaceMatcher = matcherator.GetNextItem()))
                    {
                        if (0 != strcmp(ifaceMatcher->GetPrefix(), prefix)) break;  // done with matches
                        if (!MatchInterface(*ifaceMatcher, ifName, ifIndex))
                        {
                            PLOG(PL_ERROR, "SmfApp::MonitorEventHandler() error: unable to add matched interface \"%s\" to group \"%s\"\n",
                                           ifName, ifaceMatcher->GetGroupName());
                        }
                    }
                }
                continue;
            }

            // Get list of current addresses assigned to the interface to properly update our
            ProtoAddressList addrList;
            if (!ProtoNet::GetInterfaceAddressList(ifIndex, ProtoAddress::ETH, addrList))
                PLOG(PL_WARN, "SmfApp::MonitorEventHandler() error: couldn't retrieve Ethernet address for iface: %s\n", ifName);
            if (!ProtoNet::GetInterfaceAddressList(ifIndex, ProtoAddress::IPv4, addrList))
                PLOG(PL_WARN, "SmfApp::MonitorEventHandler() error: couldn't retrieve IPv4 address for iface: %s\n", ifName);
            if (!ProtoNet::GetInterfaceAddressList(ifIndex, ProtoAddress::IPv6, addrList))
                PLOG(PL_WARN, "SmfApp::MonitorEventHandler() error: couldn't retrieve IPv6 address for iface: %s\n", ifName);
            if (addrList.IsEmpty())
                PLOG(PL_WARN, "SmfApp::MonitorEventHandler() error: no IP addresses found for iface: %s\n", ifName);

            // TBD - if an interface has no addresses left, should we consider it "down"?
            ProtoAddressList& localAddrList = smf.AccessOwnAddressList();
            ProtoAddressList& ifaceAddrList = iface->AccessAddressList();
            if (ProtoNet::Monitor::Event::IFACE_DOWN == theEvent.GetType())
            {
                // TBD - save the interface that has gone DOWN as an InterfaceMatcher so that if it
                //       comes back up we automatically assign it back to its group(s)
                //       (We'll have to troll the groups set up the matcher(s)
                // Remove interface addresses from smf local (own) address list and remove interface from handling
                PLOG(PL_DEBUG, "SmfApp::MonitorEventHandler() removing SMF interface \"%s\"\n", theEvent.GetInterfaceName());
                localAddrList.RemoveList(addrList);
                ifaceAddrList.RemoveList(addrList);
                ASSERT(NULL != iface);
                smf.RemoveInterface(iface->GetIndex());
                continue;
            }
            else if (ProtoNet::Monitor::Event::IFACE_ADDR_DELETE == theEvent.GetType())
            {
                // Remove the deleted address from the smf local (own) address list
                localAddrList.Remove(theEvent.GetAddress());
                ifaceAddrList.Remove(theEvent.GetAddress());
                addrList.Remove(theEvent.GetAddress());
            }
            // To be conservative, we _always_ update smf local (own) address list to make sure we have them all
            // for interfaces that are "UP"
            ProtoAddressList::Iterator adderator(addrList);
            ProtoAddress addr;
            while (adderator.GetNextAddress(addr))
            {
                smf.AddOwnAddress(addr, ifIndex);
            }
            if (!ifaceAddrList.AddList(addrList))
                PLOG(PL_ERROR, "SmfApp::MonitorEventHandler() error: unable to add interface addresses!\n");
            // Update Smf::Interface if_addr and ip_addr just in case
            ProtoAddress ifAddr;
            ProtoNet::GetInterfaceAddress(iface->GetIndex(), ProtoAddress::ETH, ifAddr);
            smf.AddOwnAddress(ifAddr, iface->GetIndex());
            iface->SetInterfaceAddress(ifAddr);
            iface->UpdateIpAddress();
        }  // end while()
        DisplayGroups();
    }
}  // end SmfApp::MonitorEventHandler()

#if defined(BLOCK_ICMP) && defined(LINUX)

// This is used in conjunction with "nrlsmf device" to avoid duplicate
// delivery of ICMP messages to the kernel since even unconfigured interfaces
// appear to deliver ICMP to kernal
bool SmfApp::BlockICMP(const char* ifaceName, bool enable)
{
    // Make and install "iptables" firewall rules
    const size_t RULE_MAX = 512;
    char rule[RULE_MAX];
    const char* action = enable ? "-A" : "-D";
    snprintf(rule, RULE_MAX, "iptables %s INPUT -i %s -p icmp -j DROP", action, ifaceName);
    // Add redirection so we can get stderr result
    strcat(rule, " 2>&1");
    FILE* p = popen(rule, "r");
    if (NULL != p)
    {
        char errorMsg[256];
        int result = fread(errorMsg, 1, 256, p);
        if ((0 == result) && (0 != ferror(p)))
        {
            PLOG(PL_ERROR, "SmfApp::BlockICMP() fread() error: %s\n",
                           GetErrorString());
            return false;
        }
        char* ptr = strchr(errorMsg, '\n');
        if (NULL != ptr) *ptr = '\0';
        errorMsg[255] = '\0';
        if (0 != pclose(p))
        {
            PLOG(PL_ERROR, "SmfApp::BlockICMP() \"%s\" error: %s\n",
                     rule, errorMsg);
            return false;
        }
    }
    else
    {
        PLOG(PL_ERROR, "SmfApp::BlockICMP() error: popen(%s): %s\n",
                rule, GetErrorString());
        return false;
    }
    return true;
}  // end SmfApp::BlockICMP()

#endif // LINUX

#ifdef _PROTO_DETOUR

// Forward IP packet by injecting through "firewall" or IP raw socket device (ProtoDetour)
// (NOTE: This is used ONLY when the "firewallForward" option is used!!!)
bool SmfApp::ForwardPacket(unsigned int dstCount, unsigned int* dstIfIndices, char* pktBuffer, unsigned int pktLength)
{
    bool result = false;
    for (unsigned int i = 0; i < dstCount; i++)
    {
        int dstIfIndex = dstIfIndices[i];
        Smf::Interface* dstIface = smf.GetInterface(dstIfIndex);
        InterfaceMechanism* mech = static_cast<InterfaceMechanism*>(dstIface->GetExtension());
        ProtoDetour* dstDetour = mech->GetProtoDetour();
        ASSERT(NULL != dstDetour);
        // Only the IP portion of the capture frame is injected
        if (!dstDetour->Inject(pktBuffer, pktLength))
        {
            PLOG(PL_ERROR, "SmfApp::ForwardPacket() error: unable to send packet via iface index: %d\n", dstIfIndex);
            //serr_count++;  // (TBD) set or increment "smf" send error count instead?
        }
        else
        {
            result = true;  // forwarded on at least one iface
        }
    }
    return result;
}  // end SmfApp::ForwardPacket()

// This is the notification handler called when ProtoDetour (firewallCapture) packets are received
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
	    memset(alignedBuffer, 0, (UINT8 *)ipBuffer - (UINT8 *)alignedBuffer);
        const unsigned int IP_BYTES_MAX = (ETHER_BYTES_MAX - 14);

        unsigned int numBytes = IP_BYTES_MAX;
	    ProtoAddress srcMacAddr;
	    ProtoAddress dstMacAddr;
        unsigned int ifIndex;
        // TBD - should this be a "while" loop for efficiency?
        if (detour.Recv((char*)ipBuffer, numBytes, &direction, &srcMacAddr, &ifIndex))
        {
            if (0 != numBytes)
            {
                ProtoPktIP ipPkt(ipBuffer, IP_BYTES_MAX);
                ProtoPktETH ethPkt((UINT32*)ethBuffer,ETHER_BYTES_MAX);
                unsigned int ethHdrLen = ethPkt.GetHeaderLength();
                ProtoAddress srcAddr, dstAddr;
		        bool destPktFlag = false;
		        Smf::Interface* srcIface = smf.GetInterface(ifIndex);
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
                            if (!dstAddr.IsMulticast() && !smf.GetUnicastEnabled()) // resequence only multicast packets unless unicast is enabled
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
                            {
				                UINT16 newseq = smf.IncrementIPv4LocalSequence(&dstAddr);
				                ip4Pkt.SetID(newseq, true);
                            }
                            if (ttl_set >= 0) ip4Pkt.SetTTL((UINT8)ttl_set, true);


                            // If the "tap" (diversion to another process) has been activated, pass the packet
                            // to this process, also. That process may filter the packet
                            // and use the "smfInject" command to return the packet to "nrlsmf" for forwarding.
			                // If we got up to here, we are only handling locally generated outgoing packets.
                            if (tap_active)
                            {
				                // Finally, process packet before forwarding it to the TAP interface given ipPkt, srcMacAddr, and srcIfIndex
			                    unsigned int dstIfIndices[IF_COUNT_MAX];
				                int dstCount = smf.ProcessPacket(ipPkt, srcMacAddr, dstMacAddr, *srcIface, dstIfIndices, IF_COUNT_MAX, ethPkt);
                                // To save on byte copying, we left space at the beginning of our "alignedBuffer"
                                // for the "smfPkt" message header in case it is needed.
				                if(dstCount == -1) dstCount = 0;
                                if (!ForwardFrameToTap(ifIndex, dstCount, dstIfIndices, (char*)ethBuffer, ipPkt.GetLength() + ethHdrLen))
                                    PLOG(PL_ERROR, "SmfApp::OnPktIntercept() error: unable to send packet to \"tap\" process\n");
			                }
                            else if (smf.GetUnicastEnabled() && !dstAddr.IsMulticast())
                            {
			                    // Handle unicast packets for when a tap interface is not defined
			                    unsigned int dstIfIndices[IF_COUNT_MAX];
				                unsigned int dstCount = smf.ProcessPacket(ipPkt, srcMacAddr, dstMacAddr, *srcIface, dstIfIndices, IF_COUNT_MAX, ethPkt);
				                if(dstCount == (unsigned int)-1) dstCount = 0;
                                //ProtoPktETH ethPkt((UINT32*)ethBuffer, ETHER_BYTES_MAX);
				                ProtoAddress dstMacAddr;
				                ProtoPktETH::Type protocolType = ProtoPktETH::IP;
				                char bcastAddr[6];
				                memset(bcastAddr, 0xFF, 6); // Substitute 0 with 0XFF for boadcast
				                dstMacAddr.SetRawHostAddress(ProtoAddress::ETH, bcastAddr, 6);
                                ethPkt.SetDstAddr(dstMacAddr);
                                ethPkt.SetType(protocolType);
                                //ethPkt.SetPayloadLength(numBytes);
                                if (!ForwardFrame(dstCount, dstIfIndices, (char*)ethBuffer, ethHdrLen + ipPkt.GetLength()))
				                    PLOG(PL_ERROR, "SmfApp::OnPktIntercept() error: unable to forward unicast packet via pcap device\n");
			                }
                        }
                        else if (6 == version)
                        {
                            ProtoPktIPv6 ip6Pkt(ipPkt);
                            ip6Pkt.GetDstAddr(dstAddr);
                            if (!dstAddr.IsMulticast() && !smf.GetUnicastEnabled()) // resequence only multicast packets unless unicast enabled
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
                        if (!firewall_capture && !smf.GetUnicastEnabled())
                        {
                            PLOG(PL_WARN, "SmfApp::OnPktIntercept() warning: intercepted INBOUND packet, but firewall_capture disabled?!\n");
                            break;
                        }
                        if (!ipPkt.InitFromBuffer(numBytes))
                        {
                            PLOG(PL_WARN, "SmfApp::OnPktIntercept() warning: bad IP packet size\n");
                            break;
                        }

                        // Finally, process packet for possible forwarding given ipPkt, srcMacAddr, and srcIfIndex
                        unsigned int dstIfIndices[IF_COUNT_MAX];
                        int dstCount = smf.ProcessPacket(ipPkt, srcMacAddr, dstMacAddr, *srcIface, dstIfIndices, IF_COUNT_MAX, ethPkt);
                        if ((dstCount > 0) || (tap_active && (-1 == dstCount)))
                        {
                            if (tap_active || !firewall_forward)
                            {
                                // Build the Ethernet MAC header for TAP or ProtoCap forwarding
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

                                if(smf.IsOwnAddress(dstIpAddr)) {
                                    destPktFlag = true;
                                }

                                ProtoAddress dstMacAddr;
				                if(dstIpAddr.IsMulticast())
                                {
				                    dstMacAddr.GetEthernetMulticastAddress(dstIpAddr);
				                }
                                else
                                {
				                    // Set Ethernet address to zero
				                    char bcastAddr[6];
				                    if (smf.GetUnicastEnabled() && !tap_active)
				                        memset(bcastAddr, 0XFF, 6);
				                    else
				                        memset(bcastAddr, 0, 6); // Substitute 0 with 0XFF for broadcast
				                    dstMacAddr.SetRawHostAddress(ProtoAddress::ETH, bcastAddr, 6);
				                }
                                ethPkt.SetDstAddr(dstMacAddr);
                                ethPkt.SetType(protocolType);
                                ethPkt.SetPayloadLength(numBytes);
 				                if(smf.IsOwnAddress(dstIpAddr))
				                    destPktFlag = true;
			                }

			                if(dstCount == -1) dstCount = 0;

                            // If the "tap" (diversion to another process) has been activated, pass the packet
                            // that would have been forwarded this process.  That process may filter the packet
                            // and use the "smfInject" command to return the packet to "nrlsmf" for forwarding.
                            if (tap_active)
                            {
				                // Copy the source MAC adddress into the Ethernet buffer
				                if(srcMacAddr.GetType() == ProtoAddress::ETH )
				                    memcpy((char*)ethBuffer + 6, srcMacAddr.GetRawHostAddress(), 6);
                                // To save on byte copying, we left space at the beginning of our "alignedBuffer"
                                // for the "smfPkt" message header in case it is needed.
                                if (!ForwardFrameToTap(ifIndex, dstCount, dstIfIndices, (char*)ethBuffer, ipPkt.GetLength() + ethHdrLen))
                                    PLOG(PL_ERROR, "SmfApp::OnPktIntercept() error: unable to send packet to \"tap\" process\n");
                            }
                            else if (firewall_forward)
                            {
                                if (!ForwardPacket(dstCount, dstIfIndices, (char*)ipPkt.GetBuffer(), ipPkt.GetLength()))
                                    PLOG(PL_ERROR, "SmfApp::OnPktIntercept() error firewall forwarding packet\n");
                            }
                            else
                            {
                                if (!ForwardFrame(dstCount, dstIfIndices, (char*)ethBuffer, ethHdrLen + ipPkt.GetLength()))
                                    PLOG(PL_ERROR, "SmfApp::OnPktIntercept() error: unable to forward packet via pcap device\n");
                            }
                        }  // end if (dstCount > 0)
                        break;
                    }  // end case ProtoDetour:INBOUND
                    default:
                        PLOG(PL_WARN, "SmfApp::OnPktIntercept() warning: ambiguous packet capture 'direction'\n");
                        break;
                }
		        ProtoPktIPv4 ip4Pkt(ipPkt);
		        ip4Pkt.GetDstAddr(dstAddr);
 		        if(dstAddr.IsMulticast() || (!dstAddr.IsMulticast() && direction == ProtoDetour::OUTBOUND && tap_active))
                {
		            //PLOG(PL_INFO, "   !!! SmfApp::OnPktIntercept() Allow OUTBOUND || dstAddr.IsMulticast() !!!\n");
		            detour.Allow((char*)ipBuffer, numBytes);
		        }
                else if (destPktFlag)
                {
		            // I am the destination for this packet
		            //PLOG(PL_INFO, "   !!! SmfApp::OnPktIntercept() Allow destPktFlag; Packet sent to me !!!\n");
		            detour.Allow((char*)ipBuffer, numBytes);
		        }
                else
                {
		            //PLOG(PL_INFO, "SmfApp::OnPktIntercept() Drop packet\n");
		            detour.Drop();
		        }
            }
        }
    }
}  // end SmfApp::OnPktIntercept()

bool SmfApp::SetupIPv4UnicastDetour(int hookFlags, const char *unicastPrefix, int dscpval)
{
    if (NULL != detour_ipv4_unicast)
    {
        if((dscpval == 0) || ((hookFlags != detour_ipv4_unicast_flags)))
        {
	        detour_ipv4_unicast->Close();
        }
        else
        {
	        char pfxAddr[24];
	        char *pfxMask;
	        strncpy(pfxAddr, unicastPrefix, 24);
	        pfxMask = pfxAddr;
	        while(*pfxMask != '\0' && *pfxMask != '/') pfxMask++;
	        if(*pfxMask == '\0')
            {
	            PLOG(PL_ERROR, "SmfApp::SetupIPv4UnicastDetour() incorrect prefix format\n");
		        return false;
	        }
	        *pfxMask = '\0';
	        pfxMask++;

	        ProtoAddress srcFilter;
	        ProtoAddress dstFilter;
	        unsigned int dstFilterMask;
	        srcFilter.Reset(ProtoAddress::IPv4);  // unspecified address

	        dstFilter.ResolveFromString(pfxAddr);
	        dstFilterMask = atoi(pfxMask);

	        if (!detour_ipv4_unicast->Open(hookFlags, srcFilter, 0, dstFilter, dstFilterMask, dscpval))
	        {
	            PLOG(PL_ERROR, "SmfApp::OpenIPv4UnicastDetour() error opening IPv4 detour\n");
		        return false;
	        }
	        return true;
	    }
    }

    if (NULL == (detour_ipv4_unicast = ProtoDetour::Create()))
    {
        PLOG(PL_ERROR, "SmfApp::SetupIPv4UnicastDetour() new ProtoDetour error: %s\n", GetErrorString());
	    return false;
    }
    detour_ipv4_unicast->SetNotifier(static_cast<ProtoChannel::Notifier*>(&dispatcher));
    detour_ipv4_unicast->SetListener(this, &SmfApp::OnPktIntercept);

    detour_ipv4_unicast_flags = 0;

    char pfxAddr[24];
    char *pfxMask;
    strncpy(pfxAddr, unicastPrefix, 24);
    pfxMask = pfxAddr;
    while(*pfxMask != '\0' && *pfxMask != '/') pfxMask++;

    if(*pfxMask == '\0')
    {
        PLOG(PL_ERROR, "SmfApp::SetupIPv4UnicastDetour() incorrect prefix format\n");
	    return false;
    }
    *pfxMask = '\0';
    pfxMask++;

    ProtoAddress srcFilter;
    ProtoAddress dstFilter;
    unsigned int dstFilterMask;
    srcFilter.Reset(ProtoAddress::IPv4);  // unspecified address

    dstFilter.ResolveFromString(pfxAddr);
    dstFilterMask = atoi(pfxMask);

    if(dscpval == 0)
    {
        if (!detour_ipv4_unicast->Open(hookFlags, srcFilter, 0, dstFilter, dstFilterMask))
	    {
	        PLOG(PL_ERROR, "SmfApp::OpenIPv4UnicastDetour() error opening IPv4 detour\n");
	        return false;
	    }
    }
    else if (!detour_ipv4_unicast->Open(hookFlags, srcFilter, 0, dstFilter, dstFilterMask, dscpval))
    {
	    PLOG(PL_ERROR, "SmfApp::OpenIPv4UnicastDetour() error opening IPv4 detour\n");
	    return false;
    }

    detour_ipv4_unicast_flags = hookFlags;

    return true;

}  // end SmfApp::SetupIPv4UnicastDetour()



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

