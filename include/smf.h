#ifndef _SMF
#define _SMF
#include "smfHash.h"
#include "smfDpd.h"
#include "smfQueue.h"    // for optional per-flow interface queues
#include "protoTimer.h"
#include "protoPktIP.h"  // (TBD) use something different for OPNET and/or ns-2?
#include "protoPktETH.h"
#include "protoQueue.h"
#if defined(ELASTIC_MCAST) || defined(ADAPTIVE_ROUTING)
#include "mcastFib.h"
#ifdef ADAPTIVE_ROUTING
#include "smartController.h"
#include "smartForwarder.h"
#endif // ADAPTIVE_ROUTING
#endif // ELASTIC_MCAST

/***********************************************************************

NOTES:

    1) At the moment, we only have a _single_ Elastic Multicast "mcast_fib" per Smf instance.
       We should probably have an "mcast_fib" for each configured "elastic" interface _group_.
       For the moment, this means nrlsmf can only support a single "elastic" interface group
       properly.  If multiple "elastic" interface groups are configured, the behavior is
       undefined. 


************************************************************************/

#include <stdint.h>  // for intptr_t

#define INT2VOIDP(i) (void*)(uintptr_t)(i)

#define SET_DSCP   1
#define RESET_DSCP 0

// Class to maintain state for Simplified Multicast Forwarding

class Smf
#ifdef ELASTIC_MCAST
  : public ElasticMulticastForwarder
#endif // ELASTIC_MCAST
#ifdef ADAPTIVE_ROUTING
  : public SmartForwarder
#endif // ADAPTIVE_ROUTING
{
    public:
        enum RelayType
        {
            INVALID,
            CF,
            S_MPR,
            E_CDS,
            MPR_CDS,
            NS_MPR
        };
            
        // Forwarding "modes" for a given interface group
        enum Mode {PUSH, MERGE, RELAY};
        static RelayType GetRelayType(const char* name);
        static Mode GetForwardingMode(const char* name);
            
        Smf(ProtoTimerMgr& timerMgr);
        ~Smf();
        
        bool Init(); // (TBD) add DPD window size parameters to this???
        
        bool SetHashAlgorithm(SmfHash::Type hashType, bool internalHashOnly);
        SmfHash::Type GetHashType() const
            {return ((NULL != hash_algorithm) ? hash_algorithm->GetType() : SmfHash::NONE);}
        bool GetInternalHashOnly() const
            {return ihash_only;}
        
        void SetIdpd(bool state)
            {idpd_enable = state;}
        bool GetIdpd() const
            {return idpd_enable;}
        
        void SetUseWindow(bool state)
        {
            use_window = state;
            // disable hashing if "window DPD" is enabled
            if (state) SetHashAlgorithm(SmfHash::NONE, ihash_only);
            // "window DPD" requires I-DPD operation
            idpd_enable = state ? true : idpd_enable;
        }
        
#ifdef ELASTIC_MCAST
        void SetUnreliableTOS(UINT8 tos)
            {unreliable_tos = tos;}
        UINT8 GetUnreliableTOS() const
            {return unreliable_tos;}
#endif // ELASTIC_MCAST
        
        // Manage/Query a list of the node's local MAC/IP addresses
        // (Also cache interface index so we can look that up by address)
        bool AddOwnAddress(const ProtoAddress& addr, unsigned int ifaceIndex)
        {
            bool result = local_addr_list.Insert(addr, INT2VOIDP(ifaceIndex));
            ASSERT(result);
            return result;
        }
            
        bool IsOwnAddress(const ProtoAddress& addr) const
            {return local_addr_list.Contains(addr);}
        unsigned int GetInterfaceIndex(const ProtoAddress& addr) const
            {return  (unsigned int)((intptr_t)local_addr_list.GetUserData(addr));}
        
        void RemoveOwnAddress(const ProtoAddress& addr)
            {local_addr_list.Remove(addr);}
        ProtoAddressList& AccessOwnAddressList() 
            {return local_addr_list;}
        
        UINT16 GetIPv4LocalSequence(const ProtoAddress* dstAddr,
                                    const ProtoAddress* srcAddr = NULL)
            {return ((UINT16)ip4_seq_mgr.GetSequence(dstAddr, srcAddr));}
        
        
        UINT16 IncrementIPv4LocalSequence(const ProtoAddress* dstAddr,
                                          const ProtoAddress* srcAddr = NULL)
        {
            UINT16 seq = ip4_seq_mgr.IncrementSequence(current_update_time, dstAddr, srcAddr);
            // Skip '0' because some operating systems
            // will re-number packets of id == 0 
            if (0 == seq) 
                return ip4_seq_mgr.IncrementSequence(current_update_time, dstAddr, srcAddr);
            else
                return seq;
        }
                
        UINT16 IncrementIPv6LocalSequence(const ProtoAddress* dstAddr,
                                          const ProtoAddress* srcAddr = NULL)
        {
            return ip6_seq_mgr.IncrementSequence(current_update_time, dstAddr, srcAddr);
        }
        
        class InterfaceGroup;  // really an association group, if you will
        
        // We derive from "ProtoQueue::Item here so we can keep multiple lists of 
        // "Interfaces" indexed by their "ifIndex", "ifName", etc
        class Interface : public ProtoQueue::Item
        {
            public:
                Interface(unsigned int ifIndex);
                ~Interface();
                
                bool Init(bool useWindow);// = false);  // (TBD) add parameters for DPD window, etc
                void Destroy();
                
                unsigned int GetIndex() const
                    {return if_index;}
                
                // These are the hardware address
                void SetInterfaceAddress(const ProtoAddress& ifAddr)
                    {if_addr = ifAddr;}
                const ProtoAddress& GetInterfaceAddress() const
                    {return if_addr;}
                
                ProtoAddressList& AccessAddressList()
                    {return addr_list;}
                void UpdateIpAddress()
                    {addr_list.GetFirstAddress(ip_addr);}
                const ProtoAddress& GetIpAddress() const
                    {return ip_addr;}
                        
                bool IsDuplicatePkt(unsigned int   currentTime,
                                    const char*    flowId,
                                    unsigned int   flowIdSize,   // in bits
                                    const char*    pktId,
                                    unsigned int   pktIdSize)    // in bits 
                {
                    ASSERT(NULL != dup_detector);
                    return (dup_detector->IsDuplicate(currentTime, flowId, flowIdSize, pktId, pktIdSize));   
                } 
                
                void PruneDuplicateDetector(unsigned int currentTime, unsigned int ageMax)
                {
                    ASSERT(NULL != dup_detector);
                    return (dup_detector->Prune(currentTime, ageMax));
                }
                
                unsigned int GetFlowCount() const
                    {return ((NULL != dup_detector) ? dup_detector->GetFlowCount() : 0);}
                
                void IncrementUnicastGroupCount()
                    {unicast_group_count++;}
                void DecrementUnicastGroupCount()
                {
                    ASSERT(0 != unicast_group_count);
                    unicast_group_count--;
                }                

                // Set to "true" to resequence packets inbound on this iface                
                void SetResequence(bool state)
                    {resequence = state;}
                bool GetResequence() const
                    {return resequence;}
                
                // For "tunnel" interface associations (no ttl decrement)
                void SetTunnel(bool state)
                    {is_tunnel = state;}
                bool IsTunnel() const
                    {return is_tunnel;}
                
                // Set to "true" for interfaces that provide their
                // own underlying layer of multicast flooding/distribution
                // "Layered" interfaces do the following:
                // 1) They do _not_ self-associate (i.e. no retransmit of received packets on same interface)
                // 2) The outbound DPD table is checked before forwarding (i.e. seen packets are not retransmitted)
                void SetLayered(bool state)
                    {is_layered = state;}
                bool IsLayered() const
                    {return is_layered;}
               
                // These enable/disable reliable forwarding for the interface
                void SetReliable(bool state)
                {
                    is_reliable = state;
                    use_etx = state ? true : use_etx;
                }                
                bool IsReliable() const
                    {return is_reliable;}
                void SetETX(bool state)
                    {use_etx = state;}
                bool UseETX() const
                    {return use_etx;}
                bool SetUMPOption(ProtoPktIPv4& ipPkt, bool increment);
                
                void SetEncapsulation(bool state)
                    {ip_encapsulate = state;}
                bool IsEncapsulating() const
                    {return ip_encapsulate;}
                void SetEncapsulationLink(const ProtoAddress dstMacAddr)
                    {encapsulation_link = dstMacAddr;}
                const ProtoAddress& GetEncapsulationLink() const
                    {return encapsulation_link;}
                
                // TBD - maybe use ProtoTree to index associates by ifIndex?
                class Associate : public ProtoQueue::Item
                {
                    public:
                        Associate(InterfaceGroup& ifaceGroup, Interface& targetIface);
                        ~Associate();
                        
                        InterfaceGroup& GetInterfaceGroup()
                            {return iface_group;}
                        
                        Interface& GetInterface() const
                            {return target_iface;}
                    private:
                        InterfaceGroup& iface_group;
                        Interface&      target_iface;
                };  // end class Smf::Interface::Associate  
                
                class AssociateList : public ProtoSimpleQueueTemplate<Associate>
                {
                    public:
                        class Iterator : public ProtoSimpleQueueTemplate<Interface::Associate>::Iterator
                        {
                            public:
                                Iterator(AssociateList& assocList) : ProtoSimpleQueueTemplate<Interface::Associate>::Iterator(assocList) {}    
                                Iterator(Interface& iface) : ProtoSimpleQueueTemplate<Interface::Associate>::Iterator(iface.GetAssociateTargetList()) {}
                        };  // end class Smf::Interface::AssociateList::Iterator   
                };  // end class Smf::Interface::AssociateList
                
                AssociateList& GetAssociateTargetList() 
                    {return assoc_target_list;}
                
                //AssociateList& GetAssociateSourceList()
                //    {return assoc_source_list;}
                
                bool HasAssociates() const
                    {return (!assoc_target_list.IsEmpty());}// || !assoc_source_list.IsEmpty());}
                
                bool AddAssociate(InterfaceGroup& ifaceGroup, Interface& targetIface);
                
                Associate* FindAssociate(unsigned int ifIndex);
                
                /*void IncrementUnicastAssociateCount()
                    {unicast_assoc_count++;}
                void DecrementUnicastAssociateCount()
                */

#ifdef ELASTIC_MCAST                        
                MulticastFIB::UpstreamHistory* FindUpstreamHistory(const ProtoAddress& upstreamAddr)
                    {return upstream_history_table.FindUpstreamHistory(upstreamAddr);}
                void AddUpstreamHistory(MulticastFIB::UpstreamHistory& upstreamHistory)
                    {upstream_history_table.Insert(upstreamHistory);}
                void RemoveUpstreamHistory(MulticastFIB::UpstreamHistory& upstreamHistory)
                    {upstream_history_table.Remove(upstreamHistory);}
                UINT16 GetLocalAdvId() const
                    {return local_adv_id;}
                UINT16 IncrementLocalAdvId()
                    {return local_adv_id++;}
                void PruneUpstreamHistory(unsigned int currentTick);
                void SetRepairWindow(double sec)
                    {repair_window = sec;}
                double GetRepairWindow() const
                    {return repair_window;}
#endif // ELASTIC_MCAST
                
                // This is for adding an opaque "decorator" extension to the interface
                // for external use purposes.  If an extension is set for the interface,
                // it is deleted on interface destruction and this gives the user-defined
                // extension an opportunity to gracefully clean up its own state
                class Extension 
                {
                    public:
                        Extension();
                        virtual ~Extension();
                };  // end class Smf::Interface::Extension
                void SetExtension(Extension& ext)
                    {extension = &ext;}
                Extension* GetExtension() const
                    {return extension;}
                Extension* RemoveExtension()
                {
                    Extension* ext = extension;
                    extension = NULL;
                    return ext;
                }
                
                UINT16 GetUmpSequence() const 
                    {return ump_sequence;}
                
                bool IsQueuing() const
                    {return (0 != pkt_queue.GetQueueLimit());}
                    
                bool QueueIsEmpty() const
                    {return pkt_queue.IsEmpty();}    
                    
                bool QueueIsFull() const
                    {return pkt_queue.IsFull();}
                    
                void SetQueueLimit(int qlimit)
                    {pkt_queue.SetQueueLimit(qlimit);}
                    
                bool EnqueuePacket(SmfPacket& pkt, bool prioritize = false, SmfPacket::Pool* pool = NULL)
                    {return pkt_queue.EnqueuePacket(pkt, prioritize, pool);}
                
                /* TBD This will deprecate above
                bool EnqueuePacket(SmfPacket&        pkt,
                                   bool             prioritize = false, 
                                   SmfPacket::Pool* pool = NULL, 
                                   SmfQueue::Mode   qmode = 0);
                */
                
                bool EnqueueFrame(const char* frameBuf, unsigned int frameLen, SmfPacket::Pool* pktPool);
                              
                SmfPacket* PeekNextPacket()
                    {return pkt_queue.PreviewPacket();}
                    
                SmfPacket* DequeuePacket()
                    {return pkt_queue.DequeuePacket();}
                
                // Interface statistics methods
                // (TBD - provide Reset methods
                void IncrementSentCount()
                    {sent_count++;}
                void IncrementRetransmissionCount()
                    {retr_count++;}
                void IncrementRecvCount()
                    {recv_count++;}
                void IncrementMcastCount()
                    {mrcv_count++;}
                void IncrementDuplicateCount()
                    {dups_count++;}
                void IncrementAsymCount()
                    {asym_count++;}
                void IncrementForwardCount()
                    {fwd_count++;}
                
                unsigned int GetSentCount()
                    {return sent_count;}
                unsigned int GetRetransmissionCount() 
                    {return retr_count;}
                unsigned int GetRecvCount()
                    {return recv_count;}
                unsigned int GetMcastCount()
                    {return mrcv_count;}
                unsigned int GetDuplicateCount()
                    {return dups_count;}
                unsigned int GetAsymCount()
                    {return asym_count;}
                unsigned int GetForwardCount()
                    {return fwd_count;}
                unsigned int GetQueueLength() const
                    {return pkt_queue.GetQueueLength();}
                
                // Used for InterfaceList required ProtoIndexedQueue overrides
                const char* GetKey() const
                    {return ((const char*)&if_index);}
                unsigned int GetKeysize() const
                    {return (8*sizeof(unsigned int));}
                    
            private:
                unsigned int                          if_index;                                                                 
                ProtoAddress                          if_addr;                                                                  
                ProtoAddressList                      addr_list;     // list of IP addresses of the interface                   
                ProtoAddress                          ip_addr;       // used as source addr for IPIP encapsulation              
                bool                                  resequence;                                                               
                bool                                  is_tunnel;                                                                
                bool                                  is_layered;                                                               
                bool                                  is_reliable;  
                bool                                  use_etx; 
                UINT16                                ump_sequence;                                                             
                bool                                  ip_encapsulate;                                                           
                ProtoAddress                          encapsulation_link;  // MAC addr of next hop for encapsulated packets     
                SmfDpd*                               dup_detector;                                                             
                AssociateList                         assoc_source_list;   // associates targeting this Interface                 
                AssociateList                         assoc_target_list;   // associates that this Interface targets              
                unsigned int                          unicast_group_count;                     
                                                
                SmfQueueTable                         queue_table;         // TBD - per flow (or next hop?) queues                      
                SmfQueue                              pkt_queue;           // interface output queue
#ifdef ELASTIC_MCAST                
                MulticastFIB::UpstreamHistoryTable    upstream_history_table;
                double                                repair_window;  // in secs (max retransmit packet age)
                UINT16                                local_adv_id;
#endif // ELASTIC_MCAST
                               
                unsigned int                          sent_count;  // count of outbound (sent) packets for iface
                unsigned int                          retr_count;  // count of repairs ('reliable' option)
                unsigned int                          recv_count;  // count of inbound (unicast and multicast) packets
                unsigned int                          mrcv_count;  // count of inbound IP multicast packets received
                unsigned int                          dups_count;  // count of outbound duplicate detected (non-forwarded)
                unsigned int                          asym_count;  // count of inbound packets received from non-symmetric neighbors
                unsigned int                          fwd_count;   // count of inbound packets forwarded to at least one other iface
                
                // The "extension" is used by SmfApp to optionally associate
                // an "InterfaceMechanism" instance with the Interface
                Extension*          extension;
                    
        };  // end class Smf::Interface
        
        class InterfaceList : public ProtoIndexedQueueTemplate<Interface>
        {
            public:
                Interface* FindInterface(unsigned int ifIndex)
                    {return Find((const char*)&ifIndex, 8*sizeof(unsigned int));}
            
                class Iterator : public ProtoIndexedQueueTemplate<Interface>::Iterator
                {
                    public:
                        Iterator(InterfaceList& ifaceList) : ProtoIndexedQueueTemplate<Interface>::Iterator(ifaceList) {}
                        Interface* GetNextInterface()
                            {return ProtoIndexedQueueTemplate<Interface>::Iterator::GetNextItem();}
                };  // end class InterfaceList::Iterator
            
            private:
                const char* GetKey(const Item& item) const
                    {return static_cast<const Interface&>(item).GetKey();}
                unsigned int GetKeysize(const Item& item) const
                    {return static_cast<const Interface&>(item).GetKeysize();}
        };  // end class Smf::InterfaceList
        
        Interface* AddInterface(unsigned int ifIndex);
        Interface* GetInterface(unsigned int ifIndex)
            {return iface_list.FindInterface(ifIndex);}
        InterfaceList& AccessInterfaceList()
            {return iface_list;}
        void RemoveInterface(unsigned int ifIndex);
        void RemoveInterface(Interface* iface);
        void DeleteInterface(Interface* iface);
        
        bool IsInGroup(Interface& iface)
            {return iface_list.IsInOtherQueue(iface);}
        
        // This class is used to manage interfaces that are associated
        // with each other as a group using a common relay algorithm
        // (i.e., "cf", "ecds", or "smpr")
        // An interface group is identified by a "groupName"
        // The relay status of groups are managed independently
        
        enum {IF_GROUP_NAME_MAX = 31};
        enum {IF_NAME_MAX = 255};
        class InterfaceGroup : public ProtoTree::Item
        {
            public:
                InterfaceGroup(const char* groupName);
                ~InterfaceGroup();
                
                const char* GetName() const
                    {return group_name;}
                
                bool AddInterface(Interface& iface)
                {
                    if (iface_list.Insert(iface))
                    {
                        if (elastic_ucast) iface.IncrementUnicastGroupCount();
                        iface.SetETX(use_etx);
                        return true;
                    }
                    return false;
                }
                
                bool Contains(Interface & iface)
                    {return (NULL != iface_list.FindInterface(iface.GetIndex()));}
                
                Interface* FindInterface(unsigned int ifIndex)
                    {return iface_list.FindInterface(ifIndex);}
                
                void RemoveInterface(Interface& iface)
                {
                    iface_list.Remove(iface);
                    if (elastic_ucast) iface.DecrementUnicastGroupCount();
                }

                bool IsEmpty() const
                    {return iface_list.IsEmpty();}
                
                InterfaceList& AccessInterfaceList()
                    {return iface_list;}
                
                friend class Iterator;
                class Iterator : public InterfaceList::Iterator
                {
                    public:
                        Iterator(InterfaceGroup& ifaceGroup)
                            : InterfaceList::Iterator(ifaceGroup.iface_list) {}
                };  // end class InterfaceGroup::Iterator
                
                void SetPushSource(Interface* srcIface)
                    {push_src = srcIface;}
                Interface* GetPushSource() const
                    {return push_src;}
                
                void SetTemplateGroup(bool isTemplate)
                    {is_template = isTemplate;}
                bool IsTemplateGroup() const
                    {return is_template;}
                
                // Forwarding / relay attributes
                void SetForwardingMode(Mode fwdMode)
                    {forwarding_mode = fwdMode;}
                Mode GetForwardingMode() const
                    {return forwarding_mode;}
                void SetRelayType(RelayType relayType)
                    {relay_type = relayType;}
                RelayType GetRelayType() const
                    {return relay_type;}
                void SetResequence(bool rseq)
                    {resequence = rseq;}
                bool GetResequence() const
                    {return resequence;}
                 void SetTunnel(bool state)
                    {is_tunnel = state;}
                bool IsTunnel() const
                    {return is_tunnel;}
                
                // Elastic routing state variables
                void SetElasticMulticast(bool state);
                bool GetElasticMulticast() const
                    {return elastic_mcast;}
                void SetElasticUnicast(bool state);
                bool GetElasticUnicast() const
                    {return elastic_ucast;}
				void SetAdaptiveRouting(bool state);
                bool GetAdaptiveRouting() const
                    {return adaptive_routing;}
                bool IsElastic() const
                    {return (elastic_mcast || elastic_ucast);}
                void SetETX(bool state);
                bool UseETX() const
                    {return use_etx;}
                
                void CopyAttributes(InterfaceGroup& group)
                {
                    forwarding_mode = group.forwarding_mode;
                    relay_type = group.relay_type;
                    resequence = group.resequence;
                    is_tunnel = group.is_tunnel;
                    elastic_mcast = group.elastic_mcast;
                    elastic_ucast = group.elastic_ucast;
                    use_etx = group.use_etx;
					adaptive_routing = group.adaptive_routing;
                }
                
            private:
                // required ProtoTreeItem overrides
                const char* GetKey() const
                    {return group_name;}  
                unsigned int GetKeysize() const  
                    {return group_name_bits;}
                    
                // The extended group name size allows for "<group>:<ifacePrefix>" naming
                // as needed for PUSH groups for a specific source interface family
                char            group_name[IF_GROUP_NAME_MAX+IF_NAME_MAX+2];
                unsigned int    group_name_bits;
                InterfaceList   iface_list;
                Interface*      push_src;  // for "push" (or "rpush") groups
                bool            is_template;
                // The following attributes control relay/forwarding behaviors
                Mode            forwarding_mode;
                RelayType       relay_type;
                bool            resequence;
                bool            is_tunnel;
                bool            elastic_mcast;
                bool            elastic_ucast;
                bool            use_etx;
                bool            adaptive_routing;
				
        };  // end class Smf::InterfaceGroup
        
        class InterfaceGroupList : public ProtoTreeTemplate<InterfaceGroup>
        {
            public:
                InterfaceGroup* FindGroup(const char* groupName)
                    {return FindString(groupName);}
        };  // end class Smf::InterfaceGroupList
        
        // Return value indicates how many outbound (dst) ifaces to forward over
        // Notes:
        // 1) This decrements the ttl/hopLimit of the "ipPkt"
        // 2)
        int ProcessPacket(ProtoPktIP& ipPkt, const ProtoAddress& srcMac, const ProtoAddress& dstMac, 
                          Interface& srcIface, unsigned int dstIfArray[], unsigned int dstIfArraySize, 
                          ProtoPktETH& ethPkt, bool outbound = false, bool* recvDup = NULL);
		unsigned int GetInterfaceList(Interface& srcIface, unsigned int dstIfArray[], int dstIfArrayLength);
        void SetRelayEnabled(bool state);
        bool GetRelayEnabled() const
            {return relay_enabled;}
        void SetRelaySelected(bool state); //will turn on with true and off after delay_time with false;
        bool GetRelaySelected() const
            {return relay_selected;}
        void SetUnicastEnabled(bool state)
            {unicast_enabled = state;}
        void SetAdaptiveRouting(bool state)
            {adaptive_routing = state;}
        bool GetAdaptiveRouting() const
            {return adaptive_routing;}
        bool GetUnicastEnabled() const
            {return unicast_enabled;}      
	    void SetUnicastPrefix(const char* prefix)
	        {strncpy(unicast_prefix, prefix, 24);}
            char * GetUnicastPrefix()
	        {return unicast_prefix;}
	    void SetUnicastDSCP(int idxDSCP)
	        {dscp[idxDSCP] = (char)SET_DSCP;}
	    void UnsetUnicastDSCP(int idxDSCP)
	        {dscp[idxDSCP] = (char)RESET_DSCP;}
	    char* GetUnicastDSCP(void)
	        {return dscp;}
        void SetDelayTime(double time)
            {delay_time = time;} 
        enum DpdType
        {
            DPD_NONE,   // no DPD identifier was present
            DPD_FRAG,   // use fragmentation header info (ID:flags:fragOffset) for DPD
            DPD_IPSEC,  // use IPSec header info (SPI:identifier) for DPD
            DPD_SMF_I,  // use SMF_DPD header for I-DPD
            DPD_SMF_H   // use SMF_DPD header for H-DPD
        };
            
        
        static DpdType GetIPv6PktID(ProtoPktIPv6&   ip6Pkt,      // input
                                    char*           flowId,      // output
                                    unsigned int*   flowIdSize,  // input/output, in bits
                                    char*           pktId,       // output
                                    unsigned int*   pktIdSize);  // input/output, in bits
        
        enum TaggerIdType
        {
            TID_NULL    = 0,
            TID_DEFAULT = 1,
            TID_IPV4    = 2,
            TID_IPV6    = 3,
            TID_EXT     = 7
        };
        
        static bool InsertOptionDPD(ProtoPktIPv6&             ipv6Pkt, 
                                    const char*               pktId,
                                    UINT8                     pktIdLength,  // in bytes
                                    bool                      setHAV        = false,  
                                    unsigned int*             optValOffset  = NULL,                  
                                    ProtoPktDPD::TaggerIdType tidType       = ProtoPktDPD::TID_NULL,
                                    UINT8                     tidLength     = 0,
                                    const char*               taggerId      = NULL);
        
        // This process a packet according to our "smf" configuration
        // and applies SMF_DPD for I-DPD or H-DPD as appropriate
        DpdType ResequenceIPv6(ProtoPktIPv6&   ipv6Pkt,     // input/output
                               char*           flowId,      // output
                               unsigned int*   flowIdSize,  // output, in bits
                               char*           pktId,       // output
                               unsigned int*   pktIdSize);  // output, in bits
        
        // This hashed packet, checks against local hash ("hash_stash") history, 
        // and adds SMF_DPD:HAV as needed to deconflict.
        bool ApplyHAV(ProtoPktIPv6& ipv6Pkt, char* hashResult, unsigned int* hashSize);
        
        
        enum {SELECTOR_LIST_LEN_MAX = (6*100)};
        bool IsSelector(const ProtoAddress& srcMac) const;
        bool IsNeighbor(const ProtoAddress& srcMac) const;
        
        void SetSelectorList(const char* selectorMacAddrs, unsigned int numBytes);
        void SetNeighborList(const char* neighborMacAddrs, unsigned int numBytes);
        
        static const unsigned int DEFAULT_AGE_MAX; // (in seconds)
        static const unsigned int PRUNE_INTERVAL;  // (in seconds)
        
        
        
        InterfaceGroup* AddInterfaceGroup(const char* groupName);
        InterfaceGroup* FindInterfaceGroup(const char* groupName)
            {return iface_group_list.FindGroup(groupName);}
        void DeleteInterfaceGroup(InterfaceGroup& ifaceGroup);
        InterfaceGroupList& AccessInterfaceGroupList()
            {return iface_group_list;}
        
#ifdef ELASTIC_MCAST
        void HandleAdv(unsigned int                    currentTick,
                       ElasticAdv&                     elasticAdv, 
                       Interface&                      srcIface, 
                       const ProtoAddress&             srcMac, 
                       const ProtoAddress&             msgSrc, // temporary until we UMP EM_ADV msgs
                       MulticastFIB::UpstreamHistory*  upstreamHistory);
        
        MulticastFIB::Entry* UpdateElasticRouting(unsigned int                   currentTick,
                                                  const ProtoFlow::Description&  flowDescription,
                                                  Interface&                     srcIface,
                                                  const ProtoAddress&            srcMac,
                                                  MulticastFIB::UpstreamHistory* upstreamHistory, 
                                                  bool                           outbound,
                                                  double                         metric); 
        
        MulticastFIB::UpstreamHistory* GetUpstreamHistory(Interface&    srcIface, 
                                                          ProtoPktIP&   ipPkt, 
                                                          UINT16&       upstreamSeq);  // output
                
        unsigned int UpdateUpstreamHistory(unsigned int                   currentTick,
                                           Interface&                     srcIface, 
                                           MulticastFIB::UpstreamHistory& upstreamHistory,
                                           UINT16                         upstreamSeq);
        
        void AdvertiseActiveFlows();  // override of ElasticMulticastForwarder::AdvertiseActiveFlows()
        
        // Only call if nackCount > 0
        void SendNack(Interface&                     srcIface, 
                      MulticastFIB::UpstreamHistory& upstreamHistory,
                      UINT16                         upstreamSeq,
                      UINT16                         nackCount);
     
        // required ElasticMulticastForwarder overrides
        bool SendAck(unsigned int                  ifaceIndex,   // interface it goes out on
                     const ProtoAddress&           upstreamAddr, // upstream to address it to
                     const ProtoFlow::Description& flowDescription);
        
        // shortcut version when Interface is already dereferenced
        bool SendAck(Interface&                    iface,         // interface it goes out on
                     const ProtoAddress&           upstreamAddr,  // upstream to address it to
                     const ProtoFlow::Description& flowDescription);
        
        // For reliable forwarding option
        static const double DEFAULT_REPAIR_WINDOW;
        static const unsigned int DEFAULT_REPAIR_CACHE_SIZE;
        bool CreatePacketCache(Interface& iface, unsigned int cacheSize);
        bool CachePacket(const Interface& iface, UINT16 sequence, char* frameBuffer, unsigned int frameLength);
        
#endif // ELASTIC_MCAST
        
    private:
        // These are used to mark the IPSec "type" for DPD
        static const char AH;
        static const char ESP;
        
        // SMF microsecond tick count (for ElasticMulticast flow timeout)
        static const double TICKER_DELTA_MAX;  // this is in seconds
        unsigned int UpdateTicker();
        
        // Timeout handlers
        bool OnDelayRelayOffTimeout(ProtoTimer& theTimer);
        bool OnPruneTimeout(ProtoTimer& theTimer);
        
        ProtoTimerMgr&      timer_mgr;
        
        SmfHash*            hash_algorithm;
        bool                ihash_only;
        bool                idpd_enable;
        bool                use_window;
        
        SmfCacheTable           cache_table;  // used for optional reliable forwarding
        SmfIndexedPacket::Pool  indexed_pkt_pool;
        
        InterfaceList       iface_list;
        InterfaceGroupList  iface_group_list;
        
        ProtoAddressList    local_addr_list;  // list of local interface addresses
        
        bool                relay_enabled;
        bool                relay_selected;
        bool                unicast_enabled;
        bool                adaptive_routing;
	    char                unicast_prefix[24];
	    char                dscp[256];
       
        ProtoTimer          delay_relay_off_timer;  // used to delay timeout for a given amount of time;
        double              delay_time;             // amount of time to delay turning off relays;
 
        // (TBD) update "SmfSequenceMgr" to optionally also use internal hash ???
        SmfSequenceMgr      ip4_seq_mgr;    // gives a per [src::]dst sequence space // (TBD) make proto:src:dst
        SmfSequenceMgr      ip6_seq_mgr;    // gives a per [src::]dst sequence space // (TBD) make src:dst
        SmfDpdTable         hash_stash;     // used for source and gateway HAV application 
        
        ProtoTimer          prune_timer;     // to timeout stale flows
        unsigned int        update_age_max;  // max staleness allowed for flows
        unsigned int        current_update_time;
#ifdef ELASTIC_MCAST
        UINT8               unreliable_tos;
#endif // ELASTIC_MCAST
        
        char                selector_list[SELECTOR_LIST_LEN_MAX]; 
        unsigned int        selector_list_len;

        char                neighbor_list[SELECTOR_LIST_LEN_MAX]; 
        unsigned int        neighbor_list_len;
        
        unsigned int        recv_count;
        unsigned int        mrcv_count;
        unsigned int        dups_count;
        unsigned int        asym_count;
        unsigned int        fwd_count;
        
};  // end class Smf
#endif // _SMF
