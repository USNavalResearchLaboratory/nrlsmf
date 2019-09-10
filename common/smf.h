#ifndef _SMF
#define _SMF

#include "smfHash.h"
#include "smfDpd.h"
#include "smfQueue.h"    // for optional per-flow interface queues
#include "protoTimer.h"
#include "protoPktIP.h"  // (TBD) use something different for OPNET and/or ns-2?

// Class to maintain state for Simplified Multicast Forwarding

class Smf
{
    public:
        enum RelayType
        {
            CF,
            S_MPR,
            E_CDS,
            MPR_CDS,        
            NS_MPR     
        };
            
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
        
        // Manage/Query a list of the node's local MAC/IP addresses
         bool AddOwnAddress(const ProtoAddress& addr, unsigned int ifIndex = 0)
            {return local_addr_list.Insert(addr, (void*)ifIndex);}
        bool IsOwnAddress(const ProtoAddress& addr) const
            {return local_addr_list.Contains(addr);}
        
        /*
        int GetInterfaceIndex(const ProtoAddress& addr) const
        {
            unsigned int ifIndex = ((unsigned int)local_addr_list.GetUserData(addr));
            return ((0 == ifIndex) ? 
                        (local_addr_list.Contains(addr) ? 0 : -1) : 
                        ifIndex);
        }
        */
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
        
        // We derive from "ProtoTree::Item here so we can keep a list of 
        // "Interfaces" indexed by their "ifIndex"
        class Interface : public ProtoTree::Item
        {
            public:
                Interface(unsigned int ifIndex);
                ~Interface();
                
                bool Init(bool useWindow);// = false);  // (TBD) add parameters for DPD window, etc
                void Destroy();
                
                unsigned int GetIndex() const
                    {return if_index;}
                
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

                // Set to "true" to resequence packets inbound on this iface                
                void SetResequence(bool state)
                    {resequence = state;}
                bool GetResequence() const
                    {return resequence;}
                
                
                // TBD - maybe use ProtoTree to index associates by ifIndex?
                class Associate : public ProtoList::Item
                {
                    public:
                        Associate(Interface& iface);
                        ~Associate();
                        
                        Interface& GetInterface() const
                            {return assoc_iface;}
                        
                        unsigned int GetInterfaceIndex() const
                            {return assoc_iface.GetIndex();}
                        
                        void SetRelayType(RelayType relayType)
                            {relay_type = relayType;}
                        RelayType GetRelayType() const
                            {return relay_type;}
                                                
                    private:
						Interface& assoc_iface;
                        RelayType  relay_type;
                };  // end class Smf::Interface::Associate
                
                class AssociateList : public ProtoListTemplate<Associate>
                {
                    public:
                        class Iterator : public ProtoListTemplate<Associate>::Iterator
                        {
                            public:
                                Iterator(Interface& iface) 
                                    : ProtoListTemplate<Associate>::Iterator(iface.GetAssociateList()) {}
                        };  // end class Smf::Interface::AssociateList::Iterator   
                };  // end class Smf::Interface::AssociateList
                
                AssociateList& GetAssociateList() 
                    {return assoc_list;}
                
                bool HasAssociates() const
                    {return !assoc_list.IsEmpty();}
                
                bool AddAssociate(Interface& iface, RelayType relayType);
                Associate* FindAssociate(unsigned int ifIndex);
                
                void SetUserData(void* userData)
                    {user_data = userData;}
                void* GetUserData() const
                    {return user_data;}
                
                
                bool EnqueueFrame(const char* frameBuf, unsigned int frameLen, SmfPacket::Pool* pktPool);
                
                // ProtoTree::Item required overrides
                const char* GetKey() const
                    {return ((const char*)&if_index);}
                unsigned int GetKeysize() const
                    {return (8*sizeof(unsigned int));}
                    
            private:
                unsigned int        if_index;
                bool                resequence;
                SmfDpd*             dup_detector;
                AssociateList       assoc_list;
                
                SmfQueueList        queue_list;
                
                // This "user_data" is used by SmfApp to optionally associate
                // an "InterfaceMechanism" instance with the Interface
                void*               user_data;
                    
        };  // end class Smf::Interface
        
        class InterfaceList : public ProtoTreeTemplate<Interface>
        {
            public:
                Interface* FindInterface(unsigned int ifIndex)
                    {return Find((const char*)&ifIndex, 8*sizeof(unsigned int));}
        };  // end class Smf::InterfaceList
        
        Interface* AddInterface(unsigned int ifIndex);
        Interface* GetInterface(unsigned int ifIndex)
            {return iface_list.FindInterface(ifIndex);}
        InterfaceList& AccessInterfaceList()
            {return iface_list;}
        
        // Return value indicates how many outbound (dst) ifaces to forward over
        // Notes:
        // 1) This decrements the ttl/hopLimit of the "ipPkt"
        // 2)
        unsigned int ProcessPacket(ProtoPktIP& ipPkt, const ProtoAddress& srcMac, unsigned int srcIfIndex, 
                                   unsigned int dstIfArray[], unsigned int dstIfArraySize);
        
        void SetRelayEnabled(bool state);
        bool GetRelayEnabled() const
            {return relay_enabled;}
        void SetRelaySelected(bool state); //will turn on with true and off after delay_time with false;
        bool GetRelaySelected() const
            {return relay_selected;}
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
        
    private:
        // These are used to mark the IPSec "type" for DPD
        static const char AH;
        static const char ESP;
                
        // Timeout handlers
        bool OnDelayRelayOffTimeout(ProtoTimer& theTimer);
        bool OnPruneTimeout(ProtoTimer& theTimer);
        
        ProtoTimerMgr&      timer_mgr;
        
        SmfHash*            hash_algorithm;
        bool                ihash_only;
        bool                idpd_enable;
        bool                use_window;
        
        ProtoAddressList    local_addr_list;  // list of local interface addresses
        
        InterfaceList       iface_list;
        
        bool                relay_enabled;
        bool                relay_selected;
       
        ProtoTimer          delay_relay_off_timer;  //used to delay timeout for a given amount of time;
        double              delay_time;       //amount of time to delay turnning off relays;
 
        // (TBD) update "SmfSequenceMgr" to optionally also use internal hash ???
        SmfSequenceMgr      ip4_seq_mgr;    // gives a per [src::]dst sequence space // (TBD) make proto:src:dst
        SmfSequenceMgr      ip6_seq_mgr;    // gives a per [src::]dst sequence space // (TBD) make src:dst
        SmfDpdTable         hash_stash;     // used for source and gateway HAV application 
        
        ProtoTimer          prune_timer;     // to timeout stale flows
        unsigned int        update_age_max;  // max staleness allowed for flows
        unsigned int        current_update_time;
        
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
