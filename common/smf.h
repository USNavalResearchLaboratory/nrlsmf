#ifndef _SMF
#define _SMF

#include "smfDupTree.h"
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
        
        // Manage/Query a list of the node's local MAC/IP addresses
        bool AddOwnAddress(const ProtoAddress& addr, int ifIndex = -1)
            {return local_addr_list.Insert(addr, (void*)ifIndex);}
        bool IsOwnAddress(const ProtoAddress& addr) const
            {return local_addr_list.Contains(addr);}
        
        int GetInterfaceIndex(const ProtoAddress& addr) const
        {
            int ifIndex = ((int)local_addr_list.GetUserData(addr));
            return ((0 == ifIndex) ? 
                        (local_addr_list.Contains(addr) ? 0 : -1) : 
                        ifIndex);
        }
        
        void RemoveOwnAddress(const ProtoAddress& addr)
            {local_addr_list.Remove(addr);}
        ProtoAddress::List& AccessOwnAddressList() 
            {return local_addr_list;}
        
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
        
        class Interface
        {
            public:
                Interface(int ifIndex);
                ~Interface();
                
                enum {INDEX_MAX = 15};  // (TBD) allow run time override?
                
                bool Init();  // (TBD) add parameters for DPD window, etc
                
                int GetIndex() const
                    {return if_index;}
                
                bool IsDuplicatePkt(unsigned int        currentTime,
                                    const char*         taggerId,  
                                    unsigned int        taggerIdBytes,  // in bytes
                                    const ProtoAddress* srcAddr,
                                    const ProtoAddress* dstAddr,
                                    UINT32              pktID,
                                    unsigned int        pktIDSize);     // in bits 
                
                bool IsDuplicateIPSecPkt(unsigned int        currentTime,
                                         const ProtoAddress& srcAddr,
                                         const ProtoAddress& dstAddr,
                                         UINT32              pktSPI,  // security parameter index
                                         UINT32              pktID);  // IPSec has 32-bit pktID
                
                void PruneDuplicateTree(unsigned int currentTime, unsigned int ageMax)
                    {return duplicate_tree.Prune(currentTime, ageMax);}
                
                unsigned int GetFlowCount() const
                    {return duplicate_tree.GetCount();}

                // Set to "true" to resequence packets inbound on this iface                
                void SetResequence(bool state)
                    {resequence = state;}
                bool GetResequence() const
                    {return resequence;}
                
                class Associate
                {
                    public:
                        Associate(Interface& iface);
                        ~Associate();
                        
                        Interface& GetInterface() const
                            {return interface;}
                        
                        int GetInterfaceIndex() const
                            {return interface.GetIndex();}
                        
                        void SetRelayType(RelayType relayType)
                            {relay_type = relayType;}
                        RelayType GetRelayType() const
                            {return relay_type;}
                        
                        Associate* GetNext() const
                            {return next;}
                        void Append(Associate* assoc)
                            {next = assoc;}
                        
                    private:
                        Interface& interface;
                        RelayType  relay_type;
                        Associate* next;
                };  // end class Smf::Interface::Associate
                
                bool HasAssociates() const
                    {return (NULL != assoc_top);}
                bool AddAssociate(Interface& iface, RelayType relayType);
                Associate* FindAssociate(int ifIndex) const;
                
                class AssociateIterator
                {
                    public:
                        AssociateIterator(const Interface& iface);
                        ~AssociateIterator();

                        Associate* GetNextAssociate()
                        {
                            Associate* assoc = assoc_next;
                            assoc_next = assoc_next ? assoc_next->GetNext() : NULL;
                            return assoc;
                        }
                        void Reset()
                            {assoc_next = interface.assoc_top;}
                        
                    private:
                        const Interface& interface;
                        Associate*       assoc_next;
                };  // end class Smf::Interface::AssociateIterator
                friend class AssociateIterator;
                
                Interface* GetNext() const
                    {return next;}
                void Append(Interface* iface)
                    {next = iface;}
                    
            private:
                int                 if_index;
                bool                resequence;
                SmfDuplicateTree    duplicate_tree;
                Associate*          assoc_top;  // top of Associate linked list
                
                Interface*          next;
                    
        };  // end class Smf::Interface
        
        Interface* AddInterface(int ifIndex);
        Interface* GetInterface(int ifIndex)
        {
            ASSERT((ifIndex >= 0) && (ifIndex <= Interface::INDEX_MAX));
            return iface_array[ifIndex];
        }
        
        // Return value indicates how many outbound (dst) ifaces to forward over
        // Notes:
        // 1) This decrements the ttl/hopLimit of the "ipPkt"
        // 2)
        int ProcessPacket(ProtoPktIP& ipPkt, const ProtoAddress& srcMac, int srcIfIndex, 
                          int dstIfArray[], unsigned int dstIfArraySize);
        
        void SetRelayEnabled(bool state)
            {relay_enabled = state;}
        bool GetRelayEnabled() const
            {return relay_enabled;}
        void SetRelaySelected(bool state)
            {relay_selected = state;}
        bool GetRelaySelected() const
            {return relay_selected;}
        
        enum DpdType
        {
            DPD_NONE,   // no DPD identifier available
            DPD_SMF,    // use SMF DPD option header
            DPD_IPSEC   // use IPSEC header for DPD
        };
        static DpdType GetIPv6PktID(ProtoPktIPv6&   ip6Pkt,                // input
                                    UINT32&         pktId,                 // output
                                    unsigned int&   pktIdSize,             // output, in bits
                                    UINT32*         pktSPI = NULL,
                                    char*           taggerId = NULL,       // input/output
                                    unsigned int*   taggerIdBytes = NULL); // input/output, in bytes
        
        static bool InsertOptionDPD(ProtoPktIPv6& ipv6Pkt, UINT16 pktID);
        
        enum {SELECTOR_LIST_LEN_MAX = (6*100)};
        bool IsSelector(const ProtoAddress& srcMac) const;
        bool IsNeighbor(const ProtoAddress& srcMac) const;
        
        void SetSelectorList(const char* selectorMacAddrs, unsigned int numBytes);
        void SetNeighborList(const char* neighborMacAddrs, unsigned int numBytes);
        
        static const unsigned int DEFAULT_AGE_MAX; // (in seconds)
        static const unsigned int PRUNE_INTERVAL;  // (in seconds)
        
    private:
        // Timeout handlers
        bool OnPruneTimeout(ProtoTimer& theTimer);
        
        ProtoTimerMgr&      timer_mgr;
        
        ProtoAddress::List  local_addr_list;  // list of local interface addresses
        
        Interface*          iface_array[Interface::INDEX_MAX + 1];
        Interface*          iface_list_top;
        
        bool                relay_enabled;
        bool                relay_selected;
        
        SmfSequenceMgr      ip4_seq_mgr;    // gives a per [src::]dst sequence space
        SmfSequenceMgr      ip6_seq_mgr;    // gives a per [src::]dst sequence space
        //UINT16              ip4_seq_local; // (TBD) keep per destination sequences
        //UINT16              ip6_seq_local; // (TBD) keep per destination sequences
        
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
