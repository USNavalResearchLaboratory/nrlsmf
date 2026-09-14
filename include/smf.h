#ifndef _SMF
#define _SMF
#include "protoDefs.h"
#include "smfHash.h"
#include "smfDpd.h"
#include "smfQueue.h"    // for optional per-flow interface queues
#include "protoNet.h"
#include "protoTimer.h"
#include "protoPktIP.h"  // (TBD) use something different for OPNET and/or ns-2?
#include "protoPktETH.h"
#include "protoQueue.h"
#include "smfVrf.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
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

        // This class supports lookup of interface index from interface address information
        // The address information includes a local address and _optional_ remote address
        // to help identify interfaces associated with tunnel address information
        // (i.e., local/remote endpoint addresses)
        class InterfaceInfo : public ProtoTree::Item
        {
            public:
                InterfaceInfo(unsigned int          ifaceIndex,
                              const ProtoAddress&   localAddr,
                              const ProtoAddress*   remoteAddr = NULL,
                              bool                  fromConfig = false,
                              bool                  fromKernel = false)
                  : iface_index(ifaceIndex), local_addr(localAddr),
                    from_config(fromConfig), from_kernel(fromKernel), is_learned(false)
                {
                    // address_info_key is tuple of [remoteAddr]localAddr  (i.e. remoteAddr is optional)
                    unsigned int len = 0;
                    if (NULL != remoteAddr)
                    {
                        // remoteAddr is first in key for FindTunnelInfo() for mGRE to work
                        remote_addr = *remoteAddr;
                        len = remoteAddr->GetLength();
                        memcpy(address_info_key, remoteAddr->GetRawHostAddress(), len);
                    }
                    local_mask_len = 8*localAddr.GetLength();
                    memcpy(address_info_key+len, localAddr.GetRawHostAddress(), localAddr.GetLength());
                    len += localAddr.GetLength();
                    address_info_size = 8*len;
                }
                ~InterfaceInfo() {}
                void SetIndex(unsigned int index) {iface_index = index;}
                void SetMaskLength(unsigned int maskLen) {local_mask_len = maskLen;}
                void MarkConfig() {from_config = true;}
                void MarkKernel() {from_kernel = true;}
                unsigned int GetIndex() const {return iface_index;}
                unsigned int GetMaskLength() const {return local_mask_len;}
                const ProtoAddress& GetLocalAddress() const {return local_addr;}
                const ProtoAddress& GetRemoteAddress() const {return remote_addr;}
                void SetMapped(bool state) {from_config = state;}
                bool IsMapped() const {return from_config;}
                void SetLearned(bool state) {is_learned = state;}
                bool IsLearned() const {return is_learned;}
                bool FromConfig() const {return from_config;}
                bool FromKernel() const {return from_kernel;}

            private:
               // Required ProtoTreeItem overrides
                const char* GetKey() const {return address_info_key;}
                unsigned int GetKeysize() const {return address_info_size;}

                unsigned int iface_index;
                ProtoAddress local_addr;
                unsigned int local_mask_len;
                ProtoAddress remote_addr;             // invalid for non-tunnels, INADDR_ANY for mGRE tunnels
                bool         from_config;             // true if added with the map command
                bool         from_kernel;             // true if learned from GRE device attributes
                bool         is_learned;              // true for kernel-neigh learned remotes (map ...,dynamic)
                char         address_info_key[16+16]; // big enough for IPv6
                unsigned int address_info_size;       // in bits
        };  // end class Smf::InterfaceInfo

        class InterfaceInfoTable : public ProtoTreeTemplate<InterfaceInfo>
        {
            public:
                InterfaceInfo* InsertIndex(unsigned int         ifaceIndex,
                                           const ProtoAddress&  localAddr,
                                           const ProtoAddress*  remoteAddr = NULL,
                                           bool                 fromConfig = false,
                                           bool                 fromKernel = false)
                {
                    InterfaceInfo* info = (NULL == remoteAddr) ? FindInfo(localAddr) : FindInfo(localAddr, *remoteAddr);
                    if (NULL == info)
                    {
                        info = new InterfaceInfo(ifaceIndex, localAddr, remoteAddr, fromConfig, fromKernel);
                        if (NULL == info)
                        {
                            PLOG(PL_ERROR, "InterfaceInfoTable::InsertIndex() new InterfaceInfo error: %s\n", GetErrorString());
                        }
                        else if (!Insert(*info))
                        {
                            PLOG(PL_ERROR, "InterfaceInfoTable::InsertIndex() InsertInfo() error: %s\n", GetErrorString());
                            delete info;
                            return NULL;
                        }
                    }
                    else
                    {
                        info->SetIndex(ifaceIndex);
                        if (fromConfig) info->MarkConfig();
                        if (fromKernel) info->MarkKernel();
                    }
                    return info;
                }
                InterfaceInfo* FindInfo(const ProtoAddress& addr) const
                    {return Find(addr.GetRawHostAddress(), 8*addr.GetLength());}
                InterfaceInfo* FindInfo(const ProtoAddress& localAddr, const ProtoAddress& remoteAddr) const
                {
                    // Must match InterfaceInfo key order: [remoteAddr][localAddr]
                    char addrInfo[16 + 16];
                    unsigned int len = remoteAddr.GetLength();
                    memcpy(addrInfo, remoteAddr.GetRawHostAddress(), len);
                    memcpy(addrInfo + len, localAddr.GetRawHostAddress(), localAddr.GetLength());
                    return Find(addrInfo, 8*(len + localAddr.GetLength()));
                }
                unsigned int GetIndex(const ProtoAddress& addr) const
                {
                    InterfaceInfo* info = FindInfo(addr);
                    return (NULL != info) ? info->GetIndex() : 0;
                }
                unsigned int GetIndex(const ProtoAddress& localAddr, const ProtoAddress& remoteAddr) const
                {

                    InterfaceInfo* info = FindInfo(localAddr, remoteAddr);
                    return (NULL != info) ? info->GetIndex() : 0;
                }
                void RemoveIndex(unsigned int ifaceIndex)
                {
                    InterfaceInfoTable::Iterator iterator(*this);
                    InterfaceInfo* info;
                    while (NULL != (info = iterator.GetNextItem()))
                    {
                        if (info->GetIndex() == ifaceIndex)
                        {
                            Remove(*info);
                            delete info;
                        }
                    }
                }
                void RemoveAddress(const ProtoAddress& localAddr, const ProtoAddress* remoteAddr = NULL)
                {
                    // addrInfoKey is tuple of [remoteAddr]localAddr  (i.e. remoteAddr is optional)
                    char addrInfoKey[16 + 16];
                    unsigned int len = 0;
                    if (NULL != remoteAddr)
                    {
                        // remoteAddr is first in key for FindTunnelInfo() for mGRE to work
                        len = remoteAddr->GetLength();
                        memcpy(addrInfoKey, remoteAddr->GetRawHostAddress(), len);
                    }
                    memcpy(addrInfoKey+len, localAddr.GetRawHostAddress(), localAddr.GetLength());
                    len += localAddr.GetLength();
                    InterfaceInfo* info = Find(addrInfoKey, 8*len);
                    if (NULL != info)
                    {
                        Remove(*info);
                        delete info;
                    }
                }
                void RemoveList(ProtoAddressList& addrList)
                {
                    ProtoAddressList::Iterator iterator(addrList);
                    ProtoAddress addr;
                    while (iterator.GetNextAddress(addr))
                        RemoveAddress(addr);
                }

                class Iterator : public ProtoTreeTemplate<InterfaceInfo>::Iterator
                {
                    public:
                        Iterator(InterfaceInfoTable& ifaceTable) : ProtoTreeTemplate<InterfaceInfo>::Iterator(ifaceTable) {}
                        //InterfaceInfo* GetNextItem()
                        //    {return ProtoTreeTemplate<Interface>::Iterator::GetNextItem();}
                };  // end class Smf::InterfaceInfoTable::Iterator

        };  // end class Smf::InterfaceInfoTable

        // Manage/Query a list of the node's local MAC/IP addresses
        // (Also cache interface index so we can look that up by address)
        bool AddOwnAddress(const ProtoAddress& addr, unsigned int ifaceIndex)
        {
            // This will update index/mask if address already in table
            InterfaceInfo* info = iface_info_table.InsertIndex(ifaceIndex, addr);
            if (NULL == info)
            {
                PLOG(PL_ERROR, "Smf::AddOwnAddress() error inserting index into iface_info_table\n");
                return false;
            }
            if (ProtoAddress::ETH != addr.GetType())
            {
                unsigned int maskLen = ProtoNet::GetInterfaceAddressMask(ifaceIndex, addr);
                if (0 != maskLen) info->SetMaskLength(maskLen);
            }
            return true;
        }
        void RemoveOwnAddress(const ProtoAddress& addr)
            {iface_info_table.RemoveAddress(addr);}
        bool IsOwnAddress(const ProtoAddress& addr) const
            {return (0 != iface_info_table.GetIndex(addr));}
        unsigned int GetInterfaceIndex(const ProtoAddress& addr) const
            {return iface_info_table.GetIndex(addr);}

        bool AddTunnelInfo(unsigned int ifaceIndex, const ProtoAddress& localAddr, const ProtoAddress& remoteAddr,
                           bool mapped = true, bool learned = false)
        {
            TRACE("mapping tunnel addrs local:%s", localAddr.GetHostString());
            TRACE(" remote:%s\n", remoteAddr.GetHostString());
            bool fromKernel = !mapped && !learned;
            InterfaceInfo* ifaceInfo = iface_info_table.InsertIndex(ifaceIndex, localAddr, &remoteAddr,
                                                                    mapped, fromKernel);
            if (NULL == ifaceInfo)
            {
                PLOG(PL_ERROR, "Smf::AddTunnelInfo() iface_info_table.InsertIndex() failed\n");
                return false;
            }
            if (mapped) ifaceInfo->SetMapped(true);
            if (learned) ifaceInfo->SetLearned(true);
            unsigned int maskLen = ProtoNet::GetInterfaceAddressMask(ifaceIndex, localAddr);
            ifaceInfo->SetMaskLength(maskLen);
            return true;
        }
        void RemoveTunnelInfo(const ProtoAddress& localAddr, const ProtoAddress& remoteAddr)
            {ClearTunnelSource(localAddr, remoteAddr, true, true);}
        void ClearTunnelSource(const ProtoAddress& localAddr, const ProtoAddress& remoteAddr,
                               bool mapped, bool learned)
        {
            InterfaceInfo* info = iface_info_table.FindInfo(localAddr, remoteAddr);
            if (NULL == info)
                return;
            if (mapped) info->SetMapped(false);
            if (learned) info->SetLearned(false);
            if (!info->IsMapped() && !info->IsLearned())
                iface_info_table.RemoveAddress(localAddr, &remoteAddr);
        }

        unsigned int GetTunnelIndex(const ProtoAddress& localAddr, const ProtoAddress& remoteAddr) const
        {
            // For point-to-point GRE tunnel interfaces where endpoint information is explicit
            return iface_info_table.GetIndex(localAddr, remoteAddr);
        }
        // Match an EM_ACK upstream addr to *this* node's tunnel local or
        // overlay IP. Do not use GetInterfaceIndex() here: map remotes are
        // also in that table, so a peer underlay would match every spoke.
        unsigned int FindInterfaceByLocalEndpoint(const ProtoAddress& addr);
        unsigned int FindTunnelIndex(const ProtoAddress& localAddr, const ProtoAddress& remoteAddr)
        {
            // For point-to-multipoint (mGRE) tunnel interfaces.
            // Finds interface index for tunnel that is best match to given local/remote endpoint addrs
            // Note "remote" should be an exact match (generally INADDDR_ANY for mGRE) and the "local"
            // should be within the subnet mask of a local tunnel overlay address if not an exact match
            // to tunnel endpoint information.
            // TBD - a bona fide route table lookup should be better but needs to be efficient
            //       for per-packet processing (e.g., route caching approach)
            char key[32];  // big enough for remote/local IPv6 addr
            unsigned int keysize = remoteAddr.GetLength();
            memcpy(key, remoteAddr.GetRawHostAddress(), keysize);
            memcpy(key + keysize, localAddr.GetRawHostAddress(), localAddr.GetLength());
            keysize = 8*(keysize + localAddr.GetLength());
            TRACE("   finding closest match ...\n");
            InterfaceInfo* ifaceInfo = iface_info_table.FindClosestMatch(key, keysize);
            TRACE("   info: %p\n", ifaceInfo);
            if (NULL != ifaceInfo)
            {
                TRACE("    local:%s ", ifaceInfo->GetLocalAddress().GetHostString());
                TRACE("    remote:%s\n", ifaceInfo->GetRemoteAddress().GetHostString());
            }
            if ((NULL != ifaceInfo) &&
                remoteAddr.HostIsEqual(ifaceInfo->GetRemoteAddress()) &&
                localAddr.PrefixIsEqual(ifaceInfo->GetLocalAddress(), ifaceInfo->GetMaskLength()))
            {
               return ifaceInfo->GetIndex();
            }
            else
            {
               return 0;
            }
        }

        InterfaceInfoTable& AccessInterfaceInfoTable()
            {return iface_info_table;}

        // Mapped remotes used as GRE inject destinations for overlay
        // multicast: unicast peers and (optionally) an underlay multicast
        // group. Skip 0.0.0.0 (kernel wildcard, not a send dest).
        void GetTunnelUnicastRemotes(unsigned int ifaceIndex, ProtoAddressList& dests)
        {
            InterfaceInfoTable::Iterator iterator(iface_info_table);
            InterfaceInfo* info;
            while (NULL != (info = iterator.GetNextItem()))
            {
                if (info->GetIndex() != ifaceIndex)
                    continue;
                const ProtoAddress& remote = info->GetRemoteAddress();
                if (remote.IsValid() && (remote.IsUnicast() || remote.IsMulticast()))
                    dests.Insert(remote);
            }
        }
        // First mapped underlay multicast remote (multicast-underlay mGRE).
        bool GetTunnelMulticastRemote(unsigned int ifaceIndex, ProtoAddress& dest)
        {
            InterfaceInfoTable::Iterator iterator(iface_info_table);
            InterfaceInfo* info;
            while (NULL != (info = iterator.GetNextItem()))
            {
                if (info->GetIndex() != ifaceIndex)
                    continue;
                const ProtoAddress& remote = info->GetRemoteAddress();
                if (remote.IsValid() && remote.IsMulticast())
                {
                    dest = remote;
                    return true;
                }
            }
            return false;
        }
        // True if addr is a unicast GRE peer on this iface (map or learned).
        bool FindTunnelUnicastPeer(unsigned int ifaceIndex, const ProtoAddress& addr,
                                   ProtoAddress& dest);
        bool FindOverlayForUnderlay(unsigned int ifaceIndex, const ProtoAddress& underlay,
                                    ProtoAddress& overlay);

        unsigned int FindMappedIndexForRemote(const ProtoAddress& remote)
        {
            if (!remote.IsValid())
                return 0;
            InterfaceInfoTable::Iterator iterator(iface_info_table);
            InterfaceInfo* info;
            while (NULL != (info = iterator.GetNextItem()))
            {
                if (info->IsMapped() &&
                    info->GetRemoteAddress().IsValid() &&
                    info->GetRemoteAddress().HostIsEqual(remote))
                    return info->GetIndex();
            }
            return 0;
        }

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

        SmfVRFList* GetVRFs()
          {return &vrf_list;}

        SmfVRFPolicies* GetVRFPolicies()
          {return &vrf_policies;}

        // We derive from "ProtoQueue::Item here so we can keep multiple lists of
        // "Interfaces" indexed by their "ifIndex", "ifName", etc
        class Interface : public ProtoQueue::Item
#ifdef ELASTIC_MCAST
                , public ElasticMulticastController::Interface
#endif // ELASTIC_MCAST
        {
            public:
                Interface(unsigned int ifIndex, const char *ifName);
                ~Interface();

                bool Init(bool useWindow);// = false);  // (TBD) add parameters for DPD window, etc
                void Destroy();

                unsigned int GetIndex() const
                    {return if_index;}
                void SetIndex(unsigned int ifIndex)
                    {if_index = ifIndex;}

                // Pending (not yet in the kernel) stubs use 0 or a high
                // synthetic index so more than one name can be queued.
                bool IsStub() const
                    {return (0 == if_index) || (if_index >= 0x80000000u);}

                const char * GetNameStr()
                    {return if_name.c_str();}

                // These is the hardware MAC address (if GRE this will also be GRE tunnel local addr)
                void SetInterfaceAddress(const ProtoAddress& ifAddr)
                    {if_addr = ifAddr;}
                const ProtoAddress& GetInterfaceAddress() const
                    {return if_addr;}

                void SetTunnelLocalAddress(const ProtoAddress& addr)
                    {tunnel_local_addr = addr;}
                const ProtoAddress& GetTunnelLocalAddress() const
                    {return tunnel_local_addr;}
                void SetTunnelRemoteAddress(const ProtoAddress& addr)
                    {tunnel_remote_addr = addr;}
                const ProtoAddress& GetTunnelRemoteAddress() const
                    {return tunnel_remote_addr;}
                void SetTunnelLearnDynamic(bool state)
                    {tunnel_learn_dynamic = state;}
                bool GetTunnelLearnDynamic() const
                    {return tunnel_learn_dynamic;}
                ProtoAddressList& AccessLearnedOverlays()
                    {return learned_overlays;}
                void ClearLearnedOverlays();
                bool IsGRE() const
                    {return tunnel_local_addr.IsValid();}

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

                // Set to "true" to send igmp joins for the groups we want to receive on this interface
                // This would typically be a layered interface as well.
                void SetIgmpProxy(bool state)
                    {is_igmp_proxy = state;}
                bool IsIgmpProxy() const
                    {return is_igmp_proxy;}

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

                // This for the simple IPIP encapsulation capability
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
                // Elastic routing state variables
                void SetElasticMulticast(bool state)
                    {elastic_mcast = state;}
                bool GetElasticMulticast() const
                    {return elastic_mcast;}
                void SetManaged(bool state)
                    {managed = state; if (!managed) managed_memberships.Destroy();}
                bool IsManaged() const
                    {return managed;}
                void AddManagedMembership(const ProtoAddress& grpAddr)
                    {managed_memberships.Insert(grpAddr);}
                void RemoveManagedMembership(const ProtoAddress& grpAddr)
                    {managed_memberships.Remove(grpAddr);}
                bool HasActiveMembership(const ProtoAddress& grpAddr) const
                    {return managed_memberships.Contains(grpAddr);}
                ProtoAddressList& AccessManagedMemberships()
                    {return managed_memberships;}
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

                // bool isVRF(const SmfVRF* new_vrf) const;  // check whether the interface belongs to this vrf
                // void SetVRF(SmfVRF* new_vrf)
                //     {vrf = new_vrf;}

                // Used for InterfaceList required ProtoIndexedQueue overrides
                const char* GetKey() const
                    {return ((const char*)&if_index);}
                unsigned int GetKeysize() const
                    {return (8*sizeof(unsigned int));}

            private:
                unsigned int                          if_index;
                ProtoAddress                          if_addr;
                ProtoAddressList                      addr_list;     // list of IP addresses of the interface
                ProtoAddress                          tunnel_local_addr;  // valid when Smf::Interface is GRE endpoint
                ProtoAddress                          tunnel_remote_addr;
                bool                                  tunnel_learn_dynamic; // map <iface>,<local>,dynamic
                ProtoAddressList                      learned_overlays;  // overlay neigh dst -> underlay (userData)
                ProtoAddress                          ip_addr;       // used as source addr for nrlsmf IPIP encapsulation
                std::string                           if_name;
                bool                                  resequence;
                bool                                  is_tunnel;     // _not_ GRE tunnel, but indicates nrlsmf IPIP encapsulation
                bool                                  is_layered;
                bool                                  is_igmp_proxy;
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
                double                                repair_window;      // in secs (max retransmit packet age)
                UINT16                                local_adv_id;
                bool                                  elastic_mcast;
                bool                                  managed;
                ProtoAddressList                      managed_memberships; // List of groups with active receivers
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

        // This interface list is indexed by an integer interface index value
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

        Interface *AddInterface(unsigned int ifIndex, const char *ifName);
        Interface* GetInterface(unsigned int ifIndex)
            {return iface_list.FindInterface(ifIndex);}
        Interface* FindInterfaceByName(const char* ifName);
        bool RekeyInterface(Interface& iface, unsigned int newIndex);
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
        bool withFRR() const
            {return with_FRR;}
        void SetWithFRR(bool state)
            {with_FRR = state;}
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

        InterfaceInfoTable  iface_info_table;  // list of local interface addresses and indices

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
        SmfVRFList          vrf_list;
        SmfVRFPolicies      vrf_policies;
        bool                with_FRR;             // running along side FRR

};  // end class Smf
#endif // _SMF
