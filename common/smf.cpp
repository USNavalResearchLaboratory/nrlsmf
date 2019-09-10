#include "smf.h"

const unsigned int Smf::DEFAULT_AGE_MAX = 10;  // 10 seconds 
const unsigned int Smf::PRUNE_INTERVAL = 5;  // 5 seconds 

Smf::Interface::Interface(int ifIndex)
 : if_index(ifIndex), resequence(false), assoc_top(NULL), 
   next(NULL)
{
}

Smf::Interface::~Interface()
{
    duplicate_tree.Destroy();
    Associate* nextAssoc = assoc_top;
    while (NULL != nextAssoc)
    {
        Associate* assoc = nextAssoc;
        nextAssoc = nextAssoc->GetNext();
        delete assoc;
    }
    assoc_top = NULL;
}

bool Smf::Interface::Init()
{
    if (!duplicate_tree.Init(1024, 1024))
    {
        DMSG(0, "Smf::Interface::Init() error initializing duplicate table: %s\n", GetErrorString());
        return false;
    }
}  // end Smf::Interface::Init()

bool Smf::Interface::AddAssociate(Interface& iface, RelayType relayType)
{
    // (TBD) Should we verify that there isn't already an "Associate"
    //       with for the given "iface"
    Associate* assoc = new Associate(iface);
    if (NULL == assoc)
    {
        DMSG(0, "Smf::Interface::AddAssociate() new Associate error: %s\n", GetErrorString());
        return false;
    }
    assoc->SetRelayType(relayType);
    assoc->Append(assoc_top);
    assoc_top = assoc;
    return true;
}  // end Smf::Interface::AddAssociate()

Smf::Interface::Associate* Smf::Interface::FindAssociate(int ifIndex) const
{
    AssociateIterator iterator(*this);
    Associate* nextAssoc; 
    
    while (NULL != (nextAssoc = iterator.GetNextAssociate()))
    {
        if (ifIndex == nextAssoc->GetInterfaceIndex())
            return nextAssoc;
    }
    return NULL;
}  // end Smf::Interface::FindAssociate()


bool Smf::Interface::IsDuplicatePkt(unsigned int        currentTime,
                                    const char*         taggerId,  
                                    unsigned int        taggerIdBytes,  // in bytes
                                    const ProtoAddress* srcAddr,
                                    const ProtoAddress* dstAddr,
                                    UINT32              pktId,
                                    unsigned int        pktIdSize)      // in bits 
{
    char key[48];  // IPv6 taggerId:src:dst worst case
    unsigned int keyBytes = 0;
    if (NULL != taggerId)
    {
        memcpy(key+keyBytes, taggerId, taggerIdBytes);
        keyBytes += taggerIdBytes;
    }
    if (NULL != srcAddr)
    {
        keyBytes = srcAddr->GetLength();
        memcpy(key, srcAddr->GetRawHostAddress(), keyBytes);
    }
    if (NULL != dstAddr)
    {
        unsigned int dstLen = dstAddr->GetLength();
        memcpy(key+keyBytes, dstAddr->GetRawHostAddress(), dstLen);
        keyBytes += dstLen;
    }
    return (duplicate_tree.IsDuplicate(currentTime, pktId, pktIdSize, key, keyBytes << 3));
}  // end Smf::Interface::IsDuplicatePkt()

// IPSec duplicate packet detection
bool Smf::Interface::IsDuplicateIPSecPkt(unsigned int        currentTime,
                                         const ProtoAddress& srcAddr,
                                         const ProtoAddress& dstAddr,
                                         UINT32              pktSPI,  // security parameter index
                                         UINT32              pktId)   // IPSec has 32-bit pktId
{
    char key[36];  // IPv6 src:dst:spi
    unsigned int keyBytes = 0;
    keyBytes = srcAddr.GetLength();
    memcpy(key, srcAddr.GetRawHostAddress(), keyBytes);
    unsigned int dstLen = dstAddr.GetLength();
    memcpy(key+keyBytes, dstAddr.GetRawHostAddress(), dstLen);
    keyBytes += dstLen;
    pktSPI = htonl(pktSPI);
    memcpy(key+keyBytes, &pktSPI, 4);
    keyBytes += 4;
    return (duplicate_tree.IsDuplicate(currentTime, pktId, 32, key, keyBytes << 3));
}  // end Smf::Interface::IsDuplicateIPSecPkt()




Smf::Interface::AssociateIterator::AssociateIterator(const Interface& iface)
 : interface(iface), assoc_next(iface.assoc_top)
{
}

Smf::Interface::AssociateIterator::~AssociateIterator()
{
}

Smf::Interface::Associate::Associate(Smf::Interface& iface)
  : interface(iface), relay_type(CF), next(NULL)
{
}

Smf::Interface::Associate::~Associate()
{
}


Smf::Smf(ProtoTimerMgr& timerMgr)
 : timer_mgr(timerMgr), 
   iface_list_top(NULL), relay_enabled(false), relay_selected(false),
   update_age_max(DEFAULT_AGE_MAX), current_update_time(0),
   selector_list_len(0), neighbor_list_len(0),
   recv_count(0), mrcv_count(0), dups_count(0), asym_count(0), fwd_count(0) 
{
    prune_timer.SetInterval((double)PRUNE_INTERVAL);
    prune_timer.SetRepeat(-1);
    prune_timer.SetListener(this, &Smf::OnPruneTimeout);
}

Smf::~Smf()
{
    if (prune_timer.IsActive())
        prune_timer.Deactivate();
    
    Interface* nextIface = iface_list_top;
    while (NULL != nextIface)
    {
        Interface* iface = nextIface;
        nextIface = iface->GetNext();
        delete iface;
    }
    iface_list_top = NULL;
    memset(iface_array, 0, sizeof(Interface*) * (Interface::INDEX_MAX+1));
}

bool Smf::Init()
{
    if (!ip4_seq_mgr.Init(16))
    {
        DMSG(0, "Smf::Init() error: IPv4 sequence mgr init failure\n");
        return false;
    }
    if (!ip6_seq_mgr.Init(16))
    {
        DMSG(0, "Smf::Init() error: IPv6 sequence mgr init failure\n");
        return false;
    }
    timer_mgr.ActivateTimer(prune_timer);
}  // end Smf::Init()


Smf::Interface* Smf::AddInterface(int ifIndex)
{
    if ((ifIndex < 0 ) || (ifIndex > Interface::INDEX_MAX))
    {
        DMSG(0, "Smf::AddInterface() error: ifIndex(%d) exceeds allowed range\n", ifIndex);
        return NULL;
    }
    if (NULL == GetInterface(ifIndex))
    {
        Interface* iface = new Interface(ifIndex);
        if (NULL == iface)
        {
            DMSG(0, "Smf::AddInterface() new Smf::Interface error: %s\n", GetErrorString());
            return NULL;
        }
        if (!iface->Init())
        {
            DMSG(0, "Smf::AddInterface() Smf::Interface initialization error: %s\n", GetErrorString());
            delete iface;
            return NULL;
        }
        
        iface_array[ifIndex] = iface;
        iface->Append(iface_list_top);
        iface_list_top = iface;
        return iface;
    }
    else
    {
        return GetInterface(ifIndex);
    }
}  // end Smf::AddInterface()

Smf::DpdType Smf::GetIPv6PktID(ProtoPktIPv6&   ip6Pkt,          // input
                               UINT32&         pktId,           // output
                               unsigned int&   pktIdSize,       // output, in bits
                               UINT32*         pktSPI,          // output, IPSec packets only
                               char*           taggerId,        // input/output
                               unsigned int*   taggerIdBytes)   // input/output, in bytes
{
    
    
    ProtoPktIP::Protocol nextHeader = ip6Pkt.GetNextHeader();
    if (ProtoPktIP::IsExtension(nextHeader))//(ip6Pkt.HasExtendedHeader())
    {
        // Hey, it might have the hop-by-hop option header, let's iterate and see
        ProtoPktIPv6::Extension::Iterator extIterator(ip6Pkt);
        ProtoPktIPv6::Extension ext;
        while (extIterator.GetNextExtension(ext))
        {
            switch (ext.GetType())
            {
                case ProtoPktIP::HOPOPT:
                {
                    // OK, found hop-by-hop option header, now search for SMF-DPD option
                    ProtoPktIPv6::Option::Iterator optIterator(ext);
                    ProtoPktIPv6::Option opt;
                    while (optIterator.GetNextOption(opt))
                    {
                        if (ProtoPktIPv6::Option::SMF_DPD == opt.GetType())
                        {
                            ProtoPktDPD dpdOpt;
                            if (dpdOpt.InitFromBuffer(opt.AccessBuffer(), opt.GetLength()))
                            {
                                // 1) Get taggerId if wanted and available
                                if ((NULL != taggerId) && (NULL != taggerIdBytes))
                                {
                                    if (ProtoPktDPD::TID_NULL != dpdOpt.GetTaggerIdType())
                                    {
                                        unsigned int taggerIdLength = dpdOpt.GetTaggerIdLength();
                                        if (taggerIdLength <= *taggerIdBytes)
                                        {
                                            memcpy(taggerId, dpdOpt.GetTaggerId(), taggerIdLength);
                                            *taggerIdBytes = taggerIdLength;
                                        }
                                        else
                                        {
                                            DMSG(0, "Smf::GetIPv6PktID() error: SMF_DPD TaggerId field too large!\n");
                                            *taggerIdBytes = 0;
                                            return DPD_NONE;
                                        }
                                    }
                                    else if (NULL != taggerIdBytes)
                                    {
                                        *taggerIdBytes = 0;
                                    }
                                }
                                // 2) Get "pktId" and "pktIdSize"
                                switch (dpdOpt.GetPktIdLength())
                                {
                                    case 1:
                                    {
                                        UINT8 temp8;
                                        dpdOpt.GetPktId(temp8);
                                        pktId = (UINT32)temp8;
                                        pktIdSize = 8;
                                        break;
                                    }
                                    case 2:
                                    {
                                        UINT16 temp16;
                                        dpdOpt.GetPktId(temp16);
                                        pktId = (UINT32)temp16;
                                        pktIdSize = 16;
                                        break;
                                    }
                                    case 3:
                                    {
                                        memcpy(&pktId, dpdOpt.GetPktId(), 3);
                                        pktId >>= 8;
                                        pktId = ntohl(pktId);
                                        pktIdSize = 24;
                                    }
                                    case 4:
                                    {
                                        dpdOpt.GetPktId(pktId);
                                        pktIdSize = 32;
                                        break;
                                    }
                                    default:
                                    {
                                        DMSG(0, "Smf::GetIPv6PktID() error: SMF_DPD PktId field too large!\n");
                                        return DPD_NONE;
                                    }
                                }
                            }
                            else
                            {
                                DMSG(0, "Smf::GetIPv6PktID() error: bad SMF_DPD header option\n");
                                return DPD_NONE;
                            }
                            return DPD_SMF;
                        }
                    }
                    break;
                }
                case ProtoPktIP::AUTH:
                {
                    ProtoPktAUTH ah;
                    if (ah.InitFromBuffer(ext.AccessBuffer(), ext.GetLength()))
                    {
                        if (NULL != pktSPI) *pktSPI = ah.GetSPI();
                        pktId = ah.GetSequence();
                        pktIdSize = 32;
                        if (NULL != taggerIdBytes) *taggerIdBytes = 0;
                        return DPD_IPSEC;
                    }
                    else
                    {
                        DMSG(0, "Smf::GetIPv6PktID() error: bad AUTH header!\n");
                        return DPD_NONE;
                    }
                    break;
                }
                default:
                    break;
            }  // end switch (ext.GetType())
        }  // end while (extIterator.GetNextExtension(ext))
        nextHeader = ext.GetNextHeader();  // header _after_ extension headers (might be ESP)
    }  // end if (ip6Pkt.HasExtendedHeader())
    if (ProtoPktIP::ESP == nextHeader)
    {
        ProtoPktESP esp;
        if (esp.InitFromBuffer(ip6Pkt.GetPayloadLength(), ip6Pkt.AccessPayload(), ip6Pkt.GetPayloadLength()))
        {
            if (NULL != pktSPI) *pktSPI = esp.GetSPI();
            pktId = esp.GetSequence();
            pktIdSize = 32;
            return DPD_IPSEC;
        }
        else
        {
            DMSG(0, "Smf::GetIPv6PktID() error: bad ESP header!\n");
        }
    }
    if (NULL != taggerIdBytes) *taggerIdBytes = 0; 
    return DPD_NONE;  // packet had no SMF-DPD or IPSEC header option
}  // end Smf::GetIPv6PktID()

bool Smf::InsertOptionDPD(ProtoPktIPv6& ipv6Pkt, UINT16 pktId)
{  
    // (TBD) Maintain sequence space on a per src/dst basis instead of a global one
    // 1) Does the packet already have a hop-by-hop options header?
    if (ipv6Pkt.HasExtendedHeader())
    {
        ProtoPktIPv6::Extension::Iterator iterator(ipv6Pkt);
        ProtoPktIPv6::Extension ext;
        // HOP-BY-HOP options MUST be first extension if present!
        iterator.GetNextExtension(ext);
        if (ProtoPktIP::HOPOPT == ext.GetType())
        {
            // 1) Copy extension w/ any current hop-by-hop options
            UINT32 buffer[64];
            ProtoPktIPv6::Extension ext2(ProtoPktIP::HOPOPT, buffer, 64*sizeof(UINT32), false);
            if (!ext2.Copy(ext))
            {
                DMSG(0, "Smf::InsertOptionDPD() error: incoming packet options header already too big\n");
                ASSERT(0);
                return false;
            }
            // 2) Add SMF-DPD option type to list of options
            ProtoPktDPD* dpdOpt = static_cast<ProtoPktDPD*>(ext2.AddOption(ProtoPktIPv6::Option::SMF_DPD));
            if (NULL == dpdOpt)
            {
                DMSG(0, "Smf::InsertOptionDPD() error: couldn't fit SMF-DPD option into extension?!\n");
                return false;
            }
            // TBD set "taggerId" if user has configured one
            if (!dpdOpt->SetTaggerId(ProtoPktDPD::TID_NULL, NULL, 0))
            {
                DMSG(0, "Smf::InsertOptionDPD() error: couldn't set TID_NULL taggerId?!\n");
                return false;
            }
            if (!dpdOpt->SetPktId(pktId))
            {
                DMSG(0, "Smf::InsertOptionDPD() error: couldn't fit sequence into option space?!\n");
                return false;
            }
            // 3) "Pack" and pad extended option header
            if (!ext2.Pack())
            {
                DMSG(0, "Smf::InsertOptionDPD() error: couldn't pack HOPOPT extension?!\n");
                return false;
            }
            // 4) Replay existing hop-by-hop option header with new one
            if (ipv6Pkt.ReplaceExtension(ext, ext2))
            {
                return true;
            }
            else
            {
                DMSG(0, "Smf::InsertOptionDPD() error: couldn't replace HOPOPT extension\n");
                return false;
            }
        }
    }
    // Insert new HOPOPT header extension w/ SMF_DPD option
    UINT32 buffer[64];  // plenty big to hold our new extension
    ProtoPktIPv6::Extension ext(ProtoPktIP::HOPOPT, buffer, 64*sizeof(UINT32), false);
    // Add SMF-DPD option (Use default "skip" unknown policy and immutable status)
    ProtoPktDPD* dpdOpt = static_cast<ProtoPktDPD*>(ext.AddOption(ProtoPktIPv6::Option::SMF_DPD));
    // TBD set "taggerId" if user has configured one
    if (!dpdOpt->SetTaggerId(ProtoPktDPD::TID_NULL, NULL, 0))
    {
        DMSG(0, "Smf::InsertOptionDPD() error: couldn't set TID_NULL taggerId?!\n");
        return false;
    }
    if (!dpdOpt->SetPktId(pktId))
    {
        DMSG(0, "Smf::InsertOptionDPD() error: couldn't fit sequence into option space?!\n");
        return false;
    }
    // "pack" and pad our newly-created option header
    if (!ext.Pack())
    {
        DMSG(0, "Smf::InsertOptionDPD() error: couldn't pack HOPOPT extension?!\n");
        return false;
    }
    // insert the new header extension into the IPv6 packet buffer
    if (!ipv6Pkt.PrependExtension(ext))
    {
        DMSG(0, "Smf::InsertOptionDPD() error: couldn't prepend packet w/ HOPOPT extension?!\n");
        return false;
    }
    return true;
}  // end Smf::InsertOptionDPD()

int Smf::ProcessPacket(ProtoPktIP& ipPkt,            // input/output - the packet (may be modified)
                       const ProtoAddress& srcMac,   // input - source MAC addr of packet
                       int srcIfIndex,               // input - index of interface on which packet arrived
                       int dstIfArray[],             // output - list of interface indices to which packet should be forwarded
                       unsigned int dstIfArraySize)  // input - size of "dstIfArray[]" passed in
{
    if (srcMac.IsValid() && IsOwnAddress(srcMac)) // don't forward outbound locally-generated packets captured
    {
        DMSG(8, "Smf::ProcessPacket() skipping locally-generated IP pkt\n");
        return 0;
    }
    
    if (!srcMac.IsValid())
    {
        DMSG(3, "Smf::ProcessPacket() warning: invalid srcMacAddr from ifIndex: %d!\n", srcIfIndex);
    }
    else
    {
        DMSG(3, "Smf::ProcessPacket() processing pkt from srcMac: %s recv'd on ifIndex: %d...\n", 
                 srcMac.GetHostString(), srcIfIndex);
    }
    
    Interface* srcIface = GetInterface(srcIfIndex);
    ASSERT(srcIface);
    
    recv_count++;  // increment total IP packets recvd stat count
    
    // 1) Get IP protocol version
    unsigned char version = ipPkt.GetVersion();

    // 2) Get IP packet dst and src addresses, packet ID (for DPD), 
    //    and ttl/hopLimit (and also decrement ttl/hopLimit for forwarding)
    char taggerId[16];
    unsigned int taggerIdLength = 16;
    ProtoAddress srcIp, dstIp;
    UINT32 pktSPI;
    UINT32 pktId;
    unsigned int pktIdSize;  // in bits
    UINT8 ttl;
    bool isIPSecPkt = false;
    switch (version)
    {
        case 4:
        {
            ProtoPktIPv4 ipv4Pkt(ipPkt);
            ipv4Pkt.GetDstAddr(dstIp);
            if (!dstIp.IsMulticast())      // only forward multicast dst
            {
                DMSG(8, "Smf::ProcessPacket() skipping non-multicast IPv4 pkt\n");
                return 0;
            }
            else if (dstIp.IsLinkLocal())  // don't forward if link-local dst
            {
                DMSG(8, "Smf::ProcessPacket() skipping link-local IPv4 pkt\n");
                return 0;
            }
            ipv4Pkt.GetSrcAddr(srcIp);
            if (IsOwnAddress(srcIp))       // don't forward locally-generated packets
            {
                DMSG(8, "Smf::ProcessPacket() skipping locally-generated IPv4 pkt\n");
                return 0;
            }
            else if (srcIp.IsLinkLocal())  // don't forward if link-local src
            {
                DMSG(8, "Smf::ProcessPacket() skipping link-local sourced IPv4 pkt\n");
                return 0;
            }
            // Is this an IPSec packet?
            // (TBD) Do we need to search a chain of headers for IPv4 packets
            //       (I.e., implement a GetIPv4PktID() method as we did for IPv6?)
            switch (ipv4Pkt.GetProtocol())
            {
                case ProtoPktIP::AUTH:
                {
                    TRACE("smf processing IPv4 AUTH packet ...\n");
                    ProtoPktAUTH ah;
                    if (ah.InitFromBuffer(ipv4Pkt.AccessPayload(), ipv4Pkt.GetPayloadLength()))
                    {
                        pktSPI = ah.GetSPI();
                        pktId = ah.GetSequence();
                        pktIdSize = 32;
                        TRACE("AUTH pkt: src>%s ", srcIp.GetHostString());
                        TRACE("dst>%s spi>%08x seq>%lu\n", dstIp.GetHostString(), pktSPI, pktId);
                        isIPSecPkt = true;
                    }
                    else
                    {
                        TRACE("AUTH init failed!\n");
                    }
                    break;
                }
                case ProtoPktIP::ESP:
                {
                    TRACE("smf processing IPv4 ESP packet ...\n");
                    ProtoPktESP esp;
                    if (esp.InitFromBuffer(ipv4Pkt.GetPayloadLength(), ipv4Pkt.AccessPayload(), ipv4Pkt.GetPayloadLength()))
                    {
                        pktSPI = esp.GetSPI();
                        pktId = esp.GetSequence();
                        pktIdSize = 32;
                        TRACE("ESP pkt: src>%s ", srcIp.GetHostString());
                        TRACE("dst>%s spi>%08x seq>%lu\n", dstIp.GetHostString(), pktSPI, pktId);
                        isIPSecPkt = true;
                    }
                    else
                    {
                        TRACE("ESP init failed!\n");
                    }
                    break;
                }
                default:
                    // Fetch packet ID for DPD (optionally resequence)
                    if (srcIface->GetResequence())
                    {
                        pktId = ip4_seq_mgr.IncrementSequence(current_update_time, &dstIp, &srcIp);
                        ipv4Pkt.SetID(pktId, true);
                    }
                    else
                    {
                        pktId = ipv4Pkt.GetID();
                    }
                    pktIdSize = 16;
                    break;
            }
            ttl = ipv4Pkt.GetTTL();
            if (ttl > 1) ipv4Pkt.DecrementTTL();
            break;
        }
        case 6:
        {
            ProtoPktIPv6 ipv6Pkt(ipPkt);
            ipv6Pkt.GetDstAddr(dstIp); 
            if (!dstIp.IsMulticast())      // only forward multicast dst
            {
                DMSG(8, "Smf::ProcessPacket() skipping non-multicast IPv6 pkt\n");
                return 0;
            }
            else if (dstIp.IsLinkLocal())  // don't forward if link-local dst
            {
                DMSG(8, "Smf::ProcessPacket() skipping link-local IPv6 pkt\n");
                return 0;
            }
            ipv6Pkt.GetSrcAddr(srcIp);
            if (IsOwnAddress(srcIp))       // don't forward locally-generated packets
            {
                DMSG(8, "Smf::ProcessPacket() skipping locally-generated IPv6 pkt\n");
                return 0;
                
            }
            else if (srcIp.IsLinkLocal())  // don't forward if link-local src
            {
                DMSG(8, "Smf::ProcessPacket() skipping link-local sourced IPv6 pkt\n");
                return 0;
            }
            // (TBD) What about site local?
            // Fetch packet ID for DPD (optionally resequence packets not already DPD marked)
            
            switch (GetIPv6PktID(ipv6Pkt, pktId, pktIdSize, &pktSPI, taggerId, &taggerIdLength))
            {
                case DPD_NONE:
                    if (srcIface->GetResequence())
                    {
                        pktId = ip6_seq_mgr.IncrementSequence(current_update_time, &dstIp, &srcIp);
                        if (!InsertOptionDPD(ipv6Pkt, pktId))
                        {
                            DMSG(0, "Smf::ProcessPacket(): error marking IPv6 pkt for DPD ...\n");
                            return 0;
                        }
                        pktIdSize = 16; // we apply a 16-bit DPD sequence
                        // Update length of ProtoPktIP passed into this routine
                        ipPkt.SetLength(ipv6Pkt.GetLength());
                    }
                    else
                    {
                        DMSG(0, "Smf::ProcessPacket() warning: received IPv6 packet with no DPD option ...\n");
                        return 0;
                    }
                    break;
                case DPD_IPSEC:
                    isIPSecPkt = true;
                    break;
                case DPD_SMF:
                    break;
            }       
            ttl = ipv6Pkt.GetHopLimit();
            if (ttl > 1) ipv6Pkt.SetHopLimit(ttl - 1);
            break;
        }
        default:
            DMSG(0, "Smf::ProcessPacket() unknown IP protocol version\n");
            return 0;   
    }  // end switch (version)
    
    mrcv_count++;  // increment multicast received count
    
    // If we are "resequencing" packets recv'd on this srcIface (smf rpush|rmerge)
    // we need to mark the DPD table so we don't end up potentially sending the
    // resequenced version of the packet back out this srcIface on which it
    // arrived (due to hearing a MANET neighbor forwarding this packet)
    if (srcIface->GetResequence())
    {
        srcIface->IsDuplicatePkt(current_update_time, NULL, 0, &srcIp, &dstIp, pktId, pktIdSize);
    }
    
    // Iterate through potential outbound interfaces ("associate" interfaces)
    // for this "srcIfIndex" and populate "dstIfArray" with indices of
    // interfaces through which the packet should be forwarded.
    bool asym = false;
    int dstCount = 0;
    Interface::AssociateIterator iterator(*srcIface);
    Interface::Associate* assoc;
    while (NULL != (assoc = iterator.GetNextAssociate()))
    {
        RelayType relayType = assoc->GetRelayType();
        
        // Should we forward this packet on this associated "dstIface"?
        bool forward = false;
        bool updateDupTree = false;
        switch (relayType)
        {
            case CF:
                forward = relay_enabled;
                updateDupTree = forward;
                break;   
            case E_CDS:
                forward = (relay_enabled && relay_selected);
                updateDupTree = forward;
                break;
            case MPR_CDS:
                // (TBD) implement this one
                break;
            case S_MPR:
                forward = relay_enabled && IsSelector(srcMac);
                if (IsNeighbor(srcMac))
                {
                    updateDupTree = true;
                }
                else if (forward)
                {
                    DMSG(0,"nrlsmf: received packet from asymmetric neighbor while in s-mpr mode, but neighbor was selector?!\n");
                    asym = true;
                    updateDupTree = true;
                }
                else
                {
                    DMSG(6,"nrlsmf: received packet from asymmetric neighbor while in s-mpr mode, not marking duplicate table\n");
                    asym = true;
                    updateDupTree = false;
                }
                break;
        }  // end switch (relayType)
        
        if (asym) asym_count++;
        
        Interface& dstIface = assoc->GetInterface();
        
        if (updateDupTree)
        {
            bool isDuplicate;
            if (isIPSecPkt)
                isDuplicate = dstIface.IsDuplicateIPSecPkt(current_update_time, srcIp, dstIp, pktSPI, pktId);
            else  
                isDuplicate = dstIface.IsDuplicatePkt(current_update_time, taggerId, taggerIdLength, &srcIp, &dstIp, pktId, pktIdSize);
            if (isDuplicate)
            {
                DMSG(6, "nrlsmf: received duplicate IPv%d packet ...\n", version);
                dups_count++;
                forward = false;
            }
        }
        
        if (forward)
        {
            if ((ttl > 1) && (dstCount < dstIfArraySize))
                dstIfArray[dstCount] = dstIface.GetIndex();
            dstCount++;   
        }
    }
    if ((dstCount > 0) && (ttl <= 1))
    {
        DMSG(6, "nrlsmf: received ttl-expired packet ...\n");
        dstCount = 0;
    }
    if (dstCount > 0) fwd_count++;
    return dstCount;
    
}  // end Smf::ProcessPacket()

bool Smf::OnPruneTimeout(ProtoTimer& /*theTimer*/)
{
    ip4_seq_mgr.Prune(current_update_time, update_age_max);
    ip6_seq_mgr.Prune(current_update_time, update_age_max);
    
    // The SmfDuplicateTree::Prune() method removes
    // entries which are stale for more than "update_age_max"
    unsigned int flowCount = 0;
    Interface* nextIface = iface_list_top;
    while (NULL != nextIface)
    {
        nextIface->PruneDuplicateTree(current_update_time, update_age_max);
        flowCount += nextIface->GetFlowCount();
        nextIface = nextIface->GetNext();
    }
    DMSG(0, "flows:%u recv:%u mrcv:%u dups:%u asym:%u fwd:%u\n",
            flowCount, recv_count, mrcv_count, 
            dups_count, asym_count, fwd_count); 
    
    current_update_time += (unsigned int)prune_timer.GetInterval();
    
    return true;
}  // end Smf::OnPruneTimeout()

void Smf::SetSelectorList(const char* selectorMacAddrs, unsigned int numBytes)
{
    if (numBytes > SELECTOR_LIST_LEN_MAX)
    {
        DMSG(0, "Smf::SetSelectorList() error: excessive selector list size\n");
        numBytes = SELECTOR_LIST_LEN_MAX;
    }
    memcpy(selector_list, selectorMacAddrs, numBytes); 
    selector_list_len = numBytes;      
}  // end Smf::SetSelectorList()

void Smf::SetNeighborList(const char* neighborMacAddrs, unsigned int numBytes)
{
    if (numBytes > SELECTOR_LIST_LEN_MAX)
    {
        DMSG(0, "Smf::SetSelectorList() error: excessive selector list size\n");
        numBytes = SELECTOR_LIST_LEN_MAX;
    }
    memcpy(neighbor_list, neighborMacAddrs, numBytes); 
    neighbor_list_len = numBytes;      
}  // end Smf::SetNeighborList()

bool Smf::IsSelector(const ProtoAddress& macAddr) const
{
    const char *ptr = selector_list;
    const char* endPtr = selector_list + selector_list_len;
    while (ptr < endPtr)
    {
        if (!memcmp(ptr, macAddr.GetRawHostAddress(), macAddr.GetLength()))
            return true;   
        ptr += macAddr.GetLength();
    }
    return false;
}  // end SmfApp::IsSelector()

bool Smf::IsNeighbor(const ProtoAddress& macAddr) const
{
    const char *ptr = neighbor_list;
    const char* endPtr = neighbor_list + neighbor_list_len;
    while (ptr < endPtr)
    {
        if (!memcmp(ptr, macAddr.GetRawHostAddress(), macAddr.GetLength()))
            return true;   
        ptr += macAddr.GetLength();
    }
    return false;
}  // end SmfApp::IsNeighbor()


