#include "smf.h"

#include "smfHashMD5.h"
#include "smfHashSHA1.h"

#include "protoPktETH.h"
#include "protoPktIP.h"
#include "protoNet.h"

const unsigned int Smf::DEFAULT_AGE_MAX = 10;  // 10 seconds 
const unsigned int Smf::PRUNE_INTERVAL = 5;    // 5 seconds 

// These are used to mark the IPSec "type" for DPD
const char Smf::AH = 0;
const char Smf::ESP = 1;

Smf::RelayType Smf::GetRelayType(const char* name)
{
    // TBD - support MPR_CDS and NS_MPR ???
    if (0 == strcmp(name, "cf"))
        return Smf::CF;
    else if (0 == strcmp(name, "smpr"))
        return Smf::S_MPR;
    else if (0 == strcmp(name, "ecds"))
        return Smf::E_CDS;
    else
        return Smf::INVALID;
}  // end Smf::GetRelayType()

Smf::Mode Smf::GetForwardingMode(const char* name)
{
    if (0 == strcmp(name, "push"))
        return PUSH;
    else if (0 == strcmp(name, "rpush"))
        return PUSH;
    else if (0 == strcmp(name, "merge"))
        return MERGE;
    else if (0 == strcmp(name, "rmerge"))
        return MERGE;
    else
        return RELAY;
}  // end Smf::GetForwardingMode()

Smf::Interface::Extension::Extension()
{
}

Smf::Interface::Extension::~Extension()
{
}                   

Smf::Interface::Interface(unsigned int ifIndex)
 : if_index(ifIndex), resequence(false), tunnel(false), ip_encapsulate(false), dup_detector(NULL),  
   unicast_group_count(0),recv_count(0), mrcv_count(0), dups_count(0), asym_count(0), fwd_count(0),
   extension(NULL)
{
}

Smf::Interface::~Interface()
{
    Destroy();
}

bool Smf::Interface::Init(bool useWindow)
{
    Destroy();
    if (useWindow)
    {
        SmfDpdWindow* dpdWindow = new SmfDpdWindow;
        if (NULL != dpdWindow)
        {
            if (!dpdWindow->Init(1024, 1024))
            {
                PLOG(PL_ERROR, "Smf::Interface::Init() error: dpdWindow init failed: %s\n", GetErrorString());
                return false;
            }
            dup_detector = static_cast<SmfDpd*>(dpdWindow);
        }
    }
    else
    {
        dup_detector = static_cast<SmfDpd*>(new SmfDpdTable);
    }
    if (NULL == dup_detector)
    {
        PLOG(PL_ERROR, "Smf::Interface::Init() error: couldn't allocate dup_detector: %s\n", GetErrorString());
        return false;
    }
    return true;    
}  // end Smf::Interface::Init()

void Smf::Interface::Destroy()
{
    if (NULL != extension)
    {
        delete extension;  // it's destructor will be called
        extension = NULL;
    }
    if (NULL != dup_detector)
    {
        dup_detector->Destroy();
        delete dup_detector;
        dup_detector = NULL;
    }
    // Remove us from assoc_target_list of anyone targeting us
    assoc_source_list.Destroy();  // this deletes the items which also removes them from the sources' target lists
    // Destroy our target list
    assoc_target_list.Destroy();
}  // end Smf::Interface::Destroy()

bool Smf::Interface::AddAssociate(InterfaceGroup& ifaceGroup, Interface& iface)
{
    // (TBD) Should we verify that there isn't already an "Associate"
    //       with for the given "iface"
    Associate* assoc = new Associate(ifaceGroup, iface);
    if (NULL == assoc)
    {
        PLOG(PL_ERROR, "Smf::Interface::AddAssociate() new Associate error: %s\n", GetErrorString());
        return false;
    }
    if (!iface.assoc_source_list.Append(*assoc))
    {
        PLOG(PL_ERROR, "Smf::Interface::AddAssociate() error: unable to add to target's associate source list\n");
        delete assoc;
        return false;
    }
    if (!assoc_target_list.Append(*assoc))
    {
        PLOG(PL_ERROR, "Smf::Interface::AddAssociate() error: unable to add to associate target list\n");
        delete assoc;  // note deletion also removes it from target's associate source list
        return false;
    }
    return true;
}  // end Smf::Interface::AddAssociate()

bool Smf::Interface::EnqueueFrame(const char* frameBuf, unsigned int frameLen, SmfPacket::Pool* pktPool)
{
    if (frameLen > SmfPacket::PKT_SIZE_MAX)
    {
        PLOG(PL_ERROR, "Smf::Interface::EnqueueFrame() error: frame is too large\n");
        return false;
    }
    
    // First, make sure we have an "SmfPacket" to copy the frame into
    SmfPacket* smfPkt = (NULL != pktPool) ? pktPool->Get() : NULL;
    if (NULL == smfPkt) smfPkt = new SmfPacket();
    if (NULL == smfPkt)
    {
        PLOG(PL_ERROR, "Smf::Interface::EnqueueFrame() new SmfPkt error: %s\n", GetErrorString());
        return false;
    }
    // We offset by 2 bytes here so ProtoPktIP ends up with proper alignment
    UINT32* alignedBuffer = smfPkt->AccessBuffer();
    UINT16* ethBuffer = ((UINT16*)alignedBuffer) + 1;
    
    // Copy the frame to SmfPacket buffer (TBD - refactor nrlsmf code to avoid copy)
    memcpy(ethBuffer, frameBuf, frameLen);
    
    // Parse to pull out src:dst:proto information as flow identification
    // (TBD - pass pre-parsed details from receive SMF packet handling
    //        so we don't have to re-parse as we are doing here).
    ProtoPktETH ethPkt((UINT32*)ethBuffer, frameLen);
    if (!ethPkt.InitFromBuffer(frameLen))
    {
        // Note this should not happen since this frame was already parse earlier
        PLOG(PL_ERROR, "Smf::Interface::EnqueueFrame() error: bad Ether frame\n");
        return false;
    }
    // Only process IP packets (skip others)
    ProtoPktETH::Type ethType = (ProtoPktETH::Type)ethPkt.GetType();
    if ((ethType != ProtoPktETH::IP) && (ethType != ProtoPktETH::IPv6))
    {
        // Note this should not happen since this frame was already parsed earlier
        PLOG(PL_ERROR, "Smf::Interface::EnqueueFrame() error: non-IP Ether type\n");
        return false;
    }
    // Map ProtoPktIP instance into buffer and init for processing.
    UINT32* ipBuffer = alignedBuffer + 4;
    unsigned int ipLen = frameLen - 14;
    ProtoPktIP ipPkt(ipBuffer, ipLen);
    if (!ipPkt.InitFromBuffer(ipLen))
    {
        PLOG(PL_ERROR, "SmfApp::OnPktCapture() error: bad IP packet\n");
        return false;
    }
    // Does a queue exist for this src:dst:proto flow?
    
    ProtoAddress srcAddr, dstAddr;
    ProtoPktIP::Protocol protocol;
    /*switch (ipPkt.GetVersion())
    {
        case 4:
        case 6:
        default:
        {
            
        }
    }
    */
    
    SmfQueue* smfQueue = queue_list.FindQueue(srcAddr, dstAddr, protocol, 0);
    
            
            
    // TBD!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    
    return true;
}  // end Smf::Interface::EnqueueFrame()


Smf::Interface::Associate* Smf::Interface::FindAssociate(unsigned int ifIndex)
{
    AssociateList::Iterator iterator(assoc_target_list);
    Associate* assoc; 
    while (NULL != (assoc = iterator.GetNextItem()))
    {
        if (ifIndex == assoc->GetInterface().GetIndex())
            return assoc;
    }
    return NULL;
}  // end Smf::Interface::FindAssociate()

Smf::Interface::Associate::Associate(InterfaceGroup& ifaceGroup, Interface& iface)
  : iface_group(ifaceGroup), target_iface(iface)
{
}

Smf::Interface::Associate::~Associate()
{
}

Smf::InterfaceGroup::InterfaceGroup(const char* groupName)
 : push_src(NULL), is_template(false), 
   forwarding_mode(RELAY), relay_type(CF), 
   resequence(false), tunnel(false),
   elastic_mcast(false), elastic_ucast(false)
{
    strncpy(group_name, groupName, IF_GROUP_NAME_MAX + IF_NAME_MAX+1);
    group_name[IF_GROUP_NAME_MAX + IF_NAME_MAX + 1] = '\0';
    group_name_bits = strlen(group_name) << 3;
}  

Smf::InterfaceGroup::~InterfaceGroup()
{
    iface_list.Empty();
    push_src = NULL;
}

void Smf::InterfaceGroup::SetElasticMulticast(bool state)
{
    elastic_mcast = state;
}  // end Smf::InterfaceGroup::SetElasticMulticast()

void Smf::InterfaceGroup::SetElasticUnicast(bool state)
{
    if (state == elastic_ucast) return;  // no change
    elastic_ucast = state;
    InterfaceList::Iterator ifaceIterator(iface_list);
    Interface* iface;
    while (NULL != (iface = ifaceIterator.GetNextItem()))
    {
        if (state)
            iface->IncrementUnicastGroupCount();
        else
            iface->DecrementUnicastGroupCount();
    }
}  // end Smf::InterfaceGroup::SetElasticUnicast()


Smf::Smf(ProtoTimerMgr& timerMgr)
 : timer_mgr(timerMgr), hash_algorithm(NULL), ihash_only(true),
   idpd_enable(true), use_window(false),
   relay_enabled(false), relay_selected(false),
   delay_time(0),
   update_age_max(DEFAULT_AGE_MAX), current_update_time(0),
   selector_list_len(0), neighbor_list_len(0),
   recv_count(0), mrcv_count(0), dups_count(0), asym_count(0), fwd_count(0) 
{
    delay_relay_off_timer.SetInterval(delay_time);
    delay_relay_off_timer.SetListener(this,&Smf::OnDelayRelayOffTimeout);
    prune_timer.SetInterval((double)PRUNE_INTERVAL);
    prune_timer.SetRepeat(-1);
    prune_timer.SetListener(this, &Smf::OnPruneTimeout);
    memset(dscp, 0, 256);
}

Smf::~Smf()
{
    if (prune_timer.IsActive())
        prune_timer.Deactivate();
    iface_list.Destroy();
    iface_group_list.Destroy();
}

bool Smf::Init()
{
    if (!ip4_seq_mgr.Init(16))
    {
        PLOG(PL_ERROR, "Smf::Init() error: IPv4 sequence mgr init failure\n");
        return false;
    }
    if (!ip6_seq_mgr.Init(16))
    {
        PLOG(PL_ERROR, "Smf::Init() error: IPv6 sequence mgr init failure\n");
        return false;
    }
#ifdef ELASTIC_MCAST
    time_ticker.Reset();
#endif // ELASTIC_MCAST
    timer_mgr.ActivateTimer(prune_timer);
    return true;
}  // end Smf::Init()

bool Smf::SetHashAlgorithm(SmfHash::Type hashType, bool internalHashOnly)
{
    SmfHash* hashAlgorithm = NULL;
    switch (hashType)
    {
        case SmfHash::NONE:
            break;
        case SmfHash::CRC32:
            hashAlgorithm = new SmfHashCRC32;
            break;
        case SmfHash::MD5:
            hashAlgorithm = new SmfHashMD5;
            break;
        case SmfHash::SHA1:
            hashAlgorithm = new SmfHashSHA1;
            break;
       default:
            PLOG(PL_ERROR, "Smf::SetHashAlgorithm() error: unsupported hash algorithm\n");
            return false;
    }
    if ((SmfHash::NONE != hashType) && (NULL == hashAlgorithm))
    {
        PLOG(PL_ERROR, "Smf::SetHashAlgorithm() error: unable to allocate SmfHash instance: %s\n", GetErrorString());
        return false;    
    }    
    if (NULL != hash_algorithm) delete hash_algorithm;
    hash_algorithm = hashAlgorithm;
    use_window = (SmfHash::NONE != hashType) ?  false : use_window;
    ihash_only = internalHashOnly;
    return true;
}  // end Smf::SetHashAlgorithm()

Smf::InterfaceGroup* Smf::AddInterfaceGroup(const char* groupName)
{
    InterfaceGroup* ifaceGroup = new InterfaceGroup(groupName);
    if (NULL == ifaceGroup)
    {
        PLOG(PL_ERROR, "Smf::AddInterfaceGroup() new InterfaceGroup error: %s\n", GetErrorString());
        return NULL;
    }
    if (!iface_group_list.Insert(*ifaceGroup))
    {
        PLOG(PL_ERROR, "Smf::AddInterfaceGroup() error: unable to add group to iface_group_list\n");
        return NULL;
    }
    return ifaceGroup;
}  // end Smf::AddInterfaceGroup()

void Smf::DeleteInterfaceGroup(InterfaceGroup& ifaceGroup)
{
    // Remove all interfaces for given group and remove/delete group
    Smf::InterfaceGroup::Iterator ifacerator(ifaceGroup);
    Smf::Interface* iface;
    while (NULL != (iface = ifacerator.GetNextItem()))
    {
        ifaceGroup.RemoveInterface(*iface);
        if (!IsInGroup(*iface))
        {
            DeleteInterface(iface); // It's not in any other groups, so deactivate / delete it
        }
    }
    iface_group_list.Remove(ifaceGroup);
    delete &ifaceGroup;
}  // end Smf::DeleteInterfaceGroup()

Smf::Interface* Smf::AddInterface(unsigned int ifIndex)
{
    Interface* iface = GetInterface(ifIndex);
    if (NULL == iface)
    {
        iface = new Interface(ifIndex);
        if (NULL == iface)
        {
            PLOG(PL_ERROR, "Smf::AddInterface() new Smf::Interface error: %s\n", GetErrorString());
            return NULL;
        }
        if (!iface->Init(use_window))
        {
            PLOG(PL_ERROR, "Smf::AddInterface() Smf::Interface initialization error: %s\n", GetErrorString());
            delete iface;
            return NULL;
        }
        iface_list.Insert(*iface);
    }
    return iface;
}  // end Smf::AddInterface()

void Smf::RemoveInterface(unsigned int ifIndex)
{
    Interface* iface = GetInterface(ifIndex);
    if (NULL == iface) return;
    InterfaceGroupList::Iterator iterator(iface_group_list);
    InterfaceGroup* ifaceGroup;
    while (NULL != (ifaceGroup = iterator.GetNextItem()))
    {
        if (ifaceGroup->Contains(*iface))
        {
            ifaceGroup->RemoveInterface(*iface);
            if (!ifaceGroup->IsTemplateGroup() && (ifaceGroup->GetPushSource() == iface))
            {
                // Remove all interfaces from this PUSH group
                // (it it's not a template group)
                InterfaceGroup::Iterator ifacerator(*ifaceGroup);
                Interface* dstIface;
                while (NULL != (dstIface = ifacerator.GetNextInterface()))
                {
                    ifaceGroup->RemoveInterface(*dstIface);
                    // If dstIface is no other group, delete it
                    if (!IsInGroup(*dstIface))
                        DeleteInterface(dstIface);
                }
            }
            if (ifaceGroup->IsEmpty() && !ifaceGroup->IsTemplateGroup())
            {
                PLOG(PL_DEBUG, "Smf::RemoveInterface() deleting interface group \"%s\"\n", ifaceGroup->GetName());
                iface_group_list.Remove(*ifaceGroup);
                delete ifaceGroup;
            }
        }
    }
    DeleteInterface(iface);
}  // end Smf::RemoveInterface()

void Smf::DeleteInterface(Interface* iface)
{
    // These properly shutdown the interface
    if (NULL != iface)
    {
        iface_list.Remove(*iface);
        delete iface;
    }
}  // end Smf::DeleteInterface()


// (TBD) We may want this function to return some richer than a "bool"
//       For example, we might like to know if it detected a corrupt
//       packet somehow.
Smf::DpdType Smf::GetIPv6PktID(ProtoPktIPv6&   ip6Pkt,      // input
                               char*           flowId,      // output
                               unsigned int*   flowIdSize,  // input/output, in bits
                               char*           pktId,       // output
                               unsigned int*   pktIdSize)   // input/output, in bits
{
    
    
    ProtoPktIP::Protocol nextHeader = ip6Pkt.GetNextHeader();
    UINT32* nextBuffer = ip6Pkt.AccessPayload();
    unsigned int extHeaderLength = 0; 
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
                                // flowId == srcAddr:dstAddr[:taggerIdStuff]" (256 + "taggerIdStuff" bits)
                                // Note: we're not including "protocol" as mentioned in the current SMF 
                                //       draft snapshot 19 Sept 2007
                                ASSERT(*flowIdSize >= 256);
                                memcpy(flowId, ip6Pkt.GetSrcAddrPtr(), 16+16);
                                *flowIdSize = (128 + 128);  // in bits
                                DpdType dpdType;
                                if (!dpdOpt.HasHAV())
                                {
                                    // Is there a "taggerId"? If so, add to "flowId" 
                                    if (ProtoPktDPD::TID_NULL != dpdOpt.GetTaggerIdType())
                                    {
                                        unsigned int taggerIdLength = dpdOpt.GetTaggerIdLength();
                                        memcpy(flowId+32, opt.GetData(), 1 + taggerIdLength); 
                                        *flowIdSize += (8 + (taggerIdLength << 3));   
                                    }
                                    dpdType = DPD_SMF_I;
                                }
                                else
                                {
                                    dpdType = DPD_SMF_H;
                                }
                                // Note: Normally the SMF HAV will be used when the H-DPD
                                //       technique is used.  This ("GetIPv6PktID()") code
                                //       doesn't typically apply when "nrlsmf" is using H-DPD
                                //       So we assume, pktId == (8*havLength) bits of 
                                //       SMF hash assist value in that case
                                //       (GetPktIdLength() gives us the havLength when
                                //        the H-bit is set)
                                //
                                //  So, in either case, pktId = (8*pktIdLength) bits
                                ASSERT(*pktIdSize >= (unsigned int)(dpdOpt.GetPktIdLength() << 3));
                                *pktIdSize = dpdOpt.GetPktIdLength();
                                memcpy(pktId, dpdOpt.GetPktId(), *pktIdSize);
                                *pktIdSize <<= 3;  // convert from bytes to bits
                                return dpdType;
                            }
                            else
                            {
                                PLOG(PL_ERROR, "Smf::GetIPv6PktID() error: bad SMF_DPD header option\n");
                                return DPD_NONE;
                            }
                        }
                    }
                    break;
                }
                case ProtoPktIP::FRAG:
                {
                    ProtoPktFRAG frag;
                    if (frag.InitFromBuffer(ext.AccessBuffer(), ext.GetLength()))
                    {
                        // flowId == srcAddr:dstAddr (256 bits)
                        ASSERT(*flowIdSize >= 256);
                        memcpy(flowId, ip6Pkt.GetSrcAddrPtr(), 16+16);
                        *flowIdSize = (128 + 128);  // in bits
                        // pktId == 48 bits of ID: fragmentOffset:res:mf:identifier
                        ASSERT(*pktIdSize >= 48);
                        memcpy(pktId, frag.GetFragmentOffsetPtr(), 6);
                        *pktIdSize = (16 + 32);
                        return DPD_FRAG;
                    }
                    else
                    {
                        PLOG(PL_ERROR, "Smf::GetIPv6PktID() error: bad FRAG header!\n");
                        return DPD_NONE;;  // (TBD) return error condition?
                    }
                    break;
                }
                case ProtoPktIP::AUTH:
                {
                    ProtoPktAUTH ah;
		    if (ah.InitFromBuffer(ext.AccessBuffer(), ext.GetLength()))
                    {
                        // flowId == ipSecType:srcAddr:dstAddr:spi (296 bits)
                        ASSERT(*flowIdSize >= 328);
                        flowId[0] = AH;
                        memcpy(flowId+1, ip6Pkt.GetSrcAddrPtr(), 16+16);
                        memcpy(flowId+33, ah.GetSPIPtr(), 4);
                        *flowIdSize = (8 + 128 + 128 + 32);
                        // pktId == 32 bits of IPSec AH sequence no.
                        ASSERT(*pktIdSize >= 32);
                        memcpy(pktId, ah.GetSequencePtr(), 4);
                        *pktIdSize = 32;
                        return DPD_IPSEC;
                    }
		    else
                    {
                        PLOG(PL_ERROR, "Smf::GetIPv6PktID() error: bad AUTH header!\n");
                        return DPD_NONE;  // (TBD) return error condition?
                    }
                    break;
                }
                default:
                    break;
            }  // end switch (ext.GetType())
            extHeaderLength += ext.GetLength();
        }  // end while (extIterator.GetNextExtension(ext))
        nextHeader = ext.GetNextHeader();  // header _after_ extension headers (might be ESP)
    }  // end if (ip6Pkt.HasExtendedHeader())
    if (ProtoPktIP::ESP == nextHeader)
    {
        unsigned int espLength = ip6Pkt.GetPayloadLength() - extHeaderLength;
        ProtoPktESP esp;
        if (esp.InitFromBuffer(espLength, ip6Pkt.AccessPayload() + (extHeaderLength >> 2), espLength))
        {
            // flowId == ipSecType:srcAddr:dstAddr:spi (296 bits)
            ASSERT(*flowIdSize >= 328);
            flowId[0] = ESP;
            memcpy(flowId+1, ip6Pkt.GetSrcAddrPtr(), 16+16);
            memcpy(flowId+33, esp.GetSPIPtr(), 4);
            *flowIdSize = (8 + 128 + 128 + 32);
            // pktId == 32 bits of IPSec ESP sequence no.
            ASSERT(*pktIdSize >= 32);
            memcpy(pktId, esp.GetSequencePtr(), 4);
            *pktIdSize = 32;
            return DPD_IPSEC;
        }
        else
        {
            PLOG(PL_ERROR, "Smf::GetIPv6PktID() error: bad ESP header!\n");
        }
    }
    return DPD_NONE;  // packet had no SMF, FRAG, or IPSEC header option
}  // end Smf::GetIPv6PktID()

// (pktId, pktIdLen, hbit, tidType, tidLen, tidValue)
bool Smf::InsertOptionDPD(ProtoPktIPv6&             ipv6Pkt, 
                          const char*               pktId,
                          UINT8                     pktIdLength,  // in bytes
                          bool                      setHAV,
                          unsigned int*             optValueOffset,                  
                          ProtoPktDPD::TaggerIdType tidType,
                          UINT8                     tidLength,
                          const char*               taggerId)
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
                PLOG(PL_ERROR, "Smf::InsertOptionDPD() error: incoming packet options header already too big\n");
                ASSERT(0);
                return false;
            }
            
            // 2) Do we already have an existing SMF_DPD option?
            bool hasSmfDpdOpt = false;
            ProtoPktIPv6::Option::Iterator opterator(ext2);
            ProtoPktIPv6::Option oldDpdOpt;
            while (opterator.GetNextOption(oldDpdOpt))
            {
                if (ProtoPktIPv6::Option::SMF_DPD == oldDpdOpt.GetType())
                {
                    hasSmfDpdOpt = true;
                    break;
                }                   
            }
            char optBuffer[32];
            ProtoPktDPD newDpdOpt(optBuffer, 32);
            ProtoPktDPD* dpdOpt = (hasSmfDpdOpt)?
                &newDpdOpt : 
                static_cast<ProtoPktDPD*>(ext2.AddOption(ProtoPktIPv6::Option::SMF_DPD));         
            
            // 3) Set our new SMF-DPD option attributes
            if (NULL == dpdOpt)
            {
                PLOG(PL_ERROR, "Smf::InsertOptionDPD() error: couldn't fit SMF-DPD option into extension?!\n");
                return false;
            }
            if (setHAV)
            {
                // "pktId" is actually a HAV
                if (!dpdOpt->SetHAV(pktId, pktIdLength))
                {
                    PLOG(PL_ERROR, "Smf::InsertOptionDPD() error: couldn't fit sequence into option space?!\n");
                    return false;
                }
            }
            else 
            {
                if (ProtoPktDPD::TID_NULL != tidType)
                {
                    if (!dpdOpt->SetTaggerId(tidType, taggerId, tidLength))
                    {
                        PLOG(PL_ERROR, "Smf::InsertOptionDPD() error: couldn't set taggerId?!\n");
                        return false;
                    }
                }
                else
                {
            
                    if (!dpdOpt->SetTaggerId(ProtoPktDPD::TID_NULL, NULL, 0))
                    {
                        PLOG(PL_ERROR, "Smf::InsertOptionDPD() error: couldn't set TID_NULL taggerId?!\n");
                        return false;
                    }
                }
                if (!dpdOpt->SetPktId(pktId, pktIdLength))
                {
                    PLOG(PL_ERROR, "Smf::InsertOptionDPD() error: couldn't fit sequence into option space?!\n");
                    return false;
                }
            }
            
            // 4) Replace oldDpdOpt with new one or pack the new one we added
            if (hasSmfDpdOpt)
            {
                // We're replacing the old one
                if (!ext2.ReplaceOption(oldDpdOpt, newDpdOpt))
                {
                    PLOG(PL_ERROR, "Smf::InsertOptionDPD() error: couldn't replace SMF_DPD option?!\n");
                    return false;
                }
            }
            else
            {
                // We added a new option, so "Pack" and pad extended option header
                if (!ext2.Pack())
                {
                    PLOG(PL_ERROR, "Smf::InsertOptionDPD() error: couldn't pack HOPOPT extension?!\n");
                    return false;
                }
            }
            
            // 5) Replace existing hop-by-hop option header with new one
            if (ipv6Pkt.ReplaceExtension(ext, ext2))
            {
                // Fill in byte offset of SMF_DPD option data (wr2 ipv6Pkt buffer) if it was requested
                if (NULL != optValueOffset)
                {
                    // Calculate offset within IPv6 packet of extension header
                    *optValueOffset = ((const char*)ext.GetBuffer() - (const char*)ipv6Pkt.GetBuffer());
                    // Add offset of DPD data wr2 extension header
                    *optValueOffset += (dpdOpt->GetHAV() - (const char*)ext2.GetBuffer());
                }
                return true;
            }
            else
            {
                PLOG(PL_ERROR, "Smf::InsertOptionDPD() error: couldn't replace HOPOPT extension\n");
                return false;
            }
        }
    }
    // Insert new HOPOPT header extension w/ SMF_DPD option
    UINT32 buffer[64];  // plenty big to hold our new extension
    ProtoPktIPv6::Extension ext(ProtoPktIP::HOPOPT, buffer, 64*sizeof(UINT32), false);
    // Add SMF-DPD option (Use default "skip" unknown policy and immutable status)
    ProtoPktDPD* dpdOpt = static_cast<ProtoPktDPD*>(ext.AddOption(ProtoPktIPv6::Option::SMF_DPD));    
    if (setHAV)
    {
        // "pktId" is actually a HAV
        if (!dpdOpt->SetHAV(pktId, pktIdLength))
        {
            PLOG(PL_ERROR, "Smf::InsertOptionDPD() error: couldn't fit sequence into option space?!\n");
            return false;
        }
    }
    else 
    {
        if (ProtoPktDPD::TID_NULL != tidType)
        {
            if (!dpdOpt->SetTaggerId(tidType, taggerId, tidLength))
            {
                PLOG(PL_ERROR, "Smf::InsertOptionDPD() error: couldn't set taggerId?!\n");
                return false;
            }
        }
        else
        {

            if (!dpdOpt->SetTaggerId(ProtoPktDPD::TID_NULL, NULL, 0))
            {
                PLOG(PL_ERROR, "Smf::InsertOptionDPD() error: couldn't set TID_NULL taggerId?!\n");
                return false;
            }
        }
        if (!dpdOpt->SetPktId(pktId, pktIdLength))
        {
            PLOG(PL_ERROR, "Smf::InsertOptionDPD() error: couldn't fit sequence into option space?!\n");
            return false;
        }
    }
    // "pack" and pad our newly-created option header
    if (!ext.Pack())
    {
        PLOG(PL_ERROR, "Smf::InsertOptionDPD() error: couldn't pack HOPOPT extension?!\n");
        return false;
    }
    // insert the new header extension into the IPv6 packet buffer
    if (!ipv6Pkt.PrependExtension(ext))
    {
        PLOG(PL_ERROR, "Smf::InsertOptionDPD() error: couldn't prepend packet w/ HOPOPT extension?!\n");
        return false;
    }
    // Fill in byte offset of SMF_DPD option data (wr2 ipv6Pkt buffer) if it was requested
    if (NULL != optValueOffset)
    {
        // Calculate offset within IPv6 packet of extension header 
        // (Note we have put it first right after the 40 byte IPv6 header)
        *optValueOffset = 40;
        // Add offset of DPD data wr2 extension header
        *optValueOffset += (dpdOpt->GetHAV() - (const char*)ext.GetBuffer());
    }           
    return true;
}  // end Smf::InsertOptionDPD()

bool Smf::ApplyHAV(ProtoPktIPv6& ipv6Pkt, char* hashResult, unsigned int* hashSize)
{
    // a) Compute hash
    ASSERT(NULL != hash_algorithm);
    hash_algorithm->ComputeHashIPv6(ipv6Pkt);
    unsigned int hashBytes = hash_algorithm->GetLength();
    memcpy(hashResult, hash_algorithm->GetValue(), hashBytes);
    // b) check hash history
    const char* flowId = (const char*)ipv6Pkt.GetSrcAddrPtr();
    unsigned int flowIdSize = 128;
    bool noHAV = true;
    UINT8 havValue = 0;  // (TBD) make HAV size parametric?
    unsigned int havOffset;
    // c) while (conflicting) add or incrementally change HAV ...
    while (hash_stash.IsDuplicate(current_update_time, flowId, flowIdSize, hashResult, hashBytes << 3))
    {
        if (noHAV)
        {
            if (!Smf::InsertOptionDPD(ipv6Pkt, (char*)&havValue, 1, true, &havOffset))
            {
                PLOG(PL_ERROR, "Smf::ApplyHAV() error: unable to mark IPv6 pkt for DPD ...\n");
                return false;
            }
            noHAV = false;
        }
        else
        { 
             if (0xff == havValue)
             {
                 PLOG(PL_ERROR, "Smf::ApplyHAV() error: unable to set deconflicting HAV ...\n");
                 break;
             }
             havValue++;
             UINT8* havPtr = (UINT8*)ipv6Pkt.GetBuffer();
             *havPtr = (havValue | 0x80);  // the 0x80 sets the "h-bit"
        }
        hash_algorithm->ComputeHashIPv6(ipv6Pkt);
        memcpy(hashResult, hash_algorithm->GetValue(), hashBytes);
    }
    *hashSize = hashBytes << 3;
    return true;
}  // end Smf::ApplyHAV()

Smf::DpdType Smf::ResequenceIPv6(ProtoPktIPv6&   ipv6Pkt,     // input/output
                                 char*           flowId,      // output
                                 unsigned int*   flowIdSize,  // output, in bits
                                 char*           pktId,       // output
                                 unsigned int*   pktIdSize)   // output, in bits
{
    // Check to see if packet already has useful identifier for I-DPD or H-DPD
    Smf::DpdType dpdType = GetIPv6PktID(ipv6Pkt, flowId, flowIdSize, pktId, pktIdSize);

    // Possible IPv6 "resequencing" actions
    //
    // 1) I-DPD + hash : (idpd_enable = true, hashType != NONE, ihash_only = "true")
    //    a) Do I-DPD for everything (forwarders keep internal hash)
    //    b) Add SMF_DPD (w/ 'h-bit' cleared) to non-IPSec, non-FRAG pkts
    //
    // 2) I-DPD-only : (idpd_enable = true, hashType == NONE, ihash_only = "don't care")
    //    a) Do I-DPD for everything (no internal hash kept)
    //    b) Add SMF_DPD (w/ 'h-bit' cleared) to non-IPSec, non-FRAG pkts

    // 3) I-DPD - hash : (idpd_enable = true, hashType != NONE, ihash_only = "false")
    //    a) Do I-DPD for IPSec or FRAG, else H-DPD 
    //    b) Add SMF_DPD::HAV (w/ 'h-bit' set) as needed to non-IPSec, non-FRAG pkts
    //
    // 4) H-DPD-only : (idpd_enable = false, hashType != NONE, ihash_only = "don't care")
    //    a) Do H-DPD for everything, using HAV except for IPSec packets
    //    b) Add SMF_DPD HAV as needed/possible to avoid hash (incl FRAG)
    //       (note: can't add HAV to IPSec packets)
    //
    // Note: i) "ihash_only" (internal hash only) means no H-DPD regardless of hashType
    //      ii) #1 is the default mode of operation  
    //     iii) #1 and #2 equivalent here ...


    // This leads to 4 distinct cases:
    //
    // A) Add SMF_DPD identifier to non-IPSec, non-FRAG  (#1 and #2) 
    //    idpd_enable && ((NONE == hashType) || ihash_only)

    // B) Add SMF_DPD HAV to non-IPSec, non-FRAG (#3) 
    //    idpd_enable && (NONE != hashType) && !ihash_only

    // C) Add SMF_DPD HAV to non-IPSec (#4)
    //    !idpd_enable
    
    // D) Do nothing if none of the above apply
  
    if (!idpd_enable)
    {
        // Add SMF_DPD HAV as needed/possible to avoid hash (incl FRAG) (#4)
        // (note: can't add HAV to IPSec packets)    
        if (DPD_IPSEC != dpdType)
        {
            if (!ApplyHAV(ipv6Pkt, pktId, pktIdSize))
            {
                PLOG(PL_ERROR, "Smf::ResequenceIPv6() error: unable to insert HAV!\n");
                return dpdType; 
            }
            // flowId = 128 bits of IPv6 srcAddr
            memcpy(flowId, ipv6Pkt.GetSrcAddrPtr(), 16);
            *flowIdSize = 128;
            return DPD_SMF_H;
        }
    }
    else if ((SmfHash::NONE == GetHashType()) || ihash_only)
    {
        // Add SMF_DPD identifier to non-IPSec, non-FRAG  (#1 and #2) 
        if (DPD_NONE == dpdType)
        {
            ProtoAddress dstAddr;
            ipv6Pkt.GetDstAddr(dstAddr);
            UINT16 pktSeq = IncrementIPv6LocalSequence(&dstAddr);
            pktSeq = htons(pktSeq);
            if (!InsertOptionDPD(ipv6Pkt, (char*)&pktSeq, 2))
            {
                PLOG(PL_ERROR, "Smf::ResequenceIPv6() error: unable to mark IPv6 pkt for DPD!\n");
                return DPD_NONE;
            }
            // flowId = 256 bits of IPv6 srcAddr::dstAddr
            memcpy(flowId, ipv6Pkt.GetSrcAddrPtr(), (2*16));
            *flowIdSize = (128+128);
            // pktId = 16 bits of SMF_DPD sequence info
            memcpy(pktId, &pktSeq, 2);
            *pktIdSize = 16;
            return DPD_SMF_I;
        }
    }
    else
    {
        // Add SMF_DPD HAV to non-IPSec, non-FRAG (#3)
        if ((DPD_IPSEC != dpdType) && (DPD_FRAG != dpdType))
        {
            if (!ApplyHAV(ipv6Pkt, pktId, pktIdSize))
            {
                PLOG(PL_ERROR, "Smf::ResequenceIPv6() error: unable to apply HAV!\n");
                return GetIPv6PktID(ipv6Pkt, flowId, flowIdSize, pktId, pktIdSize);
            }
            // flowId = 128 bits of IPv6 srcAddr
            memcpy(flowId, ipv6Pkt.GetSrcAddrPtr(), 16);
            *flowIdSize = 128;
            return DPD_SMF_H;
        }
    }
    return dpdType;
}  // end Smf::ResequenceIPv6()


// Return value here is the number of interfaces to which the packet should be forwarded
// (the "dstIfArray" is populated with the list of indices for those interfaces)
unsigned int Smf::ProcessPacket(ProtoPktIP&         ipPkt,          // input/output - the packet (may be modified)
                                const ProtoAddress& srcMac,         // input - source MAC addr of packet
                                Interface&          srcIface,       // input - Smf::Interface on which packet arrived
                                unsigned int        dstIfArray[],   // output - list of interface indices to which packet should be forwarded
                                unsigned int        dstIfArraySize) // input - size of "dstIfArray[]" passed in
{
    if (!srcMac.IsValid())
    {
        //PLOG(PL_WARN, "Smf::ProcessPacket() warning: invalid srcMacAddr from ifIndex: %d!\n", srcIface.GetIndex());
    }
    else
    {
        PLOG(PL_DETAIL, "Smf::ProcessPacket() processing pkt from srcMac: %s recv'd on ifIndex: %d...\n", 
                 srcMac.GetHostString(), srcIface.GetIndex());
    }
    srcIface.IncrementRecvCount();
    recv_count++;  // increment total IP packets recvd stat count
    
    // 1) Get IP protocol version
    unsigned char version = ipPkt.GetVersion();

    // 2) Get IP packet dst and src addresses, packet ID (for DPD), 
    //    and ttl/hopLimit (and also decrement ttl/hopLimit for forwarding)
    ProtoAddress srcIp, dstIp;
    
    char flowId[48];  // worst case is probably IPV6 <taggerID:srcAddr:dstAddr> w/ taggerID a IPv6 addr (3*128 bits)
    unsigned int flowIdSize = (48*8);
    char pktId[32];  // worst case 32-bits of ID plus 160 bits of hash
    const unsigned int PKT_ID_SIZE_MAX = 20*8; // in bits
    unsigned int pktIdSize = PKT_ID_SIZE_MAX;  
    UINT8 ttl;
    
    // If this "srcIface" is a "tunnel" entrance, we will promiscuously forward
    // multicast packets without TTL adjustment
    bool tunnel = srcIface.GetTunnel();

    switch (version)
    {
        case 4:
        {
            // This section of code makes sure its a valid packet to forward
            // per Section 4.0 of draft-ietf-manet-smf-06
  
            ProtoPktIPv4 ipv4Pkt(ipPkt);
            ipv4Pkt.GetDstAddr(dstIp);
            if (!dstIp.IsMulticast() && !GetUnicastEnabled())  // only forward multicast dst, unless unicast enabled
            {
                PLOG(PL_DETAIL, "Smf::ProcessPacket() skipping non-multicast IPv4 pkt\n");
                return 0;
            }
            else if (dstIp.IsLinkLocal() && !tunnel)  // don't forward if link-local dst
            {   
#ifdef ELASTIC_MCAST
                // Is this an ElasticMulticast ACK? (if so, notify controller)
                if (dstIp.HostIsEqual(ElasticAck::ELASTIC_ADDR) &&
                     (ProtoPktIP::UDP == ipv4Pkt.GetProtocol()))
                {
                    ProtoPktUDP udpPkt;
                    ElasticAck elasticAck;
                    if (udpPkt.InitFromPacket(ipv4Pkt) &&
                        (udpPkt.GetDstPort() == ElasticAck::ELASTIC_PORT) &&
                        (elasticAck.InitFromBuffer(udpPkt.AccessPayload(), udpPkt.GetPayloadLength())))
                    {
                        // Is it for me?
                        ProtoAddress upstreamAddr;
                        UINT8 upstreamCount = elasticAck.GetUpstreamListLength();
                        for (UINT8 i = 0; i < upstreamCount; i++)
                        {
                            if (elasticAck.GetUpstreamAddr(i, upstreamAddr) && 
                                (upstreamAddr.HostIsEqual(srcIface.GetInterfaceAddress())))
                            {
                                mcast_controller->HandleAck(elasticAck, srcIface.GetIndex(), srcMac);
                                return 0;
                            }
                        }
                    }
                    else
                    {
                        PLOG(PL_WARN, "Smf::ProcessPacket() warning: invalid ELASTIC_ACK\n");
                    }
                }
#endif // ELASTIC_MCAST    
                PLOG(PL_DETAIL, "Smf::ProcessPacket() skipping link-local IPv4 pkt\n");           
                return 0;
            }
            // don't forward locally-generated packets unless unicast enabled
            ipv4Pkt.GetSrcAddr(srcIp);
            if (IsOwnAddress(srcIp) && (dstIp.IsMulticast() || !GetUnicastEnabled())) 
	        {                            // 
                PLOG(PL_DETAIL, "Smf::ProcessPacket() skipping locally-generated IPv4 pkt\n");
                return 0;
            }
            else if (srcIp.IsLinkLocal() && !tunnel)  // don't forward if link-local src
            {
                PLOG(PL_DETAIL, "Smf::ProcessPacket() skipping link-local sourced IPv4 pkt\n");
                return 0;
            }

            // This section of code implements the checks for I-DPD for IPv4 packets
            // per Section 5.2.2 of draft-ietf-manet-smf-06
            // It sets the "flowId" (pktId context) and "pktId" appropriately
            // depending upon the type of packet (i.e., fragment, IPSec, etc)
            
            if (!idpd_enable)
            {
                // Assume H-DPD and set flowId accordingly
                // flowId == protocol:srcAddr:dstAddr (72 bits)
                flowId[0] = ipv4Pkt.GetProtocol();
                memcpy(flowId+1, srcIp.GetRawHostAddress(), 4);
                memcpy(flowId+5, dstIp.GetRawHostAddress(), 4);
                flowIdSize = (8 + 32 + 32);
                pktIdSize = 0;
            }
            else if (ipv4Pkt.FlagIsSet(ProtoPktIPv4::FLAG_MF) ||
                     0 != ipv4Pkt.GetFragmentOffset())
            {
                // It's a fragment.
                // (make sure it doesn't have DF set!)
                if (ipv4Pkt.FlagIsSet(ProtoPktIPv4::FLAG_DF))
                {
                    // "Don't Fragment" flag set on a fragment? Invalid packet!
                    PLOG(PL_ERROR, "Smf::ProcessPacket() invalid packet: DF bit set on a fragment?\n");
                    return 0;   
                }
                // flowId == protocol:srcAddr:dstAddr (72 bits)
                flowId[0] = ipv4Pkt.GetProtocol();
                memcpy(flowId+1, srcIp.GetRawHostAddress(), 4);
                memcpy(flowId+5, dstIp.GetRawHostAddress(), 4);
                flowIdSize = (8 + 32 + 32);
                // pktId == 32 bits of ID:df:mf:fragmentOffset
                memcpy(pktId, ipv4Pkt.GetIDPtr(), 4);
                pktIdSize = 32;
            }
            else
            {
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
                            // flowId == protocol:srcAddr:dstAddr:spi (104 bits)
                            flowId[0] = ipv4Pkt.GetProtocol();
                            memcpy(flowId+1, srcIp.GetRawHostAddress(), 4);
                            memcpy(flowId+5, dstIp.GetRawHostAddress(), 4);
                            memcpy(flowId+9, ah.GetSPIPtr(), 4);
                            flowIdSize = (8 + 32 + 32 + 32);
                            // pktIdPtr == 32 bits of IPSec AH sequence no.
                            memcpy(pktId, ah.GetSequencePtr(), 4);
                            pktIdSize = 32;
                            TRACE("AUTH pkt: src>%s ", srcIp.GetHostString());
                            TRACE("dst>%s spi>%08x seq>%lu\n", dstIp.GetHostString(), ah.GetSPI(), ah.GetSequence());
                        }
                        else
                        {
                            TRACE("ProtoPktIP::AUTH::InitFromBuffer() failed!\n");
                            return 0;
                        }
                        break;
                    }
                    case ProtoPktIP::ESP:
                    {
                        TRACE("smf processing IPv4 ESP packet ...\n");
                        ProtoPktESP esp;
                        if (esp.InitFromBuffer(ipv4Pkt.GetPayloadLength(), ipv4Pkt.AccessPayload(), ipv4Pkt.GetPayloadLength()))
                        {
                            // flowId == protocol:srcAddr:dstAddr:spi (104 bits)
                            flowId[0] = ipv4Pkt.GetProtocol();
                            memcpy(flowId+1, srcIp.GetRawHostAddress(), 4);
                            memcpy(flowId+5, dstIp.GetRawHostAddress(), 4);
                            memcpy(flowId+9, esp.GetSPIPtr(), 4);
                            flowIdSize = (8 + 32 + 32 + 32);
                            // pktIdPtr == 32 bits of IPSec ESP sequence no.
                            memcpy(pktId, esp.GetSequencePtr(), 4);
                            pktIdSize = 32;
                            TRACE("ESP pkt: src>%s ", srcIp.GetHostString());
                            TRACE("dst>%s spi>%08x seq>%lu\n", dstIp.GetHostString(), esp.GetSPI(), esp.GetSequence());
                        }
                        else
                        {
                            TRACE("ProtoPktIP::ESP::InitFromBuffer() failed!\n");
                            return 0;
                        }
                        break;
                    }
                    default:
                        // Fetch packet ID for DPD (optionally resequence)
                        if (srcIface.GetResequence())
                        {
                            // (TBD) The ip4_seq_mgr should use "protocol" as part of its "flowId"
                            UINT16 newPktId = ip4_seq_mgr.IncrementSequence(current_update_time, &dstIp, &srcIp);
                            ipv4Pkt.SetID(newPktId, true);
                        }
                        // flowId == protocol:srcAddr:dstAddr (72 bits)
                        flowId[0] = ipv4Pkt.GetProtocol();
                        memcpy(flowId+1, srcIp.GetRawHostAddress(), 4);
                        memcpy(flowId+5, dstIp.GetRawHostAddress(), 4);
                        flowIdSize = (8 + 32 + 32);
                        // pktIdPtr == 16 bits of IPv4 ID field
                        memcpy(pktId, ipv4Pkt.GetIDPtr(), 2);
                        pktIdSize = 16;
                        break;
                }  // end switch(ipv4Pkt.GetProtocol())
            }  // end if/else (isFragment)
            
                        
            // If hashing is enabled, compute and append "pktId" with hashValue
            if (SmfHash::NONE != GetHashType())
            {
                // How much space in our pktId is left for a hash value
                unsigned int pktIdBytes = (pktIdSize >> 3);
                unsigned int sizeRemainder = pktIdSize & 0x07;
                if (0 != (sizeRemainder & 0x07)) 
                {
                    // Pad pktId with zeroes to next byte boundary
                    unsigned char mask = 0xff << (8 - sizeRemainder);
                    pktId[pktIdBytes] &= mask;
                    pktIdBytes++;
                }
                // Put hash value after pktId (if applicable)
                char* hashValuePtr = pktId + pktIdBytes; 
            
                hash_algorithm->ComputeHashIPv4(ipv4Pkt);
                unsigned int hashBytes = hash_algorithm->GetLength();
                memcpy(hashValuePtr, hash_algorithm->GetValue(), hashBytes);
                pktIdBytes += hashBytes;
                pktIdSize = pktIdBytes << 3;  // convert to length in bits
            }  // end if (SmfHash::NONE != GetHashType())
            
            ttl = ipv4Pkt.GetTTL();
            if ((ttl > 1) && !tunnel) ipv4Pkt.DecrementTTL();
            
            break;
        }  // end case(4)  (IPv4 packet)
        
        case 6:
        {
            // This section of code makes sure its a valid packet to forward
            // per Section 4.0 of draft-ietf-manet-smf-06
            ProtoPktIPv6 ipv6Pkt(ipPkt);
            ipv6Pkt.GetDstAddr(dstIp); 
            if (!dstIp.IsMulticast() && !GetUnicastEnabled())      // only forward multicast dst unless unicast enabled
            {
                PLOG(PL_DETAIL, "Smf::ProcessPacket() skipping non-multicast IPv6 pkt\n");
                return 0;
            }
            else if (dstIp.IsLinkLocal() && !tunnel)  // don't forward if link-local dst
            {
                PLOG(PL_DETAIL, "Smf::ProcessPacket() skipping link-local IPv6 pkt\n");
                return 0;
            }
            ipv6Pkt.GetSrcAddr(srcIp);
            if (IsOwnAddress(srcIp))       // don't forward locally-generated packets
            {
                PLOG(PL_DETAIL, "Smf::ProcessPacket() skipping locally-generated IPv6 pkt\n");
                return 0;
                
            }
            else if (srcIp.IsLinkLocal() && !tunnel)  // don't forward if link-local src
            {
                PLOG(PL_DETAIL, "Smf::ProcessPacket() skipping link-local sourced IPv6 pkt\n");
                return 0;
            }
            // (TBD) What about site local?
            
            DpdType dpdType;
            if (srcIface.GetResequence())
            {
                // Resequence or fetch dpdType, etc as appropriate
                dpdType = ResequenceIPv6(ipv6Pkt, flowId, &flowIdSize, pktId, &pktIdSize);
                // Update length of ProtoPktIP passed into this routine
                ipPkt.SetLength(ipv6Pkt.GetLength());
            }
            else
            {
                // Fetch the dpdType, etc
                dpdType = GetIPv6PktID(ipv6Pkt, flowId, &flowIdSize, pktId, &pktIdSize);
            }
            
            // At this point we have a valid dpdType
            if (SmfHash::NONE != GetHashType())
            {
                // We are either doing H-DPD or a hybrid
                if (idpd_enable)
                {
                    if (ihash_only)
                    {
                        // I-DPD + hash mode
                        ASSERT(DPD_SMF_H != dpdType);
                        if (DPD_NONE == dpdType)
                        {
                            // Can't do I-DPD for unmarked packets!
                            // (TBD) we could use hash to attempt DPD anyway??
                            PLOG(PL_ERROR, "Smf::ProcessPacket() received IPv6 pkt with no DPD identifier\n");
                            return 0; 
                        }
                        // will append hash to current pktId
                    }
                    else
                    {
                        // I-DPD - hash_mode
                        // hash non-IPSec, non-FRAG
                        switch (dpdType)
                        {
                            case DPD_IPSEC:
                            case DPD_FRAG:
                                // append hash value to pktId
                                break;
                            case DPD_SMF_H:
                                // pktId already is hash value
                                break;
                            default:
                                // pure H-DPD, will use hash value for pktId
                                memcpy(flowId, ipv6Pkt.GetSrcAddrPtr(), 16);
                                flowIdSize = 128;
                                pktIdSize = 0;  // hash calc below will set this
                                break;
                        } 
                    }  // end if/else (ihash_only)
                }
                else
                {
                    // pure H-DPD
                    if (DPD_SMF_H != dpdType)
                    {
                        memcpy(flowId, ipv6Pkt.GetSrcAddrPtr(), 16);
                        flowIdSize = 128;
                        pktIdSize = 0;  // hash calc below will set this
                    }
                } 
                // We don't need to rehash when dpdType == DPD_SMF_H
                if (DPD_SMF_H != dpdType)
                {
                    // This section performs a hash of the packet for SMF H-DPD
                    // How much space in our pktId is left for a hash value
                    unsigned int pktIdBytes = (pktIdSize >> 3);
                    unsigned int sizeRemainder = pktIdSize & 0x07;
                    if (0 != (sizeRemainder & 0x07)) 
                    {
                        // Pad pktId with zeroes to next byte boundary
                        unsigned char mask = 0xff << (8 - sizeRemainder);
                        pktId[pktIdBytes] &= mask;
                        pktIdBytes++;
                    }
                    // Put hash value after pktId (if applicable)
                    char* hashValuePtr = pktId + pktIdBytes; 
                    hash_algorithm->ComputeHashIPv6(ipv6Pkt);
                    unsigned int hashBytes = hash_algorithm->GetLength();
                    memcpy(hashValuePtr, hash_algorithm->GetValue(), hashBytes);
                    pktIdBytes += hashBytes;
                    pktIdSize = pktIdBytes << 3;
                }   
            } 
            else if (idpd_enable)
            {
                // pure I-DPD
                if (DPD_NONE == dpdType)
                {
                    // Can't do I-DPD for unmarked packets!
                    // (TBD) we could use hash to attempt DPD anyway??
                    PLOG(PL_ERROR, "Smf::ProcessPacket() received IPv6 pkt with no DPD identifier\n");
                    return 0; 
                }
            }          
            else
            {
                // no DPD at all (yikes!!)
                PLOG(PL_DETAIL, "Smf::ProcessPacket() warning: forwarding packet with no DPD\n");
            } 
               
            ttl = ipv6Pkt.GetHopLimit();
            if ((ttl > 1) && !tunnel) 
                ipv6Pkt.SetHopLimit(ttl - 1);
            break;
        }  // end case IPv6
        default:
            PLOG(PL_ERROR, "Smf::ProcessPacket() unknown IP protocol version\n");
            return 0;   
    }  // end switch (version)
    
    mrcv_count++;  // increment multicast received count
    srcIface.IncrementMcastCount();
    
    // If we are "resequencing" packets recv'd on this srcIface (smf rpush|rmerge)
    // we need to mark the DPD table so we don't end up potentially sending the
    // resequenced version of the packet back out this srcIface on which it
    // arrived (e.g., due to hearing a MANET neighbor forwarding this packet)
    if (srcIface.GetResequence())
    {
        srcIface.IsDuplicatePkt(current_update_time, flowId, flowIdSize, pktId, pktIdSize);
    }
    
#ifdef ELASTIC_MCAST        
        // If there is an ElasticMcast interface group, this will
        // be looked up (or created as needed for new flows)
        MulticastFIB::Entry* fibEntry = NULL;   
        MulticastFIB::UpstreamRelay* upstream = NULL;
        unsigned int pktCount = 0;
        unsigned int updateInterval = 0;
        bool sendAck = false;
        bool updateController = false;
        
        // Lookup/compute current time for purposes of 
        // elastic multicast token bucket update, etc
        // (We do it here, so it's once per packet, worst case.
        //  In the future, the packet capture time may be passed
        //  into this method so we won't have to do this here.)
        // This will wrap about every 4000 seconds for 32-bit unsigned int, but that's OK
        // since we use delta times only and our update timer has a short enough period
        unsigned int currentTick = time_ticker.Update();
#endif  // ELASTIC_MCAST
    
    // Iterate through potential outbound interfaces ("associate" interfaces)
    // for this "srcIface" and populate "dstIfArray" with indices of
    // interfaces through which the packet should be forwarded.
    bool asym = false;
    unsigned int dstCount = 0;
    bool ecdsBlock = false;
    Interface::AssociateList::Iterator iterator(srcIface);
    Interface::Associate* assoc;
    while (NULL != (assoc = iterator.GetNextItem()))
    {
        InterfaceGroup& ifaceGroup = assoc->GetInterfaceGroup();
        RelayType relayType = ifaceGroup.GetRelayType();
#ifdef ELASTIC_MCAST
        bool elastic = ifaceGroup.GetElasticMulticast();  // yyy - change to use IsElastic() method
#else
        bool elastic = false;
#endif // if/else ELASTIC_MCAST
        
        // Should we forward this packet on this associated "dstIface"?
        bool forward = false;
        bool updateDupTree = false;
        switch (relayType)
        {
            case CF:
            {
                forward = relay_enabled;
                updateDupTree = forward;
                break;   
            }
            case E_CDS:
            {
 		        if (dstIp.IsMulticast()) 
                {
		            PLOG(PL_MAX, "nrlsmf: E_CDS relay_enable:%d relay_selected:%d\n", relay_enabled, relay_selected); 
		            forward = (relay_enabled && relay_selected);
		        }
                else 
                {
		            // Unicast DPD unique packets should be handled by the routing daemon 
		            // regardless of the ECDS status. Compute the interface array
		            // as if the node was a relay, and return (unsigned int)-1 if the relay was disabled.
		            forward = true;

		            // Locally generated unicast packets should not be blocked by ECDS
		            // They are identified as they do not have a valid source MAC address.
		            if (srcMac.IsValid())
		                ecdsBlock = !(relay_enabled && relay_selected);
		        }
		        updateDupTree = forward;
                break;
            }
            case S_MPR:
            {
                bool isSelector = IsSelector(srcMac);
#ifdef ELASTIC_MCAST
                elastic &= isSelector;
#endif // ELASTIC_MCAST
                forward = relay_enabled && isSelector;
                if (IsNeighbor(srcMac))
                {
                    updateDupTree = true;
                }
                else if (forward)
                {
                    PLOG(PL_ERROR,"nrlsmf: received packet from asymmetric neighbor while in s-mpr mode, but neighbor was selector?!\n");
                    asym = true;
                    updateDupTree = true;
                }
                else
                {
                    PLOG(PL_DEBUG,"nrlsmf: received packet from asymmetric neighbor while in s-mpr mode, not marking duplicate table\n");
                    asym = true;
                    updateDupTree = false;
                }
                break;
            }
            // none of these below cases should occur
            case MPR_CDS:
            case NS_MPR:
                // (TBD) implement these
            default:
                ASSERT(0);
                break;
        }  // end switch (relayType)
        
        if (asym) 
        {
            asym_count++;
            srcIface.IncrementAsymCount();
        }
        
        Interface& dstIface = assoc->GetInterface();
        
        if (GetDebugLevel() >= PL_MAX)
        {
            char flowIdText[2048];
            char* ptr = flowIdText;
            unsigned int flowIdBytes = flowIdSize >> 3;
            if (flowIdBytes > 1027) flowIdBytes = 1027;
            for (unsigned int i = 0; i < flowIdBytes; i++) 
            {
                sprintf(ptr, "%02x", (unsigned char)flowId[i]);
                ptr += 2;
            }
            char pktIdText[2048];
            ptr = pktIdText;
            unsigned int pktIdBytes = pktIdSize >> 3;
            if (pktIdBytes > 1027) pktIdBytes = 1027;
            for (unsigned int i = 0; i < pktIdBytes; i++)
            {
                sprintf(ptr, "%02x", (unsigned char)pktId[i]);
                ptr += 2;
            }
            PLOG(PL_MAX, "nrlsmf: evaluating packet for forwarding: forward>%d flowIdSize>%u flowId>%s pktIdSize>%u pktId>%s\n", 
                         forward, flowIdSize, flowIdText, pktIdSize, pktIdText);
        }
        // For Elastic Multicast, we always need to do the duplicate check
        if (forward || elastic || (updateDupTree && (&dstIface == &srcIface)))
        {
	        if (dstIface.IsDuplicatePkt(current_update_time, flowId, flowIdSize, pktId, pktIdSize))
            {
                PLOG(PL_DEBUG, "nrlsmf: received duplicate IPv%d packet ...\n", version);
                dups_count++;
                dstIface.IncrementDuplicateCount();
#ifdef ELASTIC_MCAST
                elastic = false;  // ElasticMulticast only pays attention to non-duplicates
#endif // ELASTIC_MCAST
                forward = false;
            }
        }

	    if (srcMac.IsValid() && IsOwnAddress(srcMac)) // don't forward outbound locally-generated packets captured
	    {
	        PLOG(PL_DETAIL, "Smf::ProcessPacket() skipping locally-generated IP pkt\n");
	        return 0;
	    }

#ifdef ELASTIC_MCAST      
        if (elastic)
        {
            // TBD - we can probably move this section of Elastic Multicast packet handling code to
            //       a method embedded in the MulticastFIB class???
            // Diatribe on when do we update the controller:
            // a) When a new flow (no pre-existing fibEntry) is detected
            // b) When the upstreamRelay is new
            // c) Upon the configured "refresh" condition:
            //      i) Enough time since last refresh, or
            //     ii) Upon enough packets received from the upstreamRelay
            if (NULL == fibEntry)
            {
                // TBD - first match the flow against some policy list to determine "indexFlags" dynamically?
                FlowDescription flowDescription;
                flowDescription.InitFromPkt(ipPkt);
                // TBD - we could call FindEntry() here instead to be slightly more efficient
                //  (and then for new flows, call FindBestMatch() to find a matching managed entry if it exists)
                MulticastFIB::Entry* match = mcast_fib.FindBestMatch(flowDescription);
                if (NULL != match)
                {
                    if (0 != match->GetSrcLength())
                    {
                        // It's a full match, so use for flow
                        fibEntry = match;
                        match = NULL;
                    }
                    // else it's a dst-only match so a flow entry needs to be created
                }
                if (NULL == fibEntry)
                {
                    // This is a newly-detected flow, so we need to alert control plane!!!!!
                    // TBD - implement default handling policies for new flows
                    // (for now, we implement forwarding governed by default token bucket)
                    if (NULL == (fibEntry = new MulticastFIB::Entry(flowDescription)))//dstIp, srcIp)))
                    {
                        PLOG(PL_ERROR, "Smf::ProcessPacket() new MulticastFIB::Entry() error: %s\n", GetErrorString());
	                    return 0;
                    }
                    if (NULL != match)
                    {
                        TRACE("recv'd packet for newly matched flow ");
                        fibEntry->GetFlowDescription().Print();
                        TRACE(" matching ");
                        match->GetFlowDescription().Print();
                        TRACE(" ( SMF forwarder: %d)\n", forward);
                        if (!fibEntry->CopyStatus(*match))
                        {
                            PLOG(PL_ERROR, "Smf::ProcessPacket() error: unable to copy entry status!\n");
                            delete fibEntry;
                            return 0;
                        }
                    }
                    else
                    {
                        TRACE("recv'd packet for newly detected flow ");
                        fibEntry->GetFlowDescription().Print();
                        TRACE(" ( SMF forwarder: %d)\n", forward);
                    }
                    mcast_fib.InsertEntry(*fibEntry);
                    // Put the new, dynamically detected flow in our "active_list"
                    mcast_fib.ActivateFlow(*fibEntry, currentTick);
                    updateController = true;  
                }
                else 
                {
                    if (GetDebugLevel() >= PL_MAX)
                    {
                        PLOG(PL_MAX, "recv'd packet (flow ");
                        flowDescription.Print();
                        PLOG(PL_ALWAYS, ") from relay %s for existing flow ", srcMac.GetHostString());
                        fibEntry->GetFlowDescription().Print();
                        PLOG(PL_ALWAYS, " ackingStatus:%d SMF forwarder: %d\n", fibEntry->GetAckingStatus(), forward);
                    }
                    // This keeps our time ticks current
                    fibEntry->Refresh(currentTick);
                    if (fibEntry->IsActive())
                    {
                        // Refresh active flow
                        mcast_fib.TouchEntry(*fibEntry, currentTick);
                    }
                    else
                    {
                        // Reactivate idle flow
                        TRACE("reactivating flow ");
                        fibEntry->GetFlowDescription().Print();
                        TRACE("\n");
                        mcast_fib.ReactivateFlow(*fibEntry, currentTick);
                        updateController = true;
                    }
                }
            }  // end if (NULL == fibEntry)
            // We track upstreams regardless of ackingStatus so we can be more responsive
            // to send an EM-ACK upon topology changes, etc
            if ((NULL == upstream)) // && fibEntry->GetAckingStatus())
            {
                ASSERT(0 != fibEntry->GetFlowDescription().GetSrcLength());
                // Get (or create if needed) upstream relay info
                upstream = fibEntry->FindUpstreamRelay(srcMac);
                if (NULL == upstream)
                {
                    if (NULL == (upstream = new MulticastFIB::UpstreamRelay(srcMac, srcIface.GetIndex())))
                    {
                        PLOG(PL_ERROR, "Smf::ProcessPacket() new MulticastFib::UpstreamRelay error: %s\n", GetErrorString());
                        return 0;
                    }
                    fibEntry->AddUpstreamRelay(*upstream);
                    updateController = true;  // new upstream, so update controller
                    if (fibEntry->GetAckingStatus()) sendAck = true;  // TBD - sendAck only when there's not another upstream?
                    upstream->Reset(currentTick);
                    pktCount = 1;
                    updateInterval = 0;
                }
                else
                {
                    upstream->Refresh(currentTick);  // TBD - have "Refresh()" return acking interval?
                    // Existing upstream relay.  Acking controller when needed.
                    if (fibEntry->GetAckingStatus())
                    {
                        pktCount = upstream->GetUpdateCount() - 1;
                        updateInterval = upstream->GetUpdateInterval();
                        if (upstream->AckPending(*fibEntry))
                        {
                            sendAck = true;
                            updateController = true;
                            upstream->Reset(currentTick);
                        }
                    }
                }
                /*
                This code is still not right ... need a way to know if a flow has been recently ACK'd for anouther upstream
                ... the approach sketched out here won't work.  E.g., we could use UpstreamRelay::GetUpdateInterval() to see
                how long it's been since the flow was last ACK'd by that upstream to help decide.
                if (sendAck)
                {
                    // if another upstream relay is "current", then squelch this ACK
                    MulticastFIB::UpstreamRelayList::Iterator upstreamerator(fibEntry->AccessUpstreamRelayList());
                    MulticastFIB::UpstreamRelay* altRelay;
                    while (NULL != (altRelay = upstreamerator.GetNextItem()))
                    {
                        if (altRelay == upstream) continue;
                        altRelay->Refresh(currentTick, 0);  // 
                        if (!altRelay->AckPending(*fibEntry, false))
                        {
                            sendAck = false;
                            break;
                        }
                    }
                }*/
            }
            // Get (or create if needed) the token bucket for this outbound iface
            MulticastFIB::TokenBucket* bucket = fibEntry->GetBucket(dstIface.GetIndex());
            if (NULL != bucket)
            {
                // Check if the flow passes the bucket's rate limit test
                // according to its current forwarding status
                if (forward)
                    forward = bucket->ProcessPacket(currentTick);
            }
            else
            {
                PLOG(PL_ERROR, "Smf::ProcessPacket() error: new MulticastFIB::TokenBucket error: %s\n", GetErrorString());
                forward = false;  // for safety? TBD - or should we forward by default on error???
            }
        }  // end if (elastic)
#endif  // ELASTIC_MCAST
        
        if (forward)
        {
            if (((ttl > 1) || tunnel) && (dstCount < dstIfArraySize))
                dstIfArray[dstCount] = dstIface.GetIndex();
            dstCount++;   
        }
    }
    
#ifdef ELASTIC_MCAST
    if (updateController)  // ??? only signal controller when "forward" is true ???
    {
        // Report how many packets seen for this flow and interval from this upstream relay since last update
        // (TBD - if controller and forwarder have shared FIB, this could be economized)
        mcast_controller->Update(fibEntry->GetFlowDescription(), srcIface.GetIndex(), srcMac, pktCount, updateInterval);
    }    
    if (sendAck)
    {
        // Note that due to alignment, the built frame will have 2-byte offset from "ackBuffer" head
        UINT32 ackBuffer[1400/4];
        // "srcMac" is upstream relay address
        unsigned int ackLength = MulticastFIB::BuildAck(ackBuffer, 1400, srcMac, 
                                                        srcIface.GetInterfaceAddress(), 
                                                        srcIface.GetIpAddress(),
                                                        fibEntry->GetFlowDescription());     
        if (0 != ackLength)
        {
            
            if (GetDebugLevel() >= PL_DEBUG)
            {
                PLOG(PL_ALWAYS, "nrlsmf: sending EM_ACK for flow \"");
                fibEntry->GetFlowDescription().Print();  // to debug output or log
                PLOG(PL_ALWAYS, " to relay %s via interface index %d\n", srcMac.GetHostString(), srcIface.GetIndex());
            }
            // TBD - Implement ACK rate limiter by bundling multiple flow acks for common upstream relay
            // (i.e. do this with a timer and some sort of helper classes)
            output_mechanism->SendFrame(srcIface.GetIndex(), ((char*)ackBuffer) + 2, ackLength);
        }       
    }
    
#endif // ELASTIC_MCAST
    
    if ((dstCount > 0) && ((ttl <= 1) && !tunnel))
    {
        PLOG(PL_DEBUG, "nrlsmf: received ttl-expired packet (ttl = %d)...\n", ttl);
        dstCount = 0;
    }
    if (dstCount > 0) 
    {
        fwd_count++;
        srcIface.IncrementForwardCount();
    }

    if((dstCount > 0) && ecdsBlock) 
    {
	    // This node is not a selected ECDS relay
	    // Treat unicast packets specially
	    dstCount = -1;
    }

    return dstCount;
    
}  // end Smf::ProcessPacket()

#ifdef ELASTIC_MCAST
bool Smf::SendAck(unsigned int           ifaceIndex, 
                  const ProtoAddress&    relayAddr,
                  const FlowDescription& flowDescription)
{
    Interface* iface = GetInterface(ifaceIndex);
    ASSERT(NULL != iface);
    // Note that due to alignment, the built frame will have 2-byte offset from "ackBuffer" head
    UINT32 ackBuffer[1400/4];
    // "srcMac" is upstream relay address
    unsigned int ackLength = MulticastFIB::BuildAck(ackBuffer, 1400, relayAddr, 
                                                    iface->GetInterfaceAddress(), 
                                                    iface->GetIpAddress(),
                                                    flowDescription);     
    if (0 != ackLength)
    {

        if (GetDebugLevel() >= PL_DEBUG)
        {
            PLOG(PL_ALWAYS, "nrlsmf: sending preemptive EM_ACK for flow \"");
            flowDescription.Print();  // to debug output or log
            PLOG(PL_ALWAYS, " to relay %s via interface index %d\n", relayAddr.GetHostString(), ifaceIndex);
        }
        // TBD - Implement ACK rate limiter by bundling multiple flow acks for common upstream relay
        // (i.e. do this with a timer and some sort of helper classes)
        return output_mechanism->SendFrame(ifaceIndex, ((char*)ackBuffer) + 2, ackLength);
    } 
    else
    {
        PLOG(PL_ERROR, "Smf:SendAck() error: invalid flowDescription?!\n");
        return false;
    }
}  // end SmfApp::SendAck()
#endif // ELASTIC_MCAST


void Smf::SetRelayEnabled(bool state)
{
    if(state) 
        PLOG(PL_DEBUG, "SMF::SetRelayEnabled(true)\n");
    else
        PLOG(PL_DEBUG, "SMF::SetRelayEnabled(false)\n");
    relay_enabled = state;
}


void Smf::SetRelaySelected(bool state)
{
    if(state)
    {
        PLOG(PL_DEBUG, "Smf::SetRelaySelected(true)\n");
        if(delay_relay_off_timer.IsActive())
        {
            delay_relay_off_timer.Deactivate();
        }
        relay_selected=true;
    }
    else
    {
        PLOG(PL_DEBUG, "Smf::SetRelaySelected(false): ");
        if(delay_time==0)
        {
            PLOG(PL_DEBUG, "Turning off now.\n");
            relay_selected=false;
        }
        else
        {
            if(!delay_relay_off_timer.IsActive())//timer isn't active so set correct timeout time and activate it
            {
                PLOG(PL_DEBUG, "Turning off in %f.\n",delay_time);
                delay_relay_off_timer.SetInterval((delay_time));
                delay_relay_off_timer.SetRepeat(1);
                timer_mgr.ActivateTimer(delay_relay_off_timer);
            }
            else
            {
                PLOG(PL_DEBUG, "Timer is active. Turning off in less than %f\n",delay_time);
                //timer is active do nothing
            }
        }
    }
    return;
}

bool Smf::OnDelayRelayOffTimeout(ProtoTimer& theTimer)
{
    PLOG(PL_DEBUG, "Smf::OnDelayRelayOffTimeout(): Turning off\n");
    if(theTimer.IsActive())
    {
        theTimer.Deactivate();
    }
    relay_selected = false;
    return true;
}

bool Smf::OnPruneTimeout(ProtoTimer& /*theTimer*/)
{
    bool outputReport = GetDebugLevel() >= PL_INFO;
    ip4_seq_mgr.Prune(current_update_time, update_age_max);
    ip6_seq_mgr.Prune(current_update_time, update_age_max);
    
    hash_stash.Prune(current_update_time, update_age_max);
    
    // The SmfDuplicateTree::Prune() method removes
    // entries which are stale for more than "update_age_max"
    unsigned int flowCount = 0;
    InterfaceList::Iterator iterator(iface_list);
    Interface* nextIface;
    if (outputReport) PLOG(PL_ALWAYS, "nrlsmf report:\n");  // TBD - add date / timestamp
    char ifaceName[IF_NAME_MAX+1];
    ifaceName[IF_NAME_MAX] = '\0';        
    while (NULL != (nextIface = iterator.GetNextItem()))
    {
        nextIface->PruneDuplicateDetector(current_update_time, update_age_max);
        flowCount += nextIface->GetFlowCount();
        if (outputReport)
        {
            ProtoNet::GetInterfaceName(nextIface->GetIndex(), ifaceName, IF_NAME_MAX);
            PLOG(PL_ALWAYS, "  iface:%s flows:%u recv:%u mrcv:%u dups:%u asym:%u fwd:%u queue:%u\n",ifaceName,
                               nextIface->GetFlowCount(), nextIface->GetRecvCount(), nextIface->GetMcastCount(),
                               nextIface->GetDuplicateCount(), nextIface->GetAsymCount(), nextIface->GetForwardCount(),
                               nextIface->GetQueueLength());
        }
    }
    if (outputReport)
    {
        PLOG(PL_ALWAYS, "  summary> flows:%u recv:%u mrcv:%u dups:%u asym:%u fwd:%u\n",
                flowCount, recv_count, mrcv_count, 
                dups_count, asym_count, fwd_count); 
    }
    
    current_update_time += (unsigned int)prune_timer.GetInterval();
#ifdef ELASTIC_MCAST
    unsigned int currentTick = time_ticker.Update();  // ticker used for ElasticMulticast token buckets, etc
    mcast_fib.PruneFlowList(currentTick);
#endif // ELASTIC_MCAST
    return true;
}  // end Smf::OnPruneTimeout()

void Smf::SetSelectorList(const char* selectorMacAddrs, unsigned int numBytes)
{
    if (numBytes > SELECTOR_LIST_LEN_MAX)
    {
        PLOG(PL_ERROR, "Smf::SetSelectorList() error: excessive selector list size\n");
        numBytes = SELECTOR_LIST_LEN_MAX;
    }
    memcpy(selector_list, selectorMacAddrs, numBytes); 
    selector_list_len = numBytes;      
}  // end Smf::SetSelectorList()

void Smf::SetNeighborList(const char* neighborMacAddrs, unsigned int numBytes)
{
    if (numBytes > SELECTOR_LIST_LEN_MAX)
    {
        PLOG(PL_ERROR, "Smf::SetSelectorList() error: excessive selector list size\n");
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
}  // end Smf::IsSelector()

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
}  // end Smf::IsNeighbor()

