#include "smf.h"
//#include "smartController.h"
//#include "smartForwarder.h"

#include "smfHashMD5.h"
#include "smfHashSHA1.h"

#include "protoPktETH.h"
#include "protoPktIP.h"
#include "protoNet.h"
#include <random>

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
 : if_index(ifIndex), resequence(false), is_tunnel(false), is_layered(false), is_reliable(false),
   ip_encapsulate(false), dup_detector(NULL), unicast_group_count(0), recv_count(0), mrcv_count(0), 
   dups_count(0), asym_count(0), fwd_count(0), extension(NULL)
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
        // Note this should not happen since this frame was already parse earlier
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
   resequence(false), is_tunnel(false),
   elastic_mcast(false), elastic_ucast(false), adaptive_routing(false)
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

void Smf::InterfaceGroup::SetAdaptiveRouting(bool state)
{
    adaptive_routing = state;
    }

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


Smf::DpdType Smf::GetIPv6PktID(ProtoPktIPv6&   ip6Pkt,      // input
                               char*           flowId,      // output
                               unsigned int*   flowIdSize,  // input/output, in bits
                               char*           pktId,       // output
                               unsigned int*   pktIdSize)   // input/output, in bits
{
    ProtoPktIP::Protocol nextHeader = ip6Pkt.GetNextHeader();
    void* nextBuffer = ip6Pkt.AccessPayload();
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
        if (esp.InitFromBuffer(espLength, (char*)ip6Pkt.AccessPayload() + extHeaderLength, espLength))
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
int Smf::ProcessPacket(ProtoPktIP&         ipPkt,          // input/output - the packet (may be modified)
                       const ProtoAddress& srcMac,         // input - source MAC addr of packet
                       Interface&          srcIface,       // input - Smf::Interface on which packet arrived
                       unsigned int        dstIfArray[],   // output - list of interface indices to which packet should be forwarded
                       unsigned int        dstIfArraySize, // input - size of "dstIfArray[]" passed in
                       ProtoPktETH&        ethPkt,         // input/output - the ethernet packet (need to make sure size is changed correctly
                       bool                outbound,       // boolean that equals true if this packet is originating from this node
                       bool*               recvDup)        // returned value set to "true" if this a duplicate reception
{
    if (NULL != recvDup) *recvDup = false;  // will be checked and set later as appropriate
    if (!srcMac.IsValid())
    {
        PLOG(PL_WARN, "Smf::ProcessPacket() warning: invalid srcMacAddr from ifIndex: %d!\n", srcIface.GetIndex());
    }
    else
    {
        PLOG(PL_DEBUG, "\n\n\nSmf::ProcessPacket() processing pkt from srcMac: %s recv'd on ifIndex: %d...\n",
                 srcMac.GetHostString(), srcIface.GetIndex());
        PLOG(PL_DEBUG, "\n\n\nSmf::ProcessPacket() buffer size %d...\n",
                 ipPkt.GetBufferLength());

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
    bool is_tunnel = srcIface.IsTunnel();
    bool AR_mode = false;
    bool isARAck = false;

    PLOG(PL_DETAIL, "Smf::ProcessPacket() processing pkt IP version %d ...\n", version);
    switch (version)
    {

        case 4:
        {
            // This section of code makes sure its a valid packet to forward
            // per Section 4.0 of draft-ietf-manet-smf-06
            ProtoPktIPv4 ipv4Pkt(ipPkt);
            ipv4Pkt.GetDstAddr(dstIp);
            ipv4Pkt.GetSrcAddr(srcIp);
            PLOG(PL_DEBUG, "Smf::ProcessPacket(): IPv4 Packet detected: Source = %s\n", srcIp.GetHostString());
            PLOG(PL_DEBUG, "Smf::ProcessPacket(): IPv4 Packet detected: Destination = %s.\n" , dstIp.GetHostString());
            PLOG(PL_DEBUG, "Smf::ProcessPacket(): IPv4 Packet detected: ID = %d.\n" , (UINT16)ipv4Pkt.GetID());
            PLOG(PL_DEBUG, "Smf::ProcessPacket(): IPv4 Packet detected: TOS = %d.\n" , (UINT16)ipv4Pkt.GetTOS());
            PLOG(PL_DEBUG, "Smf::ProcessPacket(): IPv4 Packet detected: Length = %d.\n" , (UINT16)ipv4Pkt.GetLength());
            PLOG(PL_DEBUG, "Smf::ProcessPacket(): IPv4 Packet detected: FragmentOffset = %d.\n" , (UINT16)ipv4Pkt.GetFragmentOffset());


            if (!dstIp.IsMulticast() && !GetUnicastEnabled() && !GetAdaptiveRouting())      // only forward multicast dst, unless unicast enabled
            {

                PLOG(PL_DETAIL, "Smf::ProcessPacket() skipping non-multicast IPv4 pkt\n");
                return 0;
            }
            else if (dstIp.IsLinkLocal() && !is_tunnel)  // don't forward if link-local dst
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
            else
            {
                PLOG(PL_DETAIL, "Smf::ProcessPacket(): Non-link-local packet\n" );
            }

#ifdef ADAPTIVE_ROUTING
            // This section of the code handles acknowledgement packets, since they require no further processing.

             // Is this an ACK? (if so, notify controller)
                // ACKS are always udp packets, so
                // first, check for UDP
            if (ProtoPktIP::UDP == ipv4Pkt.GetProtocol())
            {
                ProtoPktUDP udpPkt;
                SmartPkt smartPkt;      // This is because we dont know if its an ACK or a Data packet
                // check for smart packet
                if (udpPkt.InitFromPacket(ipv4Pkt) &&
                    (udpPkt.GetDstPort() == SmartPkt::ADAPTIVE_PORT) &&
                    (ipv4Pkt.GetTOS() >>2 >= SmartPkt::ADAPTIVE_DSCP_MIN && ipv4Pkt.GetTOS() >> 2 <= SmartPkt::ADAPTIVE_DSCP_MAX) &&
                    (smartPkt.initFromBuffer(udpPkt.AccessPayload(), udpPkt.GetPayloadLength())))
                {
                    // Check to see if the packet is an ACK
                    if (smartPkt.isAck())
                    {

                        isARAck=true;
                        PLOG(PL_DEBUG, "Smf::ProcessPacket(): IPv4 Packet detected: Acknowledgement\n" );
                            // If it is, recast it from a SmartPacket to a SmartAck.
                        PLOG(PL_DEBUG, "Smf::ProcessPacket(): Buffer Lengths: eth = %d, ip = %d, ipv4 = %d, udp = %d\n", ethPkt.GetBufferLength(),ipPkt.GetBufferLength(), ipv4Pkt.GetBufferLength(), udpPkt.GetBufferLength() );
                        SmartAck smartAck(udpPkt.AccessPayload(), ipv4Pkt.GetBufferLength());

                        if (!IsOwnAddress(dstIp))
                        {
                            if (smart_controller->AsymmetricMode) // forward
                            {
                                PLOG(PL_DEBUG, "Smf::ProcessPacket(): Not for me, but asym mode\n" );
                                // Mark Packet... Then ignore? Until the end.
                                if (smartAck.flagIsSet(SmartPkt::FLAG_BCAST))
                                {
                                    PLOG(PL_DEBUG, "Smf::ProcessPacket(): Broadcast\n" );
                                    // DPD -- does this happen later?

                                    // Mark Packet.
                                    unsigned int dataLen = 0;
                                     // Shift the memory contents in the buffer to the right by 4 bytes (for an extra address) in the SmartPkt header.
                                    //memmove((char *)payloadPtr + 4, (char *)payloadPtr, dataLen);
                                    // Add the extra node to the path

                                    smartAck.appendNodeToPath(srcIface.GetInterfaceAddress());
                                    PLOG(PL_DEBUG, "SmartController:HandleAck. PathLength: %d\n", smartAck.getPathLength());
                                    PLOG(PL_DEBUG, "SmartController:HandleAck. Path: ");

                                    ProtoAddress tempAddr;
                                    for (int i = 0; i < smartAck.getPathLength(); i++)
                                    {
                                        smartAck.getPathNodeAt(i,tempAddr);
                                        if (GetDebugLevel() >= PL_DEBUG)
                                        {
                                            TRACE("%s, ", tempAddr.GetHostString());
                                        }

                                    }
                                    if (GetDebugLevel() >= PL_DEBUG)
                                    {
                                        TRACE("\n");
                                    }
                                    udpPkt.SetPayloadLength(udpPkt.GetPayloadLength()+8);
                                    ipv4Pkt.SetPayloadLength(udpPkt.GetLength());
                                    ipPkt.SetLength(ipv4Pkt.GetLength());
                                    // Reduce TTL (this should automatically happen)
                                    ProtoAddress bMAC;  // use broadcast ETH address for now
                                    bMAC.ResolveEthFromString("ff:ff:ff:ff:ff:ff"); // Set the mac address to the broadcast mac.
                                    ethPkt.SetDstAddr(bMAC);
                                    // Update metrics
                                    ethPkt.SetPayloadLength(ipPkt.GetLength());

                                }
                                else // This ack is not for me, and its a unicast ack meaning there is a path.
                                {
                                    PLOG(PL_DEBUG, "Smf::ProcessPacket(): Unicast\n" );
                                    // if you're not on the path, you must drop ACK.
                                    if(!smartAck.pathContains(srcIface.GetInterfaceAddress()))
                                    {
                                            PLOG(PL_DEBUG, "Smf::ProcessPacket(): I wasn't supposed to get this ack\n" );
                                            return -1;
                                    }
                                    PLOG(PL_DEBUG, "Smf::ProcessPacket(): On ACK path\n" );
                                    // otherwise we're on the path, which means we should forward ack.
                                    ProtoAddress nextHopMac;
                                    if(!smartAck.getNextAddress(srcIface.GetInterfaceAddress(),nextHopMac))
                                    {

                                        PLOG(PL_ERROR, "Smf::ProcessPacket(): Cannot forward ACK, bad path\n" );
                                        return -1;
                                    }

                                    ethPkt.SetDstAddr(nextHopMac);
                                    MulticastFIB::UpstreamRelayList relay_list = smart_controller->accessDownstreamRelayList();
                                    MulticastFIB::UpstreamRelay * nextHopRelay_ptr = (MulticastFIB::UpstreamRelay *)relay_list.FindUpstreamRelay(nextHopMac);
                                    ethPkt.SetSrcAddr(nextHopRelay_ptr->GetAddress());
                                    output_mechanism->SendFrame(nextHopRelay_ptr->GetInterfaceIndex(), (char*)ethPkt.GetBuffer(), ethPkt.GetLength());
                                    return 0;
                                }
                            }
                            else //if we're in symmetric mode, and we get an ack thats not for us
                            {
                                PLOG(PL_DEBUG, "Smf::ProcessPacket(): Dropping ACK due to being in symmetric mode, and getting an ack thats not for us.");
                                return -1; //drop
                            }

                        } // end if not our address
                        // Here, the ack is for us... we keep going with isARAck marked.

                    }
                    else if (smartPkt.isAd())
                    {
                        PLOG(PL_DEBUG, "Smf::ProcessPacket(): IPv4 Packet detected: Return Path Advertisement\n" );
                        SmartPathAd smartAd(udpPkt.AccessPayload(), udpPkt.GetPayloadLength());
                        smart_controller->HandlePathAdvertisement(smartAd, srcIp);
                        return 0; // No forward
                    }
                    else
                    {
                        // This is not an ACK. Mark Packet (after dpd)
                        PLOG(PL_DETAIL, "Smf::ProcessPacket() IpV4 SmartDataPkt Received\n");
                    }
                }
                else
                {
                    PLOG(PL_WARN, "Smf::ProcessPacket() warning: invalid ADAPTIVE ACK\n");
                }
            }
            else
            {
                PLOG(PL_WARN, "Smf::ProcessPacket() this packet is NOT a UDP Packet\n");
            }

#endif // ADAPTIVE_ROUTING

            // don't forward locally-generated packets // unless unicast enabled
            if (!outbound && IsOwnAddress(srcIp)) // && (dstIp.IsMulticast() || !GetUnicastEnabled()))
	        {
                // Locally generated packet
                PLOG(PL_DEBUG, "Smf::ProcessPacket() skipping locally-generated IPv4 pkt\n");
                if (NULL != recvDup) *recvDup = true; // so we don't receive our own unicast packets unnecessarily
                return 0;
            }
            else if (srcIp.IsLinkLocal() && !is_tunnel)  // don't forward if link-local src
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
            if ((ttl > 1) && !is_tunnel) ipv4Pkt.DecrementTTL();

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
            else if (dstIp.IsLinkLocal() && !is_tunnel)  // don't forward if link-local dst
            {
                PLOG(PL_DETAIL, "Smf::ProcessPacket() skipping link-local IPv6 pkt\n");
                return 0;
            }
            ipv6Pkt.GetSrcAddr(srcIp);
            if (!outbound && IsOwnAddress(srcIp))       // don't forward locally-generated packets
            {
                PLOG(PL_DETAIL, "Smf::ProcessPacket() skipping locally-generated IPv6 pkt\n");
                return 0;

            }
            else if (srcIp.IsLinkLocal() && !is_tunnel)  // don't forward if link-local src
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
            if ((ttl > 1) && !is_tunnel)
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
    // arrived (due to hearing a MANET neighbor forwarding this packet)
    // Also is srcIface is "layered", we mark the packet in its DPD table since
    // we don't re-forward "seen" packets on "layered" interfaces that have their
    // own independent multicast distribution mechanism.
    if (srcIface.GetResequence() || srcIface.IsLayered())
    {
        srcIface.IsDuplicatePkt(current_update_time, flowId, flowIdSize, pktId, pktIdSize);
    }

#ifdef ADAPTIVE_ROUTING

        // If there is an AdaptiveRouting interface group, this will
        // be looked up (or created as needed for new flowS)
        MulticastFIB::Entry* fibEntry = NULL;
        MulticastFIB::UpstreamRelay* nextHop = NULL;
        if (version != 4)
        {
            PLOG(PL_ERROR, "Smf::ProcessPacket() Must be ipv4\n");
            return 0;
        }
        ProtoPktIPv4 ipv4Pkt(ipPkt);

        //ProtoPktUDP udpPkt;         // We dont know if its a UDP packet, and we shouldn't actually use this.
        SmartDataPkt smartPkt;      // If it was an ACK, we would have handled it already.  TODO: Change for asymmetric.
        unsigned int pktCount = 0;
        bool duplicate = false;
        bool broadcast;
        bool duplicateMark = false;

        // Only interested in ipV4 packets
        // Initialize a smartPacket from the payload of the ip packet.
        if (!isARAck)
        {
            PLOG(PL_DEBUG, "Smf::ProcessPacket(): successfully initialized data packet\n" );
            // Check to see if that packet is a SmartPacket...
            if(ipv4Pkt.GetTOS() >>2 >= SmartPkt::ADAPTIVE_DSCP_MIN && ipv4Pkt.GetTOS() >> 2 <= SmartPkt::ADAPTIVE_DSCP_MAX)
            {
                PLOG(PL_DEBUG, "Smf::ProcessPacket(): SmartPkt\n" );
                if (outbound)
                {
                    //PLOG(PL_DEBUG, "Smf::ProcessPacket(): Outbound Smart Pkt\n" );
                    //PLOG(PL_DEBUG, "Smf::ProcessOutboundPacket(): After Mark: New UDP Length: Total: %d, Buffer: %d\n", udpPkt.GetLength(), udpPkt.GetBufferLength());
                    //PLOG(PL_DEBUG, "Smf::ProcessOutboundPacket(): After Mark: New IP Length: Total: %d, Buffer: %d\n", ipPkt.GetLength(), ipPkt.GetBufferLength());
                    //PLOG(PL_DEBUG, "Smf::ProcessOutboundPacket(): After Mark: New IPv4 Length: Total: %d, Buffer: %d\n", ipv4Pkt.GetLength(), ipv4Pkt.GetBufferLength());
                    //PLOG(PL_DEBUG, "Smf::ProcessOutboundPacket(): After Mark: New Eth Length: Total: %d, Buffer: %d\n", ethPkt.GetLength(), ethPkt.GetBufferLength());

                    // If this is a new, outbound packet, it has not had the SmartDataPkt header inserted yet.
                    // Here we add it.
                    // check buffer size. Need to incresae the buffer if the buffer isn't big enough. TODO: This hasn't been tested.
                    // If ethernet buffer is too small
                    if (ethPkt.GetLength() + 16 > ethPkt.GetBufferLength())
                    {
                        PLOG(PL_DEBUG, "Smf::ProcessOutboundPacket(): Need More ethernet buffer space\n");
                        UINT32 newBuffer[ethPkt.GetLength()/4 + 4];
                        unsigned int oldLen = ethPkt.GetBufferLength();

                        UINT32* ipBuffer = newBuffer + 4; // 14 bytes plus 2

                        memcpy((char *)newBuffer, (char*) ethPkt.GetBuffer(),ethPkt.GetBufferLength());
                        unsigned int ethBufferLen = ethPkt.GetBufferLength();
                        unsigned int ipBufferLen = ipv4Pkt.GetBufferLength();
                        ProtoPktETH ethPkt((UINT32*)newBuffer,   ethBufferLen+ 16);
                        ProtoPktIPv4 ipv4Pkt(ipBuffer,ipBufferLen + 16);

                    }
                    // If IP buffer is too small
                    else if (ipv4Pkt.GetLength() + 16 > ipv4Pkt.GetBufferLength())
                    {
                        PLOG(PL_DEBUG, "Smf::ProcessOutboundPacket(): Need More ip buffer space\n");
                        unsigned int ipBufferLen = ipv4Pkt.GetBufferLength();
                        UINT32* ipBuffer = (UINT32*)ethPkt.AccessPayload(); // 14 bytes plus 2
                        if (!ipPkt.InitFromBuffer(ethPkt.GetPayloadLength()+16,ipBuffer,ethPkt.GetPayloadLength()+16))
                        {
                            PLOG(PL_ERROR, "Smf::ProcessOutboundPacket():IP Packet modification\n");
                        }

                        ProtoPktIPv4 ipv4Pkt(ipPkt);
                    }
                    // Now we assume the buffer is "big enough".

                    // shift payload to the right by 16 bytes (dont make this constant). to make room for header.
                    // Figure out how long the actual pacekt user data is.
                    unsigned int ipDataLength = ipv4Pkt.GetPayloadLength();
                    PLOG(PL_DEBUG, "Smf::ProcessOutboundPacket(): Get IP Length\n");
                    int headerLen = smartPkt.getHeaderLengthNoPath()*4;
                    PLOG(PL_DEBUG, "Smf::ProcesOutboundPAcket(): adding %d bytes for the header\n",headerLen);
                    memmove((char*)ipv4Pkt.GetPayload()+headerLen, (char*)ipv4Pkt.GetPayload(),ipDataLength);




                    PLOG(PL_DEBUG, "Smf::ProcessOutboundPacket(): Complete Memmove\n");
                    // update data lengths
                    ipv4Pkt.SetPayloadLength(ipDataLength+16);
                    ipPkt.SetLength(ipv4Pkt.GetLength());           // Since data length is stored as a local variable
                    ethPkt.SetPayloadLength(ipv4Pkt.GetLength());
                    // Initialize smart header.
                    if(!smartPkt.initIntoBuffer(ipv4Pkt.AccessPayload(),ipv4Pkt.GetPayloadLength()))
                    {
                        PLOG(PL_ERROR, "Smf::ProcessOutboundPacket(): Smart Packet Initialization Failed\n");
                    }
                    // Just leave room for header for now
                    // Set source address in the header.
                    smartPkt.setSrcIPAddr(srcIp);
                    ProtoAddress newAddr;
                    smartPkt.getSrcIPAddr(newAddr);
                    PLOG(PL_DEBUG, "Smf::ProcessOutboundPacket(): Finished Initialization\n");

                }
                else // If this is not an outbound packet, dont need to add header.
                {
                    // Initialize packet header information, which should exist!
                    smartPkt.initFromBuffer(ipv4Pkt.AccessPayload(),ipv4Pkt.GetPayloadLength());

                }
            }
            else
            {
                PLOG(PL_DEBUG, "Smf::ProcessPacket(): Bad Packet: Packet Details:\nUDP?: %d\n", (ProtoPktIP::UDP == ipv4Pkt.GetProtocol()));
            }

        }

        // To simplify the constant checking of SmartPkt Requirements.
        bool isSmartPkt =   (ipv4Pkt.GetTOS() >> 2 >= SmartPkt::ADAPTIVE_DSCP_MIN && ipv4Pkt.GetTOS() >> 2 <= SmartPkt::ADAPTIVE_DSCP_MAX) &&
                            (smartPkt.initFromBuffer(ipv4Pkt.AccessPayload(), ipv4Pkt.GetPayloadLength()));
        Interface::AssociateList::Iterator iterator(srcIface);
        Interface::Associate* assoc;

        // Check for a duplicate packet.
        // This is DPD stage 2, where we look at the addresses marked in the packet.
        while (!isARAck && isSmartPkt && !duplicateMark && (NULL != (assoc = iterator.GetNextItem())))
        {
            if (smartPkt.pathContains(assoc->GetInterface().GetIpAddress()))
            {
                duplicateMark= true;
                // This is a duplicate packet, Drop
                PLOG(PL_DEBUG, "Smf::ProcessPacket(): Duplicate Copy! No Ack, No Forward\n");
                return 0;
            }
        }

        if (isSmartPkt && !duplicateMark && !isARAck)
        {

            // Here we add a Mark to the packet for the current node.

            // In the event that the currently allocated buffer is not large enough to add an additional node...
            // We need to increase the buffer size.
            if (ethPkt.GetLength() + 4 > ethPkt.GetBufferLength())
                {
                    PLOG(PL_DEBUG, "Smf::ProcessPacket(): Need More buffer space\n");
                    UINT32 newBuffer[ethPkt.GetLength()/4 + 1];
                    unsigned int oldLen = ethPkt.GetBufferLength();

                    UINT32* ipBuffer = newBuffer + 4; // 14 bytes plus 2

                    memcpy((char *)newBuffer, (char*) ethPkt.GetBuffer(),ethPkt.GetBufferLength());
                    unsigned int ethBufferLen = ethPkt.GetBufferLength();
                    unsigned int ipBufferLen = ipv4Pkt.GetBufferLength();
                    ProtoPktETH ethPkt((UINT32*)newBuffer,   ethBufferLen+ 4);
                    ProtoPktIPv4 ipv4Pkt(ipBuffer,ipBufferLen + 4);
                    smartPkt.initFromBuffer(ipv4Pkt.AccessPayload(), ipv4Pkt.GetPayloadLength()+4);
                }
                else if (ipv4Pkt.GetLength() + 4 > ipv4Pkt.GetBufferLength())
                {
                    unsigned int ipBufferLen = ipv4Pkt.GetBufferLength();
                    UINT32* ipBuffer = (UINT32*)ethPkt.AccessPayload(); // 14 bytes plus 2
                    if (!ipPkt.InitFromBuffer(ethPkt.GetPayloadLength()+4,ipBuffer,ethPkt.GetPayloadLength()+4))
                    {
                        PLOG(PL_ERROR, "Smf::ProcessPacket():IP Packet modification\n");
                    }

                    ProtoPktIPv4 ipv4Pkt(ipPkt);

                    smartPkt.initFromBuffer(ipv4Pkt.AccessPayload(), ipv4Pkt.GetPayloadLength()+4);

                }
                // At this point, the buffer is large enough to support the adding of a path.

                PLOG(PL_DEBUG, "Smf::ProcessPacket(): Marking... Original IP Length: %d\n", ipv4Pkt.GetPayloadLength());
                // Get a pointer to the user data.
                char* payloadPtr = (char*) smartPkt.getPayload();
                unsigned int dataLen = ipv4Pkt.GetPayloadLength() - (payloadPtr - (char*)ipv4Pkt.AccessPayload()); //convert word to bytes
                 // Shift the memory contents in the buffer to the right by 4 bytes (for an extra address) in the SmartPkt header.
                memmove(payloadPtr + 4, payloadPtr, dataLen);
                // Add the extra node to the path
                smartPkt.appendNodeToPath(srcIface.GetIpAddress());
                // Update packet lengths of all involved protocols.

                ipv4Pkt.SetPayloadLength(ipv4Pkt.GetPayloadLength()+4);
                ipPkt.SetLength(ipv4Pkt.GetLength());
                ethPkt.SetPayloadLength(ipv4Pkt.GetLength());

                PLOG(PL_DEBUG, "Smf::ProcessPacket(): Checking Received Packet... Q = %f\n", smartPkt.getQFactor());
                PLOG(PL_DEBUG, "Smf::ProcessPacket(): Checking Received Packet... C = %f\n", smartPkt.getCFactor());
                int pathlength = smartPkt.getPathLength();
                PLOG(PL_DEBUG, "Smf::ProcessPacket(): Checking Received Packet... Path length = %d\n", pathlength);
                ProtoAddress tempAddr;
                PLOG(PL_DEBUG, "Smf::ProcessPacket(): Checking Received Packet... Path: ", pathlength);

                for (int i = 0; i < pathlength; i++)
                {
                    smartPkt.getPathNodeAt(i,tempAddr);
                    if (GetDebugLevel() >= PL_DEBUG)
                    {
                        TRACE("%s, ", tempAddr.GetHostString());
                    }

                }
                if (GetDebugLevel() >= PL_DEBUG)
                {
                    TRACE("\n");
                }
                smartPkt.getSrcIPAddr(tempAddr);
                PLOG(PL_DEBUG, "Smf::ProcessPacket(): Checking Received Packet... src IP = %s\n", tempAddr.GetHostString());

        }
        if (isARAck)
        {
            broadcast = true;
        }
        else
        {
            // Update fib entry
            bool updateController;
            // Parse Flow list code added to mcastFib
            // This will make sure flow table is updated, and find the relevant fibEntry.
            if(!mcast_fib.ParseFlowList(ipPkt,fibEntry,time_ticker.Update(),updateController, srcMac)){
                PLOG(PL_ERROR, "Smf::ProcessPacket(): Unable to parse flow list\n");
                return 0;
            }
            // Add the flow to the controller if we need to. This is set via the ParseFlowList function.
            if (updateController)
            {
                PLOG(PL_DEBUG, "Smf::ProcessPacket(): New Flow, Updating Controller\n");
                smart_controller->AddFlow(fibEntry->GetFlowDescription());
            }
            // Now fib entry exists, we can ask for probability, and randomly decide whether to broadcast.
            nextHop = fibEntry->getDownstreamRelay();
            // Generate a random number
            double rand_num = ((double) rand() / (RAND_MAX));
            PLOG(PL_DEBUG, "Smf::ProcessPackeT(): Flow Table look up -> Next hop = %s.\n", nextHop->GetAddress().GetHostString());
            PLOG(PL_DEBUG, "Smf::ProcessPackeT(): Flow Table look up -> P(Unicast) = %f.\n", fibEntry->getUnicastProb());
            // Compute whether or not to broadcast, based on UnicastProbability of the fibEntry, and the generated random number
            broadcast = rand_num >= fibEntry->getUnicastProb();
            // debug.
            if (broadcast)
            {
                PLOG(PL_DEBUG, "Smf::ProcessPacket(): Random Decision: broadcast.\n");
            }
            else
            {
                PLOG(PL_DEBUG, "Smf::ProcessPacket(): Random Decision: unicast\n");
            }
        }

#endif // ADAPTIVE_ROUTING

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
    int dstCount = 0;
    bool ecdsBlock = false;
    bool forward = false;

#ifdef ADAPTIVE_ROUTING
    // If we're in ADAPTIVE_ROUTING, we've already defined the iterator.
    iterator.Reset();
#else
    Interface::AssociateList::Iterator iterator(srcIface);
    Interface::Associate* assoc;
#endif // ADAPTIVE_ROUTING

    // Loop through each interface.
    while (NULL != (assoc = iterator.GetNextItem()))
    {
        InterfaceGroup& ifaceGroup = assoc->GetInterfaceGroup();
        RelayType relayType = ifaceGroup.GetRelayType();
#ifdef ELASTIC_MCAST
        bool elastic = ifaceGroup.GetElasticMulticast();  // yyy - change to use IsElastic() method
#else
        bool elastic = false;
#endif // if/else ELASTIC_MCAST
#ifdef  ADAPTIVE_ROUTING
        bool adaptive = ifaceGroup.GetAdaptiveRouting();
#else
        bool adaptive = false;
#endif
        // Should we forward this packet on this associated "dstIface"?
        bool ifaceForward = false;
        bool updateDupTree = false;
        switch (relayType)
        {
            case CF:
            {
                ifaceForward = relay_enabled;
                updateDupTree = ifaceForward;
                PLOG(PL_DEBUG, "Smf::ProcessPacket(): Forward on interface?: %d\n", ifaceForward );
                break;
            }
            case E_CDS:
            {
 		        if (dstIp.IsMulticast())
                {
		            PLOG(PL_MAX, "nrlsmf: E_CDS relay_enable:%d relay_selected:%d\n", relay_enabled, relay_selected);
		            ifaceForward = (relay_enabled && relay_selected);
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
		        updateDupTree = ifaceForward;
                break;
            }
            case S_MPR:
            {
                bool isSelector = IsSelector(srcMac);
#ifdef ELASTIC_MCAST
                elastic &= isSelector;
#endif // ELASTIC_MCAST
#ifdef ADAPTIVE_ROUTING
                adaptive &= isSelector;
#endif
                ifaceForward = relay_enabled && isSelector;
                if (IsNeighbor(srcMac))
                {
                    updateDupTree = true;
                }
                else if (ifaceForward)
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
#ifdef ADAPTIVE_ROUTING
        smart_controller->UpdateInterfaces(dstIface.GetInterfaceAddress(),dstIface.GetIndex());
#endif // ADAPTIVE_ROUTING
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
                         ifaceForward, flowIdSize, flowIdText, pktIdSize, pktIdText);
        }
        // For Elastic Multicast, we always need to do the duplicate check
        //PLOG(PL_DEBUG, "Smf::ProcessPacket(): Duplicate Packet Detection:  \n");
        if (ifaceForward || elastic || adaptive || (updateDupTree && (&dstIface == &srcIface)))
        {
            if (dstIface.IsDuplicatePkt(current_update_time, flowId, flowIdSize, pktId, pktIdSize))
            {
                PLOG(PL_DEBUG, "nrlsmf: received duplicate IPv%d packet ...\n", version);
                dups_count++;
                dstIface.IncrementDuplicateCount();
#ifdef ELASTIC_MCAST
                elastic = false;  // ElasticMulticast only pays attention to non-duplicates
#endif // ELASTIC_MCAST
                ifaceForward = false;
                if ((NULL != recvDup) && (&dstIface == &srcIface))
                    *recvDup = true;
#ifdef ADAPTIVE_ROUTING
                // If duplicate packet detection phase 1 in SRR finds a duplicate...
                duplicate = true;   // Smart Routing pays attention to both duplicates and non-duplicates, but will not forward duplicates.
                if (isARAck)
                {
                    PLOG(PL_DEBUG, "Smf::ProcessPacket(): Duplicate ACK!! Dropping...\n");
                    return 0;
                }
                if (duplicateMark)
                {
                    // We do not ack or forward if we fail both DPD's
                    adaptive = false; // This shouldn't even be ack'd, SmartRouting can ignore this.
                    PLOG(PL_DEBUG, "Smf::ProcessPacket(): Duplicate Packet!! \n");
                }
#endif // ADAPTIVE_ROUTING
            }
        }

	    if (srcMac.IsValid() && IsOwnAddress(srcMac) && !outbound) // don't forward locally-generated packets captured
	    {
#ifdef ADAPTIVE_ROUTING
                int temp = 0;
                PLOG(PL_DEBUG, "Smf::ProcessPacket(): Local packet, noop.\n");
#else
                PLOG(PL_DETAIL, "Smf::ProcessPacket() skipping locally-generated IP pkt\n");
                return 0;
#endif // ADAPTIVE_ROUTING
	    }

#ifdef ADAPTIVE_ROUTING
        // Process ACK here (after duplicate packet detection)
        if (isARAck && IsOwnAddress(dstIp))
        {
            ProtoPktUDP udpPkt;
            udpPkt.InitFromPacket(ipv4Pkt);
            SmartAck smartAck(udpPkt.AccessPayload(), udpPkt.GetBufferLength());
            PLOG(PL_DEBUG, "Smf::ProcessPacket():  ACK for me, handling\n" );
            // TODO: Is it for me? If not we need to forward it.
            // Send ack to controller for processing.
            smart_controller->HandleAck(smartAck,srcIface.GetIndex(), srcMac, srcIface.GetInterfaceAddress(), (UINT16)ipv4Pkt.GetID());
            return -1;
        }

        // Mark forward bool based on broadcast and DPD result
        if (adaptive && isSmartPkt && !IsOwnAddress(dstIp) && !duplicate)
        {
            PLOG(PL_DEBUG, "Smf::ProcessPacket(): adaptive Routing processing \n ");
            if (broadcast)
            {
                ifaceForward = true;
            }
            else
            {
                //PLOG(PL_DEBUG, "Smf::ProcessPacket(): unicast processing: next hop interface = %d, this interface = %d \n ", nextHop->GetInterfaceIndex(),dstIface.GetIndex());
                if (nextHop->GetInterfaceIndex() == dstIface.GetIndex())
                {
                    ifaceForward =  true;
                }
                else
                {
                    ifaceForward = false;
                }
            }


        }
        else
        {
            PLOG(PL_DEBUG, "local packet, do not forward \n ");
            ifaceForward = false;
        }
#endif // ADAPTIVE_ROUTING
#ifdef ELASTIC_MCAST
        if (IsOwnAddress(dstIp))
        {
            // Don't forward unicast packets destined to ourself
            ifaceForward = false;
        }
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
                        TRACE(" ( SMF forwarder: %d)\n", ifaceForward);
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
                        TRACE(" ( SMF forwarder: %d)\n", ifaceForward);
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
                        PLOG(PL_ALWAYS, " ackingStatus:%d SMF forwarder: %d\n", fibEntry->GetAckingStatus(), ifaceForward);
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
                    if (fibEntry->GetAckingStatus()) sendAck = true;
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
                if (ifaceForward)
                    ifaceForward = bucket->ProcessPacket(currentTick);
            }
            else
            {
                PLOG(PL_ERROR, "Smf::ProcessPacket() error: new MulticastFIB::TokenBucket error: %s\n", GetErrorString());
                ifaceForward = false;  // for safety? TBD - or should we forward by default on error???
            }
        }  // end if (elastic)
#endif  // ELASTIC_MCAST
        
        if (ifaceForward && srcIface.IsLayered())
        {
            // This check is likely redundant since the srcIface.IsLeyered() check
            // above marks the packet as duplicate checked and "ifaceForward"
            // should thus be "false" and we never will get here ...
            if (dstIface.GetIndex() == srcIface.GetIndex())
                ifaceForward = false;  // don't relay on same iface if layered
        }
        // If we forward on this interface...
        if (ifaceForward)
        {
            if (((ttl > 1) || is_tunnel) && (dstCount < dstIfArraySize))
                dstIfArray[dstCount] = dstIface.GetIndex();
            dstCount++;
            PLOG(PL_DEBUG, "Smf::ProcessPacket(): Preparing to forward! DstCount = %d \n", dstCount );
        }
        // If we forward on any interface, then set the global forward boolean.
        forward = forward | ifaceForward;
    }

#ifdef ADAPTIVE_ROUTING
    // Planning to send an ACK
    if (isARAck)

    {
        if (forward)
        {
            ProtoAddress broadcastMAC;  // use broadcast ETH address for now
            broadcastMAC.ResolveEthFromString("ff:ff:ff:ff:ff:ff"); // Set the mac address to the broadcast mac.
            ethPkt.SetDstAddr(broadcastMAC);
            ethPkt.SetPayloadLength(ipPkt.GetLength());
            }
        else
            return 0;
        //}
//        else // If we're going to unicast the packet.
//        {
//            // Find host address:
//            ProtoAddress nextIp, currentIp = srcIface.GetIpAddress();
//            if (!smartAck.getNextAddress(currentIp,nextIp))
//            {
//                return 0;
//            }
//
//            ethPkt.SetDstAddr(nextHop->GetAddress()); // use the unicast MAC address
//            // Update metrics.
//            smart_controller->ProcessUnicastPacket(fibEntry->GetFlowDescription(),nextHop, (UINT16)ipv4Pkt.GetID(), (UINT16)ipv4Pkt.GetFragmentOffset());
//            ethPkt.SetPayloadLength(ipPkt.GetLength());
//        }


    }
    else if (isSmartPkt)
    {
        if (!outbound && true) // Only send ACK's if you received this packet.  If you're sending the initial packet, we dont need to ack.
        {


            // Grab some buffer space
            UINT32 ackBuffer[1400/4];
            ProtoAddress dstIpAddr;
            // Figure out to whom to send the ack.
            smartPkt.getSrcIPAddr(dstIpAddr);
            // Let the controller Build the ACK, since it has all the information.
            ProtoAddress  dstMac(srcMac);
            smart_controller->UpdateNeighbors(srcIface.GetInterfaceAddress(),srcMac);
            unsigned int ackLength = smart_controller->BuildAck(ackBuffer,                                      //buffer
                                                                1400,                                           // buffer length
                                                                dstMac,                                         // dst mac
                                                                srcIface.GetInterfaceAddress(),                 // src mac
                                                                dstIpAddr,                                      // ip of node for whom the ack is destined
                                                                srcIface.GetIpAddress(),                        // ip of node who is sending the ack
                                                                srcMac,                                         // mac of who sent original packet
                                                                srcIface.GetInterfaceAddress(),                 // mac of who received original packet
                                                                fibEntry->GetFlowDescription(),                 // flow description
                                                                (UINT16)ipv4Pkt.GetID(),                        // sequence number
                                                                (UINT32)ipv4Pkt.GetFragmentOffset(),
                                                                IsOwnAddress(dstIp),
                                                                smartPkt.flagIsSet(SmartPkt::FLAG_BCAST));
            //PLOG(PL_DEBUG, "Smf::ProcessPacket(): Ack Built \n ");
            if (0 != ackLength)
            {

                if (GetDebugLevel() >= PL_DEBUG)
                {
                    PLOG(PL_ALWAYS, "nrlsmf: sending Smart ACK for flow \"");
                    fibEntry->GetFlowDescription().Print();  // to debug output or log
                    PLOG(PL_ALWAYS, " to mac address %s\n", dstMac.GetHostString());
                    PLOG(PL_DEBUG, "Source IP = %s\n", srcIface.GetIpAddress().GetHostString());
                    PLOG(PL_DEBUG, "Destination IP= %s.\n" , dstIpAddr.GetHostString());
                }
                // Send the ack.
                // If its a unicast, or if its a broadcast, need to send differently.
                if (smart_controller->AsymmetricMode)
                {
                    if (smartPkt.flagIsSet(SmartPkt::FLAG_BCAST)) // forward broadcast acknowledgement
                    {
                        // broadcast packet
                        unsigned int ackDstIfIndices[dstIfArraySize];
                        unsigned int numInterfaces = GetInterfaceList(srcIface,ackDstIfIndices,dstIfArraySize);
                        PLOG(PL_DEBUG, "Number of interfaces: %d\n", numInterfaces);
                        for (int i = 0; i < numInterfaces; i++)
                        {

                            PLOG(PL_DEBUG, "Sending over Interface %d: ID: %d, Addr: %s\n", i+1, ackDstIfIndices[i], GetInterface(ackDstIfIndices[i])->GetInterfaceAddress().GetHostString());
                            output_mechanism->SendFrame(ackDstIfIndices[i], ((char*)ackBuffer) + 2, ackLength);
                        }

                    }
                    else // forward unicast acknowlegement
                    {

                        PLOG(PL_DEBUG, "Unicast forwarding \n" , dstIpAddr.GetHostString());
                        MulticastFIB::UpstreamRelayList relay_list = smart_controller->accessDownstreamRelayList();
                        PLOG(PL_DEBUG, "Retrieved Downsream interface list .\n" , dstIpAddr.GetHostString());

                        MulticastFIB::UpstreamRelay * nextHopRelay_ptr = (MulticastFIB::UpstreamRelay *)relay_list.FindUpstreamRelay(dstMac);
                        if (NULL != nextHopRelay_ptr)
                        {
                            PLOG(PL_DEBUG, "Relay found\n");
                            output_mechanism->SendFrame(nextHopRelay_ptr->GetInterfaceIndex(), ((char*)ackBuffer) + 2, ackLength);
                        }
                        else
                        {
                            PLOG(PL_ERROR, "No Relay with MAc address %s.... Broadcasting\n" , dstMac.GetHostString());
                             unsigned int ackDstIfIndices[dstIfArraySize];
                            unsigned int numInterfaces = GetInterfaceList(srcIface,ackDstIfIndices,dstIfArraySize);
                            PLOG(PL_DEBUG, "Number of interfaces: %d\n", numInterfaces);
                            for (int i = 0; i < numInterfaces; i++)
                            {

                                PLOG(PL_DEBUG, "Sending over Interface %d: ID: %d, Addr: %s\n", i+1, ackDstIfIndices[i], GetInterface(ackDstIfIndices[i])->GetInterfaceAddress().GetHostString());
                                output_mechanism->SendFrame(ackDstIfIndices[i], ((char*)ackBuffer) + 2, ackLength);
                            }
                        }

                    }
                }
                else{
                    output_mechanism->SendFrame(srcIface.GetIndex(), ((char*)ackBuffer) + 2, ackLength);
                }
            }
            // The actual packet needs to be marked with the current IP address.
            smartPkt.setSrcIPAddr(srcIface.GetIpAddress()); // Set IP address so destination knows who to ack. This should NOT change size of packet.
            // If this is an outbound packet, this has already been done when the header was created.
        }
        else
        {
            PLOG(PL_DEBUG, "Smf::ProcessPacket(): Outbound packet: no ACK needed \n ");
        }
        // If we  need to forward the packet: (This isn't the destination && this wasn't a duplicate)
        if (forward)
        {
            // If we're going to broadcast the packet:
            if (broadcast)
            {
                //PLOG(PL_DEBUG, "Smf::ProcessPacket(): Sending Broadcast \n ");
                // eth packet needs to be addressed to broadcast eth address. I *think* this happens, but just to be sure.
                smartPkt.setFlag(SmartPkt::FLAG_BCAST);
                ProtoAddress broadcastMAC;  // use broadcast ETH address for now
                broadcastMAC.ResolveEthFromString("ff:ff:ff:ff:ff:ff"); // Set the mac address to the broadcast mac.
                ethPkt.SetDstAddr(broadcastMAC);
                // Update metrics
                smart_controller->ProcessBroadcastPacket(fibEntry->GetFlowDescription(),(UINT16) ipv4Pkt.GetID(), (UINT16)ipv4Pkt.GetFragmentOffset());
                ethPkt.SetPayloadLength(ipPkt.GetLength());
            }
            else // If we're going to unicast the packet.
            {
                if (smart_controller->AsymmetricMode && smart_controller->checkForAdvertisement(fibEntry->GetFlowDescription(),nextHop->GetAddress()))
                {
                    UINT32 adBuffer[1400/4];
                    ProtoAddress broadcastIP;
                    broadcastIP.ResolveFromString("255.255.255.255");
                    unsigned int adLength = smart_controller->BuildPathAd(adBuffer,1400,nextHop->GetAddress(),srcIface.GetInterfaceAddress(),broadcastIP,srcIface.GetIpAddress() );
                    if (0 < adLength)
                    {
                        output_mechanism->SendFrame(dstIfArray[0], ((char*)adBuffer) + 2, adLength); // Send over the one interface we're going to unicast over.
                    }
                }
                smartPkt.resetFlag(SmartPkt::FLAG_BCAST);
                //PLOG(PL_DEBUG, "Smf::ProcessPacket(): Sending Unicast \n ");
                ethPkt.SetDstAddr(nextHop->GetAddress()); // use the unicast MAC address
                // Update metrics.
                smart_controller->ProcessUnicastPacket(fibEntry->GetFlowDescription(),nextHop, (UINT16)ipv4Pkt.GetID(), (UINT16)ipv4Pkt.GetFragmentOffset());
                ethPkt.SetPayloadLength(ipPkt.GetLength());
            }
            if (GetDebugLevel() >= PL_DEBUG)
            {
                PLOG(PL_ALWAYS, "nrlsmf: sending Smart Packet for flow \"");
                fibEntry->GetFlowDescription().Print();  // to debug output or log
                PLOG(PL_ALWAYS, " to  mac dest, %s\n", nextHop->GetAddress().GetHostString());
            }
        }
        else
        {
            PLOG(PL_DEBUG, "Smf::ProcessPacket(): No Forward \n ");
             if (IsOwnAddress(dstIp))
             {
                // Here we need to strip out the R2DN header before the packet goes upstreawm.
                // Packet length = 16 bytes + 4 * (length of path). This might change...
                PLOG(PL_DEBUG, "Smf::ProcessPacket(): Removing SRR header \n ");
                // Get a pointer to the original UDP data
                char* ipDataPtr = (char*)smartPkt.getPayload();
                // Get a pointer to the start of the smartPkt.
                char* pktPtr = (char*) ipv4Pkt.GetPayload();
                // Figure out how long the data is
                unsigned int dataLen = ipv4Pkt.GetPayloadLength() - (ipDataPtr - (char*)ipv4Pkt.AccessPayload()); //convert word to bytes
                 PLOG(PL_DEBUG, "Smf::ProcessPacket(): Data Length: %d \n ", dataLen);
                 PLOG(PL_DEBUG, "Smf::ProcessPacket(): Header Length: %d \n ", ipDataPtr - pktPtr);
                 // Shift the memory contents in the buffer to the right by 4 bytes (for an extra address) in the SmartPkt header.
                memmove(pktPtr, ipDataPtr, dataLen);
                // Update packet lengths of all involved protocols.
                ipv4Pkt.SetPayloadLength(dataLen);
                ipPkt.SetLength(ipv4Pkt.GetLength());
                ethPkt.SetPayloadLength(ipv4Pkt.GetLength());

                if (duplicate || duplicateMark)
                    dstCount = 0;
            }
        }
        if (GetDebugLevel() >= PL_DEBUG)
            smart_controller->PrintRLMetrics();
    }

#endif // ADAPTIVE_ROUTING

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

    if ((dstCount > 0) && ((ttl <= 1) && !is_tunnel))
    {
        PLOG(PL_DEBUG, "nrlsmf: received ttl-expired packet (ttl = %d)...\n", ttl);
        dstCount = 0;
    }
    if (dstCount > 0)
    {
        PLOG(PL_DEBUG, "Smf::ProcessPacket(): Preparing to forward! \n");
        fwd_count++;
        srcIface.IncrementForwardCount();
    }

    if((dstCount > 0) && ecdsBlock)
    {
        PLOG(PL_DEBUG, "Smf::ProcessPacket(): ECDS Block \n" );
	    // This node is not a selected ECDS relay
	    // Treat unicast packets specially
	    dstCount = -1;
    }

#ifdef ADAPTIVE_ROUTING
    PLOG(PL_DEBUG, "Smf::ProcessPacket(): Return Value: %d\n",dstCount);
    PLOG(PL_DEBUG, "Smf::ProcessOutboundPacket(): After Mark: New IP Length: Total: %d\n", ipPkt.GetLength());
    PLOG(PL_DEBUG, "Smf::ProcessOutboundPacket(): After Mark: New IPv4 Length: Total: %d, Payload: %d\n", ipv4Pkt.GetLength(), ipv4Pkt.GetPayloadLength());
    PLOG(PL_DEBUG, "Smf::ProcessOutboundPacket(): After Mark: New Eth Length: Total: %d, Payload: %d\n", ethPkt.GetLength(), ethPkt.GetPayloadLength());


#endif // ADAPTIVE_ROUTING
    PLOG(PL_DEBUG, "Smf::ProcessPacket(): Preparing to forward! Returning = %d \n",dstCount );
    return dstCount;

}  // end Smf::ProcessPacket()

#if defined(ELASTIC_MCAST) || defined(ADAPTIVE_ROUTING)
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

unsigned int Smf::GetInterfaceList(Interface& srcIface, unsigned int dstIfArray[], int dstIfArrayLength)
{
    Interface::AssociateList::Iterator iterator(srcIface);
    Interface::Associate* assoc;
    unsigned int dstCount = 0;

    while (NULL != (assoc = iterator.GetNextItem()))
    {
        if (assoc->GetInterfaceGroup().GetAdaptiveRouting())
        {
            Interface& dstIface = assoc->GetInterface();
            if (dstCount < dstIfArrayLength)
                dstIfArray[dstCount] = dstIface.GetIndex();
            dstCount++;
        }
    }
    return dstCount;
}

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

