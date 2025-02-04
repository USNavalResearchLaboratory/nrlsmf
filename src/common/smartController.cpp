
#include "mcastFib.h"
#include "protoNet.h"  // to get interface addresses given interface indices (TBD - addresses should be configured w/ indices externally)
#include "protoPktETH.h"
#include "protoPktIP.h"
#include "protoDebug.h"
#include <stdlib.h>
#include <math.h>
#include <iostream>
#include <algorithm>
#include <limits>

#include "r2dnMsg.h"
#include "smartController.h"
#include "smartForwarder.h"



///////////////////////////////////////////////////////////////////////////////////
// class SmartController implementation
//



SmartController::SmartController(ProtoTimerMgr& timerMgr)
  : timer_mgr(timerMgr)
{
    membership_timer.SetInterval(0);
    membership_timer.SetRepeat(-1);
    membership_timer.SetListener(this, &SmartController::OnMembershipTimeout);

}


SmartController::~SmartController()
{
}

void SmartController::SetForwarder(SmartForwarder* forwarder)
    {smart_forwarder = forwarder;}

bool SmartController::AddManagedMembership(unsigned int ifaceIndex, const ProtoAddress& groupAddr)
{
    if (GetDebugLevel() >= PL_DEBUG)
        PLOG(PL_DEBUG, "SmartController::AddManagedMembership(%s) ...\n", groupAddr.GetHostString());
    MulticastFIB::Membership* membership = membership_table.AddMembership(ifaceIndex, groupAddr);
    if (NULL == membership)
    {
        PLOG(PL_ERROR, "SmartController::AddManagedMembership() error: unable to add new membership\n");
        return false;
    }
    if (GetDebugLevel() >= PL_DEBUG)
    {
        PLOG(PL_ALWAYS, "SmartController::AddManagedMembership() new membership added ");
        membership->GetFlowDescription().Print();
        PLOG(PL_ALWAYS, "\n");
    }
    if (0 == membership->GetFlags())
        smart_forwarder->SetAckingStatus(membership->GetFlowDescription(), true);
    // Set MANAGED status for  _all_ matching memberships for this "ifaceIndex"
    //MulticastFIB::MembershipIterator iterator(membership_table, membership->GetFlowDescriptionPtr(), ifaceIndex);


    MulticastFIB::MembershipTable::Iterator iterator(membership_table, &membership->GetFlowDescription());
    while (NULL != (membership = iterator.GetNextEntry()))
    {
        // TBD - "activate" MANAGED membership with timeout instead?
        if (membership->GetInterfaceIndex() == ifaceIndex)
            membership->SetFlag(MulticastFIB::Membership::MANAGED);
    }
    return true;
}  // end SmartController::AddManagedMembership()


// The external input mechanism passes these in
// (Right this only handles "outbound" (locally generated) IGMP messages.
//  In the future, full router IGMP queries, timeouts, etc will be supported)
void SmartController::HandleIGMP(ProtoPktIGMP& igmpMsg, const ProtoAddress& srcIp, unsigned int ifaceIndex, bool inbound)
{
    if (inbound) return;  // only pay attention to outbound (locally generated) IGMP messages for an interface
    switch (igmpMsg.GetType())
    {
        case ProtoPktIGMP::REPORT_V3:
        {
            ProtoPktIGMP::GroupRecord groupRecord;
            while (igmpMsg.GetNextGroupRecord(groupRecord))
            {
                ProtoAddress groupAddr;
                groupRecord.GetGroupAddress(groupAddr);
                if (groupAddr.IsLinkLocal()) break;  // ignoore link local join / leave messages
                unsigned int nsrc = groupRecord.GetNumSources();
                if (0 == nsrc)
                {
                    if (ProtoPktIGMP::GroupRecord::CHANGE_TO_EXCLUDE_MODE == groupRecord.GetType())
                    {
                        // ASM join (with 0 == nsrc, semantic is "exclude no sources", i.e., "include all source")
                        //if (GetDebugLevel() >= PL_DEBUG)
                            PLOG(PL_ALWAYS, "nrlsmf: IGMPv3 JOIN group %s\n", groupAddr.GetHostString());
                        if (!AddManagedMembership(ifaceIndex, groupAddr))
                        {
                            PLOG(PL_ERROR, "SmartController::HandleIGMP() error: unable to add new membership\n");
                            return;
                        }
                    }
                    else if (ProtoPktIGMP::GroupRecord::CHANGE_TO_INCLUDE_MODE == groupRecord.GetType())
                    {
                        // ASM join (with 0 == nsrc, semantic is "include no sources", i.e., "exclude all sources")
                        //if (GetDebugLevel() >= PL_DEBUG)
                            PLOG(PL_ALWAYS, "nrlsmf: IGMPv3 LEAVE group %s\n", groupAddr.GetHostString());
                        // Clear MANAGED status for all matching memberships for this ifaceIndex
                        // but iterate over _all_ matching memberships to see if we should still be
                        // acking or not
                        bool match = false;
                        bool ackingStatus = false;
                        ProtoFlow::Description flowDescription(groupAddr, PROTO_ADDR_NONE, 0x03, ProtoPktIP::RESERVED);
                        MulticastFIB::MembershipTable::Iterator iterator(membership_table, &flowDescription);
                        MulticastFIB::Membership* membership;
                        while (NULL != (membership = iterator.GetNextEntry()))
                        {
                            match = true;
                            if (membership->GetInterfaceIndex() == ifaceIndex)
                                membership->ClearFlag(MulticastFIB::Membership::MANAGED);
                            if (0 == membership->GetFlags())
                            {
                                membership_table.RemoveEntry(*membership);
                                delete membership;
                            }
                            else
                            {
                                ackingStatus = true;
                            }
                        }
                        if (match && !ackingStatus)
                            smart_forwarder->SetAckingStatus(flowDescription, false);
                    }
                }
                else
                {
                    //if (GetDebugLevel() >= PL_DEBUG)
                    {
                        PLOG(PL_ALWAYS, "nrlsmf: IGMPv3 SSM REPORT ...\n");
                        for (unsigned int i = 0; i < nsrc; i++)
                        {
                            ProtoAddress srcAddr;
                            groupRecord.GetSourceAddress(i, srcAddr);
                            PLOG(PL_ALWAYS, "   (SSM src: %s)\n", srcAddr.GetHostString());
                        }
                    }
                }
            }
            break;
        }
        case ProtoPktIGMP::REPORT_V1:
        {
            ProtoAddress groupAddr;
            igmpMsg.GetGroupAddress(groupAddr);
            //if (GetDebugLevel() >= PL_DEBUG)
                PLOG(PL_ALWAYS, "nrlsmf: IGMPv1 JOIN group %s\n", groupAddr.GetHostString());
            break;
        }
        case ProtoPktIGMP::REPORT_V2:
        {
            ProtoAddress groupAddr;
            igmpMsg.GetGroupAddress(groupAddr);
            //if (GetDebugLevel() >= PL_DEBUG)
                PLOG(PL_ALWAYS, "nrlsmf: IGMPv2 JOIN group %s\n", groupAddr.GetHostString());
            break;
        }
        case ProtoPktIGMP::LEAVE:
        {
            ProtoAddress groupAddr;
            igmpMsg.GetGroupAddress(groupAddr);
            //if (GetDebugLevel() >= PL_DEBUG)
                PLOG(PL_ALWAYS, "nrlsmf: IGMPv2 LEAVE group %s\n", groupAddr.GetHostString());
            break;
        }
        default:
        {
            PLOG(PL_WARN, "nrlsmf: invalid/unknown IGMP message?!\n");
            break;
        }
    }
}  // end SmartController::HandleIGMP()
bool SmartController::AddFlow(const ProtoFlow::Description& flowDescription)
{
 /*   struct FlowSort
    {
        bool operator() (const ProtoFlow::Description& left, const ProtoFlow::Description& right)
        {
            return left.GetTrafficClass() < right.GetTrafficClass();
        }
    };
    PLOG(PL_DEBUG, "before trouble\n");
    flowDescription.Print();
    TRACE("\n");
    // Binary Search.
    std::vector<ProtoFlow::Description>::iterator it = std::lower_bound(sortedFlowTable.begin(),sortedFlowTable.end(), flowDescription, FlowSort());
    PLOG(PL_DEBUG, "Iterator returned position %d\n", it-sortedFlowTable.begin());
    PLOG(PL_DEBUG, "middle trouble\n");
    sortedFlowTable.insert(it,flowDescription);
    // check to see if flowDescription exists
    PLOG(PL_DEBUG, "after trouble\n");
    */
    return metric_table.addFlow(flowDescription);

}

unsigned int SmartController::BuildPathAd(UINT32*           buffer,
                                     unsigned int           length,
                                     const ProtoAddress&    dstMac,  // also used for ACK upstream relay addr
                                     const ProtoAddress&    srcMac,
                                     const ProtoAddress&    dstIp,      // Destination IP of ack (who sent the packet)
                                     const ProtoAddress&    srcIp)
{
    // IPv4-only at moment
    Path * returnPath_ptr = (Path * )return_path_list.GetUserData(dstMac);


    PLOG(PL_DEBUG, "SmartController::BuildPathAd(): beginning build ad for dstMac %s \n ", dstMac.GetHostString());
    if (ProtoAddress::IPv4 != srcIp.GetType())
    {
        PLOG(PL_ERROR, "SmartController::BuildPathAd() error: non-IPv4 src address! (IPv6 support is TBD)\n");
        return 0;
    }

    unsigned int ipHeaderLen = 20;
    if (length < (14 + ipHeaderLen+ 8))
    {
        PLOG(PL_ERROR, "SmartController::BuildPathAd() error: insufficient 'buffer' length!\n");
        return 0;
    }
    // Build an ACK to send to the identified  relay
    // The ACK will be sent to the "relayAddr" (MAC addr) via the "ifaceIndex" interface
    // (as a UDP/IP packet with multicast dest addr and source IP addr of given "ifaceIndex")

    unsigned int frameLength = length - 2;  // offset by 2 bytes to maintain alignment for ProtoPktIP
    UINT16* ethBuffer = ((UINT16*)buffer) + 1;  // offset for IP packet alignmen
    UINT32* ipBuffer = buffer + 4; // 14 bytes plus 2
    ProtoPktETH ethPkt((UINT32*)ethBuffer, frameLength);
    ethPkt.SetSrcAddr(srcMac); // This changes for asym.
    ethPkt.SetDstAddr(dstMac); // This changes for asym.
    ethPkt.SetType(ProtoPktETH::IP);  // TBD - based upon IP address type
    ProtoPktIPv4 ipPkt(ipBuffer, frameLength - 14);
    ipPkt.SetTTL(1);
    ipPkt.SetProtocol(ProtoPktIP::UDP); // UDP over IP
    ipPkt.SetSrcAddr(srcIp); // Set source address to the current host IP.
    ipPkt.SetDstAddr(dstIp); // Set destination address tot hte original packet sender (IP packet going backwards).
    ipPkt.SetTOS(SmartPkt::ADAPTIVE_TOS);

    ProtoPktUDP udpPkt(ipPkt.AccessPayload(), frameLength - 14 - ipHeaderLen, false);
    udpPkt.SetSrcPort(SmartPkt::ADAPTIVE_PORT); // Set port.
    udpPkt.SetDstPort(SmartPkt::ADAPTIVE_PORT);

    SmartPathAd ad(udpPkt.AccessPayload(), frameLength - 14 - ipHeaderLen - 8);
    // Make a smartAck pointing to the buffer.
    if (!ad.initIntoBuffer(udpPkt.AccessPayload(), frameLength - 14 - ipHeaderLen - 8))
    {
        PLOG(PL_ERROR, "MulticastFIB::BuildPathAd() error: insufficient 'buffer' length!\n");
        return 0;
    }
    // Set the ACK flag, so SRR knows it's an ACK and not a data packet.
    ad.setFlag(SmartPkt::FLAG_AD);
    int numAddresses = 0;
    ProtoAddress temp;

    Path * movingPtr = returnPath_ptr;
    while (movingPtr != NULL)
    {
        numAddresses++;
        PLOG(PL_DEBUG, "SmartController::BuildPathAd():: Address %d\n", numAddresses);
        PLOG(PL_DEBUG, "SmartController::BuildPathAd():: %s\n", movingPtr->getAddress().GetHostString());
        movingPtr = movingPtr->getNextPath();
    }
    if (!ad.setPath(*returnPath_ptr,numAddresses))
    {
        PLOG(PL_ERROR, "SmartController::BuildPathAd() error: insufficient 'buffer' length!\n");
        return 0;
    }


    // Set all packet sizes.

    udpPkt.SetPayloadLength(ad.GetLength());
    ipPkt.SetPayloadLength(udpPkt.GetLength());
    udpPkt.FinalizeChecksum(ipPkt);
    ethPkt.SetPayloadLength(ipPkt.GetLength());

    return ethPkt.GetLength();
}  // end MulticastFIB::BuildAck()


// Builds Acks
unsigned int SmartController::BuildAck(UINT32*                          buffer,
                                       unsigned int                     length,
                                       ProtoAddress&                    dstMac,      // who is receiving MAC (single hop) TODO: this needs to be changed for asymmetric
                                       const ProtoAddress&              srcMac,      // who is sending ACK                    
                                       const ProtoAddress&              dstIp,       // who is receiving ACK (multihop)       
                                       const ProtoAddress&              srcIp,       // who is sending ACK (multihop)         
                                       const ProtoAddress&              ackLinkSrc,      // who sent the original packet      
                                       const ProtoAddress&              ackLinkDst,      // who received the original packet  
                                       const ProtoFlow::Description&    flowDescription,
                                       const UINT16                     seqNo,
                                       const UINT32                     fragOffset,
                                       const bool                       atDestination,
                                       const bool                       broadcastedPacket)
{
    // IPv4-only at moment
    PLOG(PL_DEBUG, "SmartController::BuildAck(): beginning build ACK \n ");
    if (ProtoAddress::IPv4 != srcIp.GetType())
    {
        PLOG(PL_ERROR, "SmartController::BuildAck() error: non-IPv4 src address! (IPv6 support is TBD)\n");
        return 0;
    }

    unsigned int ipHeaderLen = 20;
    if (length < (14 + ipHeaderLen+ 8))
    {
        PLOG(PL_ERROR, "SmartController::BuildAck() error: insufficient 'buffer' length!\n");
        return 0;
    }
    // Build an ACK to send to the identified  relay
    // The ACK will be sent to the "relayAddr" (MAC addr) via the "ifaceIndex" interface
    // (as a UDP/IP packet with multicast dest addr and source IP addr of given "ifaceIndex")

    unsigned int frameLength = length - 2;  // offset by 2 bytes to maintain alignment for ProtoPktIP
    UINT16* ethBuffer = ((UINT16*)buffer) + 1;  // offset for IP packet alignmen
    UINT32* ipBuffer = buffer + 4; // 14 bytes plus 2
    ProtoPktETH ethPkt((UINT32*)ethBuffer, frameLength);
    ethPkt.SetSrcAddr(srcMac); // This changes for asym.
    bool broadcastFlag = false;
    if (AsymmetricMode)
    {
        if (broadcastedPacket)
        {
            PLOG(PL_DEBUG, "SmartController::BuildAck(): Building Broadcast ACK\n");
            ProtoAddress broadcastMAC;  // use broadcast ETH address for now
            broadcastMAC.ResolveEthFromString("ff:ff:ff:ff:ff:ff"); // Set the mac address to the broadcast mac.
            ethPkt.SetDstAddr(broadcastMAC);
            broadcastFlag = true;
        }
        else
        {
            PLOG(PL_DEBUG, "SmartController::BuildAck(): Building Unicast ACK\n");
            PrintRLMetrics();
            PLOG(PL_DEBUG, "SmartController::BuildAck(): Looking for address %s\n",dstIp.GetHostString());
            ProtoAddressList * addr_list_ptr = (ProtoAddressList *)forward_path_list.GetUserData(dstIp);
            // correct dst MAC to actual recepient
            if (NULL != addr_list_ptr)
            {
                PLOG(PL_DEBUG, "SmartController::BuildAck(): REtrieved address list pointer \n ");
                if (!addr_list_ptr->GetFirstAddress(dstMac))
                {
                    PLOG(PL_DEBUG, "SmartController::BuildAck(): No addresses \n ");
                    ProtoAddress broadcastMAC;  // use broadcast ETH address for now
                    broadcastMAC.ResolveEthFromString("ff:ff:ff:ff:ff:ff"); // Set the mac address to the broadcast mac.
                    ethPkt.SetDstAddr(broadcastMAC);
                }
                else
                {
                    PLOG(PL_DEBUG, "SmartController::BuildAck(): got first address: %s\n ",dstMac.GetHostString());

                    ethPkt.SetDstAddr(dstMac);
                }

            }
            else{
                PLOG(PL_DEBUG, "SmartController::BuildAck(): No data in forward path list \n ");
                ProtoAddress broadcastMAC;  // use broadcast ETH address for now
                    broadcastMAC.ResolveEthFromString("ff:ff:ff:ff:ff:ff"); // Set the mac address to the broadcast mac.
                    ethPkt.SetDstAddr(broadcastMAC);
                    broadcastFlag = true;
            }

        }
    }
    else
        ethPkt.SetDstAddr(dstMac);

    ethPkt.SetType(ProtoPktETH::IP);  // TBD - based upon IP address type
    ProtoPktIPv4 ipPkt(ipBuffer, frameLength - 14);
    ipPkt.SetTTL(3); // This needs to change for Asym: TTL 1 because acks currently only go 1 hop.
    ipPkt.SetProtocol(ProtoPktIP::UDP); // UDP over IP
    ipPkt.SetSrcAddr(srcIp); // Set source address to the current host IP.
    ipPkt.SetDstAddr(dstIp); // Set destination address tot hte original packet sender (IP packet going backwards).
    ipPkt.SetID(seqNo); // Set the sequence number.
    ipPkt.SetTOS(flowDescription.GetTrafficClass());

    ProtoPktUDP udpPkt(ipPkt.AccessPayload(), frameLength - 14 - ipHeaderLen, false);
    udpPkt.SetSrcPort(SmartPkt::ADAPTIVE_PORT); // Set port.
    udpPkt.SetDstPort(SmartPkt::ADAPTIVE_PORT);

    SmartAck ack(udpPkt.AccessPayload(), frameLength - 14 - ipHeaderLen - 8);
    // Make a smartAck pointing to the buffer.
    if (!ack.initIntoBuffer(udpPkt.AccessPayload(), frameLength - 14 - ipHeaderLen - 8))
    {
        PLOG(PL_ERROR, "MulticastFIB::BuildAck() error: insufficient 'buffer' length!\n");
        return 0;
    }
    // Set the ACK flag, so SRR knows it's an ACK and not a data packet.
    ack.setFlag(SmartPkt::FLAG_ACK);
    if (broadcastFlag)
        ack.setFlag(SmartPkt::FLAG_BCAST);
    ack.setTrafficClass(flowDescription.GetTrafficClass());

   // ack.setProtocol(flowDescription.GetProtocol());
   double Qack,Cack; // These will be the values of C and Q returned by the ACK
   if (atDestination)
   {
        // If this node is the destination of the packet,
        Qack = 0;  // Q_ack = 0 because there are no hops to go.
        Cack = 1; // C_ack = 1 because there is 100% confidence that there are no hops to go.
   }
   else
   {
        // Otherwise, we need to compute the next hop we *would* take, and get Q,C factors accordingly.
        // Get a pointer to the RL_Data corresponding to the flow being acknowledged.
        MulticastFIB::RL_Data * data_ptr = metric_table.FindEntry(flowDescription);
        // If there are no metrics, that is a problem since we shouldn't be ACKING yet...
        if (NULL == data_ptr)
        {
            PLOG(PL_ERROR, "SmartController::BuildAck(): cannot find metrics for flow ");
            flowDescription.Print();  // to debug output or log
        }
        // Pointer to the next hop.
        MulticastFIB::UpstreamRelay * next_hop = NULL;
        double bestScore = std::numeric_limits<double>::max();      // largest possible double.
        double score;
        //loop through array, to run simple optimization.
        ProtoAddressList::Iterator iterator(data_ptr->accessMetricList());
        ProtoAddress addr;
        while (iterator.GetNextAddress(addr))
        {
            PLOG(PL_DEBUG, "SmartController::BuildAck(): iterating on address: %s \n ", addr.GetHostString());
            // loop through all next hops
            // Compute Q*(1-C) for each hop, the smallest score wins.
            score = data_ptr->getMetrics(addr)->Q * (1-data_ptr->getMetrics(addr)->C);
            if (score < bestScore)
            {
                // If we find a value smaller then the current minimum, update the minimum as well as the pointer.
                bestScore = score;
                next_hop = downstream_relays.FindUpstreamRelay(addr);
            }

        }
        // If we were unable to find a next hop...
        if (NULL == next_hop)
        {
            PLOG(PL_DEBUG, "SmartController::BuildAck(): no metrics collected\n");
            Qack = 1;
            Cack = 0;

        }
        else
        {
            // Set Q and C accordingly.
            Qack = data_ptr->getMetrics(next_hop->GetAddress())->Q;
            Cack = data_ptr->getMetrics(next_hop->GetAddress())->getCorrectedC(data_ptr->getLearningRate());
        }
        PLOG(PL_DEBUG, "SmartController::BuildAck(): computed next hop \n ");
        //
    }

//    PLOG(PL_DEBUG,"SmartController::BuildAck(): Ack contents = ");
//    unsigned char * ptr = (unsigned char*)ack.AccessBuffer();
//    for (int idx = 0; idx < 36; idx++)
//    {
//        TRACE("%02x ",*ptr);
//        ptr++;
//    }
//    TRACE("\n");
    if (!ack.setQFactor(Qack))
    {
        PLOG(PL_ERROR, "MulticastFIB::BuildAck() error: insufficient 'buffer' length!\n");
        return 0;
    }
    else{
        PLOG(PL_DEBUG, "SmartController::BuildACK():: Q = %f\n", Qack);
        PLOG(PL_DEBUG, "SmartController::BuildACK():: Q = %f\n", ack.getQFactor());
    }
//    PLOG(PL_DEBUG,"SmartController::BuildAck(): Ack contents = ");
//    ptr = (unsigned char*)ack.AccessBuffer();
//    for (int idx = 0; idx < 36; idx++)
//    {
//        TRACE("%02x ",*ptr);
//        ptr++;
//    }
//    TRACE("\n");
    if (!ack.setCFactor(Cack))
    {
        PLOG(PL_ERROR, "MulticastFIB::BuildAck() error: insufficient 'buffer' length!\n");
        return 0;
    }
    else{
        PLOG(PL_DEBUG, "SmartController::BuildACK():: C = %f\n", Cack);
        PLOG(PL_DEBUG, "SmartController::BuildACK():: C = %f\n", ack.getCFactor());
    }
//    PLOG(PL_DEBUG,"SmartController::BuildAck(): Ack contents = ");
//    ptr = (unsigned char*)ack.AccessBuffer();
//    for (int idx = 0; idx < 36; idx++)
//    {
//        TRACE("%02x ",*ptr);
//        ptr++;
//    }
//    TRACE("\n");
     if (!ack.setDstMACAddr(ackLinkDst))
    {
        PLOG(PL_ERROR, "MulticastFIB::BuildAck() error: insufficient 'buffer' length!\n");
        return 0;
    }
//    PLOG(PL_DEBUG,"SmartController::BuildAck(): Ack contents = ");
//    ptr = (unsigned char*)ack.AccessBuffer();
//    for (int idx = 0; idx < 36; idx++)
//    {
//        TRACE("%02x ",*ptr);
//        ptr++;
//    }
//    TRACE("\n");
    if (!ack.setSrcMACAddr(ackLinkSrc))
    {
        PLOG(PL_ERROR, "MulticastFIB::BuildAck() error: insufficient 'buffer' length!\n");
        return 0;
    }
//    PLOG(PL_DEBUG,"SmartController::BuildAck(): Ack contents = ");
//    ptr = (unsigned char*)ack.AccessBuffer();
//    for (int idx = 0; idx < 36; idx++)
//    {
//        TRACE("%02x ",*ptr);
//        ptr++;
//    }
//    TRACE("\n");
    SmartAck::AddressType addrType;
    switch (flowDescription.GetDstLength())
    {
        case 4:
            addrType = SmartAck::ADDR_IPV4;
            break;
        default:
            PLOG(PL_ERROR, "MulticastFIB::BuildAck() error: invalid flow dst address\n");
            return 0;
    }
    if (!ack.setDstIPAddr(addrType, flowDescription.GetDstPtr(), flowDescription.GetDstLength()))
    {
        PLOG(PL_ERROR, "MulticastFIB::BuildAck() error: insufficient 'buffer' length!\n");
        return 0;
    }
//    PLOG(PL_DEBUG,"SmartController::BuildAck(): Ack contents = ");
//    ptr = (unsigned char*)ack.AccessBuffer();
//    for (int idx = 0; idx < 36; idx++)
//    {
//        TRACE("%02x ",*ptr);
//        ptr++;
//    }
//    TRACE("\n");
    PLOG(PL_DEBUG,"SmartController::BuildAck() : fragment offset = %d\n", fragOffset);
    ack.setFragmentOffset(fragOffset);
//    PLOG(PL_DEBUG,"SmartController::BuildAck(): Ack contents = ");
//    ptr = (unsigned char*)ack.AccessBuffer();
//    for (int idx = 0; idx < 36; idx++)
//    {
//        TRACE("%02x ",*ptr);
//        ptr++;
//    }
//    TRACE("\n");
    PLOG(PL_DEBUG, "SmartController::BuildACK():: C = %f\n", ack.getCFactor());

    if (!broadcastedPacket && AsymmetricMode)
    {
        PLOG(PL_DEBUG, "MulticastFIB::BuildAck(): asymmetric unicast processing!\n");
        int numAddresses = 0;
        Path * path_ptr = (Path *)forward_path_list.GetUserData(dstIp);
        Path * moving_path_ptr = path_ptr;
        ProtoAddress temp;
        while (moving_path_ptr != NULL)
        {


            numAddresses++;
            PLOG(PL_DEBUG, "SmartController::BuildACK():: Address %d\n", numAddresses);
            PLOG(PL_DEBUG, "SmartController::BuildACK():: %s\n", moving_path_ptr->getAddress().GetHostString());
            moving_path_ptr = moving_path_ptr->getNextPath();
        }
        if (!ack.setPath(*path_ptr,numAddresses))
        {
            PLOG(PL_ERROR, "SmartController::BuildACK() error: insufficient 'buffer' length!\n");
            return 0;
        }
         PLOG(PL_DEBUG, "SmartController:HandleAck. Path: ");

        ProtoAddress tempAddr;
        for (int i = 0; i < ack.getPathLength(); i++)
        {
            ack.getPathNodeAt(i,tempAddr);
            if (GetDebugLevel() >= PL_DEBUG)
            {
                TRACE("%s, ", tempAddr.GetHostString());
            }

        }
        if (GetDebugLevel() >= PL_DEBUG)
        {
            TRACE("\n");
        }

    }
    // Set all packet sizes.

    udpPkt.SetPayloadLength(ack.GetLength());
    ipPkt.SetPayloadLength(udpPkt.GetLength());
    udpPkt.FinalizeChecksum(ipPkt);
    ethPkt.SetPayloadLength(ipPkt.GetLength());
    PLOG(PL_DEBUG, "Smf::BuildACK(): ACK Return Value: %d\n",ack.GetLength());
    PLOG(PL_DEBUG, "Smf::BuildACK(): UDP Length: Total: %d\n", udpPkt.GetLength());
    PLOG(PL_DEBUG, "Smf::BuildACK(): IPv4 Length: Total: %d, Payload: %d\n", ipPkt.GetLength(), ipPkt.GetPayloadLength());
    PLOG(PL_DEBUG, "Smf::BuildACK(): Eth Length: Total: %d, Payload: %d\n", ethPkt.GetLength(), ethPkt.GetPayloadLength());
    return ethPkt.GetLength();
}  // end MulticastFIB::BuildAck()

// When a packet is sent from the forwarder, this controller function needs to be called in order to correctly update RL metrics.
void SmartController::ProcessUnicastPacket(const ProtoFlow::Description& flowDescription, MulticastFIB::UpstreamRelay* next_hop,  UINT16 packetID, UINT16 fragOffset)
{
    PLOG(PL_DEBUG, "SmartController::ProcessUnicastPacket(): Processing Sent Packet with ID %d to next hop %s\n ", packetID,next_hop->GetAddress().GetHostString());
    // Find the data object corresponding to the flow.
    MulticastFIB::RL_Data * data_ptr = metric_table.FindEntry(flowDescription);
    // Update corresponding metrics.
    double newC = data_ptr-> processSentPacket(next_hop->GetAddress(),packetID, fragOffset);
    // update forwarder policies
    updateForwarder(flowDescription);
}

 bool SmartController::checkForAdvertisement(const ProtoFlow::Description& flowDescription,const ProtoAddress& addr){
    MulticastFIB::RL_Data * data_ptr = metric_table.FindEntry(flowDescription);

    if (data_ptr->getMetrics(addr)->need_advertisement){
        data_ptr->getMetrics(addr)->need_advertisement = false;
        return true;
    }
    else
        return false;
}

// Calls ProcessUnicastPacket on every possible next hop (relay in the member variable downstream_relays)
// Note, this can also be called when the controller doesn't know about the neighbors yet.  In this case, no metrics will be updated.
// This is ok functionality, because if we knew the next hop, the C value would remain zero, implying a 100% chance of broadcast.
// Upon receipt of ACK, the links will be added to downstream_relays, allowing for the C factors to grow and
// a possibility of unicasting the packet.
void SmartController::ProcessBroadcastPacket(const ProtoFlow::Description& flowDescription, UINT16 packetID, UINT16 fragOffset)
{
    //PLOG(PL_DEBUG, "SmartController::ProcessBroadcastPacket(): Processing Sent Packet with ID %d \n ", packetID);
    // Find the data object corresponding to the flow
    MulticastFIB::RL_Data * data_ptr = metric_table.FindEntry(flowDescription);
    // Find the list of all next-hops.
    MulticastFIB::UpstreamRelayList::Iterator iterator(downstream_relays);
    MulticastFIB::UpstreamRelay* relay;
    // For each next hop, send the packet

    while (NULL != (relay=iterator.GetNextItem()))
    {
        ProcessUnicastPacket(flowDescription,relay, packetID,fragOffset);
    }
}

// The external input mechanism passes these in
void SmartController::PrintAddressList(ProtoAddressList& addr_list)
{
    ProtoAddressList::Iterator addr_iterator(addr_list);
    ProtoAddress addr;

    while ((addr_iterator.GetNextAddress(addr)))
    {
        PLOG(PL_ALWAYS, "      %s\n", addr.GetHostString());
    }
}

void SmartController::PrintRLMetrics()
{
    MulticastFIB::RL_Table::Iterator iterator (metric_table);
    MulticastFIB::RL_Data* data_ptr;
    ProtoAddress addr;
    PLOG(PL_ALWAYS, "RL_Metrics:\n");
    while (NULL !=  (data_ptr=iterator.GetNextEntry()))
    {
        PLOG(PL_ALWAYS, "   Flow: ");
        data_ptr->GetFlowDescription().Print();
        TRACE("\n");
        ProtoAddressList::Iterator iterator2(data_ptr->accessMetricList());
        while (iterator2.GetNextAddress(addr))
        {
            PLOG(PL_ALWAYS, "      Address: %s\n", addr.GetHostString());
            PLOG(PL_ALWAYS, "      Q: %f\n", data_ptr->getMetrics(addr)->Q);
            PLOG(PL_ALWAYS, "      C: %f\n", data_ptr->getMetrics(addr)->C);
        }

    }

    if (AsymmetricMode)
    {
        ProtoAddressList::Iterator addr_iterator(return_path_list);

        Path* path_ptr;

        ProtoAddress addr2;
        int pathlength;


        PLOG(PL_ALWAYS, "Return Paths:\n");
        while ((addr_iterator.GetNextAddress(addr)))
        {
            PLOG(PL_ALWAYS, "   Node: %s\n", addr.GetHostString());
            path_ptr = (Path*)return_path_list.GetUserData(addr);
            path_ptr->printPath();
        }

        ProtoAddressList::Iterator addr_iterator_2(forward_path_list);

        PLOG(PL_ALWAYS, "Forward Paths:\n");
        while ((addr_iterator_2.GetNextAddress(addr)))
        {
            PLOG(PL_ALWAYS, "   Node: %s\n", addr.GetHostString());
            path_ptr = (Path*)forward_path_list.GetUserData(addr);
            path_ptr->printPath();
        }
    }
}

void SmartController::HandlePathAdvertisement(SmartPathAd& ad, const ProtoAddress& srcAddr)
{
    PLOG(PL_DEBUG, "SmartController::HandlePathAdvertisement.  Received Advertisement \n");
    if (forward_path_list.Contains(srcAddr))
        forward_path_list.Remove(srcAddr);

    PLOG(PL_DEBUG, "SmartController:HandleAck. Source Addr: %s\n",srcAddr.GetHostString());
    PLOG(PL_DEBUG, "SmartController:HandleAck. PathLength: %d\n", ad.getPathLength());
    PLOG(PL_DEBUG, "SmartController:HandleAck. Path: ");


    Path * forwardPath = NULL;

    for (int idx=ad.getPathLength()-1;idx>=0;idx--)
    {
        ProtoAddress addr;
        ad.getPathNodeAt(idx,addr);
        PLOG(PL_DEBUG, "SmartController:HandleAck. Address %d, %s\n", idx, addr.GetHostString());
        forwardPath = new Path(addr, forwardPath);
    }
    if (forwardPath != NULL)
    {
        forward_path_list.Insert(srcAddr,forwardPath);
        PLOG(PL_DEBUG, "SmartController:HandleAd. Saving Path: ");
        forwardPath->printPath();
    }

}

void SmartController::UpdateInterfaces(const ProtoAddress& addr, unsigned int ifaceIndex)
{
    PLOG(PL_DEBUG, "SmartController::UpdateInterfaces(): Update Interface %d has mac %s \n ", ifaceIndex, addr.GetHostString());
    if (!interface_list.Contains(addr))
    {
        unsigned int * idx_ptr = new unsigned int(ifaceIndex);
        interface_list.Insert(addr,idx_ptr);
    }
    else
        PLOG(PL_DEBUG, "SmartController::UpdateInterfaces(): No Update \n ");
    return;
}

void SmartController::UpdateNeighbors(const ProtoAddress& src, const ProtoAddress& dst)
{
    MulticastFIB::UpstreamRelay * relay_ptr = downstream_relays.FindUpstreamRelay(dst);
    if (NULL == relay_ptr)
    {
        // to get to mac address (ackSrc), we need to send through interface (ackdest)

        unsigned int * idx_ptr = (unsigned int *)interface_list.GetUserData(src);
        PLOG(PL_DEBUG, "SmartController:UpdateNeighbors.  Ack from new neighbor: Adding Downstream Relay. Mac: %s, Iface: %d\n",dst.GetHostString(), *idx_ptr);
        relay_ptr = new MulticastFIB::UpstreamRelay(dst,*idx_ptr);
        downstream_relays.Insert(*relay_ptr);
    }
}
// Called when an ACK is received, Controller to update metrics.
void SmartController::HandleAck(SmartAck& ack, unsigned int ifaceIndex, const ProtoAddress& srcMac, const ProtoAddress& ifaceMac, UINT16 seqNo)
{
    ProtoAddress dstIp;
    ProtoAddress ackSrc,ackDst;
    // check to make sure its an ACK
    if (!ack.isAck())
    {
        PLOG(PL_ALWAYS, "HandlACK called on packet thats not an ACK");
        return;
    }

    UINT8 trafficClass = ack.getTrafficClass();
    // dst is always set.
    ack.getDstIPAddr(dstIp);
    ack.getDstMACAddr(ackSrc);
    ack.getSrcMACAddr(ackDst);
    // Check if the controller knows about the link.  If not, add it to downstream_relays.
    //MulticastFIB::UpstreamRelay * relay_ptr = downstream_relays.FindUpstreamRelay(ackSrc);
    // this ack was

    UpdateNeighbors(ackDst,ackSrc);

    // TBD - confirm that it's for me?  (if ackDst != self.IP) This is important but is handled in smf.cpp.

    PLOG(PL_DEBUG, "SmartController:HandleAck. Source MAC of ACK: %s\n",ackSrc.GetHostString());
    PLOG(PL_DEBUG, "SmartController:HandleAck. Source MAC: %s\n",srcMac.GetHostString());
    PLOG(PL_DEBUG, "SmartController:HandleAck. DstIP : %s\n", dstIp.GetHostString());
    PLOG(PL_DEBUG, "SmartController:HandleAck. Q factor: %f\n", ack.getQFactor());
    PLOG(PL_DEBUG, "SmartController:HandleAck. C factor: %f\n", ack.getCFactor());
    PLOG(PL_DEBUG, "SmartController:HandleAck. Fragment Offset: %d\n", ack.getFragmentOffset());
    PLOG(PL_DEBUG, "SmartController:HandleAck. PathLength: %d\n", ack.getPathLength());
    PLOG(PL_DEBUG, "SmartController:HandleAck. Path: ");

    ProtoAddress tempAddr;

    for (int i = 0; i < ack.getPathLength(); i++)
    {
        ack.getPathNodeAt(i,tempAddr);
        if (GetDebugLevel() >= PL_DEBUG)
        {
            TRACE("%s, ", tempAddr.GetHostString());
        }

    }
    if (GetDebugLevel() >= PL_DEBUG)
    {
        TRACE("\n");
    }

    ProtoAddress * addrList;
    //addrList = ack.getPath();
    bool needsAd = false;
    ProtoPktIP::Protocol protocol = ack.getProtocol();

    // Flow desription describes the original packet flow (destination of the data packet).
    // Use the dstIP, class, and protocol information to generate a flow description object.
    ProtoFlow::Description flowDesc= ProtoFlow::Description(dstIp, PROTO_ADDR_NONE, trafficClass, ProtoPktIP::UDP);
    // Currently *wildcarding* the source, since flow is independent of source.  If this changes, then we change these two linses of code.
    flowDesc.SetSrcMaskLength(0);
    if (GetDebugLevel() >= PL_DEBUG)
    {
        PLOG(PL_ALWAYS, "nrlsmf: recv'd SmartAck for flow ");
        flowDesc.Print();
        PLOG(PL_ALWAYS, " from %s\n", srcMac.GetHostString());
    }
    if (AsymmetricMode)
    {
        PLOG(PL_DEBUG, "SmartController:HandleAck. Checking for broadcast flag\n");
        if (ack.flagIsSet(SmartPkt::FLAG_BCAST))
        {
            PLOG(PL_DEBUG, "SmartController:HandleAck. Broadcast Flag Detected\n");
            if (return_path_list.Contains(ackSrc))
            {
                return_path_list.Remove(ackSrc);
            }
            Path * returnPathPtr = new Path(ifaceMac);
            PLOG(PL_DEBUG, "SmartController:HandleAck. Start as null\n");

            for (int idx=ack.getPathLength()-1;idx>=0;idx--)
            {
                ProtoAddress addr;
                ack.getPathNodeAt(idx,addr);
                PLOG(PL_DEBUG, "SmartController:HandleAck. Address %d, %s\n", idx, addr.GetHostString());
                returnPathPtr = new Path(addr, returnPathPtr);
            }
            return_path_list.Insert(ackSrc,returnPathPtr);
            PLOG(PL_DEBUG, "SmartController:HandleAck. Saving Path: ");
            returnPathPtr->printPath();
            needsAd = true;
        }
    }

    // Find the "Best Match" for the flow we received. This should return null if the flow isn't in the table.
    MulticastFIB::RL_Data * data_ptr = metric_table.FindBestMatch(flowDesc);
    // If the flow isn't in the table..
    if (NULL == data_ptr)

    {
        // We're receiving an ACK for a flow we didn't know about.  We SHOULD know about it, because we sent the packet...
        // This is an ERROR, rest of this code is debug printing to understand what is happeneing.
        PLOG(PL_ERROR, "SmartController:HandleAck. Error, received ACK for flow that Ive never seen\n");
        PLOG(PL_DEBUG, "\n List of flows: \n");
        MulticastFIB::RL_Table::Iterator iterator(metric_table);
        MulticastFIB::RL_Data * d;
        ProtoFlow::Description f;

        while (NULL != (d = (MulticastFIB::RL_Data *) iterator.GetNextEntry()))
        {
            f = d->GetFlowDescription();
            f.SetSrcMaskLength(0);
            f.Print();
            PLOG(PL_DEBUG, "\n");
        }

    }
    else
    {
        // We found the flow...
        //PLOG(PL_DEBUG, "SmartController:HandleAck. Found Matching Flow for ACK: ");
        //data_ptr->GetFlowDescription().Print();

        // Update the RL Metrics corresponding to the acknowledged link.
        // Here we need to send a new path acknoweldgement before next packet.

        data_ptr->update(ackSrc,ack.getQFactor(),ack.getCFactor(),seqNo, ack.getFragmentOffset());
        if (needsAd)
            data_ptr->getMetrics(ackSrc)->need_advertisement = true;
        // Debug printing
        //if (GetDebugLevel() >= PL_DEBUG)
         //   PrintRLMetrics();
        // Update the forwarder (in case the next hop / probability changes)
        updateForwarder(data_ptr->GetFlowDescription());
    }


    return;
}  // end SmartController::HandleAck()

// Called to interface with the SmartForwarder. We only update information for one flow at a time, hence passing in flow as a parameter.
void SmartController::updateForwarder(const ProtoFlow::Description& flow)
{
    // Update Forwarder.
    //PLOG(PL_DEBUG, "SmartController:updateForwarder. Call to Update forwarder for flow:");
    flow.Print();
    TRACE( "\n");

    // Get the metrics corresponding to the flow.
    MulticastFIB::RL_Data * data_ptr = (MulticastFIB::RL_Data *)metric_table.FindBestMatch(flow);

    // If there are no metrics, we should not be updating... this would be an error.
     if (NULL == data_ptr)

    {
        PLOG(PL_ERROR, "SmartController:updateForwarder. Error, received ACK for flow that Ive never seen\n");
        PLOG(PL_DEBUG, "\n List of flows: \n");
        MulticastFIB::RL_Table::Iterator iteratornew(metric_table);
        MulticastFIB::RL_Data * d;
        ProtoFlow::Description f;

        while (NULL != (d = (MulticastFIB::RL_Data *) iteratornew.GetNextEntry()))
        {
            f = d->GetFlowDescription();
            f.SetSrcMaskLength(0);
            f.Print();
            PLOG(PL_DEBUG, "\n");
        }
    }
    else
    {
        // This is just a sanity check to make sure Finding the bestt match is working as intented.
        ProtoAddress addr1,addr2;
        flow.GetDstAddr(addr1);
        data_ptr->GetFlowDescription().GetDstAddr(addr2);
        if (addr1 != addr2)
            PLOG(PL_ERROR, "SmartController:updateForwarder. Find Best Match Broken. %s != %s \n", addr1.GetHostString(), addr2.GetHostString());
    }

    // Determine Best MAC Address for next hop.
    MulticastFIB::UpstreamRelay* next_hop = NULL;


    ProtoAddress addr;
    MulticastFIB::RL_Data * temp_data_ptr;
    MulticastFIB::UpstreamRelay* temp_next_hop = NULL;
    ProtoAddressList::Iterator iterator(data_ptr->accessMetricList());

    next_hop = data_ptr->getNextHop(downstream_relays, minBroadcastProb,reliability_threshold);
    // at end of loop, we have the best choice.Here we can assume next_hop is populated correctly.
    //PLOG(PL_DEBUG, "Computing probability broadcast...\n");
    // Determine Broadcast Probability
    double broadcastProbability = minBroadcastProb + (1-minBroadcastProb) * (1-std::min(1.0,(data_ptr->getMetrics(next_hop->GetAddress())->C)/(pow(1-data_ptr->getLearningRate(),data_ptr->getMetrics(next_hop->GetAddress())->correctionFactor))));
    double otherProb = 1;
    PLOG(PL_DEBUG, "Beginning priority processing\n");
    int priority = data_ptr->GetFlowDescription().GetTrafficClass();
    MulticastFIB::RL_Table::Iterator flowIt(metric_table);
    MulticastFIB::RL_Data*  ent;
    ProtoFlow::Description f;
    MulticastFIB::RL_Data::RL_Metric_Tuple * tuple_ptr;
    PLOG(PL_DEBUG, "Looping through flows\n");
    while (NULL != (ent = flowIt.GetNextEntry()))
    {

        f = ent->GetFlowDescription();
        TRACE("\n");
        f.Print();
        TRACE("\n");
        if (f.GetTrafficClass() < priority)
        {
            /*
            PLOG(PL_DEBUG, " -> High Priority Flow\n");
            temp_data_ptr =  (MulticastFIB::RL_Data *)metric_table.FindBestMatch(f);
            PLOG(PL_DEBUG, "Computing Next Hop: \n");
            temp_next_hop = data_ptr->getNextHop(downstream_relays, minBroadcastProb,reliability_threshold);
            PLOG(PL_DEBUG, "%s\n", temp_next_hop->GetAddress().GetHostString());
            if(temp_data_ptr->hasMetrics(temp_next_hop->GetAddress()))
            {
                otherProb = minBroadcastProb + (1-minBroadcastProb) * (1-std::min(1.0,(data_ptr->getMetrics(next_hop->GetAddress())->C)/(pow(1-data_ptr->getLearningRate(),data_ptr->getMetrics(next_hop->GetAddress())->correctionFactor))));
                broadcastProbability *= (1.0-otherProb/2);
            }
            */
            PLOG(PL_DEBUG, " -> High Priority Flow\n");
            temp_next_hop = smart_forwarder->getNextHop(f);
            otherProb -= smart_forwarder->getBroadcastProbability(f);
            PLOG(PL_DEBUG, "   Prob Broadcast: %f", otherProb);

        }
        else{
            PLOG(PL_DEBUG, " -> Low Priority flow\n");
        }
    }
    broadcastProbability *= otherProb;
    PLOG(PL_DEBUG, "SmartController:updateForwarder. Probability Broadcast: %f \n Traffic Class: %d \n Correction Factor: %d \n", broadcastProbability,data_ptr->GetFlowDescription().GetTrafficClass(),data_ptr->getMetrics(next_hop->GetAddress())->correctionFactor  );
    //Update forwarder
    smart_forwarder->UpdateRoutingTable(flow,*next_hop,broadcastProbability);
    return;
}

bool SmartController::ActivateMembership(MulticastFIB::Membership&       membership,
                                                    MulticastFIB::Membership::Flag  flag,
                                                    double                          timeoutSec)
{
    if (membership_timer.IsActive())
    {
        unsigned int oldTick = membership_table.GetNextTimeout();
        unsigned int currentTick = UpdateTicker();
        unsigned int timeoutTick = (unsigned int)(timeoutSec*1.0e+06) + currentTick;
        if (!membership_table.ActivateMembership(membership, flag, timeoutTick))
        {
            PLOG(PL_ERROR, "SmartController::ActivateMembership() error: unable to activate membership\n");
            return false;
        }
        unsigned int newTick = membership_table.GetNextTimeout();
        if (newTick != oldTick)
        {
            int delta = newTick - currentTick;
            if (delta < 0) delta = 0;
            membership_timer.SetInterval(((double)delta) * 1.0e-06);
            membership_timer.Reschedule();
        }
    }
    else
    {
        ResetTicker();
        unsigned int timeoutTick = (unsigned int)(timeoutSec*1.0e+06);
        if (!membership_table.ActivateMembership(membership, flag, timeoutTick))
        {
            PLOG(PL_ERROR, "SmartController::ActivateMembership() error: unable to activate membership\n");
            return false;
        }
        timer_mgr.ActivateTimer(membership_timer);
    }
    return true;
}  // end SmartController::ActivateMembership()

void SmartController::DeactivateMembership(MulticastFIB::Membership&      membership,
                                                      MulticastFIB::Membership::Flag flag)
{
    if (membership_timer.IsActive())
    {
        unsigned int oldTick = membership_table.GetNextTimeout();
        membership_table.DeactivateMembership(membership, flag);
        if (membership_table.IsActive())
        {
            unsigned int newTick = membership_table.GetNextTimeout();
            if (newTick != oldTick)
            {
                unsigned int currentTick = UpdateTicker();
                int delta = newTick - currentTick;
                if (delta < 0) delta = 0.0;
                membership_timer.SetInterval(((double)delta) * 1.0e-06);
                membership_timer.Reschedule();
            }
        }
        else
        {
            membership_timer.Deactivate();
        }
    }
}  // end SmartController::DeactivateMembership()

bool SmartController::OnMembershipTimeout(ProtoTimer& theTimer)
{
    unsigned int currentTick = time_ticker.Update();
    MulticastFIB::Membership* leader;
    while (NULL != (leader = membership_table.GetRingLeader()))
    {
        unsigned int nextTimeout = leader->GetTimeout();
        int delta = nextTimeout - currentTick;
        if (delta <= 0)
        {
            // Membership timeout
            MulticastFIB::Membership::Flag timeoutFlag = leader->GetTimeoutFlag();
            //if (GetDebugLevel() >= PL_DEBUG)
            {
                PLOG(PL_ALWAYS, "nrlsmf: %s membership timeout for flow ",
                        (MulticastFIB::Membership::ELASTIC == timeoutFlag) ? "ELASTIC" : "IGMP");
                leader->GetFlowDescription().Print();
                PLOG(PL_ALWAYS, "\n");
            }
            DeactivateMembership(*leader, timeoutFlag);
            if (0 == leader->GetFlags())
            {
                // Are there any other memberships (i.e. interfaces) with same flowDescription?
                // (If not, acking will be disabled, too)
                bool ackingStatus = false;
                // This iteration "wildcards" the interface index (i.e. ifaceIndex = 0)
                // NOTE: it finds matching memberships of the same or tighter match as the "leader" flow description
                //       (i.e., memberhips that would considered "children" of the memberhip timing out)
                MulticastFIB::MembershipTable::Iterator iterator(membership_table, &leader->GetFlowDescription());
                MulticastFIB::Membership* membership;
                while (NULL != (membership = iterator.GetNextEntry()))
                {
                    if (0 != membership->GetFlags())
                    {
                        ackingStatus = true;
                        break;
                    }
                }

                membership_table.RemoveEntry(*leader);
                delete leader;
            }

        }
        else
        {
            theTimer.SetInterval(((double)delta) * 1.0e-06);
            return true;
        }
    }
    // If get here, there are no more membership timeouts remaining,
    // and timer was deactivated in call to DeactivateMembership() above
    //theTimer.Deactivate();
    return false;
}  // end MulticastFIB::OnMembershipTimeout()
 // end SmartController::Update()

