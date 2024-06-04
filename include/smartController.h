#ifndef _SMART_CONTROLLER
#define _SMART_CONTROLLER

#include "protoFlow.h"
#include "elasticMsg.h"
#include "r2dnMsg.h"
#include "mcastFib.h"
#include "path.h"
#include <list>
#include<vector>
#include <unordered_map>

#include "protoPktIGMP.h"
#include "protoSocket.h"  // used by ElasticMulticastController
#include "protoTimer.h"   // used by ElasticMulticastController
//#include "smartForwarder.h"

// The SmartController class represents the control plane / decision engine of the SRR algorithm.
// The SmartController maintains a list of all outgoing links, and corresponding RL metrics, and updates metrics upon
// packet transmissions and ACK reception.  Additionally the controller is responsible for building acknowledgements.
// When the metrics change, the controller updates the routing table at the forwarder.


//#include "smartForwarder.h"
// Need to pre-declare the forwarder,** since the controller will have a pointer to the forwarder.
class SmartForwarder;



class SmartController
{
    public:
        bool AsymmetricMode = false;

        SmartController(ProtoTimerMgr& timerMgr);   // May not need timer, keep for now
        ~SmartController();

        bool Open(SmartForwarder* forwarder);
        void Close();

        void SetForwarder(SmartForwarder* forwarder);

        // This method is invoked by the forwarding plane (or via interface from forwarding plane) when
        // there is a newly detected flow or upon flow activity updates
        void Update(const ProtoFlow::Description&         flowDescription,
                    unsigned int                          ifaceIndex,
                    const ProtoAddress&                   relayAddr,
                    unsigned int                          pktCount,
                    unsigned int                          pktInterval);

        // From Elastic multicast: Not used.
        void HandleIGMP(ProtoPktIGMP& igmpMsg, const ProtoAddress& srcIp, unsigned int ifaceIndex, bool inbound);
        // From Elastic Multicast: Not used
        bool AddManagedMembership(unsigned int ifaceIndex, const ProtoAddress& groupAddr);

        //This function builds an ack in the buffer passed as a parameter.
        unsigned int BuildAck(UINT32*                        buffer,
                              unsigned int                   length,
                              ProtoAddress&                  dstMac,  // also used for ACK upstream relay addr
                              const ProtoAddress&            srcMac,
                              const ProtoAddress&            dstIp,      // Destination IP of ack (who sent the packet)
                              const ProtoAddress&            srcIp,      // Source IP of the ack (who received the packet (self))
                              const ProtoAddress&            ackLinkSrc,      // who sent the original packet
                              const ProtoAddress&            ackLinkDst,      // who received the original packet
                              const ProtoFlow::Description&  flowDescription,
                              const UINT16                   seqNo,      // Sequence number of the original packet
                              const UINT32                   fragOffset, // if original packet was a fragment, this will be the fragment offset.
                              const bool                     atDestination = false,
                              const bool                     broadcastedPacket=true); // Bool Used to signify whether packet is at the destination.

        unsigned int BuildPathAd(UINT32*                buffer,
                                 unsigned int           length,
                                 const ProtoAddress&    dstMac,  // also used for ACK upstream relay addr
                                 const ProtoAddress&    srcMac,
                                 const ProtoAddress&    dstIp,      // Destination IP of ack (who sent the packet)
                                 const ProtoAddress&    srcIp);

        // Updates the metrics after a unicast packet transmission
        void ProcessUnicastPacket(const ProtoFlow::Description& flowDescription, MulticastFIB::UpstreamRelay* next_hop, UINT16 packetID, UINT16 fragOffset);
        // Updates the metrics after a broadcast packet transmission (calls ProcessUnicastPacket) for each next-hop
        void ProcessBroadcastPacket(const ProtoFlow::Description& flowDescription, UINT16 packetID, UINT16 fragOffset);
        // Updates the metrics after an acknowledgement is received.
        void HandleAck(SmartAck& ack, unsigned int ifaceIndex, const ProtoAddress& srcMac,const ProtoAddress& ifaceMac, UINT16 seqNo);
        // Updates the return path table after an advertisement is received.
        void HandlePathAdvertisement(SmartPathAd& ad, const ProtoAddress& srcAddr);
        void UpdateNeighbors(const ProtoAddress& src, const ProtoAddress& dst);
        void UpdateInterfaces(const ProtoAddress& addr, unsigned int ifaceIndex);
        // From EM: Not Used.
        bool ActivateMembership(MulticastFIB::Membership&       membership,
                                MulticastFIB::Membership::Flag  flag,
                                double                          timeoutSec);
        // From EM: Not Used
        void DeactivateMembership(MulticastFIB::Membership&      membership,
                                  MulticastFIB::Membership::Flag flag);
        // For adding flows to tables.
        bool AddFlow(const ProtoFlow::Description& flowDescription);
        // Used to print all metrics for all flows.  Primarily for debugging.
        void PrintRLMetrics();
        void PrintAddressList(ProtoAddressList& addr_list);
        MulticastFIB::UpstreamRelayList& accessDownstreamRelayList()
                    {return downstream_relays;}
        bool checkForAdvertisement(const ProtoFlow::Description& flowDescription, const ProtoAddress& addr);



    protected:
        // From EM: Not used
        // Our "ticker" is a count of microseconds that is used for our
        // membership timeouts.  The "ticker" is activated whenever the
        // membership_timer is activated.
        void ResetTicker()
            {time_ticker.Reset();}
        unsigned int UpdateTicker()
            {return time_ticker.Update();}

        bool OnMembershipTimeout(ProtoTimer& theTimer);

        // Call to update the forwarder's Routing information.
        void updateForwarder(const ProtoFlow::Description& flow);
        // EM variables, not used:
        ProtoTimerMgr&                  timer_mgr;
        ElasticTicker                   time_ticker;
        ProtoTimer                      membership_timer;
        // Minimum broadcast probability epsilon:
        double                          minBroadcastProb = 0.01;
        double                          reliability_threshold = 0.89;
        // Membership table is for EM and isn't used by SRR
        MulticastFIB::MembershipTable   membership_table;
        // Metric table is a per-flow table of RL_Data objects
        MulticastFIB::RL_Table          metric_table;
        // Downstream Relays maintains a list of all possible next hop neighbors.  This is to keep addresses and interfaces together.
        MulticastFIB::UpstreamRelayList downstream_relays;  // List of all downstream MAC addresses.
        // Pointer to the forwarder .
        ProtoAddressList    return_path_list;
        ProtoAddressList    forward_path_list;
        ProtoAddressList    interface_list;
        std::vector<ProtoFlow::Description> sortedFlowTable;
        SmartForwarder*     smart_forwarder;
};// ENd SmartController Class

#endif
