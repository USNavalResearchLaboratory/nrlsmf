
#ifndef _SMART_FORWARDER
#define _SMART_FORWARDER

#include "protoFlow.h"
#include "elasticMsg.h"
#include "r2dnMsg.h"
#include "mcastFib.h"
//#include "smartController.h"

#include <list>
#include <unordered_map>

#include "protoPktIGMP.h"
#include "protoSocket.h"  // used by ElasticMulticastController
#include "protoTimer.h"   // used by ElasticMulticastController

// The Smart forwarder class, which smf extends, handles the data plane for SRR algorithm.
// The only difference between this and the smf ElasticMulticastForwarder is that the flow table now contains a unicast
// next-hop and a unicast probability.  The forwarder is capable of generating a random number according to that probability
// and using it to decide whether to broadcast or unicast.  The probability and the next hop are set by the controller.


class SmartController;

class SmartForwarder
{
    public:
        SmartForwarder();
        virtual ~SmartForwarder();

        void SetController(SmartController* controller)
            {smart_controller = controller;}

        // set forwarding status to BLOCK, LIMIT, HYBRID, or FORWARD
        // This is from EM, not used:
        bool SetForwardingStatus(const ProtoFlow::Description&  flowDescription,
                                 unsigned int                   ifaceIndex,
                                 MulticastFIB::ForwardingStatus forwardingStatus,
                                 bool                           ackingStatus);

        bool SetAckingStatus(const ProtoFlow::Description&  flowDescription,
                             bool                           ackingStatus);
        /*
        bool SetAckingCondition(const ProtoFlow::Description&  flowDescription,
                                unsigned int            count,
                                unsigned int            intervalMax,
                                unsigned int            intervalMin)
        {
            return mcast_fib.SetAckingCondition(flowDescription, count, intervalMax, intervalMin);
        }
        */
        // Update routing tale to forward packets of a particular flow to a specific next hop, with some probability, and to broadcast with some probability.
        bool UpdateRoutingTable(const ProtoFlow::Description& flowDescription, MulticastFIB::UpstreamRelay nextHop, double broadcastProbability);


        // The following required overrides are needed since they require access
        // to a network interface output mechanism (for sending EM-ACK)
        // virtual bool SendAck(unsigned int           ifaceIndex,
        //                      const ProtoAddress&    upstreamAddr,
        //                     const ProtoFlow::Description& flowDescription) = 0;  // copied from ElasticForwarder but not _actually_ used by the SmartForwarder ...
        // To send acknoweldgements.
        class OutputMechanism
        {
            public:
                virtual bool SendFrame(unsigned int ifaceIndex, char* buffer, unsigned int length) = 0;
        };  // end class ElasticMulticastForwarder::OutputMechanism
        void SetOutputMechanism(OutputMechanism* mech)
            {output_mechanism = mech;}

        // Not sure if this is still used.
        void MarkPacket(SmartPkt& pkt, const ProtoAddress& addr);
        MulticastFIB::UpstreamRelay* getNextHop(const ProtoFlow::Description& flowDescription);
        double getBroadcastProbability(const ProtoFlow::Description& flowDescription);

    protected:
       // Our "ticker" is a count of microseconds that is used for our
        // membership timeouts.  The forwarder is responsible for
        // keeping the "time_ticker" updated.
        void ResetTicker()
            {time_ticker.Reset();}
        unsigned int UpdateTicker()
            {return time_ticker.Update();}


        MulticastFIB                    mcast_fib;
        ElasticTicker                   time_ticker;
        SmartController*                smart_controller;
        OutputMechanism*                output_mechanism;
        // tHis is deprecated, now routing information is stored in the multicastFib::flow table.
        //MulticastFIB::SmartRoutingTable routing_table;



};  // end class ElasticMulticastForwarder

#endif
