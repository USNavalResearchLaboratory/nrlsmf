#include "mcastFib.h"
#include "protoNet.h"  // to get interface addresses given interface indices (TBD - addresses should be configured w/ indices externally)
#include "protoPktETH.h"
#include "protoPktIP.h"
#include "protoDebug.h"
#include <stdlib.h>
#include <math.h>
#include <iostream>

#include "smartForwarder.h"


///////////////////////////////////////////////////////////////////////////////////
// class SmartForwarder implementation
//

SmartForwarder::SmartForwarder()
 : smart_controller(NULL), output_mechanism(NULL)
{
}

SmartForwarder::~SmartForwarder()
{
}

//void SmartForwarder::MarkPacket(SmartPkt& pkt, const ProtoAddress& addr)
//{
//    pkt.appendNodeToPath(addr);
//}

bool SmartForwarder::SetAckingStatus(const FlowDescription& flowDescription,
                                                bool                   ackingStatus)
{
    // IMPORTANT NOTE:  "Managed" entries are only made when "ackingStatus == true:
    // (TBD - add an extra parameter to mark entries as "managed".  I.e., will only
    //        be removed when controller dictates regardless of acking status.  This
    //        enables static forwarding entries).

    // Sets acking status for all matching entries.
    MulticastFIB::EntryTable& flowTable = mcast_fib.AccessFlowTable();
    MulticastFIB::EntryTable::Iterator iterator(flowTable, &flowDescription);
    MulticastFIB::Entry* entry = entry = iterator.GetNextEntry();
    bool exactMatch = false;
    if (NULL != entry)
    {
        unsigned int currentTick = UpdateTicker();
        do
        {
            //if (GetDebugLevel() >= PL_DEBUG)
            {
                PLOG(PL_ALWAYS, "nrlsmf: setting AckingStatus to %d for existing flow ", ackingStatus);
                entry->GetFlowDescription().Print();
                PLOG(PL_ALWAYS, "\n");
            }
            if (ackingStatus)
            {
#if (USE_PREEMPTIVE_ACK)
                if (!entry->GetAckingStatus())
                {
                    // If ackingStatus, flow already exists, has active upstream relays, and current
                    // flow ackingStatus is "false", then send anEM-ACK right away
                    MulticastFIB::UpstreamRelayList::Iterator upserator(entry->AccessUpstreamRelayList());
                    MulticastFIB::UpstreamRelay* upstream;
                    while (NULL != (upstream = upserator.GetNextItem()))
                    {
                        if (upstream->Age(currentTick) < entry->GetAckingIntervalMax())
                        {
                            PLOG(PL_ALWAYS, "nrlsmf: sending preemptive EM-ACK to upstream relay %s\n",
                                             upstream->GetAddress().GetHostString());
                            SendAck(upstream->GetInterfaceIndex(),
                                    upstream->GetAddress(),
                                    entry->GetFlowDescription(),
                                    upstream->GetAddress());
                            upstream->Reset(currentTick);
                        }
                    }
                }
#endif // USE_PREEMPTIVE_ACK
            }
            else if (!entry->IsActive() && !entry->IsIdle())
            {
                flowTable.RemoveEntry(*entry);
                delete entry;
                continue;
            }
            entry->SetAckingStatus(ackingStatus);
            if (entry->IsExactMatch(flowDescription))
            {
                entry->SetManaged(ackingStatus);
                exactMatch = true;
            }
        } while (NULL != (entry = iterator.GetNextEntry()));
    }
    if (ackingStatus && !exactMatch)
    {
        // Need to make an exact-match entry,  (Also, make it
        // "managed" (i.e., exempt from flow activity timeout
        // deletion since it is being emplaced by the controller)
        if (NULL == (entry = new MulticastFIB::Entry(flowDescription)))
        {
            PLOG(PL_ERROR, "SmartForwarder::SetAckingStatus() new Entry error: %s\n", GetErrorString());
            return false;
        }
        //if (GetDebugLevel() >= PL_DEBUG)
        {
            PLOG(PL_ALWAYS, "nrlsmf: setting AckingStatus to %d for new flow ", ackingStatus);
            flowDescription.Print();
            PLOG(PL_ALWAYS, " threshold:%u \n", entry->GetAckingCountThreshold());
        }
        entry->SetAckingStatus(true);
        entry->SetManaged(true);
        flowTable.InsertEntry(*entry);
    }
    return true;
}  // end SmartForwarder::SetAckingStatus()

// This is called by the controller to update the flow table with the unicast routing information.
bool SmartForwarder::UpdateRoutingTable(const FlowDescription& flowDescription, MulticastFIB::UpstreamRelay nextHop, double broadcastProbability)
{
    // Get the entry to the flow table correpsonding to the flow being updated.
    MulticastFIB::Entry * entry = mcast_fib.AccessFlowTable().FindBestMatch(flowDescription);
    // Update the downstream relay
    entry->setDownstreamRelay(nextHop);
    // Update teh unicast probability.
    entry->setUnicastProb(1-broadcastProbability);
    return true;
}

MulticastFIB::UpstreamRelay* SmartForwarder::getNextHop(const FlowDescription& flowDescription)
{
     MulticastFIB::Entry * entry = mcast_fib.AccessFlowTable().FindBestMatch(flowDescription);
    // Update the downstream relay
    return entry->getDownstreamRelay();

}

double SmartForwarder::getBroadcastProbability(const FlowDescription& flowDescription)
{
    MulticastFIB::Entry * entry = mcast_fib.AccessFlowTable().FindBestMatch(flowDescription);

    return 1.0 - entry->getUnicastProb();

}

// This is old EM code.

bool SmartForwarder::SetForwardingStatus(const FlowDescription&          flowDescription,
                                                    unsigned int                    ifaceIndex,
                                                    MulticastFIB::ForwardingStatus  forwardingStatus,
                                                    bool                            ackingStatus)
{
    // IMPORTANT NOTE:  "Managed" entries are only made when "ackingStatus == true:
    // (TBD - add an extra parameter to mark entries as "managed".  I.e., will only
    //        be removed when controller dictates regardless of acking status.  This
    //        enables static forwarding entries).

    // Sets forwarding status for all matching entries.
    MulticastFIB::EntryTable& flowTable = mcast_fib.AccessFlowTable();
    MulticastFIB::EntryTable::Iterator iterator(flowTable, &flowDescription);
    MulticastFIB::Entry* entry = entry = iterator.GetNextEntry();
    bool exactMatch = false;
    if (NULL != entry)
    {
        unsigned int currentTick = UpdateTicker();
        do
        {
            //if (GetDebugLevel() >= PL_DEBUG)
            {
                const char* forwardingStatusString = MulticastFIB::GetForwardingStatusString(forwardingStatus);
                PLOG(PL_ALWAYS, "nrlsmf: setting ForwardingStatus %s and AckingStatus to %d for existing flow ",
                                    forwardingStatusString, ackingStatus);
                entry->GetFlowDescription().Print();
                PLOG(PL_ALWAYS, "\n");
            }
            if (ackingStatus)
            {
#if (USE_PREEMPTIVE_ACK)
                if (!entry->GetAckingStatus())
                {
                    // If ackingStatus, flow already exists, has active upstream relays, and current
                    // flow ackingStatus is "false", then send and EM-ACK right away
                    MulticastFIB::UpstreamRelayList::Iterator upserator(entry->AccessUpstreamRelayList());
                    MulticastFIB::UpstreamRelay* upstream;
                    while (NULL != (upstream = upserator.GetNextItem()))
                    {
                        if (upstream->Age(currentTick) < entry->GetAckingIntervalMax())
                        {
                            PLOG(PL_ALWAYS, "nrlsmf: sending preemptive EM-ACK to upstream relay %s\n",
                                            upstream->GetAddress().GetHostString());
                            SendAck(upstream->GetInterfaceIndex(),
                                    upstream->GetAddress(),
                                    flowDescription,
                                    upstream->GetAddress());
                            upstream->Reset(currentTick);
                        }
                    }
                }
#endif // USE_PREEMPTIVE_ACK
            }
            else if (!entry->IsActive() && !entry->IsIdle())
            {
                flowTable.RemoveEntry(*entry);
                delete entry;
                continue;
            }
            entry->SetForwardingStatus(ifaceIndex, forwardingStatus, ackingStatus);
            if (entry->IsExactMatch(flowDescription))
            {
                entry->SetManaged(ackingStatus);
                exactMatch = true;
            }
        } while (NULL != (entry = iterator.GetNextEntry()));
    }
    if (ackingStatus && !exactMatch)
    {
        // Need to make an exact-match entry,  (Also, make it
        // "managed" (i.e., exempt from flow activity timeout
        // deletion since it is being emplaced by the controller)
        if (NULL == (entry = new MulticastFIB::Entry(flowDescription)))
        {
            PLOG(PL_ERROR, "MulticastFIB::SetForwardingStatus() new Entry error: %s\n", GetErrorString());
            return false;
        }
        //if (GetDebugLevel() >= PL_DEBUG)
        {
            const char* forwardingStatusString = MulticastFIB::GetForwardingStatusString(forwardingStatus);
            PLOG(PL_ALWAYS, "nrlsmf: setting ForwardingStatus %s and AckingStatus to %d for new flow ",
                                forwardingStatusString, ackingStatus);
            flowDescription.Print();
            PLOG(PL_ALWAYS, "\n");
        }
        entry->SetForwardingStatus(ifaceIndex, forwardingStatus, ackingStatus);
        entry->SetManaged(true);
        flowTable.InsertEntry(*entry);
    }
    return true;
}  // end SmartForwarder::SetForwardingStatus()
