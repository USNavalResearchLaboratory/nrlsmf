#include "mcastFib.h"
#include "protoNet.h"  // to get interface addresses given interface indices (TBD - addresses should be configured w/ indices externally)
#include "protoPktETH.h"
#include "protoPktIP.h"
#include "protoDebug.h"
#include <stdlib.h>
#include <math.h>
#include <algorithm>
#include <iostream>

#include <smf.h> // for Smf::Interface

#define USE_PREEMPTIVE_ACK 1

const unsigned int MulticastFIB::DEFAULT_RELAY_ACTIVE_TIMEOUT = (1 * 1000000);  // 1 seconds in microseconds (this is a short timeout since active relays should be sending traffic, too)
                                                                                // (this short timeout lets us rapidly adapt to a secondary relay when the primary goes quiet)
                                                                                
const unsigned int MulticastFIB::DEFAULT_RELAY_IDLE_TIMEOUT = (30 * 1000000);   // 30 seconds in microseconds

const unsigned int MulticastFIB::DEFAULT_FLOW_ACTIVE_TIMEOUT = (60 * 1000000);  // 60 seconds in microseconds
const unsigned int MulticastFIB::DEFAULT_FLOW_IDLE_TIMEOUT = (120 * 1000000);   // 120 seconds in microseconds

const double MulticastFIB::DEFAULT_LEARNING_RATE = 0.1;
const unsigned int MulticastFIB::MAX_SENT_PACKETS = 200;
// These set the default update/acking condition for a flow
const unsigned int MulticastFIB::DEFAULT_ACKING_COUNT = 10;                     // number of packets per update
const unsigned int MulticastFIB::DEFAULT_ACKING_INTERVAL_MIN = (0.1 * 1000000); // 0.1 seconds in microseconds
const unsigned int MulticastFIB::DEFAULT_ACKING_INTERVAL_MAX = (30 * 1000000);  // 30 seconds in microseconds

const double MulticastFIB::DEFAULT_ACK_TIMEOUT = 30.0;  // 30 seconds
const unsigned int MulticastFIB::DEFAULT_IDLE_COUNT_THRESHOLD = 60;    // 60 packets 

//const ProtoAddress MulticastFIB::BROADCAST_ADDR = ProtoAddress("255.255.255.255");

// This maintains our microsecond ticker
const double TICK_INTERVAL = 1.0e-06;           // 1 microsecond per "tick"
const double TICK_RATE = 1.0 / TICK_INTERVAL;

// the "delta max" needs to be less than our TICK_AGE_MAX
// and should be bigger than the longest membership timeout
// so that the ticker gets updated in a timely manner
const double ElasticTicker::DELTA_MAX = 600.0; // seconds

unsigned int ElasticTicker::Update()
{
    ProtoTime currentTime;
    currentTime.GetCurrentTime();
    double delta = currentTime - ticker_time_prev;
    if ((delta < 0) || (delta > DELTA_MAX))
    {
        PLOG(PL_WARN, "ElasticTicker::Update() warning: invalid update interval!\n");
        delta = DELTA_MAX;
    }
    ticker_count += (unsigned int)(TICK_RATE * delta);
    ticker_time_prev = currentTime;
    return ticker_count;
}  // end ElasticTicker::Update()

MulticastFIB::Membership::Membership(unsigned int           ifaceIndex,
                                     const ProtoAddress&    dst,
                                     const ProtoAddress&    src,
                                     UINT8                  trafficClass,
                                     ProtoPktIP::Protocol   protocol)
  : FlowEntryTemplate(dst, src, trafficClass, protocol, ifaceIndex),
    membership_flags(0), idle_count_threshold(DEFAULT_IDLE_COUNT_THRESHOLD),
    idle_count(0), igmp_timeout_valid(false), elastic_timeout_valid(false),
    default_forwarding_status(LIMIT)
{
}

MulticastFIB::Membership::~Membership()
{
}


MulticastFIB::FlowPolicy::FlowPolicy(const ProtoAddress&  dst,
                                     const ProtoAddress&  src,
                                     UINT8                trafficClass,
                                     ProtoPktIP::Protocol protocol)
  : FlowEntryTemplate(dst, src, trafficClass, protocol),
    bucket_rate(1.0), bucket_depth(10), 
    forwarding_status(LIMIT), acking_status(false)
{
}

MulticastFIB::FlowPolicy::FlowPolicy(const FlowDescription& description, int flags)
  : FlowEntryTemplate(description, flags), bucket_rate(1.0), bucket_depth(10), 
    forwarding_status(LIMIT), acking_status(false)
{
}


MulticastFIB::FlowPolicy::~FlowPolicy()
{
}


/*
MulticastFIB::MaskLengthList::MaskLengthList()
 : list_length(0)
{
    memset(ref_count, 0, 129*sizeof(unsigned int));
}

MulticastFIB::MaskLengthList::~MaskLengthList()
{
}

void MulticastFIB::MaskLengthList::Insert(UINT8 value)
{
    if (value > 128)
    {
        PLOG(PL_ERROR, "MulticastFIB::MaskLengthList::Insert() error: invalid value\n");
        return;
    }
    if (ref_count[value] > 0)
    {
        ref_count[value] += 1;
        return;  // already in list
    }
    else
    {
        ref_count[value] = 1;
    }
    if (0 == list_length)
    {
        mask_list[0] = value;
        list_length += 1;
    }
    else if (value > mask_list[0])
    {
        memmove(mask_list+1, mask_list, list_length);
        mask_list[0] = value;
        list_length += 1;
    }
    else if (value < mask_list[list_length - 1])
    {
        mask_list[list_length] = value;
        list_length += 1;
    }
    else
    {
        // Do a hybrid binary/linear search
        UINT8 index = list_length/2;
        UINT8 delta = index;
        UINT8 x = mask_list[index];
        // Binary search portion
        while (delta > 1)
        {
            delta /= 2;
            if (value < x)
                index += delta;
            else if (value > x)
                index -= delta;
            else
                return;  // value already in list
            x = mask_list[index];
        }
        // Linear search portion
        if (value < x)
            do {x = mask_list[++index];} while (value < x);
        else if (value > x)
            do { x = mask_list[--index];} while (value > x);
        if (value < x)
        {
            memmove(mask_list+index+2, mask_list+index+1, list_length-index-1);
            mask_list[index+1] = value;
            list_length += 1;
        }
        else if (value > x)
        {
            memmove(mask_list+index+1, mask_list+index, list_length-index);
            mask_list[index] = value;
            list_length += 1;
        }
        // else value already in list
    }
}  // end MulticastFIB::MaskLengthList::Insert()

void MulticastFIB::MaskLengthList::Remove(UINT8 value)
{
    if ((0 == list_length) || (value > mask_list[0]) || (value < mask_list[list_length-1]))
        return;  // value out of list range

    if (ref_count[value] > 1)
    {
        ref_count[value] -= 1;
        return;  // still has non-zero reference count
    }
    else if (ref_count[value] > 0)
    {
        ref_count[value] = 0;
    }
    else
    {
        return;  // not in list
    }
    // Do a hybrid binary/linear search
    UINT8 index = list_length/2;
    UINT8 delta = index;
    UINT8 x = mask_list[index];
    // Binary search portion
    while (delta > 1)
    {
        delta /= 2;
        if (value < x)
        {
            index += delta;
        }
        else if (value > x)
        {
            index -= delta;
        }
        else
        {
            // Found it directly via binary search
            memmove(mask_list+index, mask_list+index+1, list_length-index-1);
            list_length -= 1;
            return;
        }
        x = mask_list[index];
    }
    // Linear search portion
    if (value < x)
        do {x = mask_list[++index];} while (value < x);
    else if (value > x)
        do {x = mask_list[--index];} while (value > x);
    if (value == x)
    {
        memmove(mask_list+index, mask_list+index+1, list_length-index-1);
        list_length -= 1;
    }
    // else not in list
}  // end MulticastFIB::MaskLengthList::Remove()

*/
        
MulticastFIB::MembershipTable::MembershipTable()
{
}

MulticastFIB::MembershipTable::~MembershipTable()
{
    Destroy();
}

MulticastFIB::Membership* MulticastFIB::MembershipTable::AddMembership(unsigned int         ifaceIndex,
                                                                       const ProtoAddress&  dst,
                                                                       const ProtoAddress&  src,
                                                                       UINT8                trafficClass,
                                                                       ProtoPktIP::Protocol protocol)
{
    Membership* membership = FindMembership(ifaceIndex, dst, src, trafficClass, protocol);
    if (NULL == membership)
    {
        if (NULL == (membership = new Membership(ifaceIndex, dst, src, trafficClass, protocol)))
        {
            PLOG(PL_ERROR, "MulticastFIB::MembershipTable::AddMembership() new Membership error: %s\n", GetErrorString());
            return NULL;
        }
        if (!InsertEntry(*membership))
        {
            PLOG(PL_ERROR, "MulticastFIB::MembershipTable::AddMembership() error: unable to insert membership.\n");
            delete membership;
            return NULL;
        }
    }
    return membership;
}  // end MulticastFIB::MembershipTable::AddMembership()

void MulticastFIB::MembershipTable::RemoveMembership(unsigned int          ifaceIndex,
                                                     const ProtoAddress&   dst,
                                                     const ProtoAddress&   src,
                                                     UINT8                 trafficClass,
                                                     ProtoPktIP::Protocol  protocol)
{
    Membership* membership = FindMembership(ifaceIndex, dst, src, trafficClass, protocol);
    if (NULL != membership)
    {

        RemoveEntry(*membership);
        delete membership;
    }
}  // end MulticastFIB::MembershipTable::RemoveMembership()


MulticastFIB::MembershipStatus MulticastFIB::MembershipTable::GetMembershipStatus(unsigned int          ifaceIndex,
                                                                                  const ProtoAddress&   dst,
                                                                                  const ProtoAddress&   src)
{
    // Return the "best fit" membership status for give group address and optional src address
    if (src.IsValid())
    {
        if (IsMember(dst, src))
            return MEMBER_SSM;
    }
    if (IsMember(dst))
        return MEMBER_ASM;
    return MEMBER_NONE;

}  // end MulticastFIB::MembershipTable::GetMembershipStatus()

bool MulticastFIB::MembershipTable::IsMember(const ProtoAddress&   dst,
                                             const ProtoAddress&   src,
                                             bool                  wildcardSource)
{

    if (!dst.IsValid()) return false;
    FlowDescription flowDescription(dst, src);
    if (!src.IsValid() && !wildcardSource)
    {
        // Find dst-only membership entry
        return (NULL != FindMembership(flowDescription));
    }
    else
    {
        // Are there any memberships that match?
        MembershipTable::Iterator iterator(*this, &flowDescription);
        return (NULL != iterator.GetNextEntry());
    }
}  // end MulticastFIB::MembershipTable::IsMember()

// Activate or update membership to timeout at given "tick"
bool MulticastFIB::MembershipTable::ActivateMembership(Membership& membership, Membership::Flag flag, unsigned int tick)
{
    if (Membership::STATIC == flag)
    {
        membership.SetFlag(flag);
        return true;
    }
    bool insert = false;
    // If membership already in ring, determine if update affects ring position
    if (membership.elastic_timeout_valid || membership.igmp_timeout_valid)
    {
        if (flag == membership.timeout_flag)
        {
            insert = true;  // remove/ re-insert this membership to new position
        }
        else
        {
            unsigned int currentTick =
                (Membership::ELASTIC == membership.timeout_flag) ?
                    membership.elastic_timeout_tick : membership.igmp_timeout_tick;
            int delta = tick - currentTick;
            ASSERT(abs(delta) <= TICK_AGE_MAX);
            if (delta < 0) 
                insert = true;
            // else no change in position
        }
        if (insert)
        {
            // Remove the membership for re-insertion
            if (&membership == ring_leader)
            {
                Ring::Iterator iterator(membership_ring);
                iterator.SetCursor(membership_ring, membership);
                iterator.GetNextItem();  // skip cursor
                ring_leader = iterator.GetNextItem();
                membership_ring.Remove(membership);
                if (NULL == ring_leader) 
                    ring_leader = membership_ring.GetHead();
            }
            else
            {
                membership_ring.Remove(membership);
            }
        }
    }
    else
    {
        insert = true;
    }
    
    if (Membership::ELASTIC == flag)
    {
        membership.elastic_timeout_tick = tick;
        membership.elastic_timeout_valid = true;
    }
    else  // if (Membership::MANAGED == flag)
    {
        membership.igmp_timeout_tick = tick;
        membership.igmp_timeout_valid = true;
    }
    if (insert)
    {
        membership.timeout_flag = flag;
        // This assertion checks that we are inserting a compatible timeout
        ASSERT((NULL == ring_leader) || (abs((int)(ring_leader->GetTimeout() - membership.GetTimeout())) <= TICK_AGE_MAX));
        if (!membership_ring.Insert(membership))
        {
            PLOG(PL_ERROR, "MulticastFIB::MembershipTable::ActivateMembership() error: unable to insert timeout!\n");
            return false;
        }
        if (NULL == ring_leader)
        {
            ring_leader = &membership;
        }
        else
        {
            int delta = tick - ring_leader->GetTimeout(); 
            // Note that ProtoSortedTree inserts ties prior to any existing
            // matching entry, thus the "delta <= 0" condition
            if (delta <= 0) ring_leader = &membership;
        }
    }
    membership.SetFlag(flag);
    return true;
}  // end MulticastFIB::MembershipTable::ActivateMembership()

void MulticastFIB::MembershipTable::DeactivateMembership(Membership& membership, Membership::Flag flag)
{
    if ((Membership::STATIC != flag) &&
        (membership.elastic_timeout_valid ||
         membership.igmp_timeout_valid))
    {
        if (flag == membership.timeout_flag)
        {
            if (&membership == ring_leader)
            {
                Ring::Iterator iterator(membership_ring);
                iterator.SetCursor(membership_ring, membership);
                iterator.GetNextItem();  // skip cursor
                ring_leader = iterator.GetNextItem();
                membership_ring.Remove(membership);
                if (NULL == ring_leader) 
                    ring_leader = membership_ring.GetHead();
            }
            else
            {
                membership_ring.Remove(membership);
            }
            if (Membership::ELASTIC == flag)
            {
                membership.elastic_timeout_valid = false;
                if (membership.igmp_timeout_valid)
                {
                    membership.igmp_timeout_valid = false;
                    ActivateMembership(membership, Membership::MANAGED, membership.igmp_timeout_tick);
                }
            }
            else // if (Membership::MANAGED == flag)
            {
                membership.igmp_timeout_valid = false;
                if (membership.elastic_timeout_valid)
                {
                    membership.elastic_timeout_valid = false;
                    ActivateMembership(membership, Membership::ELASTIC, membership.elastic_timeout_tick);
                }
            }
        }
        else
        {
            if (Membership::ELASTIC == flag)
                membership.elastic_timeout_valid = false;
            else // if (Membership::MANAGED == flag)
                membership.igmp_timeout_valid = false;
        }
    }
    membership.ClearFlag(flag);
}  // end MulticastFIB::MembershipTable::DeactivateMembership()

MulticastFIB::MembershipTable::AgeIterator::AgeIterator(MembershipTable& table)
  : ringerator(table.membership_ring)
{
}

MulticastFIB::MembershipTable::AgeIterator::~AgeIterator()
{
}

MulticastFIB::TokenBucket::TokenBucket(unsigned int ifaceIndex)
  : iface_index(ifaceIndex), forwarding_status(LIMIT),
    bucket_depth(10), bucket_count(10), ticker_prev(0)
{
    SetRate(1.0);
}

MulticastFIB::TokenBucket::~TokenBucket()
{
}

void MulticastFIB::TokenBucket::SetRate(double pktsPerSecond)
{
    if (pktsPerSecond > 0.0)
    {
        token_interval = (unsigned int)((TICK_RATE / pktsPerSecond) + 0.5);
        if (0 == token_interval) token_interval = 1;
    }
    else
    {
        token_interval = 0.0;  // unlimited
    }
}  // end MulticastFIB::TokenBucket::SetRate()


void MulticastFIB::TokenBucket::Refresh(unsigned int currentTick)
{
    // TBD - If we restrict the "token_interval" to a power of 2 mask (2^n - 1)
    //       bit shifts can be used for division and remainder computation
    //       to  reduce the commplexity
    if (bucket_count < bucket_depth)
    {
        // How long has it been?
        int age = currentTick - ticker_prev;
        if (age < 0)
            age = TICK_AGE_MAX;
        else if (age > TICK_AGE_MAX)
            age = TICK_AGE_MAX;
        // Compute the number of tokens we can add to the bucket since
        // last refresh.
        unsigned int tokens = age / token_interval;
        // Here we credit the bucket_count. The "tickRemainder"
        // offset helps us accurately service bucket update.
        // I.e., the "currentTick" is offset to the "time" (tick)
        // when the bucket would have been logically credited.
        // (If bucket overflow, we let the "currentTick" time ride
        unsigned int tickRemainder = age - (tokens * token_interval);
        //if (HYBRID != forwarding_status) 
            bucket_count += tokens;
        if (bucket_count > bucket_depth)
            bucket_count = bucket_depth;
        else
            currentTick -= tickRemainder;
    }
    ticker_prev = currentTick;
}  // end MulticastFIB::TokenBucket::Refresh()

// Returns "true" if packet is conformant (i.e., within rate limit)
bool MulticastFIB::TokenBucket::ProcessPacket(unsigned int currentTick)
{
    // First, "refresh" bucket according to "currentTick"
    Refresh(currentTick);  // note this call is redundant w/ Entry::UpdateAge() call?
    switch (forwarding_status)
    {
        case BLOCK:
            return false;
        case FORWARD:
            return true;
        case LIMIT:
        case HYBRID:
            if (bucket_count > 0)
            {
                bucket_count--;
                return true;
            }
            else
            {
                if (HYBRID == forwarding_status)
                    forwarding_status = BLOCK;  // will be reset on flow timeout
                return false;
            }
        default:
            ASSERT(0);
            return false;
    }
}  // end MulticastFIB::TokenBucket::ProcessPacket()


MulticastFIB::ActivityStatus::ActivityStatus() 
  : age_tick(0), age_max(true), active(false) 
{
}

MulticastFIB::ActivityStatus::~ActivityStatus() 
{
}
                
unsigned int MulticastFIB::ActivityStatus::Age(unsigned int currentTick)
{
    if (age_max)
    {
        return TICK_AGE_MAX;
    }
    else
    {
        int age = currentTick - age_tick;
        if ((age < 0) || (age > TICK_AGE_MAX))
        {
            age_max = true;
            active = false;
            return TICK_AGE_MAX;
        }
        return age;
    }
}  // end MulticastFIB::ActivityStatus::Age()


MulticastFIB::UpstreamHistory::UpstreamHistory(const ProtoAddress& addr)
 : src_addr(addr), seq_prev(0), idle_count(0), good_count(0), loss_estimate(0.0)
   //,active_flow_count(0)
{
}

MulticastFIB::UpstreamHistory::~UpstreamHistory()
{
}

double MulticastFIB::UpstreamHistory::UpdateLossEstimate(unsigned int gapCount)
{
    if (0 != gapCount)
    {
        double loss = (double)gapCount / (double)(good_count + gapCount);
        loss_estimate = 0.75*loss_estimate + 0.25*loss;
        good_count = 1;
    }
    else
    {
        // This could be modified to be more optimistic with
        // "runLength" windows to halve loss_estimate every window
        // of consecutive good packets???
        good_count++;
        if (loss_estimate > 0.0)
        {
            unsigned int runLength = 1.0 / loss_estimate;
            if (good_count >= runLength)
                loss_estimate = 1.0 / (double)good_count;
        }           
    }
    return loss_estimate;
}  // end MulticastFIB::UpstreamHistory::UpdateLossEstimate()


MulticastFIB::UpstreamRelay::UpstreamRelay(const ProtoAddress& addr, unsigned int ifaceIndex)
 : relay_addr(addr), iface_index(ifaceIndex), relay_status(NULLARY), update_count(0),
   update_start(0), update_max(true), adv_id(0), adv_metric(-1.0), adv_ttl(0), adv_hop_count(0), link_quality(-1.0)
{
}

MulticastFIB::UpstreamRelay::UpstreamRelay()
: relay_addr(ProtoAddress("ff:ff:ff:ff:ff:ff")), iface_index(0), 
  update_count(0),  update_start(0), update_max(true) //, packet_rate(0.0)
{
}

MulticastFIB::UpstreamRelay::~UpstreamRelay()
{
}

/*
void MulticastFIB::UpstreamRelay::UpdatePacketRate(unsigned int currentTick)
{
    if (!update_max)
    {
        int updateInterval = currentTick - update_start;
        if ((updateInterval < 0) || (updateInterval > TICK_AGE_MAX))
        {
            update_max = true;
            packet_rate = 0.0;
        }
        else if (updateInterval > 0)
        {
            double rate = (double) update_count / (double)(TICK_INTERVAL * updateInterval);
            if (0.0 == packet_rate)
                packet_rate = rate;
            else
                packet_rate = 0.75*packet_rate + 0.25*rate;
        }
    }
    else
    {
        packet_rate = 0.0;
    }
}  // end MulticastFIB::UpstreamRelay::UpdatePacketRate()
*/

void MulticastFIB::UpstreamRelay::Refresh(unsigned int currentTick)//, unsigned int count)
{
    if (0 == update_count)
    {
        update_start = currentTick;
        update_max = false;
    }
    else if (!update_max)
    {
        //UpdatePacketRate(currentTick);  // takes care of setting "update_max" as needed
    }
    update_count += 1;
    activity_status.Refresh(currentTick);
}  // end MulticastFIB::UpstreamRelay::Refresh()

unsigned int MulticastFIB::UpstreamRelay::Age(unsigned int currentTick)
{
    unsigned int age = activity_status.Age(currentTick);
    if (TICK_AGE_MAX == age) return TICK_AGE_MAX;
    if (!update_max)
    {
        int updateInterval = currentTick - update_start;
        if ((updateInterval < 0) || (updateInterval > TICK_AGE_MAX))
            update_max = true;
    }
    return age;
}  // end MulticastFIB::UpstreamRelay::Age()

unsigned int MulticastFIB::UpstreamRelay::GetUpdateInterval() const
{
    if (update_max || !activity_status.IsValid())
    {
        return TICK_AGE_MAX;
    }
    else
    {
        int updateInterval = activity_status.GetAgeTick() - update_start;
        if ((updateInterval < 0) || (updateInterval > TICK_AGE_MAX))
        {
            // This is not expected to happen under proper
            PLOG(PL_WARN, "MulticastFIB::UpstreamRelay::GetUpdateInterval() warning: unexpected aging\n");
            return TICK_AGE_MAX;
        }
        else
        {
            return updateInterval;
        }
    }
}  // end MulticastFIB::UpstreamRelay::GetUpdateInterval()

bool MulticastFIB::UpstreamRelay::AckPending(const Entry& entry) const //, bool actual) const
{
    unsigned int ackingCountThreshold = entry.GetAckingCountThreshold();
    unsigned int ackingIntervalMax = entry.GetAckingIntervalMax();
    unsigned int ackingIntervalMin = entry.GetAckingIntervalMin();
    unsigned int pktCount = GetUpdateCount();
    //if (actual) 
        pktCount--;
    unsigned int updateInterval = GetUpdateInterval();
    if (((0 != ackingCountThreshold) &&
        (pktCount >= ackingCountThreshold) &&
        (updateInterval >= ackingIntervalMin)) ||
        ((0 != ackingIntervalMax) &&
        (updateInterval >= ackingIntervalMax)))
    {
        return true;
    }
    else
    {
        return false;
    }
}  // end MulticastFIB::UpstreamRelay::AckPending()

#ifdef ADAPTIVE_ROUTING

// R2DN Additions: Created by Matt Johnston on 9/11/17
//MulticastFIB::StochasticRoutingEntry::StochasticRoutingEntry(const ProtoAddress& addr, std::list<unsigned int> ifaceList)
//  : next_hop_addr(addr), iface_list(ifaceList), probability(1), weight(1)
//{
//}
//
//MulticastFIB::StochasticRoutingEntry::StochasticRoutingEntry(const ProtoAddress& addr, std::list<unsigned int> ifaceList, double w)
//  : next_hop_addr(addr), iface_list(ifaceList), probability(1), weight(w)
//{
//}
//
//
//MulticastFIB::StochasticRoutingEntry::~StochasticRoutingEntry()
//{
//}
//
//
//void MulticastFIB::StochasticRoutingEntry::setWeight(double w)
//{
//		weight = w;
//		return;
//}
//

//void MulticastFIB::StochasticRoutingEntry::setProbability (double p)
//{
//		probability = p;
//		return;
//}
//
//double MulticastFIB::StochasticRoutingEntry::getWeight() const
//{
//	return weight;
//}
//
//double MulticastFIB::StochasticRoutingEntry::getProbability() const
//{
//	return probability;
//}
//
//MulticastFIB::ForwardingDistribution::ForwardingDistribution()
//{
//}
//
//MulticastFIB::ForwardingDistribution::ForwardingDistribution(std::list<StochasticRoutingEntry> entries)
//{
//	distribution = entries;
//	normalize();
//}
//
//MulticastFIB::ForwardingDistribution::~ForwardingDistribution()
//{
//}
//
//void MulticastFIB::ForwardingDistribution::normalize()
//{
//	double totalWeight = 0;
//	for (std::list<StochasticRoutingEntry>::const_iterator ci = distribution.begin(); ci != distribution.end(); ++ci)
//	{
//		StochasticRoutingEntry entry = *ci;
//		totalWeight += entry.getWeight();
//	}
//	for (std::list<StochasticRoutingEntry>::const_iterator ci = distribution.begin(); ci != distribution.end(); ++ci)
//	{
//		StochasticRoutingEntry entry = *ci;
//		entry.setProbability(1.0*entry.getWeight() / totalWeight);
//	}
//}
//
//
//double MulticastFIB::ForwardingDistribution::add(StochasticRoutingEntry entry)
//{
//	distribution.push_back(entry);
//	normalize();
//	return distribution.back().getProbability();
//}
//
//double MulticastFIB::ForwardingDistribution::setDistribution(std::list<StochasticRoutingEntry> entries)
//{
//	distribution = entries;
//	normalize();
//}
//
////double MulticastFIB::ForwardingDistribution::setDistribution(ProtoAddress& unicastAddr, double probability)
////{
////    MulticastFIB::StochasticRoutingEntry unicastEntry = MulticastFIB::StochasticRoutingEntry(unicastAddr, probability);
////    MulticastFIB::StochasticRoutingEntry broadcastEntry = MulticastFIB::StochasticRoutingEntry(ProtoAddress.GetBroadcastAddress(0,MulticastFIB::BROADCAST_ADDR), 1.0-probability);
////
////	std::list<MulticastFIB::StochasticRoutingEntry> entries;
////	entries.insert(entries.end(), &unicastEntry);
////	entries.insert(entries.end(), &broadcastEntry);
////	distribution = entries;
////	normalize();
////}
//
//MulticastFIB::StochasticRoutingEntry MulticastFIB::ForwardingDistribution::getRandomElement() const
//{
//	MulticastFIB::StochasticRoutingEntry entry = *distribution.begin();
//	double r = ((double) rand() / (RAND_MAX));	// generate a random number between 0 and 1
//	double total = 0;
//	for (std::list<MulticastFIB::StochasticRoutingEntry>::const_iterator ci = distribution.begin(); ci != distribution.end(); ++ci)
//	{
//		entry = *ci;
//		total += entry.getProbability();
//		if (r <= total)
//			return entry;
//
//	}
//	PLOG(PL_ERROR, "MulticastFIB::ForwardingDistribution::getRandomElement() error: Need to normalize distribution\n");
//	std::cout << "ERROR Generating random selction.  Need to normalize distribution.";
//	return entry;
//}

// learning rate is hard-coded for now, but eventually it will be taken from a config file.
MulticastFIB::RL_Data::RL_Data()
{
    learning_rate = DEFAULT_LEARNING_RATE;
}

MulticastFIB::RL_Data::RL_Data(const FlowDescription& flow, double learningRate)
: FlowEntryTemplate(flow)
{
    learning_rate = learningRate;
}

MulticastFIB::RL_Data::~RL_Data()
{
}

MulticastFIB::RL_Data::RL_Metric_Tuple * MulticastFIB::RL_Data::getMetrics(ProtoAddress addr)
{
    // If there are no RL metrics for this address.
    if (! rl_metrics.Contains(addr))
    {
        // error
         PLOG(PL_ERROR, "MulticastFIB::RL_Data::getMetric() error: no RL Metrics for address.\n");
         return NULL;
    }
    // Return the pointer to the RL_Metric_Tuple for the address.
    RL_Metric_Tuple * metrics_ptr = (RL_Metric_Tuple *)(rl_metrics.GetUserData(addr));
    return metrics_ptr;
}

//
bool MulticastFIB::RL_Data::update(ProtoAddress addr, float ackQ, float ackC, UINT16 seqNo, UINT16 fragOffset)
{
    double alpha;
    int correction=0, spIndex;
    bool found = false;
    std::list<UINT32>::iterator it;

    //PLOG(PL_DEBUG, "MulticastFIB::RL_Data:update. Updating Data: addr = %s, Q = %f, C = %f, ID=%d, offset=%d\n", addr.GetHostString(), ackQ, ackC, seqNo, fragOffset);

    if (! rl_metrics.Contains(addr))
    {
        //PLOG(PL_DEBUG, "MulticastFIB::RL_Data:update() Address not in list, adding new address\n");
        // Could not find link in flow table. This implies that we've received an acknowledgement for a link we didn't know about.
        // In this case, we add an entry to rl_metrics to start keeping track of RL metrics.
        // To initialize, we assume C = 0 since we don't have information yet.  The value of Q is irrelevant, since the first update will
        // Weight ackQ at 100% since C = 0.  Using Qinit = 99 because its easy to notice in debug logs.

        // Create a new Metric Tuple in memory.
        RL_Metric_Tuple * new_metrics_ptr = new RL_Metric_Tuple(99,0);
        // Insert a pointer to this new tuple in the rl_metrics structure corresponding to next-hop addr.
        rl_metrics.Insert(addr,new_metrics_ptr);
    }
    // Get a pointer to the existing metrics (or newly added metrics).
    RL_Metric_Tuple * old_metrics_ptr = getMetrics(addr);
    double newQ, newC;

    // Use C to compute learning rate for Q values.
    alpha = std::max((double)ackC, 1-old_metrics_ptr->C/(1-1.0*learning_rate));
    //PLOG(PL_DEBUG, "MulticastFIB::RL_Date:update() alpha = %f\n", alpha);

    // Update Q factor using RL Recursion:
    newQ = old_metrics_ptr->Q + alpha * (ackQ + 1 - old_metrics_ptr->Q);
    //PLOG(PL_DEBUG, "MulticastFIB::RL_Data:update() Q = %f\n", newQ);

    // Need to examine the sentPackets structure to update C values.
    // First, get a pointer to the list of sequence numbers pertaining to address addr.
    std::list<UINT32> * seqNoListPtr = (std::list<UINT32> *)sentPackets.GetUserData(addr);

    // If there exists an entry for addr,
    if (NULL != seqNoListPtr)
    {
        // Iterate through the list of sequence numbers to find the sequence number of the acknowledged packet.
        int idx = 0;
        // Create an iterator that starts at the beginning of the list and goes to the end of the list.
        for (it = seqNoListPtr->begin(); it != seqNoListPtr->end(); ++it)
        {
            //PLOG(PL_DEBUG, "MulticastFIB::RL_Date:update() Sequence Number %d: %d\n", idx,  *it);
            idx +=1;
            // If the sequence number at the current location in the list equals the akc'd sequence number
            if (*it == (seqNo << 16) + fragOffset)
            {
                // Compute the number of elements after the sequence number in the list. This is the correction factor.
                std::list<UINT32> sublist(it,seqNoListPtr->end());
                correction = sublist.size()-1;
                // break loop
                found = true;
                break;
            }

        }
        if (found)
        {
            // Remove the sequence number from the list.
            //PLOG(PL_DEBUG, "MulticastFIB::RL_Date:update() Sequence Number found: correction = %d\n", correction);
            seqNoListPtr->erase(it);
        }
        else
        {

            //PLOG(PL_DEBUG, "MulticastFIB::RL_Date:update() seqNoList exists, but could not find sequence number \n");
            // This is the case when the packet was sent BEFORE the downstream Entry existed, so no seqNo could be recorded.
            // It is correct to assume this packet was sent before the earliest sequence number in the list.
            correction =  seqNoListPtr->size();
        }
    }
    else
    {
        //PLOG(PL_DEBUG, "MulticastFIB::RL_Date:update() seqNoList Not Initialized yet. \n");
        correction = 0; // We dont know any better
        // We dont need to add any data structures, as ack is received, smartController will have
        // created a downstreamList Entry, and future packets will get put in sent packets.

    }
    // Use correction factor to compute the C update according to the SRR algorithm.
    newC = old_metrics_ptr->C + learning_rate * pow((1-learning_rate),correction) * ackC;
    if (correction <= old_metrics_ptr->correctionThreshold)
    {
        old_metrics_ptr->correctionFactor = correction;
        old_metrics_ptr->correctionThreshold = correction;
        //PLOG(PL_DEBUG, "MulticastFIB::RL_Date:update() updating correction factor");
    }
    else{
        //PLOG(PL_DEBUG, "Out of order packet");
    }
    //PLOG(PL_DEBUG, "MulticastFIB::RL_Date:update() C = %f\n", newC);

    // store the new C and Q values in the rl_metrics object.
    old_metrics_ptr->C = newC;
    old_metrics_ptr->Q = newQ;



    return true;

}

double MulticastFIB::RL_Data::processSentPacket(ProtoAddress addr, UINT16 seqNo, UINT16 fragOffset)
{
    double updatedC = 0;

    // check If the address has an entry in rl_metrics.
    if (! rl_metrics.Contains(addr))
    {
       // PLOG(PL_DEBUG, "MulticastFIB::RL_Data:processSentPacket() Could not find address in rl_metrics, first packet.\n");
        // Could not find link in flow table. This means its the First packet sent over this link of the given flow.
        // Create a new entry for this link.
        // To initialize, we assume C = 0 since we don't have information yet.  The value of Q is irrelevant, since the first update will
        // Weight ackQ at 100% since C = 0.  Using Qinit = 99 because its easy to notice in debug logs.
        RL_Metric_Tuple * new_metrics_ptr = new RL_Metric_Tuple(99,0);
        rl_metrics.Insert(addr,new_metrics_ptr);
    }


    // Get pointer to relevant metrics.
    RL_Metric_Tuple * old_metrics_ptr = getMetrics(addr);

    // Reduce the value of C using the learning rate.  This is the conservative (assume packet is dropped) part of the
    // SRR algorithm.
    old_metrics_ptr->C = old_metrics_ptr->C *(1-learning_rate);
    old_metrics_ptr->correctionThreshold++; // This is to correctly modify routing algorithm
    time_t currentTime = time(0);
    // Add sent packet to list:
    // Get pointer to list of sequence numbers
    std::list<UINT32> * oldlist = (std::list<UINT32> *)(sentPackets.GetUserData(addr)); // This could be null.
   if (NULL == oldlist)
    {
        // If its the first packet out...
        // Make a new list
        oldlist = new std::list<UINT32>();
        // Add the sequence number to the new list.
        oldlist->push_back((seqNo << 16) + fragOffset);
        // Put the new list in sent packets, indexed by the address
        sentPackets.Insert(addr,oldlist);
    }
    else{
        // If its not the first packet out, then the list already exists.
        // Add the new sequence number to the list.
        oldlist->push_back((seqNo<<16)+fragOffset);
        if (oldlist->size() > MulticastFIB::MAX_SENT_PACKETS)
        {
            oldlist->pop_front();
        }
    }

    // Return; Return value isn't really used, we can probably make this void.
    return old_metrics_ptr->C;
}

// I dont believe this is used
//double MulticastFIB::RL_Data::getCorrectionFactor (ProtoAddress addr, UINT16 seqNo)
//{
//    std::list<UINT16> * seqNoListPtr = (std::list<UINT16> *)(sentPackets.GetUserData(addr));
//
//}

MulticastFIB::RL_Data * MulticastFIB::RL_Table::addFlow(const FlowDescription& flow)
{

    MulticastFIB::RL_Data * data_ptr = FindEntry(flow);
    if (NULL == data_ptr)
    {
        if (NULL == (data_ptr = new RL_Data(flow,MulticastFIB::DEFAULT_LEARNING_RATE)))
        {
            PLOG(PL_ERROR, "MulticastFIB::RL_Table::addFlow() new flow error: %s\n", GetErrorString());
            return NULL;
        }
        if (!InsertEntry(*data_ptr))
        {
            PLOG(PL_ERROR, "MulticastFIB::RL_Table::addFlow()  error: unable to insert flow.\n");
            delete data_ptr;
            return NULL;
        }
    }
    return data_ptr;
}  // end MulticastFIB::MembershipTable::AddMembership()

MulticastFIB::UpstreamRelay * MulticastFIB::RL_Data::getNextHop(MulticastFIB::UpstreamRelayList& downstream_relays, double minBroadcastProb, double reliability_threshold)
{

    ProtoAddress addr;
    double bestScore = std::numeric_limits<double>::max();      // largest possible double.
    double score;
    bool found = false;
    MulticastFIB::UpstreamRelay* next_hop = NULL;
    MulticastFIB::RL_Data * temp_data_ptr;
    ProtoAddressList::Iterator iterator(rl_metrics);
    while (iterator.GetNextAddress(addr))
    {
        //PLOG(PL_DEBUG, "MulticastFIB::RL_Data::getNextHop() -> checking addr %s as high-reliability next hop candidate: Q = %f, C=%f, C=%d\n", addr.GetHostString(),getMetrics(addr)->Q,getMetrics(addr)->C,getMetrics(addr)->correctionFactor);
        //PLOG(PL_DEBUG, "MulticastFIB::RL_Data::getNextHop() -> reliability = %f\n", getMetrics(addr)->C/(pow(1-getLearningRate(),getMetrics(addr)->correctionFactor)) );
        if (getMetrics(addr)->getCorrectedC(getLearningRate()) > reliability_threshold)
        {
            found =true;
            score =getMetrics(addr)->Q;
            //PLOG(PL_DEBUG, "SmartController::updateForwarder() -> score = %f\n", score);
            if (score < bestScore)
            {
                // PLOG(PL_DEBUG, "SmartController::updateForwarder() -> new best score \n");
                bestScore = score;
                next_hop = downstream_relays.FindUpstreamRelay(addr);

            }

        }

    }

    if (!found)
    {
        iterator.Reset();
        // iterate through list of next-hop addresses, looking for a next_hop with a lower "score"
        while (iterator.GetNextAddress(addr))
        {
            //PLOG(PL_DEBUG, "SmartController:updateForwarder. Looping through addresses: %s\n", addr.GetHostString());
            // loop through all next hops
            //PLOG(PL_DEBUG, "    Q = %f, C = %f\n", data_ptr->getMetrics(addr)->Q, data_ptr->getMetrics(addr)->C);
            //PLOG(PL_DEBUG, "SmartController::updateForwarder() -> checking addr %s as next hop candidate: Q = %f, C=%f, C=%d\n", addr.GetHostString(),getMetrics(addr)->Q,getMetrics(addr)->C,getMetrics(addr)->correctionFactor);

            // Compute score:
            score = getMetrics(addr)->Q * (1-std::min(1.0, getMetrics(addr)->getCorrectedC(getLearningRate())));
            if (score < bestScore)
            {
                //PLOG(PL_DEBUG, "SmartController:updateForwarder. New Best Score: %f\n", score);
                //PLOG(PL_DEBUG, "Best Score: %f\n",score);
                bestScore = score;
                // Returns the pointer to the next hop corresponding to the address (so we have interface info).
                next_hop = downstream_relays.FindUpstreamRelay(addr);
                //PLOG(PL_DEBUG, "nextHop addr: %s\n",addr.GetHostString());
                //PLOG(PL_DEBUG, "nextHop iface: %d\n",next_hop->GetInterfaceIndex());
            }

        }
    }

    return next_hop;
}

#endif // ADAPTIVE_ROUTING


MulticastFIB::Entry::Entry(const ProtoAddress&  dst,
                           const ProtoAddress&  src,        // invalid src addr means dst only
                           UINT8                trafficClass,
                           ProtoPktIP::Protocol protocol)
  : FlowEntryTemplate(dst, src, trafficClass, protocol),
    flow_managed(false), flow_active(false), flow_idle(false),
    default_forwarding_status(LIMIT), forwarding_count(0), 
    best_relay(NULL), unicast_probability(0.0),
    acking_status(false), 
    acking_count_threshold(DEFAULT_ACKING_COUNT),
    acking_interval_max(DEFAULT_ACKING_INTERVAL_MAX), 
    acking_interval_min(DEFAULT_ACKING_INTERVAL_MIN)
{
}

MulticastFIB::Entry::Entry(const FlowDescription& flowDescription, int flags)

 : FlowEntryTemplate(flowDescription, flags), 
   flow_managed(false), flow_active(false), flow_idle(false),
   default_forwarding_status(LIMIT), forwarding_count(0),
   //downstream_relay(), 
   best_relay(NULL), unicast_probability(0.0),
   acking_status(false),
   acking_count_threshold(DEFAULT_ACKING_COUNT),
   acking_interval_max(DEFAULT_ACKING_INTERVAL_MAX),
   acking_interval_min(DEFAULT_ACKING_INTERVAL_MIN)
{
    //PLOG(PL_DEBUG, "MulticastFIB::Entry:: constructor called\n");
    unicast_probability = 0.0;
}

MulticastFIB::Entry::~Entry()
{
}

bool MulticastFIB::Entry::CopyStatus(Entry& entry)
{
    default_forwarding_status = entry.default_forwarding_status;
    acking_status = entry.acking_status;
    acking_count_threshold = entry.acking_count_threshold;
    acking_interval_max = entry.acking_interval_max;
    acking_interval_min = entry.acking_interval_min;
    BucketList::Iterator iterator(entry.bucket_list);
    TokenBucket* bucket;
    downstream_relay = entry.downstream_relay;
    unicast_probability = entry.unicast_probability;
    while (NULL != (bucket = iterator.GetNextItem()))
    {
        unsigned int ifaceIndex = bucket->GetInterfaceIndex();
        TokenBucket* b = bucket_list.FindBucket(ifaceIndex);
        if (NULL == b)
        {
            if (NULL == (b = new TokenBucket(ifaceIndex)))
            {
                PLOG(PL_ERROR, "MulticastFIB::Entry::CopyStatus() new TokenBucket error: %s\n", GetErrorString());
                return false;
            }
        }
        b->CopyStatus(*bucket);
        bucket_list.Insert(*b);
    }
    return true;
}  // end MulticastFIB::Entry::CopyStatus()


void MulticastFIB::Entry::Reset(unsigned int currentTick)
{
    update_count = 1;
    update_start = currentTick;
    update_max = false; 
    activity_status.Refresh(currentTick);
    // Do we need to refresh the token buckets here?
    // or this just set update_count to zero and call Refresh()
}  // end MulticastFIB::Entry::Reset()

void MulticastFIB::Entry::Refresh(unsigned int currentTick)
{
    if (0 == update_count)
    {
        update_start = currentTick;
        update_max = false;
    }
    update_count += 1;
    activity_status.Refresh(currentTick);
    RefreshTokenBuckets(currentTick);
    AgeUpstreamRelays(currentTick);
}  // emd  MulticastFIB::Entry::Refresh()


unsigned int MulticastFIB::Entry::Age(unsigned int currentTick)
{
     // "Age" token buckets and upstream relays
    RefreshTokenBuckets(currentTick);
    AgeUpstreamRelays(currentTick);
    unsigned int age = activity_status.Age(currentTick);
    if (TICK_AGE_MAX == age) return TICK_AGE_MAX;
    if (!update_max)
    {
        int updateInterval = currentTick - update_start;
        if ((updateInterval < 0) || (updateInterval > TICK_AGE_MAX))
            update_max = true;
    }
    return age;
}  // end MulticastFIB::Entry::Age()

unsigned int MulticastFIB::Entry::GetUpdateInterval() const
{
    if (update_max || !activity_status.IsValid())
    {
        return TICK_AGE_MAX;
    }
    else
    {
        int updateInterval = activity_status.GetAgeTick() - update_start;
        if ((updateInterval < 0) || (updateInterval > TICK_AGE_MAX))
        {
            // This is not expected to happen under proper
            PLOG(PL_WARN, "MulticastFIB::Entry::GetUpdateInterval() warning: unexpected aging\n");
            return TICK_AGE_MAX;
        }
        else
        {
            return updateInterval;
        }
    }
}  // end MultcastFIB::Entry::GetUpdateInterval()

bool MulticastFIB::Entry::UpdatePending() const 
{
    unsigned int pktCount = GetUpdateCount();
    pktCount--;
    unsigned int updateInterval = GetUpdateInterval();
    if (((0 != acking_count_threshold) &&
        (pktCount >= acking_count_threshold) &&
        (updateInterval >= acking_interval_min)) ||
        ((0 != acking_interval_max) &&
        (updateInterval >= acking_interval_max)))
    {
        return true;
    }
    else
    {
        return false;
    }
}  // end MulticastFIB::Entry::UpdatePending()


void MulticastFIB::Entry::SetAckingStatus(bool status)
{
    if (status)
    {
        acking_status = true;
    }
    else if (acking_status)
    {
        acking_status = false;
        // Preset upstream relays so an ACK is sent
        // right away upon re-activation
        UpstreamRelayList::Iterator iterator(upstream_list);
        UpstreamRelay* upstream;
        while (NULL != (upstream = iterator.GetNextItem()))
            upstream->Preset(acking_count_threshold);
    }
}  // end MulticastFIB::Entry::SetAckingStatus()

bool MulticastFIB::Entry::SetForwardingStatus(unsigned int ifaceIndex, ForwardingStatus forwardingStatus, bool ackingStatus)
{
    if (0 != ifaceIndex)
    {
        TokenBucket* bucket = GetBucket(ifaceIndex);
        if (NULL == bucket)
        {
            PLOG(PL_ERROR, "MulticastFIB::Entry::SetForwardingStatus() error: new TokenBucket error: %s\n", GetErrorString());
            return false;
        }
        if (FORWARD == bucket->GetForwardingStatus())
        {
            if (FORWARD != forwardingStatus)
                forwarding_count -= 1;
        }
        else if (FORWARD == forwardingStatus)
        {
            forwarding_count += 1;
        }
        bucket->SetForwardingStatus(forwardingStatus);
    }
    else
    {
        // ifaceIndex == 0 means all interfaces, so
        // set default_forwarding_status and all buckets
        default_forwarding_status = forwardingStatus;
        BucketList::Iterator iterator(bucket_list);
        TokenBucket* bucket;
        while (NULL != (bucket = iterator.GetNextItem()))
        {
            if (FORWARD == bucket->GetForwardingStatus())
            {
                if (FORWARD != forwardingStatus)
                {
                    forwarding_count -= 1;
                }
            }
            else if (FORWARD == forwardingStatus)
            {
                forwarding_count += 1;
            }
            bucket->SetForwardingStatus(forwardingStatus);
        }
    }
    SetAckingStatus(ackingStatus);
    return true;
}  // end MulticastFIB::Entry::SetForwardingStatus()

MulticastFIB::ForwardingStatus MulticastFIB::Entry::GetForwardingStatus(unsigned int ifaceIndex) const
{
    TokenBucket* bucket = bucket_list.FindBucket(ifaceIndex);
    if (NULL == bucket)
    {
        PLOG(PL_WARN, "MulticastFIB::Entry::GetForwardingStatus() error: unknown interface\n");
        return default_forwarding_status;
    }
    return bucket->GetForwardingStatus();
}  // end MulticastFIB::Entry::GetForwardingStatus()

MulticastFIB::UpstreamRelay* MulticastFIB::Entry::AddUpstreamRelay(const ProtoAddress& addr, unsigned int ifaceIndex)
{
    MulticastFIB::UpstreamRelay* upstreamRelay = new UpstreamRelay(addr, ifaceIndex);
    if (NULL == upstreamRelay)
    {
        PLOG(PL_ERROR, "MulticastFIB::Entry::AddUpstreamRelay() new MulticastFib::UpstreamRelay error: %s\n", GetErrorString());
        return NULL;
    }
    upstream_list.Insert(*upstreamRelay);
    return upstreamRelay;
}  // end MulticastFIB::Entry::AddUpstreamRelay()

MulticastFIB::UpstreamRelay* MulticastFIB::Entry::GetBestUpstreamRelay(unsigned int currentTick)
{
    MulticastFIB::UpstreamRelay* bestPathRelay = NULL;  // upstream relay with best overall path quality (lowest ETX metric)
    MulticastFIB::UpstreamRelay* bestLinkRelay = NULL;  // upstream relay with best one-hop link quality
    double bestLinkQuality = -1.0; 
    double bestPathMetric = -1.0;  // lowest cost ETX path metric
    double bestLossMetric = 1.0;    // lowest packet loss path metric (bestPathMetric - hopCount)
    unsigned int bestLinkAge = 0;  // how long since last activitiy for this upstream 
    unsigned int bestPathAge = 0;
    MulticastFIB::UpstreamRelayList::Iterator uperator(upstream_list);
    MulticastFIB::UpstreamRelay* nextRelay;
    while (NULL != (nextRelay = uperator.GetNextItem()))
    {
        unsigned int upstreamAge = nextRelay->Age(currentTick);
        if (upstreamAge > MulticastFIB::DEFAULT_RELAY_IDLE_TIMEOUT)
        {
            // Prune this "dead" upstream relay
            upstream_list.Remove(*nextRelay);
            delete nextRelay;
            if (best_relay == nextRelay)
                best_relay = NULL;
            if (upstream_list.IsEmpty())
                SetTTL(0);  // so this flow isn't reactivated until another packet seen
            continue;
        }
        double linkQuality = nextRelay->GetLinkQuality();
        if (NULL != bestLinkRelay)
        {
            if (bestLinkAge >= MulticastFIB::DEFAULT_RELAY_ACTIVE_TIMEOUT)
            {
                if ((upstreamAge < MulticastFIB::DEFAULT_RELAY_ACTIVE_TIMEOUT) || (linkQuality > bestLinkQuality))
                {
                    bestLinkRelay = nextRelay;
                    bestLinkQuality = linkQuality;
                    bestLinkAge = upstreamAge;
                }
            }
            else if ((upstreamAge < MulticastFIB::DEFAULT_RELAY_ACTIVE_TIMEOUT) && (linkQuality > bestLinkQuality))
            {
                bestLinkRelay = nextRelay;
                bestLinkQuality = linkQuality;
                bestLinkAge = upstreamAge;
            }
        }
        else
        {
            // Only upstream relay assessed so far
            bestLinkRelay = nextRelay;
            bestLinkQuality = linkQuality;
            bestLinkAge = upstreamAge;
        }
        double lossMetric = -1.0;
        double pathMetric = -1.0;
        if (nextRelay->AdvMetricIsValid())
        {
            pathMetric = nextRelay->GetAdvMetric();
            if (linkQuality >= 0.0)
                pathMetric += 1.0 / linkQuality;
            else
                pathMetric += 1.0;  // assume a perfect link in absence of measurement?
            lossMetric = pathMetric - nextRelay->GetAdvHopCount();
            if (NULL != bestPathRelay)
            {
                double thePathMetric = pathMetric;
                double theBestPathMetric = bestPathMetric;
                if (false)
                {
                    thePathMetric = lossMetric;
                    theBestPathMetric = bestLossMetric;
                }
                if (bestPathAge >= MulticastFIB::DEFAULT_RELAY_ACTIVE_TIMEOUT)
                {
                    if ((upstreamAge < MulticastFIB::DEFAULT_RELAY_ACTIVE_TIMEOUT) || (thePathMetric < theBestPathMetric))
                    {
                        bestPathRelay = nextRelay;
                        bestPathMetric = pathMetric;
                        bestPathAge = upstreamAge;
                        bestLossMetric = lossMetric;
                    }
                }
                else if ((upstreamAge < MulticastFIB::DEFAULT_RELAY_ACTIVE_TIMEOUT) && (thePathMetric < theBestPathMetric))
                {
                    bestPathRelay = nextRelay;
                    bestPathMetric = pathMetric;
                    bestPathAge = upstreamAge;
                    bestLossMetric = lossMetric;
                }
            }
            else
            {
                // Only upstream relay assessed so far
                bestPathRelay = nextRelay;
                bestPathMetric = pathMetric;
                bestPathAge = upstreamAge;
                bestLossMetric = lossMetric;
            }
        }
    }
    if (NULL != bestPathRelay)
    {
        if ((NULL != best_relay) && (best_relay->GetAdvMetric() >= 0.0) && (best_relay != bestPathRelay) && 
            (best_relay->Age(currentTick) < MulticastFIB::DEFAULT_RELAY_ACTIVE_TIMEOUT))
        {
            // Only select a new upstream relay if > 10% improvement
            double delta = best_relay->GetAdvMetric() - bestPathRelay->GetAdvMetric();  // should be positive
            double percent = delta / best_relay->GetAdvMetric();
            if (percent >= 0.10)
            {
                if (GetDebugLevel() >= PL_INFO)
                {
                    PLOG(PL_INFO, "nrlsmf: new upstream relay %s for flow ", bestPathRelay->GetAddress().GetHostString());
                    GetFlowDescription().Print();
                    PLOG(PL_ALWAYS, "\n");
                }
                best_relay = bestPathRelay;
            }
        }
        else if (best_relay != bestPathRelay)
        {
            if (GetDebugLevel() >= PL_INFO)
            {
                PLOG(PL_INFO, "nrlsmf: new upstream relay %s for flow ", bestPathRelay->GetAddress().GetHostString());
                GetFlowDescription().Print();
                PLOG(PL_ALWAYS, " (timeout?)\n");
            }
            best_relay = bestPathRelay;
        }   
    }
    else if ((NULL != bestLinkRelay) && (best_relay != bestLinkRelay))
    {
        // Only have one-hop link quality so use it
        if (GetDebugLevel() >= PL_INFO)
        {
            PLOG(PL_INFO, "nrlsmf: new upstream link relay %s for flow ", bestLinkRelay->GetAddress().GetHostString());
            GetFlowDescription().Print();
            PLOG(PL_ALWAYS, "\n");
        }
        best_relay = bestLinkRelay;
    }
    return best_relay;
    
}  // end MulticastFIB::Entry::GetBestUpstreamRelay()




MulticastFIB::TokenBucket* MulticastFIB::Entry::GetBucket(unsigned int ifaceIndex)
{
    TokenBucket* bucket = bucket_list.FindBucket(ifaceIndex);
    if (NULL == bucket)
    {
        if (NULL == (bucket = new TokenBucket(ifaceIndex)))
        {
            PLOG(PL_ERROR, "MulticastFIB::Entry::GetBucket() error: new TokenBucket error: %s\n", GetErrorString());
            return NULL;
        }
        // TBD - implement way to set non-default bucket parameters
        bucket->SetForwardingStatus(default_forwarding_status);
        if (FORWARD == default_forwarding_status)
            forwarding_count += 1;
        bucket_list.Insert(*bucket);
    }
    return bucket;
}  // end MulticastFIB::Entry::GetBucket()

void MulticastFIB::Entry::RefreshTokenBuckets(unsigned int currentTick)
{
    BucketList::Iterator iterator(bucket_list);
    TokenBucket* nextBucket;
    while (NULL != (nextBucket = iterator.GetNextItem()))
        nextBucket->Refresh(currentTick);
}  // end MulticastFIB::Entry::RefreshTokenBuckets()

void MulticastFIB::Entry::ResetTokenBuckets()
{
    BucketList::Iterator iterator(bucket_list);
    TokenBucket* nextBucket;
    while (NULL != (nextBucket = iterator.GetNextItem()))
        nextBucket->Reset();
}  // end MulticastFIB::Entry::ResetBuckets()

void MulticastFIB::Entry::AgeUpstreamRelays(unsigned int currentTick)
{
    UpstreamRelayList::Iterator iterator(upstream_list);
    UpstreamRelay* relay;
    while (NULL != (relay = iterator.GetNextItem()))
        relay->Age(currentTick);
}  // end MulticastFIB::Entry::AgeUpstreamRelays()

MulticastFIB::ActiveList::ActiveList()
 : count(0), head(NULL), tail(NULL)
{
}

MulticastFIB::ActiveList::~ActiveList()
{
}

MulticastFIB::MulticastFIB()
{
}

MulticastFIB::~MulticastFIB()
{
    flow_table.Destroy();
}

const char* MulticastFIB::GetForwardingStatusString(ForwardingStatus status)
{
    switch (status)
    {
        case BLOCK:
            return "BLOCK";
        case HYBRID:
            return "HYBRID";
        case LIMIT:
            return "LIMIT";
        case FORWARD:
            return "FORWARD";
        default:
            return "???";
    }
}  // end ulticastFIB::GetForwardingStatusString()


bool MulticastFIB::ParseFlowList(ProtoPktIP& pkt, Entry*& fibEntry, unsigned int currentTick, bool& updateController, const ProtoAddress& srcMac)
{

    // If this is a new flow: no pre-existing flow table entry.
    if (NULL == fibEntry)
    {
        // Generate flow description from the packet.  This will include source, which we may want to remove.  TODO: check this
        FlowDescription flowDescription;
        flowDescription.InitFromPkt(pkt);
        flowDescription.SetSrcMaskLength(0);

        MulticastFIB::Entry* match = FindBestMatch(flowDescription);
        if (NULL != match) // if we're able to find the flow in the flow table
        {
            //PLOG(PL_DEBUG, "MulticastFIB::ParseFlowList(): We found a match\n");
            if (0 != match->GetSrcLength())
            {
                // Complete match (including source! )
                fibEntry = match;
                match = NULL;
            }
            // otherwise the destination matches, but not the source. This might be good enough...

        }
        if (NULL == fibEntry)
        {
            PLOG(PL_DEBUG, "MulticastFIB::ParseFlowList(): New Flow Detected\n");
            // This is a newly-detected flow, so we need to alert control plane!!!!!
            // TBD - implement default handling policies for new flows
            // (for now, we implement forwarding governed by default token bucket)
            if (NULL == (fibEntry = new Entry(flowDescription)))//dstIp, srcIp)))
            {
                PLOG(PL_ERROR, "MulticastFIB::ParseFlowList() new MulticastFIB::Entry() error: %s\n", GetErrorString());
                return false;
            }
            if (NULL != match)
            {
                if (GetDebugLevel() >= PL_DEBUG)
                {
                    PLOG(PL_ALWAYS, "   newly matched flow: \n");
                    fibEntry->GetFlowDescription().Print();
                    PLOG(PL_ALWAYS, " matching: ");
                    match->GetFlowDescription().Print();
                    PLOG(PL_ALWAYS, "\n");
                }
                // It will get its default forwarding status from the 'match'
                if (!fibEntry->CopyStatus(*match))
                {
                    PLOG(PL_ERROR, "MulticastFIB::ParseFlowList() error: unable to copy entry status!\n");
                    delete fibEntry;
                    return false;
                }
            }
            else
            {
                if (GetDebugLevel() >= PL_DEBUG)
                {
                    PLOG(PL_ALWAYS, "   newly unmatched flow: ");
                    fibEntry->GetFlowDescription().Print();
                    PLOG(PL_ALWAYS, "\n");
                }
                //fibEntry->SetDefaultForwardingStatus(default_forwarding_status);
            }
            InsertEntry(*fibEntry);
            // Put the new, dynamically detected flow in our "active_list"
            ActivateFlow(*fibEntry, currentTick);
            updateController = true;
        }
        else
        {
            if (GetDebugLevel() >= PL_DETAIL)
            {
                PLOG(PL_DETAIL, "MulticastFIB::ParseFlowList() recv'd packet (flow ");
                flowDescription.Print();
                PLOG(PL_ALWAYS, ") from relay %s for existing flow: ", srcMac.GetHostString());
                fibEntry->GetFlowDescription().Print();
                PLOG(PL_ALWAYS, "\n");
            }
            // This keeps our time ticks current
            if (fibEntry->IsActive())
            {
                // Refresh active flow
                RefreshFlow(*fibEntry, currentTick);
            }
            else
            {
                // Reactivate idle flow
                if (GetDebugLevel() >= PL_DEBUG)
                {
                    PLOG(PL_DEBUG, "MulticastFIB::ParseFlowList() reactivating flow: ");
                    fibEntry->GetFlowDescription().Print();
                    PLOG(PL_ALWAYS, "\n");
                }           
                ReactivateFlow(*fibEntry, currentTick);
                //updateController = true;  // why did I comment this out
            }
        }
    }  // end if (NULL == fibEntry)
    return true;
}  // end MulticastFIB::ParseFlowList()

void MulticastFIB::ActivateFlow(Entry& entry, unsigned int currentTick)
{
    entry.ResetTokenBuckets();
    entry.Refresh(currentTick);
    entry.Activate();
    active_list.Prepend(entry);
}  // end MulticastFIB::ActivateFlow()

void MulticastFIB::DeactivateFlow(Entry& entry, unsigned int currentTick)
{
    ASSERT(entry.IsActive());
    active_list.Remove(entry);
    entry.Deactivate();
    entry.Refresh(currentTick);
    entry.SetIdle(true);
    idle_list.Prepend(entry);
}  // end MulticastFIB::DeactivateFlow()


void MulticastFIB::PruneFlowList(unsigned int currentTick, ElasticMulticastController* /*controller*/)
{
    // Demote any sufficiently aged flows from "active_list" to "idle_list"
    // By removing them from the "active_list" (and moving them back in again
    // on new packet receptions) within the TICK_AGE_MAX bounds (at least),
    // this ensures the flow "UpdateTick()" time remains valid with respect to
    // wrap around the "currentTick" that is maintained.
    // IMPORTANT: The prune timer interval MUST be less than TICK_AGE_MAX - IDLE_TIMEOUT(max) for
    //            for this to work correctly.  Otherwise, the iterations here would have
    //            to exhaustively iterate through all entries to "Age" them properly.
    Entry* entry = active_list.GetTail();
    while (NULL != entry)
    {
        Entry* prevEntry = entry->GetPrev();
        if (entry->Age(currentTick) >= DEFAULT_FLOW_ACTIVE_TIMEOUT)
        {
            if (GetDebugLevel() >= PL_DEBUG)
            {
                PLOG(PL_DEBUG, "nrlsmf: deactivating flow entry ");
                entry->GetFlowDescription().Print();
                PLOG(PL_ALWAYS, "\n");
            }
            DeactivateFlow(*entry, currentTick);
        }
        else
        {
            break;
        }
        entry = prevEntry;
    }
    // Delete any sufficiently aged flows from "idle_list"
    entry = idle_list.GetTail();
    while (NULL != entry)
    {
        Entry* prevEntry = entry->GetPrev();
        if (entry->Age(currentTick) >= DEFAULT_FLOW_IDLE_TIMEOUT)
        {
            if (GetDebugLevel() >= PL_DEBUG)
            {
                PLOG(PL_DEBUG, "nrlsmf: removing/deleting flow entry ");
                entry->GetFlowDescription().Print();
                PLOG(PL_ALWAYS, "\n");
            }
            // TBD - update the controller that the flow is being removed
            //       due to inactivity?
            idle_list.Remove(*entry);
            if (!entry->IsManaged())
            {
                flow_table.RemoveEntry(*entry);
                delete entry;
            }
            else
            {
                entry->GetFlowDescription().Print();
            }
        }
        else
        {
            break;
        }
        entry = prevEntry;
    }
}  // end MulticastFIB::PruneFlowList()


///////////////////////////////////////////////////////////////////////////////////
// class ElasticMulticastForwarder implementation
//

ElasticMulticastForwarder::ElasticMulticastForwarder()
 : default_forwarding_status(MulticastFIB::LIMIT),
   mcast_controller(NULL), output_mechanism(NULL)
   
{
}

ElasticMulticastForwarder::~ElasticMulticastForwarder()
{
    // mcast_fib.Destroy(); TBD - implement something to destroy mcast_fib.entry_table
}

bool ElasticMulticastForwarder::SetAckingStatus(const FlowDescription& flowDescription,
                                                bool                   ackingStatus)
{
    // Note there are currently two kind of "managed" flow entries that are set/unset by
    // the controller.  These are:
    //     1) Managed membership entries.  These have a non-zero interface index.
    //     2) Mananged flow policy entries.  These currently have an interface index of zero.
    // If we ever provide polices that are interface-specific, we may need to handle these
    // differently somehow.
    
    // Sets acking status for all matching entries.
    MulticastFIB::EntryTable& flowTable = mcast_fib.AccessFlowTable();
    MulticastFIB::EntryTable::Iterator iterator(flowTable, &flowDescription);
    MulticastFIB::Entry* entry = iterator.GetNextEntry();
    //bool exactMatch = false;
    if (NULL != entry)
    {
        unsigned int currentTick = UpdateTicker();
        do
        {
            if (GetDebugLevel() >= PL_DEBUG)
            {
                PLOG(PL_DEBUG, "nrlsmf: setting AckingStatus to %d for existing flow ", ackingStatus);
                entry->GetFlowDescription().Print();
                PLOG(PL_ALWAYS, "\n");
            }
            if (ackingStatus)
            {
#if (USE_PREEMPTIVE_ACK)
                if (!entry->GetAckingStatus())
                {
                    // If ackingStatus, flow already exists, has active upstream relays, and current
                    // flow ackingStatus is "false", then send an EM-ACK right away
                    MulticastFIB::UpstreamRelayList::Iterator upserator(entry->AccessUpstreamRelayList());
                    MulticastFIB::UpstreamRelay* upstream = entry->GetBestUpstreamRelay(currentTick);
                    // TBD - only NACK "best upstream" in reliable mode and all upstreams if not reliable ..
                    //while (NULL != (upstream = upserator.GetNextItem()))
                    if (NULL != upstream)
                    {
                        if (upstream->Age(currentTick) < entry->GetAckingIntervalMax())
                        {
                            PLOG(PL_DEBUG, "nrlsmf: sending preemptive EM-ACK to upstream relay %s\n",
                                             upstream->GetAddress().GetHostString());
                            // If upstream address is MAC, unicast ACK to that MAC, else use multicast MAC
                            SendAck(upstream->GetInterfaceIndex(), upstream->GetAddress(), flowDescription);
                            upstream->Reset(currentTick);
                        }
                    }
                }
#endif // USE_PREEMPTIVE_ACK
            }
            else if (!entry->IsActive() && !entry->IsIdle() && !entry->IsManaged())
            {
                flowTable.RemoveEntry(*entry);
                delete entry;
                continue;
            }
            entry->SetAckingStatus(ackingStatus);
        } while (NULL != (entry = iterator.GetNextEntry()));
    }
    return true;
}  // end ElasticMulticastForwarder::SetAckingStatus()

bool ElasticMulticastForwarder::SetForwardingStatus(const FlowDescription&          flowDescription,
                                                    unsigned int                    ifaceIndex,
                                                    MulticastFIB::ForwardingStatus  forwardingStatus,
                                                    bool                            ackingStatus,
                                                    bool                            managed)
{
    // IMPORTANT NOTE:  "Managed" entries will only be removed when controller 
    //                   dictates regardless of acking status.  This enables 
    //                   static forwarding entries).

    // Sets forwarding status for all matching entries.
    MulticastFIB::EntryTable& flowTable = mcast_fib.AccessFlowTable();
    MulticastFIB::EntryTable::Iterator iterator(flowTable, &flowDescription);
    MulticastFIB::Entry* entry = iterator.GetNextEntry();
    bool exactMatch = false;
    if (NULL != entry)
    {
        unsigned int currentTick = UpdateTicker();
        do
        {
            if (GetDebugLevel() >= PL_DEBUG)
            {
                const char* forwardingStatusString = MulticastFIB::GetForwardingStatusString(forwardingStatus);
                PLOG(PL_DEBUG, "nrlsmf: setting ForwardingStatus %s and AckingStatus to %d for existing flow ",
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
                    //MulticastFIB::UpstreamRelayList::Iterator upserator(entry->AccessUpstreamRelayList());
                    MulticastFIB::UpstreamRelay* upstream = entry->GetBestUpstreamRelay(currentTick);
                    // TBD - only NACK "best upstream" in reliable mode
                    //while (NULL != (upstream = upserator.GetNextItem()))
                    if (NULL != upstream)
                    {    
                        if (upstream->Age(currentTick) < entry->GetAckingIntervalMax())
                        {
                            PLOG(PL_DEBUG, "nrlsmf: sending preemptive EM-ACK to upstream relay %s\n",
                                            upstream->GetAddress().GetHostString());
                            SendAck(upstream->GetInterfaceIndex(), upstream->GetAddress(), flowDescription);
                            upstream->Reset(currentTick);
                        }
                    }
                }
#endif // USE_PREEMPTIVE_ACK
            }
            else if (!entry->IsActive() && !entry->IsIdle()  && !entry->IsManaged())
            {
                flowTable.RemoveEntry(*entry);
                delete entry;
                continue;
            }
            entry->SetForwardingStatus(ifaceIndex, forwardingStatus, ackingStatus);
            if (managed && entry->IsExactMatch(flowDescription))
            {
                entry->SetManaged(true);
                exactMatch = true;
            }
        } while (NULL != (entry = iterator.GetNextEntry()));
    }
    // Create a new "managed" entry if there was not an exact match entry already
    if (managed && !exactMatch)
    {
        // Need to make an exact-match entry,  (Also, make it
        // "managed" (i.e., exempt from flow activity timeout
        // deletion since it is being emplaced by the controller)
        if (NULL == (entry = new MulticastFIB::Entry(flowDescription)))
        {
            PLOG(PL_ERROR, "MulticastFIB::SetForwardingStatus() new Entry error: %s\n", GetErrorString());
            return false;
        }
        if (GetDebugLevel() >= PL_DEBUG)
        {
            const char* forwardingStatusString = MulticastFIB::GetForwardingStatusString(forwardingStatus);
            PLOG(PL_DEBUG, "nrlsmf: setting ForwardingStatus %s and AckingStatus to %d for new flow ",
                                forwardingStatusString, ackingStatus);
            flowDescription.Print();
            PLOG(PL_ALWAYS, "\n");
        }
        entry->SetForwardingStatus(ifaceIndex, forwardingStatus, ackingStatus);
        entry->SetManaged(true);
        flowTable.InsertEntry(*entry);
    }
    return true;
}  // end ElasticMulticastForwarder::SetForwardingStatus()

///////////////////////////////////////////////////////////////////////////////////
// class ElasticMulticastController implementation
//

ElasticMulticastController::ElasticMulticastController(ProtoTimerMgr& timerMgr)
  : default_forwarding_status(MulticastFIB::LIMIT), timer_mgr(timerMgr)
{
    membership_timer.SetInterval(0);
    membership_timer.SetRepeat(-1);
    membership_timer.SetListener(this, &ElasticMulticastController::OnMembershipTimeout);

}


ElasticMulticastController::~ElasticMulticastController()
{
    policy_table.Destroy();
    membership_table.Destroy();
}

// Simple allow/deny policy for now
bool ElasticMulticastController::SetPolicy(const FlowDescription& flowDescription, bool allow)
{
    
    // Set a full wildcard policy as default if not already set.  This sets the opposite policy
    // for any flows that don't match allowed (or denied) flows ...
    // TBD - perhaps only set wildcard when explicitly configured???
    FlowDescription wildcardDescription;
    MulticastFIB::FlowPolicy* wildcard = policy_table.FindEntry(wildcardDescription);
    if (NULL == wildcard)
    {
        if (NULL == (wildcard = new MulticastFIB::FlowPolicy(wildcardDescription)))
        {
            PLOG(PL_ERROR, "ElasticMulticastController::SetPolicy() new wildcard FlowPolicy error: %s\n", GetErrorString());
            return false;
        } 
        MulticastFIB::ForwardingStatus status = allow ? MulticastFIB::DENY : default_forwarding_status;
        wildcard->SetForwardingStatus(status);
        policy_table.InsertEntry(*wildcard);
        // Inform forwarder of policy
        mcast_forwarder->SetForwardingStatus(wildcardDescription, 0, status, false, true);
    }    
    
    MulticastFIB::FlowPolicy* policy = policy_table.FindEntry(flowDescription);
    if (NULL == policy)
    {
        if (NULL == (policy = new MulticastFIB::FlowPolicy(flowDescription)))
        {
            PLOG(PL_ERROR, "ElasticMulticastController::SetPolicy() new FlowPolicy error: %s\n", GetErrorString());
            return false;
        }
        policy_table.InsertEntry(*policy);
    }
    // TBD - keep a count of these entries so we can remove blocking 'wildcard'
    MulticastFIB::ForwardingStatus status = allow ? default_forwarding_status : MulticastFIB::DENY;
    policy->SetForwardingStatus(status);
    
    // Inform forwarder of policy, making a "static", managed entry in the forwarder for default handling 
    // of flows that match the policy.
    mcast_forwarder->SetForwardingStatus(flowDescription, 0, status, false, true);
    return true;
}  // end ElasticMulticastController::SetPolicy()

bool ElasticMulticastController::AddManagedMembership(unsigned int ifaceIndex, const ProtoAddress& groupAddr)
{
    if (GetDebugLevel() >= PL_DEBUG)
        PLOG(PL_DEBUG, "ElasticMulticastController::AddManagedMembership(%s) ...\n", groupAddr.GetHostString());
    
    // See if we have a policy in place to DENY this membership or set other default forwarding status 
    // xxx - check policy_table here to see if membership is allowed or not
    MulticastFIB::Membership* membership = membership_table.AddMembership(ifaceIndex, groupAddr);
    if (NULL == membership)
    {
        PLOG(PL_DEBUG, "ElasticMulticastController::AddManagedMembership() error: unable to add new membership\n");
        return false;
    }
    membership->SetDefaultForwardingStatus(default_forwarding_status);
    if (GetDebugLevel() >= PL_DEBUG)
    {
        PLOG(PL_DEBUG, "ElasticMulticastController::AddManagedMembership() membership added or refreshed: ");
        membership->GetFlowDescription().Print();
        PLOG(PL_ALWAYS, "\n");
    }
    if (0 == membership->GetFlags())
        mcast_forwarder->SetAckingStatus(membership->GetFlowDescription(), true);
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
}  // end ElasticMulticastController::AddManagedMembership()

void ElasticMulticastController::RemoveManagedMembership(unsigned int ifaceIndex, const ProtoAddress& groupAddr)
{
    bool match = false;
    bool ackingStatus = false;
    FlowDescription flowDescription(groupAddr, PROTO_ADDR_NONE, 0x03, ProtoPktIP::RESERVED);
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
        mcast_forwarder->SetAckingStatus(flowDescription, false);   
}  // end ElasticMulticastController::RemoveManagedMembership()


// The external input mechanism passes these in
// (Right this only handles "outbound" (locally generated) IGMP messages.
//  In the future, full router IGMP queries, timeouts, etc will be supported)
void ElasticMulticastController::HandleIGMP(ProtoPktIGMP& igmpMsg, const ProtoAddress& srcIp, unsigned int ifaceIndex, bool inbound)
{
    // TBD - implement code to handle inbound IGMP (will need to act as IGMP router issuing queries and managing
    //       membership state
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
                        PLOG(PL_DEBUG, "nrlsmf: IGMPv3 JOIN group %s\n", groupAddr.GetHostString());
                        if (!AddManagedMembership(ifaceIndex, groupAddr))
                        {
                            PLOG(PL_ERROR, "ElasticMulticastController::HandleIGMP() error: unable to add new IGMPv3 membership\n");
                            return;
                        }
                    }
                    else if (ProtoPktIGMP::GroupRecord::CHANGE_TO_INCLUDE_MODE == groupRecord.GetType())
                    {
                        // ASM join (with 0 == nsrc, semantic is "include no sources", i.e., "exclude all sources")
                        PLOG(PL_DEBUG, "nrlsmf: IGMPv3 LEAVE group %s\n", groupAddr.GetHostString());
                        // Clear MANAGED status for all matching memberships for this ifaceIndex
                        // but iterate over _all_ matching memberships to see if we should still be
                        // acking or not
                        RemoveManagedMembership(ifaceIndex, groupAddr);
                    }
                }
                else
                {
                    if (GetDebugLevel() >= PL_DEBUG)
                    {
                        PLOG(PL_DEBUG, "nrlsmf: IGMPv3 SSM REPORT ...\n");
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
            if (groupAddr.IsLinkLocal()) break;  // ignoore link local join / leave messages
            PLOG(PL_DEBUG, "nrlsmf: IGMPv1 JOIN group %s\n", groupAddr.GetHostString());
            if (!AddManagedMembership(ifaceIndex, groupAddr))
            {
                PLOG(PL_ERROR, "ElasticMulticastController::HandleIGMP() error: unable to add new IGMPv1 membership\n");
                return;
            }
            break;
        }
        case ProtoPktIGMP::REPORT_V2:
        {
            ProtoAddress groupAddr;
            igmpMsg.GetGroupAddress(groupAddr);
            if (groupAddr.IsLinkLocal()) break;  // ignoore link local join / leave messages
            PLOG(PL_DEBUG, "nrlsmf: IGMPv2 JOIN group %s\n", groupAddr.GetHostString());
            if (!AddManagedMembership(ifaceIndex, groupAddr))
            {
                PLOG(PL_ERROR, "ElasticMulticastController::HandleIGMP() error: unable to add new IGMPv2 membership\n");
                return;
            }
            break;
        }
        case ProtoPktIGMP::LEAVE:
        {
            ProtoAddress groupAddr;
            igmpMsg.GetGroupAddress(groupAddr);
            if (groupAddr.IsLinkLocal()) break;  // ignoore link local join / leave messages
            PLOG(PL_DEBUG, "nrlsmf: IGMPv2 LEAVE group %s\n", groupAddr.GetHostString());
            RemoveManagedMembership(ifaceIndex, groupAddr);
            break;
        }
        default:
        {
            PLOG(PL_WARN, "nrlsmf: invalid/unknown IGMP message?!\n");
            break;
        }
    }
}  // end ElasticMulticastController::HandleIGMP()

// The external input mechanism passes these in
void ElasticMulticastController::HandleAck(const ElasticAck& ack, 
                                           unsigned int ifaceIndex, 
                                           const ProtoAddress& srcAddr)
{
    // TBD - confirm that it's for me
    ProtoAddress dstIp, srcIp;
    ack.GetDstAddr(dstIp);
    ack.GetSrcAddr(srcIp);
    UINT8 trafficClass = ack.GetTrafficClass();
    ProtoPktIP::Protocol protocol = ack.GetProtocol();
    FlowDescription membershipDescription(dstIp, srcIp, trafficClass, protocol, ifaceIndex);

    if (GetDebugLevel() >= PL_DETAIL)
    {
        PLOG(PL_DETAIL, "nrlsmf: recv'd EM_ACK for flow ");
        membershipDescription.Print();
        PLOG(PL_ALWAYS, " from %s\n", srcAddr.GetHostString());
    }

    // Find membership ...
    MulticastFIB::Membership* membership = membership_table.FindMembership(membershipDescription);
    if (NULL == membership)
    {
        // TBD - what if we already have a broader scope membership? 
        if (GetDebugLevel() >= PL_DEBUG)
        {
            PLOG(PL_DEBUG, "nrlsmf: recv'd EM-ACK, adding membership: ");
            membershipDescription.Print();
            PLOG(PL_ALWAYS, "\n");
        }
        if (NULL == (membership = membership_table.AddMembership(ifaceIndex, dstIp, srcIp, trafficClass, protocol)))
        {
            PLOG(PL_ERROR, "ElasticMulticastController::HandleAck() error: unable to add elastic membership\n");
            return;
        }
        membership->SetDefaultForwardingStatus(default_forwarding_status);
        membership->SetIdleCountThreshold(MulticastFIB::DEFAULT_IDLE_COUNT_THRESHOLD);
    }
    // Update forwarder only when ELASTIC membership not already set
    bool updateForwarder = membership->FlagIsSet(MulticastFIB::Membership::ELASTIC) ? false : true;
    // Activate (or refresh) ELASTIC membership
    if (GetDebugLevel() >= PL_DEBUG)
    {
        PLOG(PL_DEBUG, "nrlsmf: recv'd EM-ACK, activating/refreshing membership: ");
        membershipDescription.Print();
        PLOG(PL_ALWAYS, "\n");
    }
    if (!ActivateMembership(*membership, MulticastFIB::Membership::ELASTIC, MulticastFIB::DEFAULT_ACK_TIMEOUT))
    {
        PLOG(PL_ERROR, "ElasticMulticastController::HandleAck() error: unable to activate elastic membership\n");
        if (0 == membership->GetFlags())
        {
            membership_table.RemoveEntry(*membership);
            delete membership;
        }
        return;
    }
    membership->ResetIdleCount();  // reset packet-count based "timeout"
    if (updateForwarder)
    {
        FlowDescription flowDescription(dstIp, srcIp, trafficClass, protocol);
        mcast_forwarder->SetForwardingStatus(flowDescription, ifaceIndex, MulticastFIB::FORWARD, true, false);
    }

}  // end ElasticMulticastController::HandleAck()

bool ElasticMulticastController::ActivateMembership(MulticastFIB::Membership&       membership,
                                                    MulticastFIB::Membership::Flag  flag,
                                                    double                          timeoutSec)
{
    if (membership_timer.IsActive())
    {
        unsigned int oldTick = membership_table.GetNextTimeout();
        unsigned int currentTick = UpdateTicker();
        unsigned int timeoutTick = (unsigned int)(timeoutSec*TICK_RATE) + currentTick;
        if (!membership_table.ActivateMembership(membership, flag, timeoutTick))
        {
            PLOG(PL_ERROR, "ElasticMulticastController::ActivateMembership() error: unable to activate membership\n");
            return false;
        }
        unsigned int newTick = membership_table.GetNextTimeout();
        if (newTick != oldTick)
        {
            int delta = newTick - currentTick;
            if (delta < 0) delta = 0;
            membership_timer.SetInterval(((double)delta) * TICK_INTERVAL);
            membership_timer.Reschedule();
        }
    }
    else
    {
        ResetTicker();
        unsigned int timeoutTick = (unsigned int)(timeoutSec*TICK_RATE);
        if (!membership_table.ActivateMembership(membership, flag, timeoutTick))
        {
            PLOG(PL_ERROR, "ElasticMulticastController::ActivateMembership() error: unable to activate membership\n");
            return false;
        }
        timer_mgr.ActivateTimer(membership_timer);
    }
    return true;
}  // end ElasticMulticastController::ActivateMembership()

void ElasticMulticastController::DeactivateMembership(MulticastFIB::Membership&      membership,
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
                membership_timer.SetInterval(((double)delta) * TICK_INTERVAL);
                membership_timer.Reschedule();
            }
        }
        else
        {
            membership_timer.Deactivate();
        }
    }
}  // end ElasticMulticastController::DeactivateMembership()

bool ElasticMulticastController::OnMembershipTimeout(ProtoTimer& theTimer)
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
            if (GetDebugLevel() >= PL_DEBUG)
            {
                PLOG(PL_DEBUG, "nrlsmf: %s membership timeout for flow ",
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
                if (MulticastFIB::Membership::ELASTIC == timeoutFlag)
                {
                    mcast_forwarder->SetForwardingStatus(leader->GetFlowDescription(),
                                                         leader->GetInterfaceIndex(),
                                                         leader->GetDefaultForwardingStatus(),  // LIMIT unless advertising 
                                                         ackingStatus, false);
                }
                else if (!ackingStatus)
                {
                    mcast_forwarder->SetAckingStatus(leader->GetFlowDescription(), false);
                }
                membership_table.RemoveEntry(*leader);
                delete leader;
            }
            else if (MulticastFIB::Membership::ELASTIC == timeoutFlag)
            {
                // Stop forwarding, but keep acking
                mcast_forwarder->SetForwardingStatus(leader->GetFlowDescription(),
                                                     leader->GetInterfaceIndex(),
                                                     leader->GetDefaultForwardingStatus(),    // LIMIT unless advertising 
                                                     true, false);
            }
        }
        else
        {
            theTimer.SetInterval(((double)delta) * TICK_INTERVAL);
            return true;
        }
    }
    // If get here, there are no more membership timeouts remaining,
    // and timer was deactivated in call to DeactivateMembership() above
    //theTimer.Deactivate();
    return false;
}  // end MulticastFIB::OnMembershipTimeout()

void ElasticMulticastController::Update(const FlowDescription&  flowDescription,
                                        unsigned int            ifaceIndex,  // inbound interface index (unused)
                                        const ProtoAddress&     relayAddr,   // upstream relay addr
                                        unsigned int            pktCount,
                                        unsigned int            pktInterval,
                                        bool                    oldAckingStatus)
{
    if (GetDebugLevel() >= PL_DEBUG)
    {
        PLOG(PL_DEBUG, "nrlsmf: controller update for flow: ");
        flowDescription.Print();
        PLOG(PL_ALWAYS, " from upstream relay %s (pktCount: %u)\n", relayAddr.GetHostString(), pktCount);
    }
    
    // If set to "true", only the timeout, instead of packet/event-driven, 
    // response deactivates memnerships
    bool ignoreIdleCount = false;  // set to "true" to be more chatty, but more robust
    if (ignoreIdleCount) return;   
    
    // Iterate across all matching (per-interface) memberships, update the packet
    // counts and status for "ELASTIC" memberships as appropriate
    // NOTE: this iterator finds _all_ matching interfaces, including dst-only
    MulticastFIB::MembershipTable::Iterator iterator(membership_table, &flowDescription);
    bool ackingStatus = false;
    MulticastFIB::Membership* membership;
    while (NULL != (membership = iterator.GetNextEntry()))
    {
        if (membership->FlagIsSet(MulticastFIB::Membership::ELASTIC))
        {
            unsigned int totalPktCount = membership->IncrementIdleCount(pktCount);
            if (totalPktCount >= membership->GetIdleCountThreshold())
            {
                // We haven't gotten an ACK recently enough for this membership/interface
                if (GetDebugLevel() >= PL_DEBUG)
                {
                    PLOG(PL_DEBUG, "nrlsmf: ELASTIC membership idle for flow ");
                    flowDescription.Print();
                    PLOG(PL_ALWAYS, " totalCount:%u threshold:%u\n", totalPktCount,
                            membership->GetIdleCount());
                }
                DeactivateMembership(*membership, MulticastFIB::Membership::ELASTIC);
                mcast_forwarder->SetForwardingStatus(flowDescription, 
                                                     membership->GetInterfaceIndex(), 
                                                     membership->GetDefaultForwardingStatus(), 
                                                     oldAckingStatus, false);
                if (0 == membership->GetFlags())
                {
                    if (GetDebugLevel() >= PL_DEBUG)
                    {
                        PLOG(PL_DEBUG, "nrlsmf: removing membership ");
                        flowDescription.Print();
                        PLOG(PL_ALWAYS, "\n");
                    }
                    membership_table.RemoveEntry(*membership);
                    delete membership;
                }
                else
                {
                    ackingStatus = true;
                }
            }
            else
            {
                ackingStatus = true;
            }
        }
        else
        {
            ackingStatus = true;
        }
    }
    if (ackingStatus != oldAckingStatus)
        mcast_forwarder->SetAckingStatus(flowDescription, ackingStatus);
}  // end ElasticMulticastController::Update()
