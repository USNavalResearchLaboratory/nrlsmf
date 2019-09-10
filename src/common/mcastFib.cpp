#include "mcastFib.h"
#include "protoNet.h"  // to get interface addresses given interface indices (TBD - addresses should be configured w/ indices externally)
#include "protoPktETH.h"
#include "protoPktIP.h"
#include "protoDebug.h"
#include <stdlib.h>

#define USE_PREEMPTIVE_ACK 1

const unsigned int MulticastFIB::DEFAULT_FLOW_ACTIVE_TIMEOUT = (60 * 1000000);  // 60 seconds in microseconds    
const unsigned int MulticastFIB::DEFAULT_FLOW_IDLE_TIMEOUT = (120 * 1000000);   // 120 seconds in microseconds     

// These set the default update/acking condition for a flow
const unsigned int MulticastFIB::DEFAULT_ACKING_COUNT = 10;                     // number of packets per update
const unsigned int MulticastFIB::DEFAULT_ACKING_INTERVAL_MIN = (0.1 * 1000000); // 0.1 seconds in microseconds
const unsigned int MulticastFIB::DEFAULT_ACKING_INTERVAL_MAX = (30 * 1000000);  // 30 seconds in microseconds       
 
const double MulticastFIB::DEFAULT_ACK_TIMEOUT = 30.0;  // 30 seconds
const unsigned int MulticastFIB::DEFAULT_IDLE_COUNT_THRESHOLD = 30;    // 30 packets
        
// This maintains our microsecond ticker

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
    ticker_count += (unsigned int)(1.0e+06 * delta);
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
    idle_count(0), elastic_timeout_valid(false), igmp_timeout_valid(false)
{
}

MulticastFIB::Membership::~Membership()
{
}

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
            membership_ring.Remove(membership);
            insert = true;
        }
        else
        {
            unsigned int currentTick = 
                (Membership::ELASTIC == membership.timeout_flag) ?
                    membership.elastic_timeout_tick : membership.igmp_timeout_tick;
            int delta = tick - currentTick;
            ASSERT(abs(delta) <= TICK_AGE_MAX);
            if (delta < 0)
            {
                membership_ring.Remove(membership);
                insert = true;
            }
        }
        if (insert && (&membership == ring_leader))
        {
            Ring::Iterator iterator(membership_ring);
            iterator.SetCursor(membership_ring, membership);
            iterator.GetNextItem();  // skip cursor
            ring_leader = iterator.GetNextItem();
            membership_ring.Remove(membership);
            if (NULL == ring_leader) 
                ring_leader = membership_ring.GetHead();
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
            int delta = ring_leader->GetTimeout() - tick;
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
                if (NULL == ring_leader) ring_leader = membership_ring.GetHead();
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
        token_interval = (unsigned int)((1.0e+06 / pktsPerSecond) + 0.5);
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
        if (HYBRID != forwarding_status) bucket_count += tokens;
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
                return false;
            }
    }
}  // end MulticastFIB::TokenBucket::ProcessPacket()



MulticastFIB::UpstreamRelay::UpstreamRelay(const ProtoAddress& addr, unsigned int ifaceIndex)
 : relay_addr(addr), iface_index(ifaceIndex), update_count(0), 
   update_start(0), update_max(true), age_tick(0), age_max(true)
{
}

MulticastFIB::UpstreamRelay::~UpstreamRelay()
{
}

void MulticastFIB::UpstreamRelay::Refresh(unsigned int currentTick, unsigned int count)
{
    if (0 == update_count)
    {
        update_start = currentTick;
        update_max = false;
    }
    else if (!update_max)
    {
        int updateInterval = currentTick - update_start;
        if ((updateInterval < 0) || (updateInterval > TICK_AGE_MAX))
            update_max = true;
    }
    age_tick = currentTick;
    age_max = false;
    update_count += count;
}  // end MulticastFIB::UpstreamRelay::Refresh()

unsigned int MulticastFIB::UpstreamRelay::Age(unsigned int currentTick)
{
    // Updates age (time tick state)
    if (age_max)
    {
        return TICK_AGE_MAX;
    }
    else
    {
        if (!update_max)
        {
            int updateInterval = currentTick - update_start;
            if ((updateInterval < 0) || (updateInterval > TICK_AGE_MAX))
                update_max = true;
        }
        int age = currentTick - age_tick;
        if ((age < 0) || (age > TICK_AGE_MAX))
        {
            age_max = true;
            return TICK_AGE_MAX;
        }
        return age;
    }
}  // end MulticastFIB::UpstreamRelay::Age()

unsigned int MulticastFIB::UpstreamRelay::GetUpdateInterval() const
{
    if (update_max)
    {
        return TICK_AGE_MAX;
    }
    else
    {
        int updateInterval = age_tick - update_start;
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

bool MulticastFIB::UpstreamRelay::AckPending(const Entry& entry, bool actual) const
{
    unsigned int ackingCountThreshold = entry.GetAckingCountThreshold();
    unsigned int ackingIntervalMax = entry.GetAckingIntervalMax();
    unsigned int ackingIntervalMin = entry.GetAckingIntervalMin();
    unsigned int pktCount = GetUpdateCount();
    if (actual) pktCount--;
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

MulticastFIB::Entry::Entry(const ProtoAddress&  dst, 
                           const ProtoAddress&  src,        // invalid src addr means dst only
                           UINT8                trafficClass, 
                           ProtoPktIP::Protocol protocol)
  : FlowEntryTemplate(dst, src, trafficClass, protocol),
    flow_managed(false), flow_active(false), flow_idle(false),
    default_forwarding_status(LIMIT), forwarding_count(0), age_max(true),
    acking_status(false), acking_count_threshold(DEFAULT_ACKING_COUNT),
    acking_interval_max(DEFAULT_ACKING_INTERVAL_MAX), 
    acking_interval_min(DEFAULT_ACKING_INTERVAL_MIN)
      
{
}

MulticastFIB::Entry::Entry(const FlowDescription& flowDescription, int flags)

 : FlowEntryTemplate(flowDescription, flags), flow_active(false), 
   default_forwarding_status(LIMIT), forwarding_count(0), 
   age_max(true), acking_status(false), 
   acking_count_threshold(DEFAULT_ACKING_COUNT),
   acking_interval_max(DEFAULT_ACKING_INTERVAL_MAX), 
   acking_interval_min(DEFAULT_ACKING_INTERVAL_MIN)
{
}

MulticastFIB::Entry::~Entry()
{
}

bool MulticastFIB::Entry::CopyStatus(Entry& entry)
{
    acking_status = entry.acking_status;
    acking_count_threshold = entry.acking_count_threshold;
    acking_interval_max = entry.acking_interval_max;
    acking_interval_min = entry.acking_interval_min;
    BucketList::Iterator iterator(entry.bucket_list);
    TokenBucket* bucket;
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


unsigned int MulticastFIB::Entry::Age(unsigned int currentTick)
{
     // "Age" token buckets and upstream relays
    RefreshTokenBuckets(currentTick);
    AgeUpstreamRelays(currentTick);
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
            return TICK_AGE_MAX;
        }
        return age;
    }
}  // end MulticastFIB::Entry::Age()

unsigned int MulticastFIB::Entry::GetAge(unsigned int currentTick) const
{
    if (age_max)
    {
        return TICK_AGE_MAX;
    }
    else
    {
        int age = age_tick - currentTick;
        if ((age < 0) || (age > TICK_AGE_MAX))
            return TICK_AGE_MAX;
        else
            return age;
    }
}  // end MulticastFIB::Entry::GetAge()

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
    }
}  // end ulticastFIB::GetForwardingStatusString()

unsigned int MulticastFIB::BuildAck(UINT32*                buffer, 
                                    unsigned int           length,
                                    const ProtoAddress&    dstMac,
                                    const ProtoAddress&    srcMac,
                                    const ProtoAddress&    srcIp,
                                    const FlowDescription& flowDescription)
{
    // IPv4-only at moment
    if (ProtoAddress::IPv4 != srcIp.GetType())
    {
        PLOG(PL_ERROR, "MulticastFIB::BuildAck() error: non-IPv4 src address! (IPv6 support is TBD)\n");
        return 0;
    }
    unsigned int ipHeaderLen = 20;
    if (length < (14 + ipHeaderLen+ 8))
    {
        PLOG(PL_ERROR, "MulticastFIB::BuildAck() error: insufficient 'buffer' length!\n");
        return 0;
    }
    // Build an ACK to send to the identified upstream relay
    // The ACK will be sent to the "relayAddr" (MAC addr) via the "ifaceIndex" interface
    // (as a UDP/IP packet with multicast dest addr and source IP addr of given "ifaceIndex")
    unsigned int frameLength = length - 2;  // offset by 2 bytes to maintain alignment for ProtoPktIP
    UINT16* ethBuffer = ((UINT16*)buffer) + 1;  // offset for IP packet alignmen
    UINT32* ipBuffer = buffer + 4; // 14 bytes plus 2
    ProtoPktETH ethPkt((UINT32*)ethBuffer, frameLength);
    ethPkt.SetSrcAddr(srcMac);
    ethPkt.SetDstAddr(dstMac);
    ethPkt.SetType(ProtoPktETH::IP);  // TBD - based upon IP address type
    ProtoPktIPv4 ipPkt(ipBuffer, frameLength - 14);
    ipPkt.SetTTL(1);
    ipPkt.SetProtocol(ProtoPktIP::UDP);
    ipPkt.SetSrcAddr(srcIp);
    ipPkt.SetDstAddr(ElasticAck::ELASTIC_ADDR);
    
    ProtoPktUDP udpPkt(ipPkt.AccessPayload(), frameLength - 14 - ipHeaderLen, false);
    udpPkt.SetSrcPort(ElasticAck::ELASTIC_PORT);
    udpPkt.SetDstPort(ElasticAck::ELASTIC_PORT);

    ElasticAck ack(udpPkt.AccessPayload(), frameLength - 14 - ipHeaderLen - 8);
    if (!ack.InitIntoBuffer())
    {
        PLOG(PL_ERROR, "MulticastFIB::BuildAck() error: insufficient 'buffer' length!\n");
        return 0;
    }
    ack.SetTrafficClass(flowDescription.GetTrafficClass());
    ack.SetProtocol(flowDescription.GetProtocol());
    ElasticAck::AddressType addrType;
    switch (flowDescription.GetDstLength())
    {
        case 4:
            addrType = ElasticAck::ADDR_IPV4;
            break;
        //case 16:
        //    addrType = ElasticAck::ADDR_IPV6;
        //    break;
        default:
            PLOG(PL_ERROR, "MulticastFIB::BuildAck() error: invalid flow dst address\n");
            return 0;
    }
    if (!ack.SetDstAddr(addrType, flowDescription.GetDstPtr(), flowDescription.GetDstLength()))
    {
        PLOG(PL_ERROR, "MulticastFIB::BuildAck() error: insufficient 'buffer' length!\n");
        return 0;
    }
    if (flowDescription.GetSrcLength() != flowDescription.GetDstLength())
    {
        PLOG(PL_ERROR, "MulticastFIB::BuildAck() error: non-matching flow dst/src address types\n");
        return 0;
    }
    if (!ack.SetSrcAddr(addrType, flowDescription.GetSrcPtr(), flowDescription.GetSrcLength()))
    {
        PLOG(PL_ERROR, "MulticastFIB::BuildAck() error: insufficient 'buffer' length!\n");
        return 0;
    }
    
    if (!ack.AppendUpstreamAddr(dstMac))  // TBD - could upstream relay addr be different?
    {
        PLOG(PL_ERROR, "MulticastFIB::BuildAck() error: insufficient 'buffer' length!\n");
        return 0;
    }
    
    udpPkt.SetPayloadLength(ack.GetLength());
    ipPkt.SetPayloadLength(udpPkt.GetLength());
    udpPkt.FinalizeChecksum(ipPkt);
    ethPkt.SetPayloadLength(ipPkt.GetLength());
    return ethPkt.GetLength();
}  // end MulticastFIB::BuildAck()

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
            //if (GetDebugLevel() >= PL_DEBUG)
            {
                PLOG(PL_ALWAYS, "nrlsmf: deactivating flow entry ");
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
            //if (GetDebugLevel() >= PL_DEBUG)
            {
                PLOG(PL_ALWAYS, "nrlsmf: removing/deleting flow entry ");
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
 : mcast_controller(NULL), output_mechanism(NULL)
{
}

ElasticMulticastForwarder::~ElasticMulticastForwarder() 
{
}

bool ElasticMulticastForwarder::SetAckingStatus(const FlowDescription& flowDescription, 
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
                    // flow ackingStatus is "false", then send an EM-ACK right away
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
                                    entry->GetFlowDescription());
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
            PLOG(PL_ERROR, "ElasticMulticastForwarder::SetAckingStatus() new Entry error: %s\n", GetErrorString());
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
}  // end ElasticMulticastForwarder::SetAckingStatus()

bool ElasticMulticastForwarder::SetForwardingStatus(const FlowDescription&          flowDescription, 
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
                    // flow ackingStatus is "false", then send an EM-ACK right away
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
                                    flowDescription);
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
}  // end ElasticMulticastForwarder::SetForwardingStatus()

///////////////////////////////////////////////////////////////////////////////////
// class ElasticMulticastController implementation
//

ElasticMulticastController::ElasticMulticastController(ProtoTimerMgr& timerMgr)
  : timer_mgr(timerMgr)
{
    membership_timer.SetInterval(0);
    membership_timer.SetRepeat(-1);
    membership_timer.SetListener(this, &ElasticMulticastController::OnMembershipTimeout);
    
}


ElasticMulticastController::~ElasticMulticastController()
{
}

bool ElasticMulticastController::AddManagedMembership(unsigned int ifaceIndex, const ProtoAddress& groupAddr)
{
    if (GetDebugLevel() >= PL_DEBUG)
        PLOG(PL_DEBUG, "ElasticMulticastController::AddManagedMembership(%s) ...\n", groupAddr.GetHostString());
    MulticastFIB::Membership* membership = membership_table.AddMembership(ifaceIndex, groupAddr);
    if (NULL == membership)
    {
        PLOG(PL_ERROR, "ElasticMulticastController::AddManagedMembership() error: unable to add new membership\n");
        return false;
    }
    if (GetDebugLevel() >= PL_DEBUG)
    {
        PLOG(PL_ALWAYS, "ElasticMulticastController::AddManagedMembership() new membership added ");
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


// The external input mechanism passes these in
// (Right this only handles "outbound" (locally generated) IGMP messages.
//  In the future, full router IGMP queries, timeouts, etc will be supported)
void ElasticMulticastController::HandleIGMP(const ProtoPktIGMP& igmpMsg, const ProtoAddress& srcIp, unsigned int ifaceIndex, bool inbound)
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
                            PLOG(PL_ERROR, "ElasticMulticastController::HandleIGMP() error: unable to add new membership\n");
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
}  // end ElasticMulticastController::HandleIGMP()

// The external input mechanism passes these in
void ElasticMulticastController::HandleAck(const ElasticAck& ack, unsigned int ifaceIndex, const ProtoAddress& srcMac)
{
    // TBD - confirm that it's for me
    ProtoAddress dstIp, srcIp;
    ack.GetDstAddr(dstIp);
    ack.GetSrcAddr(srcIp);
    UINT8 trafficClass = ack.GetTrafficClass();
    ProtoPktIP::Protocol protocol = ack.GetProtocol();
    FlowDescription membershipDescription(dstIp, srcIp, trafficClass, protocol, ifaceIndex);
    
    if (GetDebugLevel() >= PL_DEBUG)
    {
        PLOG(PL_ALWAYS, "nrlsmf: recv'd EM_ACK for flow ");
        membershipDescription.Print();
        PLOG(PL_ALWAYS, " from %s\n", srcMac.GetHostString());
    }
    
    // Find membership ...
    MulticastFIB::Membership* membership = membership_table.FindMembership(membershipDescription);
    if (NULL == membership)
    {
        // TBD - what if we already have a broader scope membership?
        //if (GetDebugLevel() >= PL_DEBUG)
        {
            PLOG(PL_ALWAYS, "nrlsmf: recv'd EM-ACK, adding membership: ");
            membershipDescription.Print();
            PLOG(PL_ALWAYS, "\n");
        }
        if (NULL == (membership = membership_table.AddMembership(ifaceIndex, dstIp, srcIp, trafficClass, protocol)))
        {
            PLOG(PL_ERROR, "ElasticMulticastController::HandleAck() error: unable to add elastic membership\n");
            return;
        }
        membership->SetIdleCountThreshold(MulticastFIB::DEFAULT_IDLE_COUNT_THRESHOLD);
    }
    // Update forwarder only when ELASTIC membership not already set
    bool updateForwarder = membership->FlagIsSet(MulticastFIB::Membership::ELASTIC) ? false : true;
    // Activate (or refresh) ELASTIC membership
    if (GetDebugLevel() >= PL_DEBUG)
    {
        PLOG(PL_ALWAYS, "nrlsmf: recv'd EM-ACK, activating/refreshing membership: ");
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
        mcast_forwarder->SetForwardingStatus(flowDescription, ifaceIndex, MulticastFIB::FORWARD, true);
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
        unsigned int timeoutTick = (unsigned int)(timeoutSec*1.0e+06) + currentTick;
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
                membership_timer.SetInterval(((double)delta) * 1.0e-06);
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
                if (MulticastFIB::Membership::ELASTIC == timeoutFlag)
                {
                    mcast_forwarder->SetForwardingStatus(leader->GetFlowDescription(), 
                                                         leader->GetInterfaceIndex(), 
                                                         MulticastFIB::LIMIT, 
                                                         ackingStatus);
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
                                                     MulticastFIB::LIMIT, 
                                                     true);
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

void ElasticMulticastController::Update(const FlowDescription&  flowDescription, 
                                        unsigned int            ifaceIndex,  // inbound interface index
                                        const ProtoAddress&     relayAddr,   // upstream relay MAC addr
                                        unsigned int            pktCount,
                                        unsigned int            pktInterval)
{
    if (GetDebugLevel() >= PL_DEBUG)
    {
        PLOG(PL_ALWAYS, "nrlsmf: controller update for flow: ");
        flowDescription.Print();
        PLOG(PL_ALWAYS, " from upstream relay %s (pktCount: %u)\n", relayAddr.GetHostString(), pktCount);
    }
    // Iterate across all matching (per-interface) memberships, update the packet
    // counts and status for "ELASTIC" memberships as appropriate
    // NOTE: this iterator finds _all_ matching interfaces, including dst-only
    MulticastFIB::MembershipTable::Iterator iterator(membership_table, &flowDescription);
    bool ackingStatus = false;
    bool forwarding = false;
    MulticastFIB::Membership* membership;
    while (NULL != (membership = iterator.GetNextEntry()))
    {
        if (membership->FlagIsSet(MulticastFIB::Membership::ELASTIC))
        {
            unsigned int totalPktCount = membership->IncrementIdleCount(pktCount);
            if (totalPktCount >= membership->GetIdleCountThreshold())
            {
                //if (GetDebugLevel() >= PL_DEBUG)
                {
                    PLOG(PL_ALWAYS, "nrlsmf: ELASTIC membership idle for flow ");
                    flowDescription.Print();
                    PLOG(PL_ALWAYS, " totalCount:%u threshold:%u\n", totalPktCount, 
                            membership->GetIdleCount());
                }
                DeactivateMembership(*membership, MulticastFIB::Membership::ELASTIC);
                mcast_forwarder->SetForwardingStatus(flowDescription, membership->GetInterfaceIndex(), MulticastFIB::LIMIT, true);
                if (0 == membership->GetFlags())
                {
                    //if (GetDebugLevel() >= PL_DEBUG)
                    {
                        PLOG(PL_ALWAYS, "nrlsmf: removing membership ");
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
    if (!ackingStatus)
        mcast_forwarder->SetAckingStatus(flowDescription, false);
}  // end ElasticMulticastController::Update()
