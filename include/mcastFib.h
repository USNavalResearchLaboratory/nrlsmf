#if defined(ELASTIC_MCAST) || defined(ADAPTIVE_ROUTING)

#ifndef _MCAST_FIB
#define _MCAST_FIB

#include "flowTable.h"
#include "elasticMsg.h"
#include "r2dnMsg.h"
#include "path.h"
#include <list>
#include <vector>
#include <unordered_map>

#include "protoPktIGMP.h"
#include "protoSocket.h"  // used by ElasticMulticastController
#include "protoTimer.h"   // used by ElasticMulticastController

// This will initially be used as a Forwarding Information Base
// for Elastic Multicast within the nrlsmf implementation. Eventually.
// this may be evolved to provide a more general MANET FIB data structure.
// Note that the FIB entries also maintain timers ... we need to decide
// how we will manage timeouts.  For example, we may use ProtoTimers or
// manage timeouts in a more general way by maintaining a timer queue
// for the FIB at large ...

class ElasticMulticastController;  // forward declaration (we may refactor things a bit eventually)

class MulticastFIB
{
    public:
        MulticastFIB();
        ~MulticastFIB();

        enum ForwardingStatus
        {
            BLOCK,  // do not forward until control plane says otherwise
            HYBRID, // forward one bucket, then block (until control plane override)
            LIMIT,  // forward according to token bucket parameters
            FORWARD // forward on an unlimited basis
        };

        enum MembershipStatus
        {
            MEMBER_NONE,    // not a member
            MEMBER_ASM,     // any-source multicast member
            MEMBER_SSM      // single-source multicast member
        };

        // These are related to the pruning of stale FIB flow entries
        static const unsigned int DEFAULT_FLOW_ACTIVE_TIMEOUT;  // in microseconds
        static const unsigned int DEFAULT_FLOW_IDLE_TIMEOUT;    // in microseconds
        static const double DEFAULT_LEARNING_RATE ;
        static const unsigned int MAX_SENT_PACKETS;

        // The following are default forwarder/controller flow and EM-ACK status reporting and timeouts
        static const unsigned int DEFAULT_ACKING_COUNT;         // number of packets per update (10)
        static const unsigned int DEFAULT_ACKING_INTERVAL_MIN ; // minimum update interval (0,1 sec in microseconds)
        static const unsigned int DEFAULT_ACKING_INTERVAL_MAX;  // maximum update interval (30 seconds in microseconds)
        static const double DEFAULT_ACK_TIMEOUT;                // ELASTIC flow without ACK timeout (30 seconds in seconds)
        static const unsigned int DEFAULT_IDLE_COUNT_THRESHOLD;       // ELASTIC packet count without ACK threshold (30)

        static const char* GetForwardingStatusString(ForwardingStatus status);

        // The time units used here are assumed msecs
        void Update(unsigned int elapsedTime);
        void Prune(unsigned int currentTime, unsigned int ageMax);

        // TBD - what's the best way to sort our BucketList???
        // a) time-ordered linked list like our Entry ActiveList, or
        // b) indexed by interface index (using this for now)
        class TokenBucket : public ProtoTree::Item
        {
            public:
                TokenBucket(unsigned int ifaceIndex);
                ~TokenBucket();

                void SetForwardingStatus(ForwardingStatus status)
                    {forwarding_status = status;}
                ForwardingStatus GetForwardingStatus() const
                    {return forwarding_status;}

                void SetRate(double packetsPerSecond);

                unsigned int GetInterfaceIndex() const
                    {return iface_index;}
                void CopyStatus(const TokenBucket& bucket)
                {
                    forwarding_status = bucket.forwarding_status;
                    bucket_depth = bucket.bucket_depth;
                    token_interval = bucket.token_interval;
                    bucket_count = bucket.bucket_count;
                }

                void Reset(unsigned int currentTick = 0)
                {
                    bucket_count = bucket_depth;
                    ticker_prev = currentTick;
                }

                void Refresh(unsigned int currentTick);

                // TBD - also support packet size for byte-based tokens?
                bool ProcessPacket(unsigned int currentTick);

                const char* GetKey() const
                    {return ((const char*)&iface_index);}
                unsigned int GetKeysize() const
                    {return (sizeof(unsigned int) << 3);}

            private:
                unsigned int        iface_index;
                ForwardingStatus    forwarding_status;
                unsigned int        bucket_depth;
                unsigned int        token_interval; // microseconds per packet (1.0e+06 / packetsPerSecond)
                unsigned int        bucket_count;
                unsigned int        ticker_prev;    // last time bucket was updated (microsecond ticks)
        };  // end class MulticastFIB::TokenBucket

        // List of token buckets indexed by outbound iface index
        class BucketList : public ProtoTreeTemplate<TokenBucket>
        {
            public:
                TokenBucket* FindBucket(unsigned int ifaceIndex) const
                    {return Find((char*)&ifaceIndex, sizeof(unsigned int) << 3);}
        }; // end class MulticastFIB::BucketList

        class Entry;

        // Since an inbound "flow" may be available from multiple previous-hop ("upstream")
        // forwarders, this "UpstreamRelay" class is used to track the previous-hop(s)
        // of an inbound flow (this assumes unique MAC addrs!)
        class UpstreamRelay : public ProtoTree::Item
        {
            public:
                UpstreamRelay();
                UpstreamRelay(const ProtoAddress& addr, unsigned int ifaceIndex);
                ~UpstreamRelay();

                const ProtoAddress& GetAddress() const
                    {return relay_addr;}
                unsigned int GetInterfaceIndex() const
                    {return iface_index;}

                // Set start of update count/interval (if non-zero count)
                void Reset(unsigned int currentTick, unsigned int count = 1)
                {
                    update_count = count;
                    update_start = age_tick = currentTick;
                    update_max = age_max = count ? false : true;
                }

                void Preset(unsigned int count)
                {
                    update_count = count;
                    update_max = age_max = true;
                }

                // This is called upon receiving a packet from the upstream
                void Refresh(unsigned int currentTick, unsigned int count = 1);

                // This is called to "age" tick count status
                unsigned int Age(unsigned int currentTick);

                unsigned int GetAge(unsigned int currentTick) const;
                unsigned int GetUpdateCount() const
                    {return update_count;}
                unsigned int GetUpdateInterval() const;

                bool AckPending(const Entry& entry, bool actual = true) const;

                const char* GetKey() const
                    {return relay_addr.GetRawHostAddress();}
                unsigned int GetKeysize() const
                    {return (relay_addr.GetLength() << 3);}

            private:
                ProtoAddress    relay_addr;    // address of this previous hop (MAC or IP for encapsulated forwarding)
                unsigned int    iface_index;   // inbound interface index

                unsigned int    update_count;
                unsigned int    update_start; // tick when update_count started
                bool            update_max;
                unsigned int    age_tick;     // last time of packet from this upstream
                bool            age_max;

        };  // end class MulticastFIB::UpstreamRelay

        class UpstreamRelayList : public ProtoTreeTemplate<UpstreamRelay>
        {
            public:
                UpstreamRelay* FindUpstreamRelay(const ProtoAddress& addr) const
                    {return Find(addr.GetRawHostAddress(), addr.GetLength() << 3);}
        }; // end class MulticastFIB::UpstreamRelayList

        // The following classes have been added as part of the R2DN program
        // Author: Matt Johnston, Boeing Research & Technology.

        // RL_Data is a container class containing information pertaining to the SRR Reinforcement Learning (RL) algorithm.
		// The class maintains a list of RL_Metrics, for each "next hop" address, as well as a list of sent packets, corresponding to the packets that have been sent over each list.
		// A seperate list is maintained for each next hop. THis list is required for the computation of the correction factor in the RL algorithm.
		// Additionally, RL_Data tracks the flow for which the data is defined.
		class RL_Data : public FlowEntryTemplate<ProtoTree>
		{
            public:
			 struct RL_Metric_Tuple
			{
				double Q;
				double C;
				int correctionFactor;
				int correctionThreshold;
                double RTT_sec;
                time_t  lastPacketArrival;
                bool need_advertisement;

				RL_Metric_Tuple (double newQ, double newC)
				{
                    Q = newQ;
                    C = newC;
                    RTT_sec = 1;
                    correctionFactor = 0;
                    correctionThreshold = 0;
                    need_advertisement = false;
				}

				double getCorrectedC(double rate)
				{
                    return C / (pow(1-rate,correctionFactor));
				}
			};




				RL_Data(const FlowDescription& flow, double learningRate);
				RL_Data();
				~RL_Data();

                ProtoAddressList&   accessMetricList() {return rl_metrics;}
                //ouble              getCorrectionFactor(ProtoAddress addr, UINT16 seqNo,UINT16 fragOffset);
                // The update function is used to update the RL metrics when an ACK is received.
                // Parameters:
                //      addr: The next-hop MAC Address (link) that's being acknowledged.
                //      ackQ: The Q value returned in the acknowledgement.
                //      ackC: The C value returned in the acknowledgemetn.
                //      seqNo: The sequence number of the packet being acknoweldged.
                bool                update(ProtoAddress addr, float ackQ, float ackC, UINT16 seqNo, UINT16 fragOffset);
                RL_Metric_Tuple *   getMetrics(ProtoAddress addr);
                bool                hasMetrics(ProtoAddress addr) {return rl_metrics.Contains(addr);}
                // The processSentPacket function ris used to update the RL metrics when a packet is transmitting.
                // This involves decrementing the relevant C values, and adding the sequence number (seqNo) to the sentPackets data structure.
                double              processSentPacket(ProtoAddress addr, UINT16 seqNo,UINT16 fragOffset);
                double              getLearningRate() const
                    {return learning_rate;}
                UpstreamRelay * getNextHop(MulticastFIB::UpstreamRelayList & downstream_relays, double minBroadcastProb, double reliability_threshold);


            private:
				double 		     learning_rate;         // Maintains the learning-rate (gamma) parameter for the SRR algorithm
                ProtoAddressList rl_metrics;            // A MAC-address-indexed table of RL_Metric_Tuples
                ProtoAddressList sentPackets;           // A MAC_address-indexed table of sequence number lists -> used for C factor computation.
                ProtoAddressList timeTable;             // A MAC address-indexed table of sequence number keyed maps, where values are times.
                ProtoAddressList timeStats;             // A MAC address-indexed table of PacketTimer objects
		};

        // A per-flow talbe of RL_Data objects.
		class RL_Table : public FlowTableTemplate<RL_Data, ProtoTree>
		{
            public:
                RL_Data* addFlow(const FlowDescription& flow);
		};


        // The MulticastFIB::Entry class is used to keep state for flows detected
        class Entry : public FlowEntryTemplate<ProtoTree>
        {
            public:
                Entry(const ProtoAddress&   dst,
                      const ProtoAddress&   src,        // invalid src addr means dst only
                      UINT8                 trafficClass = 0x03,
                      ProtoPktIP::Protocol  theProtocol = ProtoPktIP::RESERVED);
                Entry(const FlowDescription& flowDescription, int flags = FlowDescription::FLAG_ALL);
                ~Entry();

                bool IsExactMatch(const FlowDescription& flowDescription) const
                {
                    return ProtoTree::ItemIsEqual(*this,
                                                  flowDescription.GetKey(),
                                                  flowDescription.GetKeysize());
                }
                bool IsExactMatch(const Entry& entry) const
                    {return ProtoTree::ItemsAreEqual(*this, entry);}

                // These are the "default" forwarding_status
                void SetDefaultForwardingStatus(ForwardingStatus status)
                    {default_forwarding_status = status;}
                ForwardingStatus GetDefaultForwardingStatus() const
                    {return default_forwarding_status;}

                bool CopyStatus(Entry& entry);  // copy status from "entry"

                BucketList& AccessBucketList()
                    {return bucket_list;}
                TokenBucket* GetBucket(unsigned int currentTick);
                void ResetTokenBuckets();
                void RefreshTokenBuckets(unsigned int currentTick);

                bool SetForwardingStatus(unsigned int       ifaceIndex,
                                         ForwardingStatus   forwardingStatus,
                                         bool               ackingStatus);
                ForwardingStatus GetForwardingStatus(unsigned int ifaceIndex) const;
                unsigned int GetForwardingCount() const
                    {return forwarding_count;}

                void ResetUpstreamRelays();
                void AgeUpstreamRelays(unsigned int currentTick);
                void SetAckingStatus(bool status);
                bool GetAckingStatus() const
                    {return acking_status;}
                void SetAckingCondition(unsigned int count,
                                        unsigned int intervalMax,
                                        unsigned int intervalMin)
                {
                    acking_count_threshold = count;
                    acking_interval_max = intervalMax;
                    acking_interval_min = intervalMin;
                }
                unsigned int GetAckingCountThreshold() const
                    {return acking_count_threshold;}
                unsigned int GetAckingIntervalMax() const
                    {return acking_interval_max;}
                unsigned int GetAckingIntervalMin() const
                    {return acking_interval_min;}

                void SetManaged(bool status)
                    {flow_managed = status;}
                bool IsManaged() const
                    {return flow_managed;}
                void Activate()
                    {flow_active = true;}
                void Deactivate()
                    {flow_active = false;}
                bool IsActive() const
                    {return flow_active;}
                void SetIdle(bool status)
                    {flow_idle = status;}
                bool IsIdle() const
                    {return flow_idle;}

                void Refresh(unsigned int currentTick)
                {
                    age_tick = currentTick;
                    age_max = false;
                    RefreshTokenBuckets(currentTick);
                    AgeUpstreamRelays(currentTick);
                }

                unsigned int Age(unsigned int currentTick);
                unsigned int GetAge(unsigned int currentTick) const;

                void AddUpstreamRelay(UpstreamRelay& relay)
                    {upstream_list.Insert(relay);}
                UpstreamRelay* FindUpstreamRelay(const ProtoAddress& addr) const
                    {return upstream_list.FindUpstreamRelay(addr);}
                UpstreamRelayList& AccessUpstreamRelayList()
                    {return upstream_list;}

                UpstreamRelay* getDownstreamRelay()
                    {return &downstream_relay;}
                void setDownstreamRelay(const UpstreamRelay& relay)
                    {downstream_relay = relay;}
                void setUnicastProb(double prob)
                    {unicast_probability = prob;}
                double getUnicastProb()
                    {return unicast_probability;}

                // List linking (used for aging/pruning entries)
                void Append(Entry* entry)
                    {active_next = entry;}
                void Prepend(Entry* entry)
                    {active_prev = entry;}
                Entry* GetPrev() {return active_prev;}
                Entry* GetNext() {return active_next;}

            private:
                bool                    flow_managed;       // true when created on command from controller
                bool                    flow_active;
                bool                    flow_idle;
                ForwardingStatus        default_forwarding_status;
                unsigned int            forwarding_count;   // how many interfaces forwarding to ...

                unsigned int            age_tick;           // units of microseconds (last time entry was tickled)
                bool                    age_max;            // if "true", the "age_tick" value is invalid
                BucketList              bucket_list;        // list of token buckets for outbound interfaces (allows independent interface policies)
                UpstreamRelayList       upstream_list;
                UpstreamRelay           downstream_relay;       // Next unicast hop (MAC address / Interface)
                double                  unicast_probability;    // probability of forwarding to next unicast hop
                bool                    acking_status;
                unsigned int            acking_count_threshold; // in packets
                unsigned int            acking_interval_max;    // in microseconds
                unsigned int            acking_interval_min;    // in microseconds

                Entry*                  active_prev;
                Entry*                  active_next;

        };  // end class MulticastFIB::Entry

        class MaskLengthList
        {
            public:
                MaskLengthList();
                ~MaskLengthList();

                void Insert(UINT8 maskLen);
                void Remove(UINT8 maskLen);

                class Iterator
                {
                    public:
                        Iterator(const MaskLengthList& maskList)
                            : mask_list(maskList), list_index(0) {}

                        void Reset()
                            {list_index = 0;}

                        int GetNextMaskLength()
                            {return ((list_index < mask_list.GetLength()) ?
                                        mask_list.GetValue(list_index++) : -1);}

                    private:
                        const MaskLengthList& mask_list;
                        int                   list_index;

                };  // end class MulticastFIB::MaskLengthList::Iterator

                friend class Iterator;

            private:
                unsigned int GetLength() const
                    {return list_length;}
                int GetValue(UINT8 index) const
                    {return ((index < list_length) ? (int)mask_list[index] : -1);}

                UINT8           mask_list[129];
                UINT8           list_length;
                unsigned int    ref_count[129];
        };  // end class MulticastFIB::MaskLengthList

        class EntryTable : public FlowTableTemplate<Entry, ProtoTree> {};

        EntryTable& AccessFlowTable()
            {return flow_table;}

        // The MulticastFIB::Membership class is used to keep state for group memberships
        // If "src" is valid, then it is an SSM membership, else ASM

        class MembershipTable;  // forward declaration to support friendship

        class Membership : public FlowEntryTemplate<ProtoIndexedQueue>
        {
            public:
                // invalid/none src addr means dst only
                Membership(unsigned int         ifaceIndex,
                           const ProtoAddress&  dst,
                           const ProtoAddress&  src = PROTO_ADDR_NONE,
                           UINT8                trafficClass = 0x03,
                           ProtoPktIP::Protocol protocol = ProtoPktIP::RESERVED);
                ~Membership();

                enum Flag
                {
                    STATIC      = 0x01, // fixed, "static" membership
                    MANAGED     = 0x02, // managed by IGMP or MLD
                    ELASTIC     = 0x04  // Elastic Multicast interm
                };

                int GetFlags() const
                    {return membership_flags;}
                bool FlagIsSet(Flag flag)
                    {return (0 != (membership_flags & flag));}
                void SetFlag(Flag flag)
                    {membership_flags |= flag;}
                void ClearFlag(Flag flag)
                    {membership_flags &= ~flag;}

                void ResetIdleCount()
                    {idle_count = 0;}
                unsigned int IncrementIdleCount(unsigned int count)
                {
                    unsigned int prevCount = idle_count;
                    idle_count += count;
                    if (prevCount > idle_count)
                        idle_count = (unsigned int)-1;
                    return idle_count;
                }
                unsigned int GetIdleCount() const
                    {return idle_count;}
                void SetIdleCountThreshold(unsigned int pktCount)
                    {idle_count_threshold = pktCount;}
                unsigned int GetIdleCountThreshold() const
                    {return idle_count_threshold;}

                Flag GetTimeoutFlag() const
                    {return timeout_flag;}
                // Only valid if igmp_timeout_valid || elastic_timeout_valid
                unsigned int GetTimeout() const
                    {return ((ELASTIC == timeout_flag) ? elastic_timeout_tick : igmp_timeout_tick);}

            private:
                const unsigned int* GetTimeoutPtr() const
                    {return ((ELASTIC == timeout_flag) ? &elastic_timeout_tick : &igmp_timeout_tick);}

                friend class MulticastFIB::MembershipTable;

                int                 membership_flags;
                unsigned int        idle_count_threshold;
                unsigned int        idle_count; // number of packets since last EM_ACK
                Flag                timeout_flag;
                unsigned int        igmp_timeout_tick;
                bool                igmp_timeout_valid;
                unsigned int        elastic_timeout_tick;
                unsigned int        elastic_timeout_valid;

        };  // end class MulticastFIB::Membership

        class MembershipTable : public FlowTableTemplate<Membership, ProtoIndexedQueue>
        {
            public:
                MembershipTable();
                ~MembershipTable();

                // invalid/none src addr means dst only
                Membership* AddMembership(unsigned int         ifaceIndex,
                                          const ProtoAddress&  dst,
                                          const ProtoAddress&  src = PROTO_ADDR_NONE,
                                          UINT8                trafficClass = 0x03,
                                          ProtoPktIP::Protocol protocol = ProtoPktIP::RESERVED);

                void RemoveMembership(unsigned int          ifaceIndex,
                                      const ProtoAddress&   dst,
                                      const ProtoAddress&   src = PROTO_ADDR_NONE,
                                      UINT8                 trafficClass = 0x03,
                                      ProtoPktIP::Protocol  protocol = ProtoPktIP::RESERVED);

                bool IsMember(const ProtoAddress&   dst,
                              const ProtoAddress&   src = PROTO_ADDR_NONE,
                              bool                  wildcardSource = false);

                MembershipStatus GetMembershipStatus(unsigned int           ifaceIndex,
                                                     const ProtoAddress&    dst,
                                                     const ProtoAddress&    src = PROTO_ADDR_NONE);

                // Note a membership may be dually "active" by both ELASTIC and MANAGED (e.g., IGMP) timeouts
                // (A membership's STATIC status is not maintained on an "active" (i.e., timer-based) basis)
                bool ActivateMembership(Membership&         membership,
                                        Membership::Flag    flag,
                                        unsigned int        timeoutTick);  // required for non-STATIC
                void DeactivateMembership(Membership&       membership,
                                          Membership::Flag    flag);

                bool IsActive() const
                    {return (NULL != ring_leader);}

                unsigned int GetNextTimeout() const
                    {return ((NULL != ring_leader) ? ring_leader->GetTimeout() : 0);}

                Membership* GetRingLeader()
                    {return ring_leader;}

                Membership* FindMembership(const FlowDescription& flowDescription)
                    {return FindEntry(flowDescription);}

                Membership* FindMembership(unsigned int         ifaceIndex,
                                           const ProtoAddress&  dst,
                                           const ProtoAddress&  src = PROTO_ADDR_NONE,
                                           UINT8                trafficClass = 0x03,
                                           ProtoPktIP::Protocol protocol = ProtoPktIP::RESERVED)
                {
                    FlowDescription description(dst, src, trafficClass, protocol, ifaceIndex);
                    return FindMembership(description);
                }

                // The Ring class maintains a queue of "activated" memberships
                // sorted by their applicable timeout value.
                class Ring : public ProtoSortedQueueTemplate<Membership>
                {
                    public:
                        // ProtoIndexedQueue required overrides
                        virtual const char* GetKey(const Item& item) const
                            {return ((const char*)static_cast<const Membership&>(item).GetTimeoutPtr());}
                        virtual unsigned int GetKeysize(const Item& item) const
                            {return (sizeof(unsigned int) << 3);}
                };  // end class MemberhipTable::Ring

                // The AgeIterator class lets us iterate over the "activated" memberships
                // held within the MembershipTable in the order of oldest to newest
                // (so we can timeout aged memberships)
                class AgeIterator
                {
                    public:
                        AgeIterator(MembershipTable& table);
                        ~AgeIterator();

                        Membership* GetNextMembership();  // oldest to newest

                    private:
                        Ring::Iterator  ringerator;
                };  // end class MembershipTable::AgeIterator

            private:
                // Member variables
                Ring            membership_ring;
                Membership*     ring_leader;  // membership that times out last; i.e., "head" of the ring

        };  // end class MulticastFIB::MembershipTable

        // TBD - is this "FlowPolicy" class redundant with our "Membership" class?
        // (i.e., the controller can use the "Membership" class in its policy_table
        class FlowPolicy : public ProtoTree::Item
        {
            public:
                FlowPolicy(const ProtoAddress&       dst,
                           const ProtoAddress&       src = PROTO_ADDR_NONE, // invalid/none src addr means dst only
                           ProtoPktIP::Protocol      theProtocol = ProtoPktIP::RESERVED,
                           int                       trafficClass = -1);
                ~FlowPolicy();

                bool GetDstAddr(ProtoAddress& addr) const
                    {return flow_description.GetDstAddr(addr);}
                bool GetSrcAddr(ProtoAddress& addr) const
                    {return flow_description.GetSrcAddr(addr);}
                ProtoPktIP::Protocol GetProtocol() const
                    {return flow_description.GetProtocol();}
                int GetTrafficClass() const
                    {return flow_description.GetTrafficClass();}

                void SetAckingStatus(bool status)
                    {acking_status = status;}
                bool GetAckingStatus() const
                    {return acking_status;}
                // TBD - add acking conditions

                void SetBucketRate(double pktRate)  // pkts / second
                    {bucket_rate = pktRate;}
                void SetBucketDepth(unsigned int depth)
                    {bucket_depth = depth;}
                void SetForwardingStatus(ForwardingStatus status)
                    {forwarding_status = status;}

                double GetBucketRate() const
                    {return bucket_rate;}
                unsigned int GetBucketDepth() const
                    {return bucket_depth;}
                ForwardingStatus GetForwardingStatus() const
                    {return forwarding_status;}

            private:
                const char* GetKey() const
                    {return flow_description.GetKey();}
                unsigned int GetKeysize() const
                    {return flow_description.GetKeysize();}

                FlowDescription flow_description;

                // Default status to be applied to matching detected flows
                double              bucket_rate;   // packets per second
                unsigned int        bucket_depth;
                ForwardingStatus    forwarding_status;
                bool                acking_status;
                // TBD - should a flow have overriding mix/max update interval/count option?

        };  // end class MulticastFIB::FlowPolicy

        class FlowPolicyTable : public ProtoTreeTemplate<FlowPolicy>
        {
            public:
                FlowPolicyTable();
                ~FlowPolicyTable();

                // TBD - implement code to find "best fit" policy

                FlowPolicy* FindPolicy(const FlowDescription& flowDescription)
                    {return Find(flowDescription.GetKey(), flowDescription.GetKeysize());}

                FlowPolicy* FindPolicy(ProtoPktIP& ipPkt, int indexFlags = (FlowDescription::FLAG_DST | FlowDescription::FLAG_SRC));

        };  // end class MulticastFIB::FlowPolicyTable

        // Currently our "tick" for aging elastic multicast flows is a one microsecond
        // tick.  For a 32-bit int with wrapping values, we can discriminate a maximum
        // "age" equivalent to about one thousand seconds (which is plenty for the purposes here)
        enum {TICK_AGE_MAX = 0x40000000}; // about a billion microseconds, or 1000 seconds

        // return values less than zero means referenceTime > currentTime
        static int ComputeAge(unsigned int currentTick, unsigned int referenceTick)
            {return (currentTick - referenceTick);}

        static unsigned int BuildAck(UINT32*                buffer,
                                     unsigned int           length,
                                     const ProtoAddress&    dstMac,  // also used for ACK upstream relay addr
                                     const ProtoAddress&    srcMac,
                                     const ProtoAddress&    srcIp,
                                     const FlowDescription& flowDescription);

        // This linked list is used to "age" entries. When a packet for an entry
        // is processed, the entry is "promoted" to the front of the list.  Stale
        // flows end up at the end of the list.  They are aged with a time counter
        // value.  This approach assumes the ActiveList is serviced before any
        // time wrap can occur.
        class ActiveList
        {
            public:
                ActiveList();
                ~ActiveList();
                unsigned int GetCount() const
                    {return count;}
                void Prepend(Entry& entry)
                {
                    if (NULL != head)
                        head->Prepend(&entry);
                    else
                        tail = &entry;
                    entry.Prepend(NULL);
                    entry.Append(head);
                    head = &entry;
                    count++;
                }
                void Remove(Entry& entry)
                {
                    Entry* prev = entry.GetPrev();
                    Entry* next = entry.GetNext();
                    if (NULL != next)
                    {
                        next->Prepend(prev);
                        entry.Append(NULL);
                    }
                    else
                    {
                        tail = prev;
                    }
                    if (NULL != prev)
                    {
                        prev->Append(next);
                        entry.Prepend(NULL);
                    }
                    else
                    {
                        head = next;
                    }
                    count--;
                }
                Entry* GetHead() const
                    {return head;}
                Entry* GetTail() const
                    {return tail;}

            private:
                unsigned int count;
                Entry*        head;
                Entry*        tail;
        };  // end class MulticastFIB::ActiveList

        void InsertEntry(Entry& entry)
            {flow_table.InsertEntry(entry);}

        Entry* FindEntry(const FlowDescription& flowDescription)
            {return flow_table.FindEntry(flowDescription);}

        Entry* FindBestMatch(const FlowDescription& flowDescription, bool exhaustiveSearch=false)
            {return flow_table.FindBestMatch(flowDescription, exhaustiveSearch);}

        bool SetForwardingStatus(const FlowDescription& flowDescription,
                                 unsigned int           ifaceIndex,
                                 ForwardingStatus       forwardingStatus,
                                 bool                   ackingStatus);

        bool SetAckingCondition(const FlowDescription&    flowDescription,
                                unsigned int              count,
                                unsigned int              intervalMax,
                                unsigned int              intervalMin);

        void ActivateFlow(Entry& entry, unsigned int currentTick);
        void ReactivateFlow(Entry& entry, unsigned int currentTick)
        {
            if (entry.IsIdle())
            {
                idle_list.Remove(entry);
                entry.SetIdle(false);
            }
            ActivateFlow(entry, currentTick);
        }
        void DeactivateFlow(Entry& entry, unsigned int currentTick);
        void TouchEntry(Entry& entry, unsigned int currentTick)
        {
            active_list.Remove(entry);
            entry.Refresh(currentTick);
            active_list.Prepend(entry);
        }

        void PruneFlowList(unsigned int currentTick, ElasticMulticastController* controller = NULL);

        bool ParseFlowList( ProtoPktIP& pkt, Entry*& fibEntry, unsigned int currentTick, bool& sendAck,const ProtoAddress& srcMac);


    private:
        EntryTable          flow_table;    // Table of detected flows (updated by forwarding plane)
        ActiveList          active_list;  // stalest flows at end, freshest first
        ActiveList          idle_list;
        //SmartRoutingTable   routing_table;  // Probabalistic Routing table for smart Adaptive Routing
};  // end class MulticastFIB

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
// The classes below are "starter" classes for separate "controller" and "forwarder"
// elements.  These classes will be used in this experimental code to explore the
// Controller <-> Forwarder interface design for Elastic Multicast, Adaptive Routing,
// and potentially other MANET protocols and algorithms (e.g., network coding, etc)
// with "nrlsmf" providing a duplicate packet detection (DPD) forwarding capability
// along with other features (e.g., encapsulated forwarding, etc).
//
// The controller and forwarder elements each maintain a "MulticastFIB".  It may be
// possible that a shared instance of a MulticastFIB could be used, but the exercise
// here is to keep the forwarder element lean and mean for possible kernel, etc
// emplacement with sufficient flexibility that different protocols might be realized
// with different forms of controller behavior.
//
// In the "nrlsmf" implementation, the Smf class (defined in smf.h) acts as the
// "forwarder", implementing the ElasticMulticastForwarder interface defined below.
// The Smf class instance is a member of the SmfApp class that comprises the "nrlsmf"
// application.  For the initial, experimental implementation of elastic multicast,
// the SmfApp class also contains an instance of the ElasticMulticastController class
// defined below. The ElasticMulticastController class is designed to be portable or
// embeddable into other processes (e.g., nrlolsrv2, etc) and, in the future, the
// controller of the "nrlsmf" fowarding process will likely be a separate process.

// The ElasticMulticastForwarder is an interface class that provides
// methods for controlling the underlying forwarding information base
// and forwarding process.

// This is a helper time-keeper class that
// tracks time as microsecond ticks.
class ElasticTicker
{
    public:
        ElasticTicker() {Reset();}
        ~ElasticTicker() {}

        // Ticker managed timeouts should not exceed DELTA_MAX
        static const double DELTA_MAX;  // 1200.0 seconds
        unsigned int Update();

        void Reset()
        {
            ticker_time_prev.GetCurrentTime();
            ticker_count = 0;
        }

    private:
        unsigned int    ticker_count;
        ProtoTime       ticker_time_prev;

};  // end ElasticTicker

class ElasticMulticastController;

class ElasticMulticastForwarder
{
    public:
        ElasticMulticastForwarder();
        virtual ~ElasticMulticastForwarder();

        void SetController(ElasticMulticastController* controller)
            {mcast_controller = controller;}

        // set forwarding status to BLOCK, LIMIT, HYBRID, or FORWARD
        bool SetForwardingStatus(const FlowDescription&  flowDescription,
                                 unsigned int                          ifaceIndex,
                                 MulticastFIB::ForwardingStatus        forwardingStatus,
                                 bool                                  ackingStatus);

        bool SetAckingStatus(const FlowDescription& flowDescription,
                             bool                   ackingStatus);
        /*
        bool SetAckingCondition(const FlowDescription&  flowDescription,
                                unsigned int            count,
                                unsigned int            intervalMax,
                                unsigned int            intervalMin)
        {
            return mcast_fib.SetAckingCondition(flowDescription, count, intervalMax, intervalMin);
        }
        */

        // The following required overrides are needed since they require access
        // to a network interface output mechanism (for sending EM-ACK)
        virtual bool SendAck(unsigned int                         ifaceIndex,
                             const ProtoAddress&                  relayAddr,
                             const FlowDescription& flowDescription) = 0;
        class OutputMechanism
        {
            public:
                virtual bool SendFrame(unsigned int ifaceIndex, char* buffer, unsigned int length) = 0;
        };  // end class ElasticMulticastForwarder::OutputMechanism
        void SetOutputMechanism(OutputMechanism* mech)
            {output_mechanism = mech;}

    protected:
       // Our "ticker" is a count of microseconds that is used for our
        // membership timeouts.  The forwarder is responsible for
        // keeping the "time_ticker" updated.
        void ResetTicker()
            {time_ticker.Reset();}
        unsigned int UpdateTicker()
            {return time_ticker.Update();}


        MulticastFIB                mcast_fib;
        ElasticTicker               time_ticker;
        ElasticMulticastController* mcast_controller;
        OutputMechanism*            output_mechanism;

};  // end class ElasticMulticastForwarder

class ElasticMulticastController
{
    public:
        ElasticMulticastController(ProtoTimerMgr& timerMgr);
        ~ElasticMulticastController();

        bool Open(ElasticMulticastForwarder* forwarder);
        void Close();

        void SetForwarder(ElasticMulticastForwarder* forwarder)
            {mcast_forwarder = forwarder;}

        // This method is invoked by the forwarding plane (or via interface from forwarding plane) when
        // there is a newly detected flow or upon flow activity updates
        void Update(const FlowDescription&  flowDescription,
                    unsigned int                          ifaceIndex,
                    const ProtoAddress&                   relayAddr,
                    unsigned int                          pktCount,
                    unsigned int                          pktInterval);

        void HandleIGMP(const ProtoPktIGMP& igmpMsg, const ProtoAddress& srcIp, unsigned int ifaceIndex, bool inbound);

        bool AddManagedMembership(unsigned int ifaceIndex, const ProtoAddress& groupAddr);

        void HandleAck(const ElasticAck& ack, unsigned int ifaceIndex, const ProtoAddress& srcMac);
        bool ActivateMembership(MulticastFIB::Membership&       membership,
                                MulticastFIB::Membership::Flag  flag,
                                double                          timeoutSec);
        void DeactivateMembership(MulticastFIB::Membership&      membership,
                                  MulticastFIB::Membership::Flag flag);

        // NEXT STEP - IMPLEMENT MECHANISM TO SEND ACKS to UPSTREAM FORWARDERS
        // 1) When do we send an ACK?
        //    a) upon newly active flow
        //    b) on timeout interval as long as flow is active
        //       (if we order our upstream list in time since last ACK, we can service efficiently?)

    protected:
        // Our "ticker" is a count of microseconds that is used for our
        // membership timeouts.  The "ticker" is activated whenever the
        // membership_timer is activated.
        void ResetTicker()
            {time_ticker.Reset();}
        unsigned int UpdateTicker()
            {return time_ticker.Update();}

        bool OnMembershipTimeout(ProtoTimer& theTimer);

        ProtoTimerMgr&                  timer_mgr;
        ElasticTicker                   time_ticker;
        ProtoTimer                      membership_timer;

        MulticastFIB::MembershipTable   membership_table;

        ElasticMulticastForwarder*      mcast_forwarder;

};  // end class ElasticMulticastController

#endif // !_MCAST_FIB

#endif // ELASTIC_MCAST
