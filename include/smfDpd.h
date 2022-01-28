/*********************************************************************
 *
 * AUTHORIZATION TO USE AND DISTRIBUTE
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that:
 *
 * (1) source code distributions retain this paragraph in its entirety,
 *
 * (2) distributions including binary code include this paragraph in
 *     its entirety in the documentation or other materials provided
 *     with the distribution, and
 *
 * (3) all advertising materials mentioning features or use of this
 *     software display the following acknowledgment:
 *
 *  The name of NRL, the name(s) of NRL  employee(s), or any entity
 *  of the United States Government may not be used to endorse or
 *  promote  products derived from this software, nor does the
 *  inclusion of the NRL written and developed software  directly or
 *  indirectly suggest NRL or United States  Government endorsement
 *  of this product.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 * Revision history
 * Date  Author Details
 * 01/07/05 William Chao init version
 * 01/07/05 Justin Dean init version
 * 03/14/05 Brian Adamson version
 */

#ifndef _SMF_DUP_TREE
#define _SMF_DUP_TREE

#include "protoTree.h"
#include "protoAddress.h"
#include "protoBitmask.h"


// Both the "window" (sequence) and "table" lookup approaches to DPD use
// "flows" to detect duplicate packets on a per-flow basis

// TBD - this code should be updated to use the more current ProtoTreeTemplate
//       classes, etc.  For example, the current ProtoTree allows for
//       variable length entries that were not supported when the code below
//       was written.


class SmfFlow : public ProtoTree::Item
{
    public:
        virtual ~SmfFlow();

        const char* GetKey() const {return flow_id;}
        unsigned int GetKeysize() const {return flow_id_size;}

        virtual void Destroy();
        class Iterator;
        class List
        {
            friend class Iterator;
            public:
                List();
                ~List();

                void Destroy(ProtoTree::ItemPool* itemPool = NULL);

                void Append(SmfFlow& flow);

                SmfFlow* Find(const char* flowId, unsigned int flowIdBits) const
                    {return static_cast<SmfFlow*>(flow_tree.Find(flowId, flowIdBits));}

                void MoveToTail(SmfFlow& flow)
                {
                    RemoveFromList(flow);
                    AppendToList(flow);
                }

                void Remove(SmfFlow& flow)
                {
                    RemoveFromList(flow);
                    flow_tree.Remove(flow);
                    count--;
                }

                unsigned int GetCount() const
                    {return count;}

                SmfFlow* GetHead() const
                    {return head;}

            private:
                static SmfFlow* GetNextFlow(SmfFlow* flow)
                    {return ((NULL != flow) ? flow->GetNext() : NULL);}
                void AppendToList(SmfFlow& flow);
                void RemoveFromList(SmfFlow& flow);

                unsigned int count;
                ProtoTree    flow_tree;
                SmfFlow*     head;  // stalest flow at head of linked list
                SmfFlow*     tail;  // freshest flow at tail of linked list
        };  // end class SmfFlow::List


        class Iterator
        {
            public:
                Iterator(const List& theList);
                ~Iterator();

                void Reset()
                    {next_flow = flow_list.GetHead();}
                SmfFlow* GetNextFlow()
                {
                    SmfFlow* flow = next_flow;
                    next_flow = List::GetNextFlow(flow);
                    return flow;
                }

            private:
                const List& flow_list;
                SmfFlow*    next_flow;

        };  // end class SmfFlow::Iterator

        friend class List;

    protected:
        SmfFlow();

        bool Init(const char*         flowId,
                  unsigned int        flowIdSize); // in bits

        // List linking (used for aging/pruning entries)
        void Append(SmfFlow* nextFlow)
            {next = nextFlow;}
        void Prepend(SmfFlow* prevFlow)
            {prev = prevFlow;}
        SmfFlow* GetPrev() {return prev;}
        SmfFlow* GetNext() {return next;}

        char*               flow_id;
        unsigned int        flow_id_size;
        SmfFlow*            prev;
        SmfFlow*            next;

};  // end class SmfFlow

class SmfDpd
{
    public:
        virtual ~SmfDpd();

        virtual void Destroy() = 0;

        virtual bool IsDuplicate(unsigned int   currentTime,
                                 const char*    flowId,
                                 unsigned int   flowIdSize,   // in bits
                                 const char*    pktId,
                                 unsigned int   pktIdSize) = 0;     // in bits

        virtual void Prune(unsigned int currentTime, unsigned int ageMax) = 0;

        virtual unsigned int GetFlowCount() const = 0;

    protected:
        SmfDpd();

};  // end class SmfDpd



///////////////////////////////////////////////////////////////////
// Table (lookup) based duplicate packet detection classes

class SmfDpdTable : public SmfDpd
{
    public:
        SmfDpdTable(unsigned int pktSizeMax);
        ~SmfDpdTable();

        enum {MAX_ID_BITS = (3*128)};
        enum {MAX_ID_BYTES = (MAX_ID_BITS/8)};

        void Destroy();

        bool IsDuplicate(unsigned int   currentTime,
                         const char*    flowId,
                         unsigned int   flowIdSize,   // in bits
                         const char*    pktId,
                         unsigned int   pktIdSize);   // in bits

        void Prune(unsigned int currentTime, unsigned int ageMax);

        unsigned int GetFlowCount() const
            {return (flow_list.GetCount());}

        // We keep packet id entries on a per-flow basis
        class PacketIdEntry;

        class PacketIdTable
        {
            public:
                PacketIdTable();
                ~PacketIdTable();

                void Append(PacketIdEntry& entry, unsigned int currentTime);
                PacketIdEntry* RemoveHead();
                bool IsDuplicate(const char* pktId, unsigned int pktIdSize) const
                    {return (NULL != id_tree.Find(pktId, pktIdSize));}

                // If "itemPool" is NULL, then stale entries are deleted
                void Prune(unsigned int             currentTime,
                           unsigned int             ageMax,
                           ProtoTree::ItemPool**    poolArray);

                void PruneSize(unsigned int sizeMax, ProtoTree::ItemPool** poolArray);

                void EmptyToPool(ProtoTree::ItemPool** poolArray);

                bool IsEmpty() const
                    {return (NULL == head);}

            private:
                ProtoTree       id_tree;
                PacketIdEntry*  head;   // oldest entry at head
                PacketIdEntry*  tail;   // newest entry at tail
                unsigned int    pkt_count;

        };  // end class SmfDpdTable::PacketIdTable

        class PacketIdEntry : public ProtoTree::Item
        {
            friend class PacketIdTable;

            public:
                PacketIdEntry();
                ~PacketIdEntry();

                unsigned int GetAge(unsigned int currentTime) const
                    {return (currentTime - arrival_time);}

                bool SetPktId(const char* pktId, UINT8 pktIdLength);
                unsigned int GetPktIdLength() const   // in bytes
                    {return ((NULL != pkt_id) ? (unsigned int)pkt_id[0] : 0);}

                virtual const char* GetKey() const
                    {return ((const char*)(pkt_id + 1));}
                virtual unsigned int GetKeysize() const  // in bits
                    {return ((NULL != pkt_id) ? ((unsigned int)pkt_id[0] << 3) : 0);}

            protected:
                void SetArrivalTime(unsigned int arrivalTime)
                    {arrival_time = arrivalTime;}

                void Append(PacketIdEntry* nextEntry)
                    {next = nextEntry;}
                PacketIdEntry* GetNext() const
                    {return next;}

            private:
                UINT8*          pkt_id;
                unsigned int    arrival_time;
                PacketIdEntry*  next;
        };  // end class SmfDpdTable::PacketIdEntry


        class Flow : public SmfFlow
        {
            public:
                Flow(unsigned int pktCountMax);
                ~Flow();

                bool Init(const char*   flowId,
                          unsigned int  flowIdSize); // in bits

                void Prune(unsigned int             currentTime,
                           unsigned int             ageMax,
                           ProtoTree::ItemPool**    poolArray = NULL)
                    {pkt_id_table.Prune(currentTime, ageMax, poolArray);}

                void EmptyToPool(ProtoTree::ItemPool** poolArray)
                    {pkt_id_table.EmptyToPool(poolArray);}

                void Destroy()
                    {SmfFlow::Destroy();}

                bool IsDuplicate(unsigned int           currentTime,
                                 const char*            pktId,
                                 unsigned int           pktIdSize,  // in bits
                                 ProtoTree::ItemPool**  itemPoolArray);

                bool IsEmpty() const
                    {return pkt_id_table.IsEmpty();}

            private:
                PacketIdTable   pkt_id_table;
                unsigned int    pkt_count_max;  // zero means unlimited

        };  // end class SmfDpdTable::Flow

    private:
        void Reset();

        SmfFlow::List           flow_list;

        unsigned int            pkt_count_max;  // per-flow table size limit (zero is unlimited)

        ProtoTree::ItemPool*    entry_pools[MAX_ID_BYTES+1];

    // (TBD) add some Pools for our different entry types

};  // end class SmfDpdTable


///////////////////////////////////////////////////////////////////
// Window (sequence) based duplicate packet detection classes

class SmfDpdWindow : public SmfDpd
{
    public:
		SmfDpdWindow ();
		~SmfDpdWindow ();

		bool Init(UINT32    windowSize,     // in packets
                  UINT32    windowPastMax); // in packets

        void Destroy()
            {flow_list.Destroy();}

		bool IsDuplicate(unsigned int   currentTime,
                         const char*    flowId,
                         unsigned int   flowIdSize,   // in bits
                         const char*    pktId,
                         unsigned int   pktIdSize);         // in bits

        void Prune(unsigned int currentTime, unsigned int ageMax);

        unsigned int GetFlowCount() const
            {return flow_list.GetCount();}

    private:
        class Flow : public SmfFlow
        {
            public:
                Flow();
                ~Flow();

                bool Init(const char*         flowId,
                          unsigned int        flowIdSize,     // in bits
                          UINT8               pktIdSize,      // in bits
                          UINT32              windowSize,     // in packets
                          UINT32              windowPastMax); // in packets

                void Destroy()
                {
                    bitmask.Destroy();
                    SmfFlow::Destroy();
                }
                void SetUpdateTime(unsigned int currentTime)
                    {update_time = currentTime;}

                unsigned int GetAge(unsigned int currentTime) const
                    {return (currentTime - update_time);}

                bool IsDuplicate(UINT32 seqNum);

                UINT32 GetRangeMask() const
                    {return bitmask.GetRangeMask();}

            private:
                ProtoSlidingMask bitmask;
                UINT32           window_past_max;
                unsigned int     update_time;

        };  // end class SmfDpdWindow::Flow


        SmfFlow::List   flow_list;
        UINT32          window_size;
		UINT32          window_past_max;

};  // end class SmfDpdWindow

/////////////////////////////////////////////////////////////////////////
// This class keeps per-flow (dst[:src] addr) sequence number
// state and is used for SMF source host resequencing purposes
class SmfSequenceMgr
{
    public:
        SmfSequenceMgr();
        ~SmfSequenceMgr();
        bool Init(UINT8 numSeqBits);
        void Destroy()
            {flow_list.Destroy();}

        UINT32 IncrementSequence(unsigned int        updateTime,
                                 const ProtoAddress* dstAddr,
                                 const ProtoAddress* srcAddr = NULL);

        UINT32 GetSequence(const ProtoAddress* dstAddr,
                           const ProtoAddress* srcAddr = NULL) const;

        void Prune(unsigned int currentTime, unsigned int ageMax);


    private:
        class Flow : public SmfFlow
        {
            public:
                Flow();
                ~Flow();

                bool Init(const char* flowId, unsigned int flowIdSize)
                    {return SmfFlow::Init(flowId, flowIdSize);}

                void SetSequence(UINT32 value)
                    {sequence = value;}
                UINT32 GetSequence() const
                    {return sequence;}
                UINT32 IncrementSequence(UINT32 seqMask)
                    {return (sequence++ & seqMask);}

                void SetUpdateTime(unsigned int currentTime)
                    {update_time = currentTime;}

                unsigned int GetAge(unsigned int currentTime) const
                    {return (currentTime - update_time);}

            private:
                UINT32          sequence;
                unsigned int    update_time;

        };  // end class SmfSequenceMgr::Flow

        UINT32              seq_mask;
        UINT32              seq_global;
        SmfFlow::List       flow_list;

};  // end class SmfSequenceMgr

#endif // !_SMF_DUP_TREE
