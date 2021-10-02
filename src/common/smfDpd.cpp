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
*/

#include "smfDpd.h"
#include <stdlib.h>  // for rand()


SmfFlow::SmfFlow()
: flow_id(NULL), flow_id_size(0), prev(NULL), next(NULL)
{
}

SmfFlow::~SmfFlow()
{   
    Destroy();
}

bool SmfFlow::Init(const char*         flowId,
                   unsigned int        flowIdSize)
{
    if (NULL != flow_id) delete[] flow_id;
    unsigned int flowIdBytes = flowIdSize >> 3;
    if (0 != (flowIdSize & 0x07)) flowIdBytes++;
    flow_id = new char[flowIdBytes];
    if (NULL == flow_id)
    {
        PLOG(PL_ERROR, "SmfFlow::Init() new flow_id error: %s\n", GetErrorString());
        flow_id_size = 0;
        return false;
    }
    memcpy(flow_id, flowId, flowIdBytes);
    flow_id_size = flowIdSize;
	return true;
}  // end SmfFlow::Init()

void SmfFlow::Destroy()
{
    if (NULL != flow_id)
    {
        delete[] flow_id;
        flow_id = NULL;
        flow_id_size = 0;
    }
}  // end SmfFlow::Destroy()



SmfFlow::List::List()
 : count(0), head(NULL), tail(NULL)
{
}

SmfFlow::List::~List()
{
    Destroy();
}

void SmfFlow::List::Destroy(ProtoTree::ItemPool* itemPool)
{
    SmfFlow* nextFlow;
    while (NULL != (nextFlow = head))
    {
        Remove(*nextFlow);
        if (NULL != itemPool)
            itemPool->Put(*nextFlow);
        else
            delete nextFlow;
    }
    count = 0;
}  // end SmfFlow::List::Destroy()


void SmfFlow::List::AppendToList(SmfFlow& flow)
{
    if (NULL != tail)
    {
        flow.Prepend(tail);
        tail->Append(&flow);
        tail = &flow;
    }
    else
    {
        flow.Prepend(NULL);
        head = tail = &flow;
    }
    flow.Append(NULL);
}  // end SmfFlow::List::AppendToList()

void SmfFlow::List::RemoveFromList(SmfFlow& flow)
{
    SmfFlow* prevFlow = flow.GetPrev();
    SmfFlow* nextFlow = flow.GetNext();
    if (NULL != prevFlow)
        prevFlow->Append(nextFlow);
    else
        head = nextFlow;
    if (NULL != nextFlow)
        nextFlow->Prepend(prevFlow);
    else
        tail = prevFlow;
}  // end SmfFlow::List::RemoveFromList()

void SmfFlow::List::Append(SmfFlow& flow)
{
    AppendToList(flow);
    flow_tree.Insert(flow);
    count++;
}  // end SmfFlow::List::Append()

SmfFlow::Iterator::Iterator(const SmfFlow::List& theList)
 : flow_list(theList), next_flow(theList.GetHead())
{
}

SmfFlow::Iterator::~Iterator()
{
}

SmfDpd::SmfDpd()
{
}

SmfDpd::~SmfDpd()
{
}


SmfDpdTable::SmfDpdTable(unsigned int pktCountMax)
    : pkt_count_max(pktCountMax)
{
    memset(entry_pools, 0, (MAX_ID_BYTES+1)*sizeof(ProtoTree::ItemPool*));
}

SmfDpdTable::~SmfDpdTable()
{
    Destroy();
}
        

void SmfDpdTable::Reset()
{
    // iterate thru all flows, remove & pool any entries, delete flows
    // (TBD) Do we want to pool flows, too?
    Flow* nextFlow;
    while (NULL != (nextFlow = static_cast<Flow*>(flow_list.GetHead())))
    {
        flow_list.Remove(*nextFlow);
        nextFlow->EmptyToPool(entry_pools);
        delete nextFlow;
    }
}  // end SmfDpdTable::Reset()

void SmfDpdTable::Destroy()
{
    // iterate thru all flows in flow lists, remove and delete any entries
    // and then destroy the pools 
    Reset();
    
    for (int i = 1; i <= MAX_ID_BYTES; i++)
    {
        if (NULL != entry_pools[i])
        {
            entry_pools[i]->Destroy();
            delete entry_pools[i];
            entry_pools[i] = NULL;
        }
    }
    
}  // end SmfDpdTable::Destroy()

void SmfDpdTable::Prune(unsigned int currentTime, unsigned int ageMax)
{
    Flow* nextFlow;
    SmfFlow::Iterator iterator(flow_list);
    while (NULL != (nextFlow = static_cast<Flow*>(iterator.GetNextFlow())))
    {
        nextFlow->Prune(currentTime, ageMax, entry_pools);
        if (nextFlow->IsEmpty())
        {
            flow_list.Remove(*nextFlow);
            delete nextFlow;
        }
    }
}  // end SmfDpdTable::Prune()

bool SmfDpdTable::IsDuplicate(unsigned int   currentTime,
                              const char*    flowId,
                              unsigned int   flowIdSize,   // in bits
                              const char*    pktId,
                              unsigned int   pktIdSize)    // in bits  
{
    unsigned int pktIdBytes = pktIdSize >> 3;
    if (0 != (pktIdSize & 0x07))
    {
        PLOG(PL_ERROR, "SmfDpdTable::IsDuplicate() error: pktIdSize not multiple of 8\n");
        return true;   
    }
    
    if (pktIdBytes > MAX_ID_BYTES)
    {
        PLOG(PL_ERROR, "SmfDpdTable::IsDuplicate() error: oversized pktId\n");
        return true;
    }
    
    ProtoTree::ItemPool* itemPool = entry_pools[pktIdBytes];
    if (NULL == itemPool)
    {
        if (NULL == (itemPool = new ProtoTree::ItemPool()))
        {
            PLOG(PL_ERROR, "SmfDpdTable::IsDuplicate() new itemPool error: %s\n", GetErrorString());
            return true;
        }
        entry_pools[pktIdBytes] = itemPool;
    }
    
    // 1) Find the "flow" w/ matching "flowId" or create a new one
    Flow* flow = static_cast<Flow*>(flow_list.Find(flowId, flowIdSize));
    if (NULL == flow)
    {
        // (TBD) should we keep a pool of Flows?
        if (NULL == (flow = new Flow(pkt_count_max)))
        {
            PLOG(PL_ERROR, "SmfDpdTable::IsDuplicate() new Flow error: %s\n", GetErrorString());
            return true;  // on failure, don't forward   
        }
        if (!flow->Init(flowId, flowIdSize))
        {
            PLOG(PL_ERROR, "SmfDpdTable::IsDuplicate() flow initialization error.\n");
            return false; // on failure, don't forward
        }   
        flow_list.Append(*flow);     
    }
    
    // 2) Given "flow", check for duplications
    return flow->IsDuplicate(currentTime, pktId, pktIdSize, itemPool);
    
}  // end SmfDpdTable::IsDuplicate()

SmfDpdTable::Flow::Flow(unsigned int pktCountMax)
    : pkt_count(0), pkt_count_max(pktCountMax)
{
}

SmfDpdTable::Flow::~Flow()
{
}

bool SmfDpdTable::Flow::Init(const char*    flowId,
                             unsigned int   flowIdSize) // in bits
{
    if (!SmfFlow::Init(flowId, flowIdSize))
    {
        PLOG(PL_ERROR, "SmfDpdTable::Flow::Init() SmfFlow initialization error\n");
        return false; 
    }
    return true;
}  // end SmfDpdTable::Flow::Init()

bool SmfDpdTable::Flow::IsDuplicate(unsigned int            currentTime,
                                    const char*             pktId,
                                    unsigned int            pktIdSize,
                                    ProtoTree::ItemPool*    itemPool)
{
    if (pkt_id_table.IsDuplicate(pktId, pktIdSize))
    {
        return true;
    }
    else
    {
        PacketIdEntry* entry;
        if ((pkt_count_max > 0) && (pkt_count >= pkt_count_max))
        {
            // This while loop may not be needed
            while (pkt_count > pkt_count_max)
            {
                entry = pkt_id_table.RemoveHead();
                if (NULL != itemPool)
                    itemPool->Put(*entry);
                else
                    delete entry;
                pkt_count--;
            }
            entry = pkt_id_table.RemoveHead();
            pkt_count--;
        }
        else
        {
            // Get an entry from the itemPool if availbe
            entry = (NULL != itemPool) ? 
                        static_cast<PacketIdEntry*>(itemPool->Get()) : 
                        NULL;
        }
        
        if (NULL == entry)
        {
            entry = new PacketIdEntry();
            if (NULL == entry)
            {
                PLOG(PL_ERROR, "SmfDpdTable::Flow::IsDuplicate() new PacketIdEntry error: %s\n",
                        GetErrorString());
                return true;  // on failure, don't forward
            }
            if (!entry->SetPktId(pktId, pktIdSize >> 3))
            {
                PLOG(PL_ERROR, "SmfDpdTable::Flow::IsDuplicate() new PacketIdEntry::SetPktId error: %s\n",
                        GetErrorString());
                return true;  // on failure, don't forward
            }
        }
        else
        {
            // "itemPool" is assumed to be for the given "pktIdSize"
            entry->SetPktId(pktId, pktIdSize >> 3);
        }
        pkt_id_table.Append(*entry, currentTime);
        pkt_count++;
        return false;   
    }
}  // end SmfDpdTable::Flow::IsDuplicate()

SmfDpdTable::PacketIdEntry::PacketIdEntry()
 : pkt_id(NULL)
{
}

SmfDpdTable::PacketIdEntry::~PacketIdEntry()
{
    if (NULL != pkt_id) 
    {
        delete[] pkt_id;
        pkt_id = NULL;
    }
}

bool SmfDpdTable::PacketIdEntry::SetPktId(const char* pktId, UINT8 pktIdLength)
{
    if (NULL == pkt_id)
    {
        if (NULL == (pkt_id = new UINT8[pktIdLength + 1]))
        {
            PLOG(PL_ERROR, "SmfDpdTable::PacketIdEntry::SetPktId() new pkt_id error: %s\n", GetErrorString());
            return false;
        }
        pkt_id[0] = pktIdLength;
    }
    ASSERT(pktIdLength == pkt_id[0]);
    memcpy(pkt_id + 1, pktId, pktIdLength);
    return true;
}  // end SmfDpdTable::PacketIdEntry::SetPktId()


SmfDpdTable::PacketIdTable::PacketIdTable()
 : head(NULL), tail(NULL)
{
}

SmfDpdTable::PacketIdTable::~PacketIdTable()
{
    id_tree.Empty();
    PacketIdEntry* nextEntry = head;
    while (NULL != nextEntry)
    {
        PacketIdEntry* entry = nextEntry;
        nextEntry = nextEntry->GetNext();
        delete entry;
    }   
}

void SmfDpdTable::PacketIdTable::Append(PacketIdEntry& entry, unsigned int currentTime)
{
    entry.SetArrivalTime(currentTime);
    entry.Append(NULL);
    if (NULL != tail)
    {
        tail->Append(&entry);
        tail = &entry;
    }   
    else
    {
        head = tail = &entry;
    }
    id_tree.Insert(entry);
}  // end SmfDpdTable::PacketIdTable::Append()

SmfDpdTable::PacketIdEntry* SmfDpdTable::PacketIdTable::RemoveHead()
{
    if (NULL != head)
    {
        PacketIdEntry* entry = head;
        head = entry->GetNext();
        id_tree.Remove(*entry);
        return entry;
    }
    return NULL;
}  // end SmfDpdTable::PacketIdTable::RemoveHead()

void SmfDpdTable::PacketIdTable::Prune(unsigned int           currentTime, 
                                       unsigned int           ageMax,
                                       ProtoTree::ItemPool**  poolArray)
{
    PacketIdEntry* next = head;
    while (NULL != next)
    {
        if (next->GetAge(currentTime) > ageMax)
        {
            PacketIdEntry* staleEntry = next;
            next = next->GetNext();
            id_tree.Remove(*staleEntry);
            if (NULL != poolArray)
            {
                ProtoTree::ItemPool* itemPool = poolArray[staleEntry->GetPktIdLength()];
                itemPool->Put(*staleEntry);
            }
            else
            {
                delete staleEntry;
            }
        }
        else
        {
            head = next;
            return;
        }
    }
    head = tail = NULL;  // everything was removed
}  // end SmfDpdTable::PacketIdTable::Prune()

void SmfDpdTable::PacketIdTable::EmptyToPool(ProtoTree::ItemPool** poolArray)
{
    PacketIdEntry* next = head;
    while (NULL != next)
    {
        PacketIdEntry* entry = next;
        next = next->GetNext();
        id_tree.Remove(*entry);
        ASSERT(NULL != poolArray[entry->GetPktIdLength()]);
        poolArray[entry->GetPktIdLength()]->Put(*entry); 
    }
    head = tail = NULL;
}  // end SmfDpdTable::PacketIdTable::EmptyToPool()


/////////////////////////////////////////////////////////////////////
// Window (sequence) based duplicate packet detection implementation


SmfDpdWindow::Flow::Flow()
{
}

SmfDpdWindow::Flow::~Flow()
{
    Destroy();
}

bool SmfDpdWindow::Flow::Init(const char*         flowId,
                              unsigned int        flowIdSize,     // in bits
                              UINT8               seqNumSize,     // in bits
                              UINT32              windowSize,     // in packets
                              UINT32              windowPastMax)  // in packets
{
    if (!SmfFlow::Init(flowId, flowIdSize))
    {
        PLOG(PL_ERROR, "SmfDpdWindow::Flow::Init() SmfFlow initialization error\n");
        return false; 
    }
    
    // Make sure all parameters are valid
    if ((seqNumSize < 8) || (seqNumSize > 32))
    {
        PLOG(PL_ERROR, "SmfDpdWindow::Flow::Init() error: invalid sequence number size: %d\n", seqNumSize);
        Destroy();
        return false;
	}
       
    if (windowSize > ((UINT32)0x01 << (seqNumSize - 1)))
    {
        PLOG(PL_ERROR, "SmfDpdWindow::Flow::Init() error: invalid windowSize\n");
        Destroy();
        return false;
    }
    
    if ((windowPastMax < windowSize) ||
        (windowPastMax > ((UINT32)0x01 << (seqNumSize - 1))))
    {
        PLOG(PL_ERROR, "SmfDpdWindow::Flow::Init() error: invalid windowPastMax value\n");
        Destroy();
        return false;
    }
    
    // Note seqRangeMask == sequence value max 
    UINT32 seqRangeMask = 0xffffffff >> (32 - seqNumSize);
    if (!bitmask.Init(windowSize, seqRangeMask))
    {
        PLOG(PL_ERROR, "SmfDpdWindow::Flow::Init() bitmask init error: %s\n", GetErrorString());
        Destroy();
        return false;
    }
    
    window_past_max = windowPastMax;
    
    return true;
    
}  // end SmfDpdWindow::Flow::Init()

bool SmfDpdWindow::Flow::IsDuplicate(UINT32 seq)
{    
    // Get the "lastSet" sequence (our current window "middle")
    UINT32 lastSet;
    if (bitmask.GetLastSet(lastSet))
    {
        // What region does this "seq" fall into
        // with respect to our "window" ?
        INT32 rangeSign = (INT32)bitmask.GetRangeSign();
        INT32 rangeMask = (INT32)bitmask.GetRangeMask();
        INT32 delta = seq - lastSet;
        delta = ((0 == (delta & rangeSign)) ? 
                        (delta & rangeMask) :
                        (((delta != rangeSign) || (seq < lastSet)) ? 
                            (delta | ~rangeMask) : delta));
        if (delta > 0)
        {
            // It's a "new" packet 
            INT32 bitmaskSize = bitmask.GetSize();
            if (delta < bitmaskSize) // "slide" the window as needed
            {
                UINT32 index = (lastSet - bitmaskSize + 1) & rangeMask;
                bitmask.UnsetBits(index, delta);
            }
            else  // It's beyond of our window range, so reset window
                bitmask.Clear();
            bitmask.Set(seq);
            return false;
        }
        else if (delta < 0)
        {
            // It's an "old" packet, so how old is it?
            delta = -delta;
            if ((unsigned int)delta < bitmask.GetSize())
            {
                // It's old, but in our window ...
               if (bitmask.Test(seq))
                   return true;
               else
                   bitmask.Set(seq);
               return false;
            }
            else if (delta < (INT32)window_past_max)
            {
                // It's "very old".
                // Newer behavior - assume it's not a duplicate and reset
                // (this presumes our window is big enough to catch old duplicates)
                // Our old behavior was to assume very old packets were duplicates
                bitmask.Clear();
                bitmask.Set(seq);
                return false;   
            } 
            else
            {
                // It's so very "ancient", we reset our window to it
                PLOG(PL_ERROR, "SmfDpdWindow::Flow::IsDuplicate() resetting window ...\n");
                bitmask.Clear();
                bitmask.Set(seq);
                return false;
            }
        }
        else
        {
            // It's a duplicate repeat of our lastSet
            return true;   
        }
    }
    else
    {
        // This is the first packet received  
        bitmask.Set(seq);
        return false;  // not a duplicate 
    }    
}  // end SmfDpdWindow::Flow::IsDuplicate()


SmfDpdWindow::SmfDpdWindow()
{
}

SmfDpdWindow::~SmfDpdWindow ()
{
    Destroy();
}

bool SmfDpdWindow::Init(UINT32 windowSize,       // in packets
                        UINT32 windowPastMax)    // in packets
{
    Destroy();
    if (windowPastMax < windowSize)
    {
        PLOG(PL_ERROR, "SmfDpdWindow::Init() error: invalid windowPastMax value\n");
        return false;
    }
    window_size = windowSize;
    window_past_max = windowPastMax;
    return true;
}  // end SmfDpdWindow::Init()

bool SmfDpdWindow::IsDuplicate(unsigned int   currentTime,
                               const char*    flowId,
                               unsigned int   flowIdSize,   // in bits
                               const char*    pktId,
                               unsigned int   pktIdSize)    // in bits  (must be <= 32)
{
    if (pktIdSize > 32)
    {
        PLOG(PL_ERROR,"SmfDpdWindow::IsDuplicate() warning: invalid pktIdSize:%u\n", pktIdSize);
        return true;
    }
    // Convert the "pktId" bits to a value stored in a UINT32 variable (sequence number)
    unsigned int pktIdValueLen = pktIdSize >> 3;
    if (0 != (pktIdSize & 0x07)) pktIdValueLen++;
    UINT32 pktIdValue = 0;
    memcpy(((char*)&pktIdValue) + (4 - pktIdValueLen), pktId, pktIdValueLen);
    pktIdValue = ntohl(pktIdValue);
    
    Flow* theFlow = static_cast<Flow*>(flow_list.Find(flowId, flowIdSize)); 
    if (NULL == theFlow) 
    {
        // (TBD) We should have a max number of entries in tree
        theFlow = new Flow();
        if (NULL == theFlow)
        {
            PLOG(PL_ERROR,"SmfDpdWindow::IsDuplicate() new Flow() error: %s\n",
                    GetErrorString());
            return true;  // returns true to be safe (but breaks forwarding)
        }
        // (TBD) set window_size_past properly
        if (!theFlow->Init(flowId, 
                           flowIdSize, 
                           pktIdSize, 
                           window_size, 
                           window_past_max))
        {
            PLOG(PL_ERROR,"SmfDpdWindow::IsDuplicate() SmfSlidingWindow::Flow::Init() error\n");
            delete theFlow;
            return true;  // returns true to be safe (but breaks forwarding)
        }
        // (TBD) we may want to set a cache limit
        // (max number of entries in flow_list/flow_tree)
        theFlow->SetUpdateTime(currentTime);
        flow_list.Append(*theFlow);
        theFlow->IsDuplicate(pktIdValue);
        return false;
    }  
    else 
    {
        // This check is for robustness, one could hope/assume that pktIdSize wouldn't change
        UINT32 pktIdMask = 0xffffffff >> (32 - pktIdSize);
        if (pktIdMask != theFlow->GetRangeMask())
        {
            PLOG(PL_ERROR,"SmfDpdWindow::IsDuplicate() warning: pktIdSize changed to %u\n", pktIdSize);
            return true;
        }
        else if (theFlow->IsDuplicate(pktIdValue))
        {
            return true;
        }
        else
        {
            // "Bubble up" fresh flow to head of list
            theFlow->SetUpdateTime(currentTime);
            flow_list.MoveToTail(*theFlow);
            return false;    
        }    
    }
}  // end SmfDpdWindow::IsDuplicate()

void SmfDpdWindow::Prune(unsigned int currentTime,
                         unsigned int ageMax)
{
    SmfFlow::Iterator iterator(flow_list);
    Flow* nextFlow;
    while (NULL != (nextFlow = static_cast<Flow*>(iterator.GetNextFlow())))
    {
        if (nextFlow->GetAge(currentTime) > ageMax)
        {
            flow_list.Remove(*nextFlow);
            delete nextFlow;
        }
        else
        {
            return;
        }
    }
}  // end SmfDpdWindow::Prune()

/////////////////////////////////////////////////////////////////////
//  Implementation of classes used for SMF resequencing functions

SmfSequenceMgr::SmfSequenceMgr()
 : seq_mask(0)
{
}

SmfSequenceMgr::~SmfSequenceMgr()
{
    Destroy();
}

bool SmfSequenceMgr::Init(UINT8 numSeqBits)
{
    seq_mask = 0xffffffff;
    if (numSeqBits < 32)
        seq_mask >>= (32 - numSeqBits);   
    return true; 
}  // end SmfSequenceMgr::Init()


UINT32 SmfSequenceMgr::GetSequence(const ProtoAddress* dstAddr, 
                                   const ProtoAddress* srcAddr) const
{
    char addrKey[32];  // big enough for up IPv6 src::dst concatenation
    unsigned int addrBits = 0;
    if (NULL != srcAddr)
    {
        addrBits = srcAddr->GetLength();
        memcpy(addrKey, srcAddr->GetRawHostAddress(), addrBits);
    }
    if (NULL != dstAddr)
    {
        unsigned int dstLen = dstAddr->GetLength();
        memcpy(addrKey+addrBits, dstAddr->GetRawHostAddress(), dstLen);
        addrBits += dstLen;
    }
    else
    {
        PLOG(PL_ERROR, "SmfSequenceMgr::IncrementSequence() warning: NULL dstAddr?!\n");
        ASSERT(0);
    }
    addrBits <<= 3;
    Flow* flow = static_cast<Flow*>(flow_list.Find(addrKey, addrBits));
    if (NULL != flow)
    {
        return flow->GetSequence();
    }
    else
    {
        PLOG(PL_ERROR, "SmfSequenceMgr::GetSequence() error: unknown flow!\n");
        return 0;
    }
        
}  // end SmfSequenceMgr::GetSequence()

UINT32 SmfSequenceMgr::IncrementSequence(unsigned int        updateTime,
                                         const ProtoAddress* dstAddr, 
                                         const ProtoAddress* srcAddr)
{
    char addrKey[32];  // big enough for up IPv6 src::dst concatenation
    unsigned int addrBits = 0;
    if (NULL != srcAddr)
    {
        addrBits = srcAddr->GetLength();
        memcpy(addrKey, srcAddr->GetRawHostAddress(), addrBits);
    }
    if (NULL != dstAddr)
    {
        unsigned int dstLen = dstAddr->GetLength();
        memcpy(addrKey+addrBits, dstAddr->GetRawHostAddress(), dstLen);
        addrBits += dstLen;
    }
    else
    {
        PLOG(PL_ERROR, "SmfSequenceMgr::IncrementSequence() warning: NULL dstAddr?!\n");
        ASSERT(0);
    }
    addrBits <<= 3;
    Flow* flow = static_cast<Flow*>(flow_list.Find(addrKey, addrBits));
    if (NULL == flow)
    {
        if (NULL == (flow = new Flow()))
        {
            PLOG(PL_ERROR, "SmfSequenceMgr::IncrementSequence() new Item error: %s\n", GetErrorString());
            return  (seq_global++ & seq_mask);
        }
        flow->Init(addrKey, addrBits);
        flow->SetSequence((UINT32)rand() & seq_mask);
        flow->SetUpdateTime(updateTime);
        flow_list.Append(*flow);
    }
    else
    {
        flow->SetUpdateTime(updateTime);
        flow_list.MoveToTail(*flow);
    }
    return flow->IncrementSequence(seq_mask);
}  // end SmfSequenceMgr::IncrementSequence()

void SmfSequenceMgr::Prune(unsigned int currentTime,
                           unsigned int ageMax)
{
    SmfFlow::Iterator iterator(flow_list);
    Flow* nextFlow;
    while (NULL != (nextFlow = static_cast<Flow*>(iterator.GetNextFlow())))
    {
        if (nextFlow->GetAge(currentTime) > ageMax)
        {
            flow_list.Remove(*nextFlow);
            delete nextFlow;
        }
        else
        {
            return;
        }
    }
}  // end SmfSequenceMgr::Prune()

SmfSequenceMgr::Flow::Flow()
{
}

SmfSequenceMgr::Flow::~Flow()
{
    Destroy();
}
