#include "smfQueue.h"

SmfQueueBase::SmfQueueBase(const ProtoAddress&  dst, 
                           const ProtoAddress&  src,
                           ProtoPktIP::Protocol proto,
                           UINT8                trafficClass)
 : queue_limit(0), queue_length(0)
{
    flow_id_size = BuildKey(flow_id, dst, src, proto, trafficClass);
}

SmfQueueBase::~SmfQueueBase()
{
}

unsigned int SmfQueueBase::BuildKey(char* keyBuffer,  // must be sized at least 2*16 + 2 (IPv6 addr worst case)
                                    const ProtoAddress&  src, 
                                    const ProtoAddress&  dst,
                                    ProtoPktIP::Protocol proto,
                                    UINT8                trafficClass)
{
    unsigned int len = 0;
    if (dst.IsValid())
    {
        unsigned int alen = dst.GetLength();
        memcpy(keyBuffer, dst.GetRawHostAddress(), alen);
        len = alen;
    }
    if (src.IsValid())
    {
        unsigned int alen = src.GetLength();
        memcpy(keyBuffer + len, src.GetRawHostAddress(), src.GetLength());
        len += alen;
    }
    if (ProtoPktIP::RESERVED != proto)
        keyBuffer[len++] = (char)proto;
    if (255 != trafficClass)
        keyBuffer[len++] = (char)trafficClass;
    return (len << 3);
}  // end SmfQueueBase::BuildKey()

// The methods here implement a FIFO queue with two levels of 
// priority.  The "priority_index" is the current "Last Out"
// packet of the higher priority. (Note a high priority packet
// can push a lower one out if there is a queue limit)
// (TBD - support an arbitrary number of priority levels)
bool SmfQueue::EnqueuePacket(SmfPacket& pkt, bool prioritize, SmfPacket::Pool* pool)
{
    if (prioritize)
    {
        if ((queue_limit >= 0) && (queue_length >= (unsigned int)queue_limit))
        {
            if (GetHead() != priority_index)
            {
                // priority packet will bump non-priority packet
                SmfPacket* drop = RemoveHead();
                queue_length--;
                if (NULL != pool)
                    pool->Put(*drop);
                else
                    delete drop;
            }
            else
            {
                // full of priority packets
                return false;
            }
        }   
        if (NULL != priority_index)
        {
            Insert(pkt, *priority_index);
            priority_index = &pkt;
        }
        else
        {
            Append(pkt);
            priority_index = &pkt;
        }
    }
    else if ((queue_limit < 0) || (queue_length < (unsigned int)queue_limit))
    {
        Prepend(pkt);
    }
    else
    {
        return false;
    }
    queue_length++;
    return true;
}  // end SmfQueue::EnqueuePacket()

SmfPacket* SmfQueue::PreviewPacket()
{
    return GetTail();
}  // end SmfQueue::PreviewPacket()

SmfPacket* SmfQueue::DequeuePacket()
{
    SmfPacket* pkt = RemoveTail();
    if (NULL == pkt)
        return NULL;
    else if (priority_index == pkt)
        priority_index = NULL;  // was last priority pkt
    queue_length--;
    return pkt;
}  // end SmfQueue::DequeuePacket()

void SmfQueue::EmptyToPool(SmfPacket::Pool& pool)
{
    SmfQueue::Iterator iterator(*this);
    SmfPacket* pkt;
    while (NULL != (pkt= iterator.GetNextItem()))
    {
        Remove(*pkt);
        pool.Put(*pkt);
    }
    queue_length = 0;
}  // end SmfQueue::EmptyToPool()

bool SmfCache::EnqueuePacket(SmfIndexedPacket& pkt)
{
    if ((queue_limit < 0) || (queue_length < (unsigned int)queue_limit))
    {
        if (NULL == oldest_pkt) oldest_pkt = &pkt;
        Insert(pkt);
        queue_length++;
        return true;
    }
    else
    {
        return false;
    }
}  // end SmfCache::EnqueuePacket()

void SmfCache::RemovePacket(SmfIndexedPacket& pkt)
{
    if (&pkt == oldest_pkt)
    {
        DequeuePacket();
    }
    else
    {
        Remove(pkt);
        queue_length--;
    }
}  // end  SmfCache::RemovePacket()

SmfIndexedPacket* SmfCache::DequeuePacket()
{
    // Remove "oldest_pkt" and point it to next oldest
    SmfIndexedPacket* pkt = oldest_pkt;
    if (NULL != pkt)
    {
        Iterator iterator(*this, false, oldest_pkt);
        oldest_pkt = iterator.GetNextItem();
        Remove(*pkt);
        queue_length--;
        if (NULL == oldest_pkt)
        {
            iterator.Reset();
            oldest_pkt = iterator.GetNextItem();
        }   
    }
    return pkt;
}  // end SmfCache::DequeuePacket()

void SmfCache::EmptyToPool(SmfIndexedPacket::Pool& pool)
{
    Iterator iterator(*this);
    SmfIndexedPacket* pkt;
    while (NULL != (pkt= iterator.GetNextItem()))
    {
        Remove(*pkt);
        pool.Put(*pkt);
    }
    queue_length = 0;
}  // end SmfCache::EmptyToPool()
