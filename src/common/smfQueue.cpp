#include "smfQueue.h"

SmfPacket::SmfPacket()
 : pkt_length(0)
{
}

SmfPacket::~SmfPacket()
{
}

SmfQueue::SmfQueue(const ProtoAddress&  dst, 
                   const ProtoAddress&  src,
                   ProtoPktIP::Protocol proto,
                   UINT8                trafficClass)
 : queue_limit(0), queue_length(0), priority_index(NULL)
{
    unsigned int len = 0;
    if (dst.IsValid())
    {
        unsigned int alen = dst.GetLength();
        memcpy(flow_id, dst.GetRawHostAddress(), alen);
        len = alen;
    }
    if (src.IsValid())
    {
        unsigned int alen = src.GetLength();
        memcpy(flow_id + len, src.GetRawHostAddress(), src.GetLength());
        len += alen;
    }
    if (ProtoPktIP::RESERVED != proto)
        flow_id[len++] = (char)proto;
    if (255 != trafficClass)
        flow_id[len++] = (char)trafficClass;
    flow_id_size = len << 3;
}

SmfQueue::~SmfQueue()
{
}

// The methods here implement a FIFO queue with two levels of 
// priority.  The "priority_index" is the current "Last Out"
// packet of the higher priority. (Note a high priority packet
// can push a lower one out if there is a queue limit)
bool SmfQueue::EnqueuePacket(SmfPacket& pkt, bool prioritize, SmfPacket::Pool* pool)
{
    if (prioritize)
    {
        if ((queue_limit >= 0) && (queue_length >= queue_limit))
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
    else if ((queue_limit < 0) || (queue_length < queue_limit))
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


////////////////////////////////////
// SmfQueueList implementation
//
SmfQueueList::SmfQueueList()
{
}

SmfQueueList::~SmfQueueList()
{
    // TBD -empty queues to pool?
    Destroy();
}

SmfQueue* SmfQueueList::FindQueue(const ProtoAddress&  src, 
                                  const ProtoAddress&  dst,
                                  ProtoPktIP::Protocol proto,
                                  UINT8                trafficClass)
{
    char keyBuffer[2*16 + 2];  // sized for IPv6 addr (worst case)
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
    return Find(keyBuffer, len << 3);
}  // end SmfQueueList::FindQueue()


        
