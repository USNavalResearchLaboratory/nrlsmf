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
 : queue_length(0)
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


        
