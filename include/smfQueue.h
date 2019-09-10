#ifndef _SMF_QUEUE
#define _SMF_QUEUE

//#include <protoList.h>

#include <protoTree.h>

#include <protoAddress.h>

#include <protoPktIP.h>

// Per-flow packet queuing classes

class SmfPacket : public ProtoList::Item
{
    public:
        enum {PKT_SIZE_MAX = 2048};
    
        SmfPacket();
        ~SmfPacket();
        
        UINT32* AccessBuffer()
            {return pkt_buffer;}
        void SetLength(unsigned int length)
            {pkt_length = length;}
        
        const UINT32* GetBuffer() const
            {return pkt_buffer;}
        unsigned int GetLength() const
            {return pkt_length;}
        
        class Pool : public ProtoListTemplate<SmfPacket>::ItemPool {};
    
    private:
        // We make the packet an extra few bytes so we can align
        // ProtoPktETH and ProtoPktIP into the same buffer here as needed
        UINT32       pkt_buffer[PKT_SIZE_MAX/sizeof(UINT32) + 1];
        unsigned int pkt_length;
        
};  // end class SmfPacket


class SmfQueue : protected ProtoListTemplate<SmfPacket>, public ProtoTree::Item
{
    public:
        typedef int Mode;  // mode identified by set of flags
        enum ModeFlags
        {
            FLAG_MAC    = 0x01, // use MAC src/dst instead of IP
            FLAG_DST    = 0x02, // use dst addr for flow classification
            FLAG_DPORT  = 0x04, // use dst port (if applicable) for flow classification
            FLAG_SRC    = 0x08, // use src addr for flow classification
            FLAG_SPORT  = 0x10, // use src port (if applicable) for flow classification
            FLAG_PROTO  = 0x20, // use IP protocol (if applicable) for flass classification
            FLAG_CLASS  = 0x40  // use IP traffic class for flow classification
        };    
            
        // The default params here define a mode zero (no classification) queue
        SmfQueue(const ProtoAddress&  dst = PROTO_ADDR_NONE, 
                 const ProtoAddress&  src = PROTO_ADDR_NONE,
                 ProtoPktIP::Protocol proto = ProtoPktIP::RESERVED,
                 UINT8                trafficClass = 255);             
        ~SmfQueue();
        
        void SetQueueLimit(int limit)
            {queue_limit = limit;}
        int GetQueueLimit() const
            {return queue_limit;}
        
        unsigned int GetQueueLength() const
            {return queue_length;}
        
        bool EnqueuePacket(SmfPacket& pkt, bool prioritize = false, SmfPacket::Pool* pool = NULL);
        SmfPacket* DequeuePacket();
        SmfPacket* PreviewPacket();
        
        bool IsEmpty() const
            {return ProtoList::IsEmpty();}
        bool IsFull() const
            {return ((queue_limit > 0) ? (queue_length >= queue_limit) : false);}
        
        void EmptyToPool(SmfPacket::Pool& pktPool);
        
    private:
        const char* GetKey() const
            {return flow_id;}
        unsigned int GetKeysize() const
            {return flow_id_size;}
        
        char            flow_id[2*16 + 2];  // sized for IPv6 (worst case)
        unsigned int    flow_id_size;
        int             queue_limit;        // -1 is no limit (default), 0 is no queuing
        unsigned int    queue_length;       // in bytes? 
        SmfPacket*      priority_index;
        
};  // end class SmfQueue


class SmfQueueList : public ProtoTreeTemplate<SmfQueue>
{
    public:
        SmfQueueList();
        ~SmfQueueList();
        
        SmfQueue* FindQueue(const ProtoAddress&  dst = PROTO_ADDR_NONE,
                            const ProtoAddress&  src = PROTO_ADDR_NONE,
                            ProtoPktIP::Protocol proto = ProtoPktIP::RESERVED,
                            UINT8                trafficClass = 255);
        
};  // end class SmfQueueList


#endif // _SMF_QUEUE
