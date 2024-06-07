#ifndef _SMF_QUEUE
#define _SMF_QUEUE

#include <protoTree.h>
#include <protoAddress.h>
#include <protoPktIP.h>
#include <protoTime.h>

// Per-flow packet queuing classes

template <class ITEM_TYPE>
class SmfPacketTemplate : public ITEM_TYPE
{
    public:
        enum {PKT_SIZE_MAX = 2048};
    
        SmfPacketTemplate() : pkt_length(0) {}
        ~SmfPacketTemplate() {}
        
        UINT32* AccessBuffer()
            {return pkt_buffer;}
        void SetLength(unsigned int length)
            {pkt_length = length;}
        
        const UINT32* GetBuffer() const
            {return pkt_buffer;}
        unsigned int GetLength() const
            {return pkt_length;}
    
    private:
        // We make the packet an extra few bytes so we can align
        // ProtoPktETH and ProtoPktIP into the same buffer here as needed
        UINT32       pkt_buffer[PKT_SIZE_MAX/sizeof(UINT32) + 1];
        unsigned int pkt_length;
       
};  // end class SmfPacketTemplate

class SmfQueueBase : public ProtoTree::Item
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
        SmfQueueBase(const ProtoAddress&  dst = PROTO_ADDR_NONE, 
                     const ProtoAddress&  src = PROTO_ADDR_NONE,
                     ProtoPktIP::Protocol proto = ProtoPktIP::RESERVED,
                     UINT8                trafficClass = 255);             
        virtual ~SmfQueueBase();
        
        void SetQueueLimit(int limit)
            {queue_limit = limit;}
        int GetQueueLimit() const
            {return queue_limit;}
        
        unsigned int GetQueueLength() const
            {return queue_length;}
        
        bool IsFull() const
            {return ((queue_limit > 0) ? (queue_length >= (unsigned int)queue_limit) : false);}
        
        static unsigned int BuildKey(char* keyBuffer,  // must be sized at least 2*16 + 2 (IPv6 addr worst case)
                                     const ProtoAddress&  src, 
                                     const ProtoAddress&  dst,
                                     ProtoPktIP::Protocol proto,
                                     UINT8                trafficClass);
    protected:
        const char* GetKey() const
            {return flow_id;}
        unsigned int GetKeysize() const
            {return flow_id_size;}
        
        char                  flow_id[2*16 + 2];  // sized for IPv6 (worst case)
        unsigned int          flow_id_size;
        int                   queue_limit;        // -1 is no limit (default), 0 is no queuing
        unsigned int          queue_length;       // in bytes? 
        
};  // end class SmfQueueBase

template <class QUEUE_TYPE>
class SmfQueueTableTemplate : public ProtoTreeTemplate<QUEUE_TYPE>
{
    public:
        SmfQueueTableTemplate() {}
        ~SmfQueueTableTemplate() {ProtoTreeTemplate<QUEUE_TYPE>::Destroy();} // deletes all the queues
        
        void InsertQueue(QUEUE_TYPE& queue)
            {Insert(queue);}
        
        QUEUE_TYPE* FindQueue(const ProtoAddress&  dst = PROTO_ADDR_NONE,
                              const ProtoAddress&  src = PROTO_ADDR_NONE,
                              ProtoPktIP::Protocol proto = ProtoPktIP::RESERVED,
                              UINT8                trafficClass = 255) const
        {
            char key[2*16 + 2];
            unsigned int keysize = SmfQueueBase::BuildKey(key, src, dst, proto, trafficClass);
            return ProtoTreeTemplate<QUEUE_TYPE>::Find(key, keysize);
        }
        
        void RemoveQueue(QUEUE_TYPE& queue)
            {Remove(queue);}
        
};  // end class SmfQueueTableTemplate

class SmfPacket : public SmfPacketTemplate<ProtoList::Item> 
{
    public:
        class Pool : public ProtoListTemplate<SmfPacket>::ItemPool
        {
            public:
                // This gets packet from pool or allocates one as needed
                // TBD - add a pool depth limit ???
                SmfPacket* GetPacket();
        };
};  // end class SmfPacket

class SmfQueue : public SmfQueueBase, public ProtoListTemplate<SmfPacket>
{
    public:
        ~SmfQueue() {Destroy();} // deletes all enqueued packets
        bool EnqueuePacket(SmfPacket& pkt, bool prioritize = false, SmfPacket::Pool* pool = NULL);
        SmfPacket* DequeuePacket();
        SmfPacket* PreviewPacket();
        
        void EmptyToPool(SmfPacket::Pool& pool);
        
    private:
        SmfPacket*            priority_index;
       
};  // end class SmfQueue

class SmfQueueTable : public SmfQueueTableTemplate<SmfQueue> {};


// These class are used for cacheing indexed (by sequence number) packets
// for potential retransmission

class SmfIndexedPacket : public SmfPacketTemplate<ProtoTree::Item>
{
    public:
        void SetIndex(UINT16 seq)
            {pkt_index = seq;}
        UINT16 GetIndex() const
            {return pkt_index;}
        
        void SetTimestamp(const ProtoTime& timestamp)
            {pkt_timestamp = timestamp;}
        const ProtoTime GetTimestamp() const
            {return pkt_timestamp;}
        
        class Pool : public ProtoTreeTemplate<SmfIndexedPacket>::ItemPool {};
        
        ProtoTree::Endian GetEndian() const 
            {return ProtoTree::GetNativeEndian();}
        
    private:
        const char* GetKey() const
            {return (char*)&pkt_index;}      
        unsigned int GetKeysize() const
            {return sizeof(UINT16) << 3;}
            
        UINT16      pkt_index;
        ProtoTime   pkt_timestamp;
};  // end class SmfIndexedPacket

class SmfCache : public SmfQueueBase, public ProtoTreeTemplate<SmfIndexedPacket>
{
    public:
        SmfCache(const ProtoAddress&  dst = PROTO_ADDR_NONE, 
                 const ProtoAddress&  src = PROTO_ADDR_NONE,
                 ProtoPktIP::Protocol proto = ProtoPktIP::RESERVED,
                 UINT8                trafficClass = 255)
              : SmfQueueBase(dst, src, proto, trafficClass), oldest_pkt(NULL), user_data(NULL) {}
        ~SmfCache() {}
        
        bool EnqueuePacket(SmfIndexedPacket& pkt);
            
        SmfIndexedPacket* FindPacket(UINT16 index)
            {return Find((char*)&index, sizeof(UINT16) << 3);}
        
        SmfIndexedPacket* DequeuePacket();  // removes/returns oldest
        
        void RemovePacket(SmfIndexedPacket& pkt);
    
        void SetUserData(void* userData)
            {user_data = userData;}
        void* GetUserData() const
            {return user_data;}    
        
        void EmptyToPool(SmfIndexedPacket::Pool& pool);
    
    private:
        SmfIndexedPacket*   oldest_pkt;
        void*               user_data;
};  // end class SmfIndexedQueue


class SmfCacheTable : public SmfQueueTableTemplate<SmfCache> {};



#endif // _SMF_QUEUE
