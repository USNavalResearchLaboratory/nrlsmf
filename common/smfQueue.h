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


class SmfQueue : public ProtoListTemplate<SmfPacket>, public ProtoTree::Item
{
    public:
        SmfQueue(const ProtoAddress&  dst, 
                 const ProtoAddress&  src,
                 ProtoPktIP::Protocol proto = ProtoPktIP::RESERVED,
                 UINT8                trafficClass = 255);             
        ~SmfQueue();
        
        void EmptyToPool(SmfPacket::Pool& pktPool);
        
    private:
        const char* GetKey() const
            {return flow_id;}
        unsigned int GetKeysize() const
            {return flow_id_size;}
        
        char            flow_id[2*16 + 2];  // sized for IPv6 (worst case)
        unsigned int    flow_id_size;
        unsigned int    queue_length;       // in bytes? 
        
};  // end class SmfQueue

class SmfQueueList : public ProtoTreeTemplate<SmfQueue>
{
    public:
        SmfQueueList();
        ~SmfQueueList();
        
        SmfQueue* FindQueue(const ProtoAddress&  dst, 
                            const ProtoAddress&  src,
                            ProtoPktIP::Protocol proto = ProtoPktIP::RESERVED,
                            UINT8                trafficClass = 255);
        
};  // end class SmfQueueList


#endif // _SMF_QUEUE
