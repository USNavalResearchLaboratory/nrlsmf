#ifndef _ELASTIC_MSG
#define _ELASTIC_MSG

#include "protoPkt.h"
#include "protoPktIP.h"
#include "protoAddress.h"

// IMPORTANT NOTE:  This current ElasticAck message is an interim
// format that is being used to validate functionality of the 
// Elastic Routing extensions to "nrlsmf".  Eventually, a finalized
// message format (likely based on the RFC 5444 "PacketBB" specification)

// 
//       0                   1                   2                   3
//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |S|P|C|R| atype | ulen  | utype |  protocol   |  traffic class  |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                                                               |
//      +                       Destination Address                     +
//      |                                                               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                                                               |
//      +                         Source Address                        +
//      |                                                               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                                                               |
//      +                      Upstream Address List                    +
//      |                               ...                             |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// FLAGS:
//
// S        : source addr present (1 bit)
// P        : protocol type valid (1 bit)
// C        : traffic class valid (1 bit)
// R        : reserved flag (1 bit)
//
// atype    :  source/dest address type (4 bits)
// ulen     :  upstream address list length (4 bits)
// utype    :  upstream addresses type (4 bits)

// Flow specification
// protocol :   OPTIONAL IP protocol type (1 byte)
// class    :   OPTIONAL IP traffic class (1 byte)
// dst_addr :   Flow destination address (atype dependent)
// src_addr :   Flow source address   (atype dependent)
// ups_list :   Upstream address list (utype and ulen dependent)

// NOTE upstream address list items are 4-byte aligned

class ElasticAck : public ProtoPkt
{
    public:
        ElasticAck(UINT32*        bufferPtr = NULL, 
                   unsigned int   bufferBytes = 0, 
                   bool           freeOnDestruct = false);
        ~ElasticAck();
        
        static const ProtoAddress ELASTIC_ADDR;  // 224.0.0.55
        static const UINT16 ELASTIC_PORT;        // 5555
        
        enum AddressType
        {
            ADDR_INVALID = 0,
            ADDR_IPV4,
            ADDR_IPV6,
            ADDR_ETHER
        };
            
        enum Flag
        {
            FLAG_SOURCE     = 0x01,
            FLAG_PROTOCOL   = 0x02,
            FLAG_CLASS      = 0x04,
            FLAG_RESERVED   = 0x08
        };
            
        // Use these to parse    
        bool InitFromBuffer(UINT32*         bufferPtr = NULL, 
                            unsigned int    numBytes = 0, 
                            bool            freeOnDestruct = false);
        bool FlagIsSet(Flag flag)
            {return (0 != (flag & (GetUINT8(OFFSET_FLAGS) >> 4)));}
        
        AddressType GetAddressType() const
            {return ((AddressType)(GetUINT8(OFFSET_ATYPE) & 0x0f));}
        
        UINT8 GetUpstreamListLength() const
            {return (GetUINT8(OFFSET_ULEN) >> 4);}
        
        AddressType GetUpstreamListType() const
            {return ((AddressType)(GetUINT8(OFFSET_UTYPE) & 0x0f));}
        
        
        ProtoPktIP::Protocol GetProtocol() const
            {return ((ProtoPktIP::Protocol)GetUINT8(OFFSET_PROTOCOL));}
        UINT8 GetTrafficClass() const
            {return GetUINT8(OFFSET_CLASS);}
        bool GetDstAddr(ProtoAddress& dst) const;
        bool GetSrcAddr(ProtoAddress& addr) const;
        bool GetUpstreamAddr(UINT8 index, ProtoAddress& addr) const;
        
        // Use these to build (MUST call in order)
        bool InitIntoBuffer(UINT32*         bufferPtr = NULL, 
                            unsigned int    bufferBytes = 0, 
                            bool            freeOnDestruct = false);
        
        void SetProtocol(ProtoPktIP::Protocol protocol)
        {
            SetUINT8(OFFSET_PROTOCOL, (UINT8)protocol);
            SetFlag(FLAG_PROTOCOL);
        }
        void SetTrafficClass(UINT8 trafficClass)
        {
            SetUINT8(OFFSET_CLASS, trafficClass);
            SetFlag(FLAG_CLASS);
        }
        bool SetDstAddr(const ProtoAddress& addr);
        bool SetDstAddr(AddressType addrType, const char* addrPtr, unsigned int addrLen);
        bool SetSrcAddr(const ProtoAddress& addr);
        bool SetSrcAddr(AddressType addrType, const char* addrPtr, unsigned int addrLen);
        bool AppendUpstreamAddr(const ProtoAddress& addr);
        
    private:
        enum
        {
            OFFSET_FLAGS    = 0,                    // 4 most significant bits
            OFFSET_ATYPE    = OFFSET_FLAGS,         // 4 least significant bits
            OFFSET_ULEN     = OFFSET_ATYPE + 1,     // 4 most significant bits
            OFFSET_UTYPE    = OFFSET_ULEN,          // 4 least significant bits
            OFFSET_PROTOCOL = OFFSET_UTYPE + 1,     // UINT8 offset
            OFFSET_CLASS    = OFFSET_PROTOCOL + 1,  // UINT8 offset
            OFFSET_DST_ADDR = (OFFSET_CLASS/4) + 1  // UINT32 offset
        };
            
        unsigned int OffsetSrcAddr() const
        {
            // Returns UINT32 offset
            switch (GetAddressType())
            {
                case ADDR_IPV4:
                    return (OFFSET_DST_ADDR + 1);  // 1 32-bit word per addr
                case ADDR_IPV6:
                    return (OFFSET_DST_ADDR + 4);  // 4 32-bit words per addr
                default:
                    // TBD - allow for ADDR_ETHER?
                    return 0;
            }
        }
        
        unsigned int OffsetUpstreamList() const
        {
            // Returns UINT32 offset
            switch (GetAddressType())
            {
                case ADDR_IPV4:
                    return (OFFSET_DST_ADDR + 2);  // 1 32-bit word per addr (dst + src)
                case ADDR_IPV6:
                    return (OFFSET_DST_ADDR + 8);  // 4 32-bit words per addr (dst + src)
                default:
                    // TBD - allow for ADDR_ETHER?
                    return 0;
            }
        }
        
        static unsigned int GetAddressFieldLength(AddressType addrType);
        
        void SetFlag(Flag flag)
        {
            UINT8 field = GetUINT8(OFFSET_FLAGS);
            field |= (flag << 4);
            SetUINT8(OFFSET_FLAGS, field);
        }
};  // end class ElasticAck



#endif // !_ELASTIC_MSG
