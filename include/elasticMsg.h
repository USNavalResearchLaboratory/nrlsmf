#ifndef _ELASTIC_MSG
#define _ELASTIC_MSG

#include "protoPkt.h"
#include "protoPktIP.h"
#include "protoAddress.h"


// This is a base class so that the different message types can
// inherit some common enums and type definitions

// ElasticMsg types can be bundled with each message having a common
// type-length message header ...
//
//       0               1               2               3               
//       0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |   Msg Type    |    Msg Len    |        ...
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

class ElasticMsg : public ProtoPkt
{
    public:
        ElasticMsg(void*          bufferPtr = NULL,
                   unsigned int   bufferBytes = 0,
                   bool           initFromBuffer = true,
                   bool           freeOnDestruct = false);
        ~ElasticMsg();
        
        static const ProtoAddress ELASTIC_ADDR;  // 224.0.0.55
        static const ProtoAddress ELASTIC_MAC;   // ethernet MAC for ELASTIC_ADDR
        static const UINT16 ELASTIC_PORT;        // 5555
        static const ProtoAddress ELASTIC_ASYM_ADDR;  // 224.55.55.55
        static const ProtoAddress ELASTIC_ASYM_MAC;   // ethernet MAC for ELASTIC_ASYM_ADDR
        static const UINT8 DEFAULT_ASYM_TTL;          // 8
        
        enum Type
        {
            MSG_INVALID = 0,
            ACK,
            ADV,
            NACK
        };
            
        // Flow description address types and flags
        enum AddressType
        {
            ADDR_INVALID = 0,
            ADDR_IPV4,
            ADDR_IPV6,
            ADDR_ETH
        };

        enum Flag
        {
            FLAG_SOURCE     = 0x01,
            FLAG_PROTOCOL   = 0x02,
            FLAG_CLASS      = 0x04,
            FLAG_RESERVED   = 0x08
        };   
            
        void SetType(Type msgType)
            {SetUINT8(OFFSET_TYPE, (UINT8)msgType);}
        void SetMsgLength(unsigned int numBytes)
        {
            SetUINT8(OFFSET_LENGTH, (UINT8)(numBytes >> 2));
            ProtoPkt::SetLength(numBytes);
        }
        
        // Use these to parse    
        bool InitFromBuffer(void*           bufferPtr = NULL, 
                            unsigned int    numBytes = 0, 
                            bool            freeOnDestruct = false);
        Type GetType() const
            {return (Type)GetUINT8(OFFSET_TYPE);}
        unsigned int GetMsgLength() const
            {return ((unsigned int)GetUINT8(OFFSET_LENGTH)) << 2;}
        
           
    protected:
        enum
        {
            OFFSET_TYPE = 0,  // one byte, UINT7 offset
            OFFSET_LENGTH = OFFSET_TYPE+1
        };
                
};  // end class ElasticMsg

// IMPORTANT NOTE:  This current ElasticAck message is an interim
// format that is being used to validate functionality of the
// Elastic Routing extensions to "nrlsmf".  Eventually, a finalized
// message format (likely based on the RFC 5444 "PacketBB" specification)

//
//       0               1               2               3               
//       0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      | Msg Type = 1  |    Msg Len    |            reserved           |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |S|P|C|R| atype | ulen  | utype |    protocol   | traffic class |
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

// NOTE upstream address list items are 4-byte aligned so padding may be required (e.g., ADDR_ETH)


class ElasticAck : public ElasticMsg
{
    public:
        ElasticAck(void*          bufferPtr = NULL,
                   unsigned int   bufferBytes = 0,
                   bool           initFromBuffer = true,
                   bool           freeOnDestruct = false);
        ElasticAck(ElasticMsg& elasticMsg);
        ~ElasticAck();
            
        // Use these to parse    
        bool InitFromBuffer(void*           bufferPtr = NULL, 
                            unsigned int    numBytes = 0, 
                            bool            freeOnDestruct = false);
        bool FlagIsSet(Flag flag) const
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
        bool InitIntoBuffer(void*           bufferPtr = NULL, 
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
            OFFSET_RESERVED = OFFSET_LENGTH + 1,    // UINT8 offset
            OFFSET_FLAGS    = OFFSET_RESERVED + 2,  // 4 most significant bits
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
                case ADDR_ETH:
                    return (OFFSET_DST_ADDR + 2);  // 6 bytes addr + 2 bytes padding
                default:
                    return OFFSET_DST_ADDR;
            }
        }
        
        unsigned int OffsetUpstreamList() const
        {
            // Returns UINT32 offset
            unsigned offset = OffsetSrcAddr();
            if (!FlagIsSet(FLAG_SOURCE)) return offset;
            switch (GetAddressType())
            {
                case ADDR_IPV4:
                    return offset + 1;  // 1 32-bit word per addr
                case ADDR_IPV6:
                    return offset + 4;  // 4 32-bit words per addr 
                case ADDR_ETH:
                    return offset + 2;  // 3 bytes addr + 1 byte padding
                default:
                    return offset;
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


// Elastic ADV message flow item
//
//       0             1               2               3               4
//       0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      | Msg Type = 2  |    Msg Len    |          DPD ID               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |S|P|C|G| atype | ulen  | utype |    protocol   | traffic class |
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
//      +                      [Advertiser Address]                     +
//      |                              ...                              |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// FLAGS:
//
// S        : source addr present (1 bit)
// P        : protocol type valid (1 bit)
// C        : traffic class valid (1 bit)
// R        : reserved flag (1 bit)


// ElasticNack Message - to support hop-by-hop reliability ARQ
// (This is a _preliminary_ definition.  Longer-term will allow
//  for a sliding window Selective ARQ of some type)
//
//       0               1               2               3               
//       0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      | Msg Type = 3  |    Msg Len    |        reserved       | utype |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                       Upstream Address                        |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |          Seq Start            |        Seq Stop               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


class ElasticNack : public ElasticMsg
{
    public:
        ElasticNack(void*          bufferPtr = NULL,
                    unsigned int   bufferBytes = 0,
                    bool           initFromBuffer = true,
                    bool           freeOnDestruct = false);
        ElasticNack(ElasticMsg& elasticMsg);
        ~ElasticNack();
            
        bool InitIntoBuffer(void*           bufferPtr = NULL, 
                            unsigned int    bufferBytes = 0, 
                            bool            freeOnDestruct = false);
        bool SetUpstreamAddress(const ProtoAddress& addr);
        void SetSeqStart(UINT16 seq)
            {SetWord16(OffsetSeqStart(), seq);}
        void SetSeqStop(UINT16 seq)
            {SetWord16(OffsetSeqStop(), seq);}
        
        // Note: use ElasticMsg::InitFromBuffer() when needed
        AddressType GetAddressType() const
            {return (AddressType)(GetUINT8(OFFSET_UTYPE) & 0x0f);}
        bool GetUpstreamAddress(ProtoAddress& addr) const;
        UINT16 GetSeqStart() const
            {return GetWord16(OffsetSeqStart());}
        UINT16 GetSeqStop() const
            {return GetWord16(OffsetSeqStop());}
            
    private:
        enum
        {
            OFFSET_RESERVED = OFFSET_LENGTH + 1,    // UINT8 offset
            OFFSET_UTYPE = OFFSET_RESERVED + 1,     // UINT8 offset
            OFFSET_UPSTREAM = (OFFSET_UTYPE + 1)/4, // UINT32 offset
        };
            
        unsigned int OffsetSeqStart() const
        {
            // returns UINT16 offset
            unsigned int offset = OFFSET_UPSTREAM << 1;
            // Returns UINT32 offset
            switch (GetAddressType())
            {
                case ADDR_IPV4:
                    return offset + 2; // 2 16-bit words per addr
                case ADDR_IPV6:
                    return offset + 8;  // 8 16-bit words per addr
                case ADDR_ETH:
                    return offset + 4;  // 3 16-bit words per addr + 1 pad
                default:
                    return offset;
            }
        }
        unsigned int OffsetSeqStop() const
            {return (OffsetSeqStart() + 1);}
        
};  // end class ElasticNack

#endif // !_ELASTIC_MSG
