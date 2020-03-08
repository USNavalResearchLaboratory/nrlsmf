
#include "elasticMsg.h"

ElasticMsg::ElasticMsg(void*        bufferPtr,
                       unsigned int bufferBytes,
                       bool         initFromBuffer,
                       bool         freeOnDestruct)
  : ProtoPkt(bufferPtr, bufferBytes, freeOnDestruct)  
{
    if (initFromBuffer && (NULL != bufferPtr))
        InitFromBuffer();
}

ElasticMsg::~ElasticMsg() 
{
}
              
bool ElasticMsg::InitFromBuffer(void*        bufferPtr, 
                                unsigned int numBytes, 
                                bool         freeOnDestruct)
{
    if (NULL != bufferPtr) 
        AttachBuffer(bufferPtr, numBytes, freeOnDestruct);
    else
        ProtoPkt::SetLength(0);
    if (GetBufferLength() > OFFSET_LENGTH)
    {
        unsigned int len = GetMsgLength();
        if (len > GetBufferLength())
        {
            PLOG(PL_ERROR, "ElasticMsg::InitFromBuffer() error: insufficient buffer size\n");
            return false;
        }
        ProtoPkt::SetLength(len);
    }
    else
    {
        PLOG(PL_ERROR, "ElasticMsg::InitFromBuffer() error: insufficient buffer size\n");
        return false;
    }
    return true;
}  // end ElasticMsg::InitFromBuffer()

///////////////////////////////////////////////////////////////////////////////////
// class ElasticAck implementation
// methods for building and parsing Elastic Multicast ACK packets
//

const ProtoAddress ElasticMsg::ELASTIC_ADDR = ProtoAddress("224.0.0.55");
const ProtoAddress ElasticMsg::ELASTIC_MAC = ProtoAddress().GetEthernetMulticastAddress(ELASTIC_ADDR);
const ProtoAddress ElasticMsg::ELASTIC_ASYM_ADDR = ProtoAddress("224.55.55.55");
const ProtoAddress ElasticMsg::ELASTIC_ASYM_MAC = ProtoAddress().GetEthernetMulticastAddress(ELASTIC_ASYM_ADDR);
const UINT16 ElasticMsg::ELASTIC_PORT = 5555;
const UINT8 ElasticMsg::DEFAULT_ASYM_TTL = 8;

        
ElasticAck::ElasticAck(void*          bufferPtr, 
                       unsigned int   bufferBytes, 
                       bool           initFromBuffer,
                       bool           freeOnDestruct)
 : ElasticMsg(bufferPtr, bufferBytes, false, freeOnDestruct)
{
    if (NULL != bufferPtr) 
    {
        if (initFromBuffer)
            InitFromBuffer();
        else
            InitIntoBuffer();
    }
}

ElasticAck::ElasticAck(ElasticMsg& elasticMsg)
{
    InitFromBuffer(elasticMsg.AccessBuffer(), elasticMsg.GetBufferLength());
}


ElasticAck::~ElasticAck()
{
}

unsigned int ElasticAck::GetAddressFieldLength(AddressType addrType)
{
    switch (addrType)
    {
        case ADDR_IPV4:
            return 4;
        case ADDR_IPV6:
            return 16;
        case ADDR_ETH:
            return 8; // includes padding
        default:
            return 0;
    }
}  // end ElasticAck::GetAddressFieldLength()

bool ElasticAck::InitFromBuffer(void*           bufferPtr, 
                                unsigned int    numBytes, 
                                bool            freeOnDestruct)
{
    if (NULL != bufferPtr) 
        AttachBuffer(bufferPtr, numBytes, freeOnDestruct);
    else
        ProtoPkt::SetLength(0);
    if (GetBufferLength() >= OFFSET_CLASS)
    {
        unsigned int len = GetMsgLength();
        if (len <= GetBufferLength())
        {
            ProtoPkt::SetLength(len);
            return true;
        }
        PLOG(PL_ERROR, "ElasticMsg::InitFromBuffer() error: insufficient buffer size\n");
    }
    if (NULL != bufferPtr) DetachBuffer();
    return false;
}  // end ElasticAck::InitFromBuffer()

bool ElasticAck::GetDstAddr(ProtoAddress& addr) const
{
    ProtoAddress::Type addrType;
    unsigned int addrLen;
    switch (GetAddressType())
    {
        case ADDR_IPV4:
            addrType = ProtoAddress::IPv4;
            addrLen = 4;
            break;
        case ADDR_IPV6:
            addrType = ProtoAddress::IPv6;
            addrLen = 16;
            break;
        case ADDR_ETH:
            addrType = ProtoAddress::ETH;
            addrLen = 6;
            break;
        default:
            PLOG(PL_ERROR, "ElasticAck::GetDstAddr() error: invalid address type!\n");
            return false;
    }
    return addr.SetRawHostAddress(addrType, (char*)GetBuffer32(OFFSET_DST_ADDR), addrLen);
}  // end ElasticAck::GetDstAddr()

bool ElasticAck::GetSrcAddr(ProtoAddress& addr) const
{
    ProtoAddress::Type addrType;
    unsigned int addrLen;
    switch (GetAddressType())
    {
        case ADDR_IPV4:
            addrType = ProtoAddress::IPv4;
            addrLen = 4;
            break;
        case ADDR_IPV6:
            addrType = ProtoAddress::IPv6;
            addrLen = 16;
            break;
        case ADDR_ETH:
            addrType = ProtoAddress::ETH;
            addrLen = 6;
            break;
        default:
            PLOG(PL_ERROR, "ElasticAck::GetDstAddr() error: invalid address type!\n");
            return false;
    }
    return addr.SetRawHostAddress(addrType, (const char*)GetBuffer32(OffsetSrcAddr()), addrLen);
}  // end ElasticAck::GetSrcAddr()

bool ElasticAck::GetUpstreamAddr(UINT8 index, ProtoAddress& addr) const
{
    if (index >= GetUpstreamListLength())
    {
        PLOG(PL_ERROR, "ElasticAck::GetUpstreamAddr() error: out-of-bounds index!\n");
        return false;
    } 
    ProtoAddress::Type addrType;
    unsigned int addrLen, fieldLen;
    switch (GetUpstreamListType())
    {
        case ADDR_IPV4:
            addrType = ProtoAddress::IPv4;
            addrLen = fieldLen = 4;
            break;
        case ADDR_IPV6:
            addrType = ProtoAddress::IPv6;
            addrLen = fieldLen = 16;
            break;
        case ADDR_ETH:
            addrType = ProtoAddress::ETH;
            fieldLen = 8;
            addrLen = 6;
            break;
        default:
            PLOG(PL_ERROR, "ElasticAck::GetUpstreamAddr() error: invalid address type!\n");
            return false;
    }
    const char* addrPtr = (const char*)GetBuffer32(OffsetUpstreamList());
    addrPtr += (index * fieldLen);
    return addr.SetRawHostAddress(addrType, addrPtr, addrLen);
}  // end ElasticAck::GetUpstreamAddr()

bool ElasticAck::InitIntoBuffer(void*         bufferPtr, 
                                unsigned int  bufferBytes, 
                                bool          freeOnDestruct)
{
    unsigned int minLength = OFFSET_CLASS + 1;
    if (NULL != bufferPtr)
    {
        if (bufferBytes < minLength)
            return false;
        else
            AttachBuffer(bufferPtr, bufferBytes, freeOnDestruct);
    }
    else if (GetBufferLength() < minLength) 
    {
        return false;
    }
    memset((char*)AccessBuffer(), 0, minLength);
    SetType(ACK);
    SetMsgLength(minLength);
    return true;
}  // end ElasticAck::InitIntoBuffer()

bool ElasticAck::SetDstAddr(const ProtoAddress& addr)
{
    // TBD - do some consistency checks in case source addr was set first?
    AddressType addrType;
    switch (addr.GetType())
    {
        case ProtoAddress::IPv4:
            addrType = ADDR_IPV4;
            break;
        case ProtoAddress::IPv6:
            addrType = ADDR_IPV6;
            break;
        case ProtoAddress::ETH:
            addrType = ADDR_ETH;
            break;
        default:
            PLOG(PL_ERROR, "ElasticAck::SetSrcAddr() error: invalid address type!\n");
            return false;
    }
    return SetDstAddr(addrType, addr.GetRawHostAddress(), addr.GetLength());
}  // end ElasticAck::SetDstAddr()

bool ElasticAck::SetDstAddr(AddressType addrType, const char* addrPtr, unsigned int addrLen)
{
    // TBD - do some consistency checks in case source addr was set first?
    // (e.g. if FlagIsSet(FLAG_SOURCE))
    unsigned int minLength = (OFFSET_DST_ADDR*4) + addrLen;
    if (minLength > GetBufferLength())
    {
        PLOG(PL_ERROR, "ElasticAck::SetSrcAddr() error: insufficient buffer space!\n");
        return false;
    }
    else if (minLength > GetLength())
    {
        SetMsgLength(minLength);
    }
    UINT8 field = GetUINT8(OFFSET_ATYPE) & 0xf0;
    field |= (UINT8)addrType;
    SetUINT8(OFFSET_ATYPE, field);
    memcpy((char*)AccessBuffer32(OFFSET_DST_ADDR), addrPtr, addrLen);
    return true;
}  // end ElasticAck::SetDstAddr()

bool ElasticAck::SetSrcAddr(const ProtoAddress& addr)
{
    AddressType addrType;
    switch (addr.GetType())
    {
        case ProtoAddress::IPv4:
            addrType = ADDR_IPV4;
            break;
        case ProtoAddress::IPv6:
            addrType = ADDR_IPV6;
            break;
        case ProtoAddress::ETH:
            addrType = ADDR_ETH;
            break;
        default:
            PLOG(PL_ERROR, "ElasticAck::SetSrcAddr() error: invalid address type!\n");
            return false;
    }
    return SetSrcAddr(addrType, addr.GetRawHostAddress(), addr.GetLength());
}  // end ElasticAck::SetSrcAddr()

bool ElasticAck::SetSrcAddr(AddressType addrType, const char* addrPtr, unsigned int addrLen)
{
    // TBD - do some consistency checks that dst/src are same
    unsigned int minLength = (OFFSET_DST_ADDR*4) + 2*addrLen;
    if (minLength > GetBufferLength())
    {
        PLOG(PL_ERROR, "ElasticAck::SetSrcAddr() error: insufficient buffer space!\n");
        return false;
    }
    else if (minLength > GetLength())
    {
        SetMsgLength(minLength);
    }
    SetFlag(FLAG_SOURCE);
    UINT8 field = GetUINT8(OFFSET_ATYPE) & 0xf0;
    field |= (UINT8)addrType;
    SetUINT8(OFFSET_ATYPE, field);
    char* ptr = (char*)AccessBuffer32(OffsetSrcAddr());
    memcpy(ptr, addrPtr, addrLen);
    return true;
}  // end ElasticAck::SetSrcAddr()

bool ElasticAck::AppendUpstreamAddr(const ProtoAddress& addr)
{
    AddressType utype;
    unsigned int fieldLen;
    switch (addr.GetType())
    {
        case ProtoAddress::IPv4:
            utype = ADDR_IPV4;
            fieldLen = 4;
            break;
        case ProtoAddress::IPv6:
            utype = ADDR_IPV6;
            fieldLen = 16;
            break;
        case ProtoAddress::ETH:
            utype = ADDR_ETH;
            fieldLen = 8;
            break;
        default:
            PLOG(PL_ERROR, "ElasticAck::AppendUpstreamAddr() error: invalid address type!\n");
            return false;
    }
    // Make sure there's enough space first
    unsigned int minLength = GetLength() + fieldLen;
    if (minLength > GetBufferLength())
    {
        PLOG(PL_ERROR, "ElasticAck::AppendUpstreamAddr() error: insufficient buffer space!\n");
        return false;
    }
    UINT8 index = GetUpstreamListLength();
    if (index >= 15)
    {
        PLOG(PL_ERROR, "ElasticAck::AppendUpstreamAddr() error: max list size exceeded!\n");
        return false;
    }
    if (index > 0)
    {
        if (GetUpstreamListType() != utype)
        {
            PLOG(PL_ERROR, "ElasticAck::AppendUpstreamAddr() error: inconsistent address type!\n");
            return false;
        }
    }
    else
    {
        UINT8 field = GetUINT8(OFFSET_UTYPE) & 0xf0;
        field |= (UINT8)utype;
        SetUINT8(OFFSET_UTYPE, field);
    }
    char* addrPtr = (char*)AccessBuffer32(OffsetUpstreamList());
    addrPtr += (index * fieldLen);
    unsigned int addrLen = addr.GetLength();
    if (fieldLen > addrLen)
        memset(addrPtr + addrLen, 0, fieldLen - addrLen);  // zero padding if needed
    memcpy(addrPtr, addr.GetRawHostAddress(), addrLen);
    index += 1;
    UINT8 field = GetUINT8(OFFSET_ULEN) & 0x0f;
    field |= (index << 4);
    SetUINT8(OFFSET_ULEN, field);
    SetMsgLength(minLength);
    return true;
}  // end ElasticAck::AppendUpstreamAddr()


///////////////////////////////////////////
// ElasticNack implementation

ElasticNack::ElasticNack(void*          bufferPtr,
                         unsigned int   bufferBytes,
                         bool           initFromBuffer,
                         bool           freeOnDestruct)
  : ElasticMsg(bufferPtr, bufferBytes, false, freeOnDestruct)
{
    if (NULL != bufferPtr)
    {
        if (initFromBuffer)
            InitFromBuffer();
        else
            InitIntoBuffer();
    }
}

ElasticNack::ElasticNack(ElasticMsg& elasticMsg)
{
    InitFromBuffer(elasticMsg.AccessBuffer(), elasticMsg.GetBufferLength());
}
        
ElasticNack::~ElasticNack()
{
}
            
bool ElasticNack::InitIntoBuffer(void*           bufferPtr, 
                                 unsigned int    bufferBytes, 
                                 bool            freeOnDestruct)
{
    unsigned int minLength = OFFSET_UPSTREAM*4;
    if (NULL != bufferPtr)
    {
        if (bufferBytes < minLength)
            return false;
        else
            AttachBuffer(bufferPtr, bufferBytes, freeOnDestruct);
    }
    else if (GetBufferLength() < minLength) 
    {
        return false;
    }
    SetType(NACK);
    SetMsgLength(2);
    return true;
}  // end ElasticNack::InitIntoBuffer()
        
bool ElasticNack::SetUpstreamAddress(const ProtoAddress& addr)
{
    AddressType utype = ADDR_INVALID;
    switch (addr.GetType())
    {
        case ProtoAddress::IPv4:
            utype = ADDR_IPV4;
            break;
        case ProtoAddress::IPv6:
            utype = ADDR_IPV6;
            break;
        case ProtoAddress::ETH:
            utype = ADDR_ETH;
            break;
        default:
            PLOG(PL_ERROR, " ElasticNack::SetUpstreamAddress() error: invalid address type\n");
            return false;
    }
    // Need space for address length + seq start/stop and padding
    unsigned int minLength = OFFSET_UPSTREAM*4 + addr.GetLength() + 4;
    if (ProtoAddress::ETH == addr.GetType())
        minLength += 2;  // 2 bytes padding
    if (GetBufferLength() < minLength) 
    {
        return false;
    }
    memcpy(AccessBuffer32(OFFSET_UPSTREAM), addr.GetRawHostAddress(), addr.GetLength());
    SetUINT8(OFFSET_UTYPE, (UINT8)utype);
    SetMsgLength((OFFSET_UPSTREAM << 2) + addr.GetLength() + 4);
    return true;
}  // end ElasticNack::SetUpstreamAddress()

bool ElasticNack::GetUpstreamAddress(ProtoAddress& addr) const
{
    switch (GetAddressType())
    {
        case ADDR_IPV4:
            addr.SetRawHostAddress(ProtoAddress::IPv4, (char*)GetBuffer32(OFFSET_UPSTREAM), 4);
            break;
        case ADDR_IPV6:
            addr.SetRawHostAddress(ProtoAddress::IPv6, (char*)GetBuffer32(OFFSET_UPSTREAM), 16);
            break;
        case ADDR_ETH:
            addr.SetRawHostAddress(ProtoAddress::ETH, (char*)GetBuffer32(OFFSET_UPSTREAM), 6);
            break;
        default:
            PLOG(PL_ERROR, "ElasticNack::GetUpstreamAddress() error: invalid address type\n");
            return false;
    }
    return true;
}  // end ElasticNack::GetUpstreamAddress()
