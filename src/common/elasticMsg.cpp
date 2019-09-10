
#include "elasticMsg.h"

///////////////////////////////////////////////////////////////////////////////////
// class ElasticAck implementation
// methods for building and parsing Elastic Multicast ACK packets
//

const ProtoAddress ElasticAck::ELASTIC_ADDR = ProtoAddress("224.0.0.55");
const UINT16 ElasticAck::ELASTIC_PORT = 5555;
        
ElasticAck::ElasticAck(UINT32*        bufferPtr, 
                       unsigned int   bufferBytes, 
                       bool           freeOnDestruct)
 : ProtoPkt(bufferPtr, bufferBytes, freeOnDestruct)
{
    InitFromBuffer();
}

ElasticAck::~ElasticAck()
{
}

unsigned int ElasticAck::GetAddressFieldLength(AddressType addrType)
{
    unsigned int addrLen = 0;
    switch (addrType)
    {
        case ADDR_IPV4:
            return 4;
        case ADDR_IPV6:
            return 16;
        case ADDR_ETHER:
            return 8; // includes padding
        default:
            return 0;
    }
}  // end ElasticAck::GetAddressFieldLength()

bool ElasticAck::InitFromBuffer(UINT32*         bufferPtr, 
                                unsigned int    numBytes, 
                                bool            freeOnDestruct)
{
    if (NULL != bufferPtr) 
        AttachBuffer(bufferPtr, numBytes, freeOnDestruct);
    else
        ProtoPkt::SetLength(0);
    if (GetBufferLength() >= OFFSET_CLASS)
    {
        // compute required length based on atype, ulen and utype
        unsigned pktLength = 4;  // 4 bytes of "header info"
        unsigned int addrLen = GetAddressFieldLength(GetAddressType());
        pktLength += addrLen;  // for dest addr
        if (FlagIsSet(FLAG_SOURCE))
            pktLength += addrLen;  // for source addr
        pktLength += GetUpstreamListLength() * GetAddressFieldLength(GetUpstreamListType());
        if (ProtoPkt::InitFromBuffer(pktLength)) return true;
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
        case ADDR_ETHER:
            addrType = ProtoAddress::ETH;
            addrLen = 6;
            break;
        default:
            PLOG(PL_ERROR, "ElasticAck::GetDstAddr() error: invalid address type!\n");
            return false;
    }
    return addr.SetRawHostAddress(addrType, (char*)(buffer_ptr+OFFSET_DST_ADDR), addrLen);
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
        case ADDR_ETHER:
            addrType = ProtoAddress::ETH;
            addrLen = 6;
            break;
        default:
            PLOG(PL_ERROR, "ElasticAck::GetDstAddr() error: invalid address type!\n");
            return false;
    }
    return addr.SetRawHostAddress(addrType, (const char*)(buffer_ptr+OffsetSrcAddr()), addrLen);
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
        case ADDR_ETHER:
            addrType = ProtoAddress::ETH;
            fieldLen = 8;
            addrLen = 6;
            break;
        default:
            PLOG(PL_ERROR, "ElasticAck::GetUpstreamAddr() error: invalid address type!\n");
            return false;
    }
    const char* addrPtr = (const char*)(buffer_ptr + OffsetUpstreamList());
    addrPtr += (index * fieldLen);
    return addr.SetRawHostAddress(addrType, addrPtr, addrLen);
}  // end ElasticAck::GetUpstreamAddr()

bool ElasticAck::InitIntoBuffer(UINT32*       bufferPtr, 
                                unsigned int  bufferBytes, 
                                bool          freeOnDestruct)
{
    unsigned int minLength = OFFSET_DST_ADDR*4;
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
    memset(buffer_ptr, 0, minLength);
    SetLength(minLength);
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
            addrType = ADDR_ETHER;
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
        SetLength(minLength);
    }
    UINT8 field = GetUINT8(OFFSET_ATYPE) & 0xf0;
    field |= (UINT8)addrType;
    SetUINT8(OFFSET_ATYPE, field);
    char* ptr = (char*)(buffer_ptr + OFFSET_DST_ADDR);
    memcpy(ptr, addrPtr, addrLen);
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
            addrType = ADDR_ETHER;
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
        SetLength(minLength);
    }
    SetFlag(FLAG_SOURCE);
    UINT8 field = GetUINT8(OFFSET_ATYPE) & 0xf0;
    field |= (UINT8)addrType;
    SetUINT8(OFFSET_ATYPE, field);
    char* ptr = (char*)(buffer_ptr + OffsetSrcAddr());
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
            utype = ADDR_ETHER;
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
    char* addrPtr = (char*)(buffer_ptr + OffsetUpstreamList());
    addrPtr += (index * fieldLen);
    unsigned int addrLen = addr.GetLength();
    if (fieldLen > addrLen)
        memset(addrPtr + addrLen, 0, fieldLen - addrLen);  // zero padding if needed
    memcpy(addrPtr, addr.GetRawHostAddress(), addrLen);
    index += 1;
    UINT8 field = GetUINT8(OFFSET_ULEN) & 0x0f;
    field |= (index << 4);
    SetUINT8(OFFSET_ULEN, field);
    SetLength(minLength);
    return true;
}  // end ElasticAck::AppendUpstreamAddr()
