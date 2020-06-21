
#include "elasticMsg.h"


const double ElasticAdv::METRIC_MAX = 256.0;

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

ElasticMsg::AddressType ElasticMsg::GetAddressType(ProtoAddress::Type addrType)
{
    switch (addrType)
    {
        case ProtoAddress::IPv4:
            return ADDR_IPV4;
        case ProtoAddress::IPv6:
            return ADDR_IPV6;
        case ProtoAddress::ETH:
            return ADDR_ETH;
        default:
            return ADDR_INVALID;
    }
}  // end ElasticMsg::GetAddressType()

unsigned int ElasticMsg::GetAddressFieldWords(AddressType addrType)
{
    // returns field length in number of UINT32 words
    switch (addrType)
    {
        case ADDR_IPV4:
            return 1;  // 1 32-bit word per addr
        case ADDR_IPV6:
            return 4;  // 4 32-bit words per addr
        case ADDR_ETH:
            return 2;  // 6 bytes addr + 2 bytes padding
        default:
            return 0;
    }
}  // end ElasticMsg::GetAddressFieldWords()

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
        PLOG(PL_ERROR, "ElasticAck::InitFromBuffer() error: insufficient buffer size\n");
    }
    if (NULL != bufferPtr) DetachBuffer();
    SetLength(0);
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
            PLOG(PL_ERROR, "ElasticAck::GetSrcAddr() error: invalid address type!\n");
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
    unsigned int minLength = 4*OFFSET_DST_ADDR + 4*GetAddressFieldWords(addrType);
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
    unsigned int minLength = 4*OFFSET_DST_ADDR + 2*4*GetAddressFieldWords(addrType);
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
// ElasticAdv implementation

ElasticAdv::ElasticAdv(void*          bufferPtr, 
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

ElasticAdv::ElasticAdv(ElasticMsg& elasticMsg)
{
    InitFromBuffer(elasticMsg.AccessBuffer(), elasticMsg.GetBufferLength());
}


ElasticAdv::~ElasticAdv()
{
}

UINT16 ElasticAdv::EncodeMetric(double value)
{
    ASSERT((0.0 == value) || (value >= 1.0));

    if (value <= 0.0)
    {
        return 0;
    }
    else if (value <= 1.0)
    {
        return 1;
    }
    else if (value >= METRIC_MAX)
    {
        return 0xffff;
    }
    else
    {
        value -= 1.0;
        double scale = (double)((UINT16)0xffff) / METRIC_MAX;
        UINT16 field = (UINT16)(value * scale);
        if (field < 2)
            return 2;
        else 
            return field;
    }
} // end ElasticAdv::EncodeMetric()

double ElasticAdv::DecodeMetric(UINT16 value)
{
    if (value <= 1)
    {
        return (double)value;
    }
    else
    {
        double scale = METRIC_MAX / (double)((UINT16)0xffff);
        return ((double)value*scale + 1.0);
    }
}  // end ElasticAdv::DecodeMetric()

bool ElasticAdv::InitFromBuffer(void*           bufferPtr, 
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
        PLOG(PL_ERROR, "ElasticAdv::InitFromBuffer() error: insufficient buffer size\n");
    }
    if (NULL != bufferPtr) DetachBuffer();
    SetLength(0);
    return false;
}  // end ElasticAdv::InitFromBuffer()


bool ElasticAdv::GetDstAddr(ProtoAddress& addr) const
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
            PLOG(PL_ERROR, "ElasticAdv::GetDstAddr() error: invalid address type!\n");
            return false;
    }
    return addr.SetRawHostAddress(addrType, (char*)GetBuffer32(OFFSET_DST_ADDR), addrLen);
}  // end ElasticAdv::GetDstAddr()

bool ElasticAdv::GetSrcAddr(ProtoAddress& addr) const
{
    if (!FlagIsSet(FLAG_SOURCE)) return false;
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
            PLOG(PL_ERROR, "ElasticAdv::GetSrcAddr() error: invalid address type!\n");
            return false;
    }
    return addr.SetRawHostAddress(addrType, (const char*)GetBuffer32(OffsetSrcAddr()), addrLen);
}  // end ElasticAdv::GetSrcAddr()

bool ElasticAdv::GetAdvAddr(ProtoAddress& addr) const
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
            PLOG(PL_ERROR, "ElasticAdv::GetSrcAddr() error: invalid address type!\n");
            return false;
    }
    return addr.SetRawHostAddress(addrType, (const char*)GetBuffer32(OffsetAdvAddr()), addrLen);
}  // end ElasticAdv::GetAdvAddr()

bool ElasticAdv::InitIntoBuffer(void*         bufferPtr, 
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
    SetType(ADV);
    SetMsgLength(minLength);
    return true;
}  // end ElasticAdv::InitIntoBuffer()

bool ElasticAdv::SetDstAddr(const ProtoAddress& addr)
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
            PLOG(PL_ERROR, "ElasticAdv::SetSrcAddr() error: invalid address type!\n");
            return false;
    }
    return SetDstAddr(addrType, addr.GetRawHostAddress(), addr.GetLength());
}  // end ElasticAdv::SetDstAddr()

bool ElasticAdv::SetDstAddr(AddressType addrType, const char* addrPtr, unsigned int addrLen)
{
    // TBD - do some consistency checks in case source addr was set first?
    // (e.g. if FlagIsSet(FLAG_SOURCE))
    unsigned int minLength = 4*OFFSET_DST_ADDR + 4*GetAddressFieldWords(addrType);
    if (minLength > GetBufferLength())
    {
        PLOG(PL_ERROR, "ElasticAdv::SetSrcAddr() error: insufficient buffer space!\n");
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
}  // end ElasticAdv::SetDstAddr()

bool ElasticAdv::SetSrcAddr(const ProtoAddress& addr)
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
            PLOG(PL_ERROR, "ElasticAdv::SetSrcAddr() error: invalid address type!\n");
            return false;
    }
    return SetSrcAddr(addrType, addr.GetRawHostAddress(), addr.GetLength());
}  // end ElasticAdv::SetSrcAddr()

bool ElasticAdv::SetSrcAddr(AddressType addrType, const char* addrPtr, unsigned int addrLen)
{
    // TBD - do some consistency checks that dst/src are same
    unsigned int minLength = 4*OFFSET_DST_ADDR + 2*4*GetAddressFieldWords(addrType);
    if (minLength > GetBufferLength())
    {
        PLOG(PL_ERROR, "ElasticAdv::SetSrcAddr() error: insufficient buffer space!\n");
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
}  // end ElasticAdv::SetSrcAddr()

bool ElasticAdv::SetTTL(UINT8 ttl)
{
    unsigned int minLength = OffsetTTL() + 1;
    if (minLength > GetBufferLength())
    {
        PLOG(PL_ERROR, "ElasticAdv::SetTTL() error: insufficient buffer space!\n");
        return false;
    }
    else if (minLength > GetLength())
    {
        SetMsgLength(minLength);
    }
    SetUINT8(OffsetTTL(), ttl);
    return true;
}  // end ElasticAdv::SetTTL()

bool ElasticAdv::SetHopCount(UINT8 hopCount)
{
    unsigned int minLength = OffsetHopCount() + 1;
    if (minLength > GetBufferLength())
    {
        PLOG(PL_ERROR, "ElasticAdv::SetHopCount() error: insufficient buffer space!\n");
        return false;
    }
    else if (minLength > GetLength())
    {
        SetMsgLength(minLength);
    }
    SetUINT8(OffsetHopCount(), hopCount);
    return true;
}  // end ElasticAdv::SetHopCount()


bool ElasticAdv::SetMetric(double value)
{
    unsigned int minLength = 2*OffsetMetric() + 2;
    if (minLength > GetBufferLength())
    {
        PLOG(PL_ERROR, "ElasticAdv::SetMetric() error: insufficient buffer space!\n");
        return false;
    }
    else if (minLength > GetLength())
    {
        SetMsgLength(minLength);
    }
    UINT16 field = EncodeMetric(value);
    SetWord16(OffsetMetric(), field);
    return true;
}  // end ElasticAdv::SetMetric()

bool ElasticAdv::SetAdvAddr(const ProtoAddress& addr)
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
            PLOG(PL_ERROR, "ElasticAdv::SetAdvAddr() error: invalid address type!\n");
            return false;
    }
    return SetAdvAddr(addrType, addr.GetRawHostAddress(), addr.GetLength());
}  // end ElasticAdv::SetAdvAddr()

bool ElasticAdv::SetAdvAddr(AddressType addrType, const char* addrPtr, unsigned int addrLen)
{
    unsigned int minLength = 4*OffsetAdvAddr();
    minLength += 4*GetAddressFieldWords(addrType);
    if (minLength > GetBufferLength())
    {
        PLOG(PL_ERROR, "ElasticAdv::SetAdvAddr() error: insufficient buffer space!\n");
        return false;
    }
    else if (minLength > GetLength())
    {
        SetMsgLength(minLength);
    } 
    UINT8 field = GetUINT8(OFFSET_VTYPE) & 0xf0;
    field |= (UINT8)addrType;
    SetUINT8(OFFSET_VTYPE, field);
    char* ptr = (char*)AccessBuffer32(OffsetAdvAddr());
    memcpy(ptr, addrPtr, addrLen);
    return true;
}  // end ElasticAdv::SetAdvAddr()


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
    unsigned int minLength = OFFSET_UPSTREAM*4 + 4*GetAddressFieldWords(utype);
    if (GetBufferLength() < minLength) 
    {
        return false;
    }
    memcpy(AccessBuffer32(OFFSET_UPSTREAM), addr.GetRawHostAddress(), addr.GetLength());
    // TBD - zero the padding?
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
