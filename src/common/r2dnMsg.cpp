#include "r2dnMsg.h"

///////////////////////////////////////////////////////////////////////////////////
// class SmartPkt implementation
// methods for building and parsing Elastic Multicast ACK packets
//

const UINT16 SmartPkt::ADAPTIVE_PORT = 5656;
const UINT16 SmartPkt::ADAPTIVE_TOS = 56;
const UINT16 SmartPkt::ADAPTIVE_MAX_TOS = 66;
const UINT16 SmartPkt::ADAPTIVE_DSCP_MIN = 14;
const UINT16 SmartPkt::ADAPTIVE_DSCP_MAX = 23;

SmartPkt::SmartPkt(UINT32*        bufferPtr,
                       unsigned int   bufferBytes,
                       bool           freeOnDestruct)
 : ProtoPkt(bufferPtr, bufferBytes, freeOnDestruct)
{
    initFromBuffer();
    //PLOG(PL_DEBUG, "SmartPkt::SmartPacket() making a smart packet! !\n");
//    AddressType addrType = ADDR_IPV4;
//    PLOG(PL_DEBUG, "SmartPkt::SmartPacket(): Ipv4 : %d!\n", addrType);
//    UINT8 field = GetUINT8(OFFSET_ATYPE) & 0xf0;
//    PLOG(PL_DEBUG, "SmartPkt::SmartPacket() field! %d\n", field);
//    field |= (UINT8)addrType;
//    PLOG(PL_DEBUG, "SmartPkt::SmartPacket() gouing to put field %d here: %d !\n", field, OFFSET_ATYPE);
//    SetUINT8(OFFSET_ATYPE, field);

}

SmartPkt::~SmartPkt()
{
}

unsigned int SmartPkt::getAddressFieldLength(AddressType addrType)
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
}  // end SmartPkt::GetAddressFieldLength()

bool SmartPkt::initFromBuffer(UINT32*         bufferPtr,
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
        unsigned int pktLength = 4;  // 4 bytes of "header info"
        pktLength += 4; // for Q factor
        pktLength += 4; // for C factor
        pktLength += getPathLength() * getAddressFieldLength(getPathType()); // most likely one byte per hop
        if (ProtoPkt::InitFromBuffer(pktLength)) return true;
    }
    if (NULL != bufferPtr) DetachBuffer();
    return false;
}  // end SmartPkt::InitFromBuffer()

float SmartPkt::getQFactor() const
{
    float value;
    memcpy(&value, (char*)(buffer_ptr + OFFSET_Q_FACTOR), 4);
    return value;
    return ntohl(value);
}

float SmartPkt::getCFactor() const
{
    float value;
    memcpy(&value, (char*)(buffer_ptr + OFFSET_C_FACTOR), 4);
    return value;
    return ntohl(value);
}

bool SmartPkt::initIntoBuffer(UINT32*       bufferPtr,
                                unsigned int  bufferBytes,
                                bool          freeOnDestruct)
{
    PLOG(PL_DEBUG, "smartPkt::initIntoBuffer(): function call\n");
    unsigned int minLength = OFFSET_C_FACTOR*4;
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
}  // end SmartPkt::InitIntoBuffer()



bool SmartPkt::setQFactor(float Q)
{
    char* ptr = (char*)(buffer_ptr + OFFSET_Q_FACTOR);
    memcpy(ptr, &Q, 4);
    return true;
}

bool SmartPkt::setCFactor(float C)
{
    char* ptr = (char*)(buffer_ptr + OFFSET_C_FACTOR);
    memcpy(ptr, &C, 4);
    return true;
}



SmartDataPkt::SmartDataPkt(UINT32*        bufferPtr,
                       unsigned int   bufferBytes,
                       bool           freeOnDestruct)
 : SmartPkt(bufferPtr, bufferBytes, freeOnDestruct)
{
    //initFromBuffer();
    //PLOG(PL_DEBUG, "SmartDataPkt::SmartDataPacket() making a smart data packet!\n");

}

SmartDataPkt::~SmartDataPkt()
{
}

bool SmartDataPkt::appendNodeToPath(const ProtoAddress& addr)
{
    AddressType ptype;
    unsigned int fieldLen;
    //PLOG(PL_DEBUG,"SmartPkt::appendNodeToPath() Appending %s to list of addresses\n", addr.GetHostString());
    switch (addr.GetType())
    {
        case ProtoAddress::IPv4:
            ptype = ADDR_IPV4;
            fieldLen = 4;
            break;
        case ProtoAddress::IPv6:
            ptype = ADDR_IPV6;
            fieldLen = 16;
            break;
        case ProtoAddress::ETH:
            ptype = ADDR_ETHER;
            fieldLen = 8;
            break;
        default:
            PLOG(PL_ERROR, "SmartPkt::appendNodeToPath() error: invalid address type!\n");
            return false;
    }
    // Make sure there's enough space first
    unsigned int minLength = GetLength() + fieldLen;
    if (minLength > GetBufferLength())
    {
        PLOG(PL_ERROR, "SmartPkt::appendNodeToPath() error: insufficient buffer space!\n");
        return false;
    }
    UINT8 index = getPathLength();
    if (index >= 15)
    {
        PLOG(PL_ERROR, "SmartPkt::appendNodeToPath() error: max list size exceeded!\n");
        return false;
    }

    else // index == 0?
    {
        UINT8 field = GetUINT8(OFFSET_PTYPE) & 0xf0;
        field |= (UINT8)ptype;
        SetUINT8(OFFSET_PTYPE, field);
    }
    char* addrPtr = (char*)(buffer_ptr + offsetPath());
    addrPtr += ((index) * fieldLen);
    unsigned int addrLen = addr.GetLength();
    if (fieldLen > addrLen)
        memset(addrPtr + addrLen, 0, fieldLen - addrLen);  // zero padding if needed
    memcpy(addrPtr, addr.GetRawHostAddress(), addrLen);
    index += 1;
    UINT8 field = GetUINT8(OFFSET_PLEN) & 0x0f;
    field |= (index << 4);
    SetUINT8(OFFSET_PLEN, field);
    SetLength(minLength);
    return true;
}

bool SmartDataPkt::pathContains(const ProtoAddress& addr)
{
    //PLOG(PL_DEBUG, "SmartPkt::pathContains() checking path for address: %s, of type: %d\n", addr.GetHostString(),getAddressType());
    ProtoAddress otherAddr;
    for (UINT8 i = 0; i < getPathLength(); i++)
    {
        if (!getPathNodeAt(i,otherAddr))
            return false;

        //PLOG(PL_DEBUG, "SmartPkt::pathContains() comparing address 1 : %s\n", addr.GetHostString());
        //PLOG(PL_DEBUG, "SmartPkt::pathContains() comparing address 2 : %s\n", otherAddr.GetHostString());
        if (otherAddr == addr){

            //PLOG(PL_DEBUG, "SmartPkt::pathContains() MATCH\n" );
            return true;
            }
        //else
            //PLOG(PL_DEBUG, "SmartPkt::pathContains() no match\n" );
    }
    return false;
}

bool SmartDataPkt::initFromBuffer(UINT32*         bufferPtr,
                                unsigned int    numBytes,
                                bool            freeOnDestruct)
{
    if (NULL != bufferPtr)
        AttachBuffer(bufferPtr, numBytes, freeOnDestruct);
    else
        ProtoPkt::SetLength(0);
    unsigned int headerLength =4;
    unsigned int addrLen = getAddressFieldLength(getAddressType());
         // for src addr
    headerLength += addrLen;  // for source addr
    headerLength += 4; // for Q factor
    headerLength += 4; // for C factor
    //headerLength += 8; // for timestamp
    headerLength += getPathLength() * getAddressFieldLength(getPathType()); // most likely one byte per hop


    if (numBytes >= headerLength)
    {
       // pkt_length = headerLength+payloadLength;
        return true;
    }
    else
    {
        pkt_length = 0;
        if (NULL != bufferPtr) DetachBuffer();
        return false;
    }

}

bool SmartDataPkt::initIntoBuffer(UINT32* bufferPtr,unsigned int bufferBytes, bool freeOnDestruct)
{
    unsigned int minLength = offsetPath()*4; // words into bytes
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
    memset(buffer_ptr, 0, minLength);;
    SetLength(minLength);
    return true;
}

bool SmartDataPkt::getPathNodeAt(UINT8 index, ProtoAddress& addr) const
{
    if (index >= getPathLength())
    {
        PLOG(PL_ERROR, "SmartDataPkt::getPathNodeAt() error: out-of-bounds index!\n");
        return false;
    }
    ProtoAddress::Type addrType;
    unsigned int addrLen, fieldLen;
    switch (getAddressType())
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
            PLOG(PL_ERROR, "SmartDataPkt::getPathNodeAt() error: invalid address type!\n");
            return false;
    }
    const char* addrPtr = (const char*)(buffer_ptr + offsetPath());
    addrPtr += (index * fieldLen);
    //PLOG(PL_DEBUG, "SmartDataPkt::getPathNodeAt(): getting address at index %d\n", addrPtr - (char*)buffer_ptr);
    return addr.SetRawHostAddress(addrType, addrPtr, addrLen);
}  // end SmartPkt::getPathNodeAt()


bool SmartDataPkt::setSrcIPAddr(const ProtoAddress& addr)
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
        default:
            PLOG(PL_ERROR, "SmartPkt::SetSrcAddr() error: invalid address type!\n");
            return false;
    }
    return setSrcIPAddr(addrType, addr.GetRawHostAddress(), addr.GetLength());
}  // end SmartPkt::SetSrcAddr()

bool SmartDataPkt::setSrcIPAddr(AddressType addrType, const char* addrPtr, unsigned int addrLen)
{
    // TBD - do some consistency checks that dst/src are same
    unsigned int minLength = (offsetPath()*4) + addrLen;
    if (minLength > GetBufferLength())
    {
        PLOG(PL_ERROR, "SmartPkt::setSrcAddr() error: insufficient buffer space!\n");
        return false;
    }
    else if (minLength > GetLength())
    {
        SetLength(minLength);
    }
    //setFlag(FLAG_SOURCE);
    UINT8 field = GetUINT8(OFFSET_ATYPE) & 0xf0;
    field |= (UINT8)addrType;
    SetUINT8(OFFSET_ATYPE, field);
    char* ptr = (char*)(buffer_ptr + offsetSrcIPAddr());
    memcpy(ptr, addrPtr, addrLen);
    return true;
}

bool SmartDataPkt::getSrcIPAddr(ProtoAddress& addr) const
{
    ProtoAddress::Type addrType;
    unsigned int addrLen;
    switch (getAddressType())
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
    if(addr.SetRawHostAddress(addrType, (const char*)(buffer_ptr+offsetSrcIPAddr()), addrLen))
    {
        //PLOG(PL_DEBUG,"SmartDataPkt::getSrcIPAddr() getting address from offset %d: %s\n", offsetSrcIPAddr(), addr.GetHostString());
        return true;
    }
    else{
        PLOG(PL_ERROR,"SmartDataPkt::getSrcIPAddr() cannot set address\n");
        return true;
    }
}  // end SmartPkt::GetSrcAddr()


SmartAck::SmartAck(UINT32*        bufferPtr,
                       unsigned int   bufferBytes,
                       bool           freeOnDestruct)
 : SmartPkt(bufferPtr, bufferBytes, freeOnDestruct)
{
    initFromBuffer(bufferPtr,bufferBytes);
    //PLOG(PL_DEBUG, "SmartAck::SmartAcK() making a smart ack! %d\n", isAck());
    setFlag(FLAG_ACK);
    //PLOG(PL_DEBUG, "SmartAck::SmartAcK() making a smart ack! %d\n", isAck());
//    AddressType addrType = ADDR_IPV4;
//    PLOG(PL_DEBUG, "SmartPkt::SmartPacket(): Ipv4 : %d!\n", addrType);
//    UINT8 field = GetUINT8(OFFSET_ATYPE) & 0xf0;
//    PLOG(PL_DEBUG, "SmartPkt::SmartPacket() field! %d\n", field);
//    field |= (UINT8)addrType;
//    PLOG(PL_DEBUG, "SmartPkt::SmartPacket() gouing to put field %d here: %d !\n", field, OFFSET_ATYPE);
//    SetUINT8(OFFSET_ATYPE, field);
}

SmartAck::~SmartAck()
{
}

bool SmartAck::initFromBuffer(UINT32*         bufferPtr,
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
        unsigned int addrLen = getAddressFieldLength(getAddressType());
        pktLength += 2*(2*4); // for mac addresses, assuming we round from 6 bits to 8 bits per address.
        pktLength += 4;  // for dest addr
        pktLength += 4; // for Q factor
        pktLength += 4; // for C factor
        pktLength += 4; // for fragment offset
        pktLength += getPathLength() * 8; // most likely one byte per hop
        if (ProtoPkt::InitFromBuffer(pktLength)) return true;
    }
    if (NULL != bufferPtr) DetachBuffer();
    return false;
}

bool SmartAck::setSrcMACAddr(const ProtoAddress& addr)
{
    // TBD - do some consistency checks that dst/src are same
    unsigned int addrLen = addr.GetLength();
    AddressType addrType = ADDR_ETHER;
    unsigned int minLength = offsetPath()*4;
    if (minLength > GetBufferLength())
    {
        PLOG(PL_ERROR, "SmartPkt::setSrcMACAddr() error: insufficient buffer space!\n");
        return false;
    }
    else if (minLength > GetLength())
    {
        SetLength(minLength);
    }
    //setFlag(FLAG_SOURCE);
    UINT8 field = GetUINT8(OFFSET_ATYPE) & 0xf0;
    field |= (UINT8)ADDR_ETHER;
    SetUINT8(OFFSET_ATYPE, field);
    char* ptr = (char*)(buffer_ptr + offsetSrcMACAddr());
    memcpy(ptr, addr.GetRawHostAddress(), addrLen);
    return true;
}

bool SmartAck::setDstMACAddr(const ProtoAddress& addr)
{
    // TBD - do some consistency checks that dst/src are same
    unsigned int addrLen = addr.GetLength();
    unsigned int minLength = offsetPath()*4;
    if (minLength > GetBufferLength())
    {
        PLOG(PL_ERROR, "SmartPkt::setDstMACAddr() error: insufficient buffer space!\n");
        return false;
    }
    else if (minLength > GetLength())
    {
        SetLength(minLength);
    }
    //setFlag(FLAG_SOURCE);
    UINT8 field = GetUINT8(OFFSET_ATYPE) & 0xf0;
    field |= (UINT8)ADDR_ETHER;
    SetUINT8(OFFSET_ATYPE, field);
    char* ptr = (char*)(buffer_ptr + offsetDstMACAddr());
    memcpy(ptr, addr.GetRawHostAddress(), addrLen);
    return true;
}  // end SmartPkt::SetSrcAddr()


bool SmartAck::setDstIPAddr(const ProtoAddress& addr)
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
        default:
            PLOG(PL_ERROR, "SmartPkt::SetDstAddr() error: invalid address type!\n");
            return false;
    }
    return setDstIPAddr(addrType, addr.GetRawHostAddress(), addr.GetLength());
}  // end SmartPkt::SetDstAddr()

bool SmartAck::setDstIPAddr(AddressType addrType, const char* addrPtr, unsigned int addrLen)
{
    // TBD - do some consistency checks in case source addr was set first?
    // (e.g. if FlagIsSet(FLAG_SOURCE))
    unsigned int minLength = offsetPath()*4;
    if (minLength > GetBufferLength())
    {
        PLOG(PL_ERROR, "SmartPkt::SetDstAddr() error: insufficient buffer space!\n");
        return false;
    }
    else if (minLength > GetLength())
    {
        SetLength(minLength);
    }
    UINT8 field = GetUINT8(OFFSET_ATYPE) & 0xf0;
    field |= (UINT8)addrType;
    SetUINT8(OFFSET_ATYPE, field);
    char* ptr = (char*)(buffer_ptr + offsetDstIPAddr());
    memcpy(ptr, addrPtr, addrLen);
    return true;
}

bool SmartAck::getSrcMACAddr(ProtoAddress& addr) const
{
    ProtoAddress::Type addrType;
    unsigned int addrLen;

    addrType = ProtoAddress::ETH;
    addrLen = 6;

    return addr.SetRawHostAddress(addrType, (const char*)(buffer_ptr+offsetSrcMACAddr()), addrLen);
}

bool SmartAck::getDstMACAddr(ProtoAddress& addr) const
{
    ProtoAddress::Type addrType;
    unsigned int addrLen;

    addrType = ProtoAddress::ETH;
    addrLen = 6;

    return addr.SetRawHostAddress(addrType, (const char*)(buffer_ptr+offsetDstMACAddr()), addrLen);
}

bool SmartAck::getDstIPAddr(ProtoAddress& addr) const
{
    ProtoAddress::Type addrType;
    unsigned int addrLen;
    switch (getAddressType())
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
    return addr.SetRawHostAddress(addrType, (const char*)(buffer_ptr+offsetDstIPAddr()), addrLen);
}

bool SmartAck::appendNodeToPath(const ProtoAddress& addr)
{
    AddressType ptype;
    unsigned int fieldLen;
    //PLOG(PL_DEBUG,"SmartPkt::appendNodeToPath() Appending %s to list of addresses\n", addr.GetHostString());
    switch (addr.GetType())
    {
        case ProtoAddress::IPv4:
            ptype = ADDR_IPV4;
            fieldLen = 4;
            break;
        case ProtoAddress::IPv6:
            ptype = ADDR_IPV6;
            fieldLen = 16;
            break;
        case ProtoAddress::ETH:
            ptype = ADDR_ETHER;
            fieldLen = 8;
            break;
        default:
            PLOG(PL_ERROR, "SmartPkt::appendNodeToPath() error: invalid address type!\n");
            return false;
    }

    // Make sure there's enough space first
    unsigned int minLength = GetLength() + fieldLen;
    PLOG(PL_DEBUG, "ptype = %d, fieldlen = %d, min length = %d, buffer length = %d\n",ptype,fieldLen, minLength, GetBufferLength());
    if (minLength > GetBufferLength())
    {
        PLOG(PL_ERROR, "SmartPkt::appendNodeToPath() error: insufficient buffer space!\n");
        return false;
    }
    UINT8 index = getPathLength();
    if (index >= 15)
    {
        PLOG(PL_ERROR, "SmartPkt::appendNodeToPath() error: max list size exceeded!\n");
        return false;
    }

    else // index == 0?
    {
        UINT8 field = GetUINT8(OFFSET_PTYPE) & 0xf0;
        field |= (UINT8)ptype;
        SetUINT8(OFFSET_PTYPE, field);
    }
    char* addrPtr = (char*)(buffer_ptr + offsetPath());
    addrPtr += ((index) * fieldLen);
    unsigned int addrLen = addr.GetLength();
    if (fieldLen > addrLen)
        memset(addrPtr + addrLen, 0, fieldLen - addrLen);  // zero padding if needed
    memcpy(addrPtr, addr.GetRawHostAddress(), addrLen);
    index += 1;
    UINT8 field = GetUINT8(OFFSET_PLEN) & 0x0f;
    field |= (index << 4);
    SetUINT8(OFFSET_PLEN, field);
    SetLength(minLength);
    return true;
}

bool SmartAck::pathContains(const ProtoAddress& addr)
{
    //PLOG(PL_DEBUG, "SmartPkt::pathContains() checking path for address: %s, of type: %d\n", addr.GetHostString(),getAddressType());
    ProtoAddress otherAddr;
    for (UINT8 i = 0; i < getPathLength(); i++)
    {
        if (!getPathNodeAt(i,otherAddr))
            return false;

        //PLOG(PL_DEBUG, "SmartPkt::pathContains() comparing address 1 : %s\n", addr.GetHostString());
        //PLOG(PL_DEBUG, "SmartPkt::pathContains() comparing address 2 : %s\n", otherAddr.GetHostString());
        if (otherAddr == addr){

            //PLOG(PL_DEBUG, "SmartPkt::pathContains() MATCH\n" );
            return true;
            }
        //else
            //PLOG(PL_DEBUG, "SmartPkt::pathContains() no match\n" );
    }
    return false;
}

bool SmartAck::getNextAddress(const ProtoAddress & addr, ProtoAddress& next_addr) const
{
    ProtoAddress otherAddr;
    for (UINT8 i = 0; i < getPathLength(); i++)
    {
        if (!getPathNodeAt(i,otherAddr))
            return false;

        //PLOG(PL_DEBUG, "SmartPkt::pathContains() comparing address 1 : %s\n", addr.GetHostString());
        //PLOG(PL_DEBUG, "SmartPkt::pathContains() comparing address 2 : %s\n", otherAddr.GetHostString());
        if (otherAddr == addr){
            if(!getPathNodeAt(i+1,next_addr))
            {
                return false;
            }
            //PLOG(PL_DEBUG, "SmartPkt::pathContains() MATCH\n" );
            return true;
        }
        //else
            //PLOG(PL_DEBUG, "SmartPkt::pathContains() no match\n" );
    }
    return false;
}
bool SmartAck::getPathNodeAt(UINT8 index, ProtoAddress& addr) const
{
    if (index >= getPathLength())
    {
        PLOG(PL_ERROR, "SmartDataPkt::getPathNodeAt() error: out-of-bounds index!\n");
        return false;
    }
    ProtoAddress::Type addrType;
    unsigned int addrLen, fieldLen;

    addrType = ProtoAddress::ETH;
    fieldLen = 8;
    addrLen = 6;
    const char* addrPtr = (const char*)(buffer_ptr + offsetPath());
    addrPtr += (index * fieldLen);
    return addr.SetRawHostAddress(addrType, addrPtr, addrLen);
}

/*ProtoAddress * SmartAck::getPath()
{
    unsigned int plen = getPathLength();  
    ProtoAddress* addrList = new ProtoAddress[plen];
    if (NULL == addrList)
    {
        PLOG(PL_ERROR, "SmartAck::getPath() new ProtoAddress list error: %s\n", GetErrorString());
        return NULL;
    }
    for (int idx  = 0; idx < plen; idx++)
    {
        getPathNodeAt(idx, addrList[idx]);
    }
    return addrList;
}  // end SmartAck::getPath()

}*/

bool SmartAck::setPath(Path p, int numAddresses)
{
    AddressType ptype;
    unsigned int fieldLen=8; // Ether rounded to 2 words

    // Make sure there's enough space first
    unsigned int minLength = 36 + fieldLen*numAddresses;
    if (minLength > GetBufferLength())
    {
        PLOG(PL_ERROR, "SmartPkt::setPat() error: insufficient buffer space!\n");
        return false;
    }
    UINT8 index = getPathLength();


    char* addrPtr = (char*)(buffer_ptr + offsetPath());
    int addr_idx = 0;
    unsigned int addrLen = 6;
    Path * path_ptr = &p;
    while (addr_idx < numAddresses && path_ptr != NULL)
    {
        if (fieldLen > addrLen)
            memset(addrPtr + addrLen, 0, fieldLen - addrLen);  // zero padding if needed
        memcpy(addrPtr, path_ptr->getAddress().GetRawHostAddress(), addrLen);
        addrPtr += fieldLen;
        addr_idx += 1;
        path_ptr = path_ptr->getNextPath();
    }


    // SEt length
    UINT8 field = GetUINT8(OFFSET_PLEN) & 0x0f;
    field |= (numAddresses << 4);
    SetUINT8(OFFSET_PLEN, field);

    SetLength(minLength);
    return true;
}

SmartPathAd::SmartPathAd(UINT32*        bufferPtr,
                       unsigned int   bufferBytes,
                       bool           freeOnDestruct)
 : SmartPkt(bufferPtr, bufferBytes, freeOnDestruct)
{
    initFromBuffer();
    //PLOG(PL_DEBUG, "SmartAck::SmartAcK() making a smart ack! %d\n", isAck());
    setFlag(FLAG_AD);
    //PLOG(PL_DEBUG, "SmartAck::SmartAcK() making a smart ack! %d\n", isAck());
//    AddressType addrType = ADDR_IPV4;
//    PLOG(PL_DEBUG, "SmartPkt::SmartPacket(): Ipv4 : %d!\n", addrType);
//    UINT8 field = GetUINT8(OFFSET_ATYPE) & 0xf0;
//    PLOG(PL_DEBUG, "SmartPkt::SmartPacket() field! %d\n", field);
//    field |= (UINT8)addrType;
//    PLOG(PL_DEBUG, "SmartPkt::SmartPacket() gouing to put field %d here: %d !\n", field, OFFSET_ATYPE);
//    SetUINT8(OFFSET_ATYPE, field);
}

SmartPathAd::~SmartPathAd()
{
}

bool SmartPathAd::initFromBuffer(UINT32*         bufferPtr,
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
        unsigned int addrLen = getAddressFieldLength(getAddressType());

        pktLength += 4; // for Q factor
        pktLength += 4; // for C factor
        pktLength += getPathLength() * 2; // most likely one byte per hop
        if (ProtoPkt::InitFromBuffer(pktLength)) return true;
    }
    if (NULL != bufferPtr) DetachBuffer();
    return false;
}

bool SmartPathAd::setPath(Path p, int numAddresses)
{
    AddressType ptype;
    unsigned int fieldLen=8; // Ether rounded to 2 words

    // Make sure there's enough space first
    unsigned int minLength = 12 + fieldLen*numAddresses;
    if (minLength > GetBufferLength())
    {
        PLOG(PL_ERROR, "SmartPkt::setPat() error: insufficient buffer space!\n");
        return false;
    }
    UINT8 index = getPathLength();


    char* addrPtr = (char*)(buffer_ptr + offsetPath());
    int addr_idx = 0;
    unsigned int addrLen = 6;
    Path * path_ptr = &p;
    while (addr_idx < numAddresses && path_ptr != NULL)
    {
        if (fieldLen > addrLen)
            memset(addrPtr + addrLen, 0, fieldLen - addrLen);  // zero padding if needed
        memcpy(addrPtr, path_ptr->getAddress().GetRawHostAddress(), addrLen);
        addrPtr += fieldLen;
        addr_idx += 1;
        path_ptr = path_ptr->getNextPath();
    }


    // SEt length
    UINT8 field = GetUINT8(OFFSET_PLEN) & 0x0f;
    field |= (numAddresses << 4);
    SetUINT8(OFFSET_PLEN, field);

    SetLength(minLength);
    return true;
}

int SmartPathAd::getPath(ProtoAddressList& addr_list)
{
    addr_list.RemoveList(addr_list);
    unsigned int plen = getPathLength();
    unsigned int addrLen=6, fieldLen =8;
    ProtoAddress::Type addrType;

    for (int idx = 0; idx<plen;idx++)
    {
        ProtoAddress addr;
        addrType = ProtoAddress::ETH;
        addr.SetRawHostAddress(addrType, (const char*)(buffer_ptr+offsetPath()+fieldLen*idx), addrLen);
        addr_list.Insert(addr);
    }
    return plen;

}

bool SmartPathAd::getPathNodeAt(UINT8 index, ProtoAddress& addr) const
{
    if (index >= getPathLength())
    {
        PLOG(PL_ERROR, "SmartDataPkt::getPathNodeAt() error: out-of-bounds index!\n");
        return false;
    }
    ProtoAddress::Type addrType;
    unsigned int addrLen, fieldLen;

    addrType = ProtoAddress::ETH;
    fieldLen = 8;
    addrLen = 6;
    const char* addrPtr = (const char*)(buffer_ptr + offsetPath());
    addrPtr += (index * fieldLen);
    return addr.SetRawHostAddress(addrType, addrPtr, addrLen);
}



// end SmartPkt::AppendUpstreamAddr()
