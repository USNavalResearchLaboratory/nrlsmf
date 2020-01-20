#ifndef _R2DN_MSG
#define _R2DN_MSG

#include "protoPkt.h"
#include "protoPktIP.h"
#include "protoAddress.h"
#include "path.h"
#include <time.h>

// Data Packet:

//       0               1               2               3
//       0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |S|B|C|R| atype | plen  | rplen |                               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                                                               |
//      +                            Q Factor                           +
//      |                                                               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                                                               |
//      +                            C Factor                           +
//      |                                                               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                                                               |
//      +                      Source (Hop) IP Addr                     +
//      |                               ...                             |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                                                               |
//      +                 timestamp (8 bytes = 2 words)                 +
//      |                                                               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                                                               |
//      +              tentative:Path  (rplen * 6 bytes)                +
//      |                                                               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                                                               |
//      +                        Path  (plen * 4 bytes)                 +
//      |                                                               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// Ack Packet:

//       0               1               2               3
//       0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |S|B|C|R| atype | plen  | ptype  |  protocol   |  traffic class |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                                                               |
//      +                            Q Factor                           +
//      |                                                               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                                                               |
//      +                            C Factor                           +
//      |                                                               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//      |                                                               |
//      +            Packet Sender MAC Addr (round to 2 words)          +
//      |                                                               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                                                               |
//      +                    Packet Received MAC Addr   (2 words)       +
//      |                                                               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                                                               |
//      +                        Flow Destination IP                    +
//      |                                                               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                                                               |
//      +                        Fragmet Offset                         +
//      |                                                               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                                                              |
//      |
//      +                               Path
//      |                               ...                             |

// REturn Path Advertisement (SmartPathAd)

//       0               1               2               3
//       0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |S|B|C|R| atype | plen  | rplen |                               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//      |                                                               |
//      +               Return   Path  (plen * 8 bytes)                 +
//      |                                                               |

// TODO: Change the order so path goes at the end.  It'll make appending the path easier.

// FLAGS:
//
// S        : source addr present (1 bit)
// B        : broadcast packet?
// A        : ack?  (1 bit)
// R        : reserved flag (1 bit)
//
// atype    :  source/dest address type (4 bits)
// plen     :  length of Path to follow. (4 bits)

// Flow specification
// protocol :   OPTIONAL IP protocol type (1 byte)
// class    :   OPTIONAL IP traffic class (1 byte)
// dst_addr :   Flow destination address (atype dependent)
// src_addr :   Flow source address   (atype dependent)

// Other
// Path      :   Data packet: Path the packet has taken. Ack: Path the ack should take.
// Q Factor :   RL Learning Metric: Expected cost-to-go (4 bytes, float)
// C Factor :   RL Learning Metric: Reliability (4 bytes, float)

// NOTE upstream address list items are 4-byte aligned

// SmartPacket is a base class for SmartDataPacket and SmartAck.  This is only used before you know if its a data packet or an ack,
// and want to check the ack flag.
// Contains some shared functionality of both AKCs and Packets.

class SmartPkt : public ProtoPkt
{
    public:
        SmartPkt(void*          bufferPtr = NULL,
                 unsigned int   bufferBytes = 0,
                 bool           freeOnDestruct = false);
        ~SmartPkt();


        static const UINT16 ADAPTIVE_PORT;        //
        static const UINT16 ADAPTIVE_TOS;        //
        static const UINT16 ADAPTIVE_MAX_TOS;
        static const UINT16 ADAPTIVE_DSCP_MIN;
        static const UINT16 ADAPTIVE_DSCP_MAX;

        enum AddressType
        {
            ADDR_INVALID = 0,
            ADDR_IPV4,
            ADDR_IPV6,
            ADDR_ETHER
        };

        enum DSCP_Value
        {
            DSCP_1 = 1,
            DSCP_2,
            DSCP_3,
            DSCP_4
        };

        enum Flag
        {
            FLAG_AD     = 0x01,
            FLAG_BCAST   = 0x02,
            FLAG_ACK     = 0x04,
            FLAG_RESERVED   = 0x08
        };

        // Use these to parse
        bool initFromBuffer(void*           bufferPtr = NULL,
                            unsigned int    numBytes = 0,
                            bool            freeOnDestruct = false);

        bool flagIsSet(Flag flag)
            {return (0 != (flag & (GetUINT8(OFFSET_FLAGS) >> 4)));}

        // Check to see if its an ACK
        bool isAck()
            {return flagIsSet(FLAG_ACK);}

        bool isAd()
            {return flagIsSet(FLAG_AD);}

        // For simplicity, we assume SMart packets are all IPv4 packets.
        AddressType getAddressType() const
            {
                //return ((AddressType)(GetUINT8(OFFSET_ATYPE) & 0x0f));
                return ADDR_IPV4;
            }

        // This should always be ipV4 too.
        AddressType getPathType() const
            {return ((AddressType)(GetUINT8(OFFSET_PTYPE) & 0x0f));}

        // Gets the number of addresses in the path.
        UINT8 getPathLength() const
            {return (GetUINT8(OFFSET_PLEN) >> 4);}

        ProtoPktIP::Protocol getProtocol() const
            {return ((ProtoPktIP::Protocol)GetUINT8(OFFSET_PROTOCOL));}
        UINT8 getTrafficClass() const
            {return GetUINT8(OFFSET_CLASS);}

        float getQFactor() const;
        float getCFactor() const;

        // Gets the <index>th element of the path.
        bool getPathNodeAt(UINT8 index, ProtoAddress& addr) const;

        // Use these to build (MUST call in order)
        bool initIntoBuffer(void*           bufferPtr = NULL,
                            unsigned int    bufferBytes = 0,
                            bool            freeOnDestruct = false);

//        void setProtocol(ProtoPktIP::Protocol protocol)
//        {
//            SetUINT8(OFFSET_PROTOCOL, (UINT8)protocol);
//            setFlag(FLAG_PROTOCOL);
//        }
        void setTrafficClass(UINT8 trafficClass)
        {
            SetUINT8(OFFSET_CLASS, trafficClass);
        }

        bool setQFactor(float Qack);
        bool setCFactor(float Cack);
        // Adds an address to the path.
        bool appendNodeToPath(const ProtoAddress& addr);
        // checks to see if an address is in the path.
        bool pathContains(const ProtoAddress& addr);
        void setFlag(Flag flag)
        {
            UINT8 field = GetUINT8(OFFSET_FLAGS);
            field |= (flag << 4);
            SetUINT8(OFFSET_FLAGS, field);
        }
        void resetFlag(Flag flag)
        {
            UINT8 field = GetUINT8(OFFSET_FLAGS);
            field &= 0xff - (flag << 4);
            SetUINT8(OFFSET_FLAGS, field);
        }

    protected:
        enum
        {
            OFFSET_FLAGS    = 0,                    // 4 most significant bits
            OFFSET_ATYPE    = OFFSET_FLAGS,         // 4 least significant bits
            OFFSET_PLEN     = OFFSET_ATYPE + 1,     // 4 most significant bits
            OFFSET_PTYPE    = OFFSET_PLEN,          // 4 least significant bits
            OFFSET_PROTOCOL = OFFSET_PTYPE + 1,     // UINT8 offset
            OFFSET_CLASS    = OFFSET_PROTOCOL + 1,  // UINT8 offset
            OFFSET_Q_FACTOR = (OFFSET_CLASS/4) + 1, // UINT32 offset
            OFFSET_C_FACTOR = OFFSET_Q_FACTOR + 1
        };


        unsigned int offsetPath() const
        {
            return OFFSET_C_FACTOR+1;
        }

        static unsigned int getAddressFieldLength(AddressType addrType);


};  // end class R2DNAck


class SmartDataPkt : public SmartPkt
{
    public:
        SmartDataPkt(void*          bufferPtr = NULL,
                     unsigned int   bufferBytes = 0,
                     bool           freeOnDestruct = false);
        ~SmartDataPkt();

        bool initFromBuffer(void*           bufferPtr = NULL,
                            unsigned int    numBytes = 0,
                            bool            freeOnDestruct = false);
        bool initIntoBuffer(void* bufferPtr = NULL,unsigned int bufferBytes = 0, bool freeOnDestruct  = false);
        bool setSrcIPAddr(const ProtoAddress& addr);
        bool setSrcIPAddr(AddressType addrType, const char* addrPtr, unsigned int addrLen);
        bool getSrcIPAddr(ProtoAddress& addr) const;
        bool appendNodeToPath(const ProtoAddress& addr);
        bool getPathNodeAt(UINT8 index, ProtoAddress& addr) const;
        bool pathContains(const ProtoAddress& addr);

        const void* getPayload() const
            {return GetBuffer32(offsetPayload());}

        void setPayload(const char* payload, UINT16 numBytes)
            {memcpy((char*)AccessBuffer32(offsetPayload()), payload, numBytes);}
        
        int getHeaderLengthNoPath() {return offsetPath();}




    private:
        unsigned int offsetSrcIPAddr() const  // UINT32 offset
            {return OFFSET_C_FACTOR + 1;}
        
        unsigned int offsetPayload() const  // UINT32 offset
        {
//            switch (getAddressType())
//            {
               //case ADDR_IPV4:
                return offsetPath() + 1 * (getPathLength());
//                case ADDR_IPV6:
//                    return offsetPath() + 4 * (getPathLength());
//                case ADDR_ETHER:
//                    return offsetPath() + 2 * (getPathLength());
//                default:
//                    // TBD - allow for ADDR_ETHER?
//                    return 0;

//            }
        }
        unsigned int offsetPath() const  // UINT32 offset
            {return offsetSrcIPAddr() + 1;}
};  // end class SmartDataPkt

class SmartAck : public SmartPkt
{
    public:
        SmartAck(void*          bufferPtr = NULL,
                 unsigned int   bufferBytes = 0,
                 bool           freeOnDestruct = false);
        ~SmartAck();

        bool initFromBuffer(void*           bufferPtr = NULL,
                            unsigned int    numBytes = 0,
                            bool            freeOnDestruct = false);
        bool setDstMACAddr(const ProtoAddress& addr);
        bool setSrcMACAddr(const ProtoAddress& addr);
        bool setDstIPAddr(const ProtoAddress& addr);
        bool setDstIPAddr(AddressType addrType, const char* addrPtr, unsigned int addrLen);
        void setFragmentOffset(UINT32 fragOffset)
        {
            PLOG (PL_DEBUG,"Setting frag offset of %d\n",fragOffset);
            SetWord32(offsetFragOffset(), fragOffset);
        }
        UINT32 getFragmentOffset() const
        {
            float value;
            memcpy(&value, (char*)GetBuffer32(offsetFragOffset()), 4);
            return ntohl(value);
        }
        bool getDstMACAddr(ProtoAddress& addr) const;
        bool getSrcMACAddr(ProtoAddress& addr) const;
        bool getDstIPAddr(ProtoAddress& addr) const;
        bool appendNodeToPath(const ProtoAddress& addr);
        bool getPathNodeAt(UINT8 index, ProtoAddress& addr) const;
        bool pathContains(const ProtoAddress& addr);
        bool getNextAddress(const ProtoAddress & addr, ProtoAddress& next_addr) const;
        //ProtoAddress* getPath();
        bool setPath(Path p, int numAddresses);

    private:
        unsigned int offsetPath() const
        {
            return offsetFragOffset()+1;
        }
        unsigned int offsetSrcMACAddr() const
        {
            // Returns UINT32 offset

            return OFFSET_C_FACTOR +1;
        }
        unsigned int offsetDstMACAddr() const
        {
            // Returns UINT32 offset

            return offsetSrcMACAddr() + 2; // Were going to round up here.  Theres really 6 bytes in a MAC address.
        }
        unsigned int offsetDstIPAddr() const
        {
            // Returns UINT32 offset

            return offsetDstMACAddr() + 2; // Were going to round up here.  Theres really 6 bytes in a MAC address.
        }
        unsigned int offsetFragOffset() const
        {
            return offsetDstIPAddr() + 1;
        }
};  // end class SmartAck

class SmartPathAd : public SmartPkt
{
    public:
        SmartPathAd(void*         bufferPtr = NULL,
                   unsigned int   bufferBytes = 0,
                   bool           freeOnDestruct = false);
        ~SmartPathAd();

        bool initFromBuffer(void*           bufferPtr = NULL,
                            unsigned int    numBytes = 0,
                            bool            freeOnDestruct = false);
        bool setPath( Path p, int numAddresses);
        int  getPath(ProtoAddressList& addr_list);
        bool getPathNodeAt(UINT8 index, ProtoAddress& addr) const;
    private:
        unsigned int offsetPath() const
        {
            return OFFSET_C_FACTOR+1;
        }
};

#endif // !R2DN_ACK

