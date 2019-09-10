// This the the "node test" (nt) program to exercise our node, iface, link data structures


#include "manetMsg.h"

#include <stdio.h>  // for sprintf()
#include <stdlib.h>  // for rand(), srand()

#define PACKET_SIZE_MAX 1024

#define WIDTH_MAX 300
#define HEIGHT_MAX 300

// (TBD) Probably should create a SMF message/tlv header file?

// SMF message types
enum SmfMsg
{
    SMF_RESERVED = 0,
    SMF_HELLO    = 1
};

// SMF TLV types    
enum SmfTlv
{
    SMF_TLV_RESERVED        = 0,
    SMF_TLV_RELAY_ALGORITHM = 1,
    SMF_TLV_HELLO_INTERVAL  = 2,
    SMF_TLV_RELAY_WILLING   = 3,
    SMF_TLV_LINK_STATUS     = 4,  
    SMF_TLV_MPR_SELECT      = 5,
    SMF_TLV_RTR_PRIORITY    = 6 
};
  
// SMF relay algorithm types  
enum SmfRelayAlgorithm
{
    SMF_RELAY_RESERVED  = 0,
    SMF_RELAY_CF        = 1,  
    SMF_RELAY_SMPR      = 2,
    SMF_RELAY_ECDS      = 3,
    SMF_RELAY_MPR_CDS   = 4       
};    

// SMF neighbor link states    
enum SmfLinkStatus
{
    SMF_LINK_RESERVED  = 0,
    SMF_LINK_LOST      = 1,
    SMF_LINK_HEARD     = 2,
    SMF_LINK_SYMMETRIC = 3   
};

int main(int argc, char* argv[])
{
    struct timeval currentTime;
    ProtoSystemTime(currentTime);
    srand(currentTime.tv_usec);
    
    // 1) Test the generic pkt, msg, tlv stuff
    
    // a) Instantiate an "ManetPkt" from the stack
    UINT32 buffer[PACKET_SIZE_MAX/4];
    ManetPkt pkt;
    if (!pkt.InitIntoBuffer(buffer, PACKET_SIZE_MAX)) TRACE("ManetPkt::Init() error\n");
    
    // b) Append a message to the pkt (multiple messages may go in an ManetPkt)
    //    (Note: the msg pointer returned here is invalid after another message is appended!)
    ManetMsg* msg = pkt.AppendMessage();
    if (NULL == msg)
        TRACE("ManetPkt::AppendMessage() error\n");
    // c) Set msg header fields
    msg->SetType(SMF_HELLO);
    ProtoAddress myAddr;
    myAddr.ResolveFromString("192.168.1.1");
    msg->SetOriginator(myAddr);
    
    TRACE("adding a message tlv ...\n");
    // d) Append any message tlv's ...
    ManetTlv* tlv = msg->AppendTlv(SMF_TLV_RELAY_ALGORITHM, 0);
    UINT8 relayAlgorithm = (UINT8)SMF_RELAY_SMPR;
    tlv->SetValue((char*)&relayAlgorithm, 1);  // set TLV value
    
    TRACE("adding an address block ...\n");
    // e) Add an address block 
    ManetAddrBlock* addrBlk = msg->AppendAddressBlock();
    if (NULL == addrBlk) 
        TRACE("ManetMsg::AppendAddressBlock() error\n");
    
    TRACE("setting address block head ...\n");
    ProtoAddress prefix;
    prefix.ResolveFromString("192.168.1.0");
    if (!addrBlk->SetHead(prefix, 3))
        TRACE("addrBlk.SetHead() error\n");
    
    // For testing, we add a batch of addresses w/ link status & willingness tlv's for each
    UINT8 tlvType = (UINT8)SMF_TLV_LINK_STATUS;
    UINT8 tlvSemantics = (UINT8)ManetTlv::MULTIVALUE;
    UINT32* linkStatusTlvBuffer[256];
    ManetTlv linkStatusTlv;
    linkStatusTlv.InitIntoBuffer(tlvType, tlvSemantics, (char*)linkStatusTlvBuffer, 256*sizeof(UINT32));
    linkStatusTlv.SetIndexRange(0, 7); 
    
    tlvType = (UINT8)SMF_TLV_RELAY_WILLING;
    tlvSemantics = (UINT8)ManetTlv::MULTIVALUE;
    UINT32* willingnessTlvBuffer[256];
    ManetTlv willingnessTlv;
    willingnessTlv.InitIntoBuffer(tlvType, tlvSemantics, (char*)willingnessTlvBuffer, 256*sizeof(UINT32));
    willingnessTlv.SetIndexRange(0, 7);         
                        
    for (int i = 0; i < 8; i++)
    {
        char addrString[32];
        sprintf(addrString, "192.168.1.%d", i+2);
        ProtoAddress neighbor;
        neighbor.ResolveFromString(addrString);
        addrBlk->AppendAddress(neighbor);  // should check result
        UINT8 linkStatus;
        if (0 == (i & 0x01))
            linkStatus = SMF_LINK_HEARD;
        else
            linkStatus = SMF_LINK_SYMMETRIC;
        linkStatusTlv.SetValue(linkStatus, i);
        willingnessTlv.SetValue((UINT8)i, i);
    }
    
    if (!addrBlk->AppendTlv(linkStatusTlv))
        TRACE("ManetAddrBlk::AppendTlv(linkStatusTlv) error\n");
    if (!addrBlk->AppendTlv(willingnessTlv))
        TRACE("ManetAddrBlk::AppendTlv(willingnessTlv) error\n");
    
    // Identify all nodes in block as MPRs (no index needed)
    tlv = addrBlk->AppendTlv(SMF_TLV_MPR_SELECT, ManetTlv::NO_INDEX);
    if (NULL == tlv)
        TRACE("ManetAddrBlk::AppendTlv() error\n");
    if (!tlv->SetValue((UINT8)1))  // set value to TRUE
        TRACE("ManetTlv::SetValue() error\n");
    
    /*
    // Add another address block for testing purposes
    addrBlk = msg->AppendAddressBlock();
    if (NULL == addrBlk) 
        TRACE("ManetMsg::AppendAddressBlock() error\n");
    
    prefix.ResolveFromString("192.168.2.0");
    if (!addrBlk->SetHead(prefix, 3))
        TRACE("addrBlk.SetHead() error\n");
    
    // For testing, we add a batch of addresses
    for (int i = 2; i < 6; i++)
    {
        char addrString[32];
        sprintf(addrString, "192.168.1.%d", i);
        ProtoAddress neighbor;
        neighbor.ResolveFromString(addrString);
        addrBlk->AppendAddress(neighbor);  
    }*/
    
    // f) Finally, "pack" the packet to finalize structure
    TRACE("finalizing packet ...\n");
    pkt.Pack();
    
    TRACE("pkt build completed, len:%d (mtype:%d)\n", pkt.GetLength(), msg->GetType());
    
    // OK, let's parse a "received" packet using sent "buffer" and "pktLen"
    UINT16 pktLen = pkt.GetLength();
    ManetPkt recvPkt;  // "received" packet in "buffer" already ...
    if (!recvPkt.InitFromBuffer(pktLen, buffer, PACKET_SIZE_MAX))
        TRACE("recvPkt.InitFromBuffer() error\n");
    
    // Iterate through messages ...
    ManetPkt::MsgIterator iterator(recvPkt);
    ManetMsg recvMsg;
    while (iterator.GetNextMessage(recvMsg, ProtoAddress::IPv4))
    {
        ProtoAddress origin;
        recvMsg.GetOriginator(origin);
        TRACE("Got message, type:%d len:%d origin:%s\n", 
              recvMsg.GetType(), recvMsg.GetLength(), origin.GetHostString());
        
        // Iterate through any message tlv's ...
        ManetMsg::TlvIterator iterator(recvMsg);
        ManetTlv recvTlv;
        while (iterator.GetNextTlv(recvTlv))
        {
            TRACE("   got msg-tlv, type = %d\n", recvTlv.GetType());
        }
        
        // Iterate through any address blocks
        ManetMsg::AddrBlockIterator addrBlkIterator(recvMsg);
        ManetAddrBlock recvAddrBlock;
        while (addrBlkIterator.GetNextAddressBlock(recvAddrBlock))
        {
            TRACE("   got addr block w/ %d addresses\n", recvAddrBlock.GetAddressCount());
            // Iterate through addresses in this block
            unsigned int addrCount = recvAddrBlock.GetAddressCount();
            for (unsigned int i = 0; i < addrCount; i++)
            {
                ProtoAddress addr;
                if (recvAddrBlock.GetAddress(i, addr))
                    TRACE("      addr(%u): %s\n", i, addr.GetHostString());
                else
                    TRACE("      ManetAddrBlock::GetAddress(%u) error\n", i);  
            }
            
            // Iterate through any tlv's associated with this block
            ManetAddrBlock::TlvIterator iterator(recvAddrBlock);
            while (iterator.GetNextTlv(recvTlv))
            {
                if (recvTlv.HasIndex())
                {
                    if (recvTlv.IsMultiValue())
                    {
                        UINT8 start = recvTlv.GetIndexStart();
                        UINT8 stop = recvTlv.GetIndexStop();
                        for (UINT8 i = start; i <= stop; i++)
                        {
                            TRACE("      got indexed multi-value addr-block-tlv, "
                                  "index = %d, type = %d\n", i, recvTlv.GetType());
                            switch (recvTlv.GetType())
                            {
                                case SMF_TLV_LINK_STATUS:
                                {
                                    UINT8 status;
                                    recvTlv.GetValue(status, i);
                                    TRACE("         (link status = %d)\n", status);
                                }   
                                case SMF_TLV_RELAY_WILLING:
                                {
                                    UINT8 willingness;
                                    recvTlv.GetValue(willingness, i);
                                    TRACE("         (willingness = %d)\n", willingness);
                                }   
                                default:
                                    break;
                            }   
                        }
                    }
                    else
                    {
                       TRACE("      got indexed single-value addr-block-tlv, type = %d\n", 
                             recvTlv.GetType());
                    }
                }
                else
                {
                    ASSERT(!recvTlv.IsMultiValue());
                    TRACE("      got non-indexed addr-block-tlv, type = %d\n", recvTlv.GetType());
                }
            }
        }
    }
    TRACE("receive packet parsing completed\n");
    
    return 0;
}  // end main()
