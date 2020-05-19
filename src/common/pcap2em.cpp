
// This program parses PCAP files and builds a trace of per-flow Elastic Multicast EM-ACK
// activity that can be used for analytics of Elastic Multicast performance.

#include "protoFile.h"
#include "protoString.h"  // for ProtoTokenator
#include "protoPktETH.h"
#include "protoPktIP.h"
#include "elasticMsg.h"
#include "flowTable.h"
#include <pcap.h>
#include <stdio.h>

void Usage()
{
    fprintf(stderr, "Usage: pcap2emtrace <file/directory 1> [file/directory 2> ...]\n");
}

int main(int argc, char* argv[])
{
    FILE* outfile = stdout;
    
    for (int i = 1; i < argc; i++)
    {
        ProtoFile::DirectoryIterator diterator;
        if (!diterator.Open(argv[i]))
        {
            fprintf(stderr, "pcap2emtrace error: unable to open \"%s\"\n", argv[1]);
            return -1;
        }
        char path[PATH_MAX+1];
        path[PATH_MAX] = '\0';
        while (diterator.GetNextPath(path))
        {
            // Look for .pcap files ...
            ProtoTokenator tk(path, '.', true, 1, true);  // single reverse split to get file extension
            if (0 != strcmp("pcap", tk.GetNextItem()))
                continue;
            char pcapErrBuf[PCAP_ERRBUF_SIZE+1];
            pcapErrBuf[PCAP_ERRBUF_SIZE] = '\0';
            pcap_t* pcapDevice = pcap_open_offline(path, pcapErrBuf);
            if (NULL == pcapDevice)
            {
                fprintf(stderr, "pcap2mgen: pcap_fopen_offline() error: %s\n", pcapErrBuf);
                return -1;
            }
            UINT32 alignedBuffer[4096/4];   // 128 buffer for packet parsing
            UINT16* ethBuffer = ((UINT16*)alignedBuffer) + 1; 
            unsigned int maxBytes = 4096 - 2;  // due to offset, can only use 4094 bytes of buffer

            pcap_pkthdr hdr;
            const u_char* pktData;
            while(NULL != (pktData = pcap_next(pcapDevice, &hdr)))
            {
                unsigned int numBytes = maxBytes;
                if (hdr.caplen < numBytes) numBytes = hdr.caplen;
                memcpy(ethBuffer, pktData, numBytes);
                ProtoPktETH ethPkt(ethBuffer, maxBytes);
                if (!ethPkt.InitFromBuffer(hdr.len))
                {
                    fprintf(stderr, "pcap2emtrace error: invalid Ether frame in pcap file\n");
                    continue;
                }    
                ProtoPktIP ipPkt;
                ProtoAddress srcAddr, dstAddr;
                ProtoPktETH::Type ethType = ethPkt.GetType();
                if ((ProtoPktETH::IP == ethType) ||
                    (ProtoPktETH::IPv6 == ethType))
                {
                    unsigned int payloadLength = ethPkt.GetPayloadLength();
                    if (!ipPkt.InitFromBuffer(payloadLength, ethPkt.AccessPayload(), payloadLength))
                    {
                        fprintf(stderr, "pcap2mgen error: bad IP packet\n");
                        continue;
                    }
                    switch (ipPkt.GetVersion())
                    {
                        case 4:
                        {
                            ProtoPktIPv4 ip4Pkt(ipPkt);
                            ip4Pkt.GetDstAddr(dstAddr);
                            ip4Pkt.GetSrcAddr(srcAddr);
                            break;
                        } 
                        case 6:
                        {
                            ProtoPktIPv6 ip6Pkt(ipPkt);
                            ip6Pkt.GetDstAddr(dstAddr);
                            ip6Pkt.GetSrcAddr(srcAddr);
                            break;
                        }
                        default:
                        {
                            fprintf(stderr,"pcap2emtrace error: Invalid IP pkt version.\n");
                            break;
                        }
                    }
                }
                if (!srcAddr.IsValid()) continue;  // wasn't an IP packet
                ProtoPktUDP udpPkt;
                if (!udpPkt.InitFromPacket(ipPkt)) continue;  // not a UDP packet
            
                if (ElasticMsg::ELASTIC_PORT != udpPkt.GetDstPort())
                    continue;  // not an Elastic Multicast message
                else if (!dstAddr.HostIsEqual(ElasticMsg::ELASTIC_ADDR))
                    fprintf(stderr, "pcap2emtrace warning: EM message to non-standard address\n");
                ElasticMsg emsg;
                if (!emsg.InitFromBuffer(udpPkt.AccessPayload(), udpPkt.GetPayloadLength()))
                {
                    fprintf(stderr, "pcap2emtrace warning: invalid EM/UDP message\n");
                    continue;
                }
                if (ElasticMsg::ACK != emsg.GetType())
                    continue;  // only trace ACKs for now
                
                ElasticAck ack(emsg);
                if (!ack.IsValid())
                {
                    fprintf(stderr, "pcap2emtrace warning: invalid EM-ACK message\n");
                    continue;
                }
                fprintf(outfile, "%lu.%06lu EM-ACK ", (unsigned long)hdr.ts.tv_sec, (unsigned long)hdr.ts.tv_usec);
                ProtoAddress ethAddr;
                ethPkt.GetSrcAddr(ethAddr);
                fprintf(outfile, "esrc>%s ", ethAddr.GetHostString());
                ethPkt.GetDstAddr(ethAddr);
                fprintf(outfile, "edst>%s ", ethAddr.GetHostString());
                fprintf(outfile, "src>%s ", srcAddr.GetHostString());
                ProtoAddress upstreamAddr;
                ack.GetUpstreamAddr(0, upstreamAddr);
                if (!upstreamAddr.HostIsEqual(ethAddr))
                    fprintf(outfile, "upstream>%s ", upstreamAddr.GetHostString());
                // Pull out the flow description
                ProtoAddress dstIp, srcIp;
                ack.GetDstAddr(dstIp);
                ack.GetSrcAddr(srcIp);
                UINT8 trafficClass = ack.GetTrafficClass();
                ProtoPktIP::Protocol protocol = ack.GetProtocol();
                FlowDescription flowDescription(dstIp, srcIp, trafficClass, protocol);
                flowDescription.Print(outfile);
                
                fprintf(outfile, " len>%u ", ack.GetLength());
                fprintf(outfile, "\n");
                
            }  // end while pcap_next()
        }  // end while diterator.GetNextPath() 
    }  // end for (i < argc)
}  // end main()
