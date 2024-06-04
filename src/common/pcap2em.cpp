
// This program parses PCAP files and builds a trace of per-flow Elastic Multicast 
// activity that can be used for analytics of Elastic Multicast performance.

#include "protoFile.h"
#include "protoString.h"  // for ProtoTokenator
#include "protoPktETH.h"
#include "protoPktIP.h"
#include "elasticMsg.h"
#include "protoFlow.h"
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
                continue;
            }
            fprintf(stderr, "pcap2em: processing %s ....\n", path);
            UINT32 alignedBuffer[16384/4];   // 128 buffer for packet parsing
            UINT16* ethBuffer = ((UINT16*)alignedBuffer) + 1; 
            unsigned int maxBytes = 16384 - 2;  // due to offset, can only use 4094 bytes of buffer

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
                    fprintf(stderr, "pcap2emtrace error: invalid Ether frame in pcap file \"%s\" %u/%u\n", 
                            path, maxBytes, (unsigned)hdr.len);
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
                if (!udpPkt.InitFromPacket(ipPkt)) 
                {
                    continue;  // not a UDP packet
                }
            
                
                // TBD - change this code to allow for EM message bundling of any type
                
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
                
                switch (emsg.GetType())
                {
                    case ElasticMsg::ACK:
                        fprintf(outfile, "%lu.%06lu EM-ACK  ", (unsigned long)hdr.ts.tv_sec, (unsigned long)hdr.ts.tv_usec);
                        break;
                    case ElasticMsg::ADV:
                        fprintf(outfile, "%lu.%06lu EM-ADV  ", (unsigned long)hdr.ts.tv_sec, (unsigned long)hdr.ts.tv_usec);
                        break;
                    case ElasticMsg::NACK:
                        fprintf(outfile, "%lu.%06lu EM-NACK ", (unsigned long)hdr.ts.tv_sec, (unsigned long)hdr.ts.tv_usec);
                        break;
                    default:
                        fprintf(stderr, "pcap2emtrace warning: invalid EM message type\n");
                        continue;
                }
                ProtoAddress ethAddr;
                ethPkt.GetSrcAddr(ethAddr);
                fprintf(outfile, "esrc>%s ", ethAddr.GetHostString());
                ethPkt.GetDstAddr(ethAddr);
                fprintf(outfile, "edst>%s ", ethAddr.GetHostString());
                fprintf(outfile, "src>%s ", srcAddr.GetHostString());
                switch (emsg.GetType())
                {
                    case ElasticMsg::ACK:
                    {
                        ElasticAck ack(emsg);
                        if (!ack.IsValid())
                        {
                            fprintf(outfile, "(invalid msg)\n");
                            fprintf(stderr, "pcap2emtrace warning: invalid EM-ACK message\n");
                            continue;
                        }
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
                        ProtoFlow::Description flowDescription(dstIp, srcIp, trafficClass, protocol);
                        fprintf(outfile, "flow>");
                        flowDescription.Print(outfile);
                        fprintf(outfile, "\n");
                        break;
                    }
                    case ElasticMsg::ADV:
                    {
                        char* bufptr = (char*)udpPkt.AccessPayload();
                        unsigned int buflen = udpPkt.GetPayloadLength();
                        unsigned int index = 0;
                        ElasticAdv adv;
                        
                        bool first = true;
                        while (index < buflen)
                        {
                            if (!first) fprintf(outfile, "; ");  // semi-colon EM_ADV item delimiter
                    
                            if (!adv.InitFromBuffer(bufptr + index, buflen - index))
                            {
                                fprintf(outfile, " malformed");
                                break;
                            }   
                            fprintf(outfile, "flow>");
                            ProtoAddress dstIp, srcIp;
                            adv.GetDstAddr(dstIp);
                            adv.GetSrcAddr(srcIp);
                            UINT8 trafficClass = adv.GetTrafficClass();
                            ProtoPktIP::Protocol protocol = adv.GetProtocol();
                            ProtoFlow::Description flowDescription(dstIp, srcIp, trafficClass, protocol);
                            flowDescription.Print(outfile);
                            fprintf(outfile, " ttl>%u hops>%u metric>%lf", adv.GetTTL(), adv.GetHopCount(), adv.GetMetric());
                            ProtoAddress advAddr;
                            adv.GetAdvAddr(advAddr);
                            fprintf(outfile, " adv>%s id>%hu", advAddr.GetHostString(), adv.GetId());
                            index += adv.GetLength();
                        }
                        fprintf(outfile, "\n");
                        break;    
                    }
                    case ElasticMsg::NACK:
                    {
                        ElasticNack nack(emsg);
                        ProtoAddress upstreamAddr;
                        nack.GetUpstreamAddress(upstreamAddr);
                        UINT16 start = nack.GetSeqStart();
                        UINT16 stop = nack.GetSeqStop();
                        UINT16 count = stop - start + 1;
                        fprintf(outfile, "dst>%s start>%hu stop>%hu count:%u\n", upstreamAddr.GetHostString(), start, stop, count);
                        fprintf(outfile, "\n");
                        break;
                    }
                    default:
                        // won't get here because of previous check
                        break;
                }
                
            }  // end while pcap_next()
        }  // end while diterator.GetNextPath() 
    }  // end for (i < argc)
}  // end main()
