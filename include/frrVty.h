#ifndef __FRR_VTY
#define __FRR_VTY

#include <string>
#include <stdexcept>
#include <vector>
#include <cstdint>
#include "protoPipe.h"
#include "protoDebug.h"
#ifndef WIN32
#include <sys/select.h>
#include <sys/time.h>
#include <ctime>
#endif

/* Cap a single VTY exchange. A blocking recv with no deadline leaves
 * the SMF control socket unread, so queued datagrams can fill and the
 * peer send can stall until this reply arrives -- or never does.
 */
#ifndef FRR_VTY_REPLY_TIMEOUT_SEC
#define FRR_VTY_REPLY_TIMEOUT_SEC 8
#endif

// This file contains a collection of functions to help with communicating
// to FRR through the VTY socket interface
namespace FRR
{
    enum Daemon {Zebra,OSPF,PIM};

    static std::string GetDaemonVtyPath(Daemon d)
    {
        static const std::string VTY_BASE = "/var/run/frr/";
        switch (d)
        {
            case Zebra: return VTY_BASE + "zebra.vty";
            case OSPF: return VTY_BASE + "ospfd.vty";
            case PIM: return VTY_BASE + "pimd.vty";
            default: throw std::runtime_error("Unknown FRR Daemon");
        }
    }

    // Sends the command to the protopipe socket, parses out the response from the frr daemon
    static std::pair<std::string, std::int16_t> DoVtyCommand(ProtoPipe& sock, const std::string& cmd)
    {
        unsigned int sz = cmd.size() + 1;
        if (!sock.Send(cmd.c_str(), sz) || sz != (cmd.size() + 1))
        {
            return std::make_pair("", -1);
        }

        std::pair<std::string, std::int8_t> ret = {"", -1};
        // Make sure we have allocated at least 16K to help make sure we don't have to reallocate while receiving the reply
        if (ret.first.capacity() < 16536)
        {
            ret.first.reserve(16536);
        }

        // Continue receiving until we get the end of reply signal, 3 null bytes + 1 return code byte
#ifndef WIN32
        const time_t deadline = time(NULL) + FRR_VTY_REPLY_TIMEOUT_SEC;
#endif
        while (true)
        {
#ifndef WIN32
            {
                fd_set fds;
                struct timeval tv;
                const time_t now = time(NULL);
                const int fd = sock.GetHandle();

                if (now >= deadline || fd < 0)
                {
                    PLOG(PL_ERROR, "FRR::DoVtyCommand() timeout waiting for reply to \"%s\"\n",
                         cmd.c_str());
                    return std::make_pair("", -1);
                }
                FD_ZERO(&fds);
                FD_SET(fd, &fds);
                tv.tv_sec = deadline - now;
                tv.tv_usec = 0;
                if (select(fd + 1, &fds, NULL, NULL, &tv) <= 0 || !FD_ISSET(fd, &fds))
                {
                    PLOG(PL_ERROR, "FRR::DoVtyCommand() timeout waiting for reply to \"%s\"\n",
                         cmd.c_str());
                    return std::make_pair("", -1);
                }
            }
#endif
            char buf[2048];
            sz = 2048;
            if (!sock.Recv(buf, sz))
            {
                return std::make_pair("", -1);
            }

            if (sz == 0)
            {
                PLOG(PL_ERROR, "FRR::DoVtyCommand() peer closed during \"%s\"\n", cmd.c_str());
                return std::make_pair("", -1);
            }

            if (sz > 0)
            {
                // Check for the end of the response signal
                if (sz >= 4 && buf[sz-4] == 0 && buf[sz-3] == 0 && buf[sz-2] == 0)
                {
                    ret.first.append(buf, sz-4); // Don't copy the null bytes or return code
                    ret.second = buf[sz-1];
                    break;
                }
                else
                {
                    ret.first.append(buf, sz);
                }
            }
        }
        return ret;
    }

    // Open a protopipe (local unix) stream socket to the given daemon
    // Run each command given, returns at the first failure, or the result of the last command
    static std::pair<std::string, std::int8_t> FRRVty(Daemon d, const std::vector<std::string>& cmds)
    {
        std::pair<std::string, std::int8_t> ret = {"", -1};
        ProtoPipe sock(ProtoPipe::STREAM);
        if (!sock.Connect(GetDaemonVtyPath(d).c_str()))
        {
            return ret;
        }
        for (const auto& c : cmds)
        {
            ret = DoVtyCommand(sock, c);
            if (ret.second != 0)
            {
                return ret;
            }
        }
        sock.SetState(ProtoSocket::IDLE);
        sock.Close();
        return ret;
    }
}

#endif