#ifndef __FRR_VTY
#define __FRR_VTY

#include <string>
#include <stdexcept>
#include <vector>
#include "protoPipe.h"

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
        std::pair<std::string, std::int8_t> ret = {"", -1};
        unsigned int sz = cmd.size() + 1;
        if (!sock.Send(cmd.c_str(), sz) || sz != (cmd.size() + 1))
        {
            return ret;
        }

        char buf[2048];
        sz = 2048;
        if (!sock.Recv(buf, sz))
        {
            return ret;
        }

        // A valid response will have a minimum of 4 bytes, and must end with 3 null charactors and the return code
        if (sz >= 4 && buf[sz-4] == 0 && buf[sz-3] == 0 && buf[sz-2] == 0)
        {
            if (sz > 4)
            {
                ret.first.assign(buf, sz - 4);
            }
            ret.second = buf[sz-1];
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