#ifdef ELASTIC_MCAST

#ifndef _SMF_IGMP
#define _SMF_IGMP

#include "smf.h"
#include <map>
#include <set>
#include <vector>
#include <sstream>
#include <unistd.h>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <protoChannel.h>
#include <protoDebug.h>
#include <protoAddress.h>

/**
 * @class SmfIgmp
 *
 * @brief Polls FRR for IGMP interface and group state. The poll runs on its
 * own thread so a slow pimd reply does not stall the SMF control socket.
 * The worker diffs each successful read and hands the main thread only
 * the added and removed interfaces and groups. The core app applies that
 * list.
 *
 */

class SmfIgmp : public ProtoChannel
{
    using MembershipMap = std::map<std::uint32_t, std::set<ProtoAddress>>;
    using MembershipChangeArray = std::vector<std::tuple<ProtoAddress, bool, std::uint32_t>>;
    using InterfacesMap = std::map<std::uint32_t, std::pair<std::string, bool>>;

    public:
        SmfIgmp();
        ~SmfIgmp();

        virtual bool Open(bool withFRR);
        virtual void Close();
        virtual bool IsOpen() const;
        // Start polling FRR PIM for IGMP ifaces/groups.
        // Safe after Open(false) so "with-frr" can be sent at runtime.
        void EnableFrrPolling();

        void ProcessUpdates();
        bool HasMembershipUpdates() const
            {return !membership_changes.empty();}
        MembershipChangeArray GetMembershipUpdates()
            {return std::move(membership_changes);}
        bool HasInterfaceUpdates() const
            {return !interface_changes.empty();}
        InterfacesMap GetInterfaceUpdates()
            {return std::move(interface_changes);}

        std::vector<std::tuple<std::string, std::string>> NewNetworkInterface(const std::string& ifaceName) const;

    private:
        struct Handoff
        {
            InterfacesMap interface_changes;
            MembershipChangeArray membership_changes;
        };

        void PollLoop();
        void StopPollThread();
        bool Stopping();
        bool CollectInterfaces(InterfacesMap& out);
        bool CollectMemberships(MembershipMap& out);
        static void DiffInterfaces(const InterfacesMap& previous, const InterfacesMap& current,
                                   InterfacesMap& changes);
        static void DiffMemberships(MembershipMap& previous, const MembershipMap& current,
                                    MembershipChangeArray& changes);

        int wpipe;
        MembershipChangeArray membership_changes;
        InterfacesMap active_interfaces;
        InterfacesMap interface_changes;

        std::mutex mu;
        std::condition_variable cv;
        bool stop;
        bool notify_armed;
        Handoff pending;
        std::thread poll_thread;
};

#endif // _SMF_IGMP

#endif // ELASTIC_MCAST
