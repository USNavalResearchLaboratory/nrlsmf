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
 * The worker parses each read. Group changes are a delta. The full
 * IGMP-up interface set is handed over on every successful poll so the
 * main thread can reconcile it with the interfaces SMF still has.
 *
 */

class SmfIgmp : public ProtoChannel
{
    public:
        using MembershipMap = std::map<std::uint32_t, std::set<ProtoAddress>>;
        using MembershipChangeArray = std::vector<std::tuple<ProtoAddress, bool, std::uint32_t>>;
        using InterfacesMap = std::map<std::uint32_t, std::pair<std::string, bool>>;
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
            {return have_fresh_interfaces;}
        // Latest IGMP-up interfaces from the worker. Main thread only.
        bool TakeInterfaceSnapshot(InterfacesMap& out);
        InterfacesMap ActiveInterfaces() const
            {return active_interfaces;}
        void SetActiveInterfaces(const InterfacesMap& next)
            {active_interfaces = next;}

        std::vector<std::tuple<std::string, std::string>> NewNetworkInterface(const std::string& ifaceName) const;

    private:
        struct Handoff
        {
            bool have_interfaces;
            InterfacesMap interface_table;
            MembershipChangeArray membership_changes;
            Handoff() : have_interfaces(false) {}
        };

        void PollLoop();
        void StopPollThread();
        bool Stopping();
        bool CollectInterfaces(InterfacesMap& out);
        bool CollectMemberships(MembershipMap& out);
        static void DiffMemberships(const MembershipMap& previous, const MembershipMap& current,
                                    MembershipChangeArray& changes);

        int wpipe;
        MembershipChangeArray membership_changes;
        InterfacesMap active_interfaces;
        bool have_fresh_interfaces;
        InterfacesMap fresh_interfaces;

        std::mutex mu;
        std::condition_variable cv;
        bool stop;
        bool notify_armed;
        Handoff pending;
        std::thread poll_thread;
};

#endif // _SMF_IGMP

#endif // ELASTIC_MCAST
