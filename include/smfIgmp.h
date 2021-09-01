#ifdef ELASTIC_MCAST

#ifndef _SMF_IGMP
#define _SMF_IGMP

#include "smf.h"
#include <map>
#include <set>
#include <vector>
#include <sstream>
#include <unistd.h>
#include <protoChannel.h>
#include <protoDebug.h>
#include <protoTimer.h>
#include <protoAddress.h>

/**
 * @class SmfIgmp
 *
 * @brief This class can deploy a variety of methods to determine IGMP join information
 * and sends updates to the SMF core via a pipe. It uses a timer to periodically check
 * IGMP state in FRR to discover IGMP membership changes and sends those updates to the pipe
 * to notify the smf core app. The core app uses the GetMemeberUpdates interface to retrieve
 * a list of all group memberships that have been added/removed in the last update
 *
 */

class SmfIgmp : public ProtoChannel
{
    using GroupMap = std::map<std::uint32_t, std::set<ProtoAddress>>;
    using GroupChangeArray = std::vector<std::tuple<ProtoAddress, bool, std::uint32_t>>;

    public:
        SmfIgmp(ProtoTimerMgr& timerMgr, Smf& _smf);
        ~SmfIgmp();

        virtual bool Open(bool withFRR);
        virtual void Close();
        virtual bool IsOpen() const;

        GroupChangeArray GetMembershipUpdates();

    private:
        void DoUpdate(ProtoTimer& theTimer);
        void UpdateInterfaces();
        void UpdateMemberships();
        bool FindChanges(const GroupMap& currentGroups);

        int wpipe;
        ProtoTimerMgr& timer_mgr;
        Smf& smf;
        ProtoTimer update_timer;
        GroupMap previous_groups;
        GroupChangeArray group_changes;
        std::map<std::uint32_t, bool> active_interfaces;
};

#endif // _SMF_IGMP

#endif // ELASTIC_MCAST