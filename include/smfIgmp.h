#ifdef ELASTIC_MCAST

#ifndef _SMF_IGMP
#define _SMF_IGMP

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
    using GroupMap = std::map<std::string, std::set<ProtoAddress>>;
    using GroupChangeArray = std::vector<std::tuple<ProtoAddress, bool, std::uint32_t>>;

    public:
        SmfIgmp(ProtoTimerMgr& timerMgr);
        ~SmfIgmp();

        virtual bool Open();
        virtual void Close();
        virtual bool IsOpen() const;

        GroupChangeArray GetMembershipUpdates();

    private:
        void DoUpdate(ProtoTimer& theTimer);
        bool FindChanges(const GroupMap& currentGroups);
        unsigned int GetInterfaceIndex(const std::string& iface);

        int wpipe;
        ProtoTimerMgr& timer_mgr;
        ProtoTimer update_timer;
        GroupMap previous_groups;
        GroupChangeArray group_changes;
        std::map<std::string, unsigned int> iface_index_cache;
};

#endif // _SMF_IGMP

#endif // ELASTIC_MCAST