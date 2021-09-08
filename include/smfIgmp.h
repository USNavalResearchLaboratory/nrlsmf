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
    using MembershipMap = std::map<std::uint32_t, std::set<ProtoAddress>>;
    using MembershipChangeArray = std::vector<std::tuple<ProtoAddress, bool, std::uint32_t>>;
    using InterfacesMap = std::map<std::uint32_t, std::pair<std::string, bool>>;

    public:
        SmfIgmp(ProtoTimerMgr& timerMgr, Smf& _smf);
        ~SmfIgmp();

        virtual bool Open(bool withFRR);
        virtual void Close();
        virtual bool IsOpen() const;

        void ProcessUpdates();
        bool HasMembershipUpdates() const 
            {return !membership_changes.empty();}
        MembershipChangeArray GetMembershipUpdates()
            {return std::move(membership_changes);}
        bool HasInterfaceUpdates() const
            {return !interface_changes.empty();}
        InterfacesMap GetInterfaceUpdates()
            {return std::move(interface_changes);}

        std::vector<std::tuple<std::string, std::string>> NewManetInterface(const std::string& ifaceName) const;

    private:
        void DoUpdate(ProtoTimer& theTimer);
        void UpdateInterfaces();
        void UpdateMemberships();

        int wpipe;
        ProtoTimerMgr& timer_mgr;
        Smf& smf;
        ProtoTimer update_timer;
        MembershipMap active_memberships;
        MembershipChangeArray membership_changes;
        InterfacesMap active_interfaces;
        InterfacesMap interface_changes;
};

#endif // _SMF_IGMP

#endif // ELASTIC_MCAST