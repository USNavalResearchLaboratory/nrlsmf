#include "smfIgmp.h"
#include "frrVty.h"
#include <regex>
#include <set>
#include <protoNet.h>

SmfIgmp::SmfIgmp(ProtoTimerMgr& timerMgr) :
    ProtoChannel(),
    wpipe(INVALID_HANDLE),
    timer_mgr(timerMgr),
    update_timer(),
    previous_groups(),
    group_changes(),
    iface_index_cache()
{
    update_timer.SetInterval(5.0);
    update_timer.SetRepeat(-1);
    update_timer.SetListener(this, &SmfIgmp::DoUpdate);
}

SmfIgmp::~SmfIgmp() {}

bool SmfIgmp::Open(bool withFRR)
{
    // Open the pipe here and set descriptor
    int p[2];
    if (pipe(p) < 0)
    {
        PLOG(PL_ERROR, "SmfIgmp::Open() pipe() error: %s\n", GetErrorString());
        return false;
    }

    descriptor = p[0]; // For reading in SMF core app
    wpipe = p[1]; // For writing IGMP updates locally

    if (withFRR && !update_timer.IsActive())
    {
        timer_mgr.ActivateTimer(update_timer);
    }

    // This must be called at the end of the Open
    if (!ProtoChannel::Open())
    {
        PLOG(PL_ERROR, "SmfIgmp::Open() Failed to open ProtoChannel\n");
        Close();
        return false;
    }
    return true;
}

void SmfIgmp::Close()
{
    // This must be called first
    ProtoChannel::Close();

    if (update_timer.IsActive())
    {
        update_timer.Deactivate();
    }

    // Close the pipe
    close(descriptor);
    descriptor = INVALID_HANDLE;
    close(wpipe);
    wpipe = INVALID_HANDLE;
}

bool SmfIgmp::IsOpen() const
{
    return ProtoChannel::IsOpen() && wpipe != INVALID_HANDLE;
}

SmfIgmp::GroupChangeArray SmfIgmp::GetMembershipUpdates()
{
    char c[2];
    if (read(descriptor, c, 2) == -1)
    {
        PLOG(PL_ERROR, "SmfIgmp::GetMembershipUpdates() Failed to read from pipe, %s\n", GetErrorString());
    }
    // This will invalidate the current group_changes, moving the contents rather than copying them.
    return std::move(group_changes);
}

void SmfIgmp::DoUpdate(ProtoTimer& theTimer)
{
    std::pair<std::string, std::int8_t> ret = FRR::FRRVty(FRR::PIM, {"enable","show ip igmp groups"});
    if (ret.second != 0)
    {
        PLOG(PL_ERROR, "SmfIgmp::DoUpdate() Failed to retrieve group information from FRR-PIM\n");
        return;
    }

    // Example output from FRR-PIM
    // # show ip igmp groups
    // Total IGMP groups: 1
    // Watermark warn limit(Not Set): 0
    // Interface        Address         Group           Mode Timer    Srcs V Uptime
    // eth1             192.168.229.87  239.255.255.250 EXCL 00:03:11    1 3 03:34:01
    // ***** Older FRR output may be
    // # show ip igmp groups
    // Interface        Address         Group           Mode Timer    Srcs V Uptime
    // eth1             192.168.229.87  239.255.255.250 EXCL 00:03:11    1 3 03:34:01
    PLOG(PL_DEBUG, "SmfIgmp::DoUpdate() Current IGMP Groups\n%s\n", ret.first.c_str());
    std::istringstream iss(ret.first);
    std::string line;
    int totalGroups = 0;
    GroupMap currentGroups;
    int groupCnt = 0;
    bool inList = false;
    while (std::getline(iss, line))
    {
        if (!inList)
        { // Haven't found the header line that preceeds the group list, so look for that
            // First look for the total groups info if we haven't found it already
            if (totalGroups == 0 && line.find("Total IGMP groups:") != std::string::npos)
            {
                totalGroups = std::stoi(line.substr(19));
            }
            inList = (line.find("Interface") != std::string::npos);
        }
        else
        { // Found the header line already, the rest of the lines should be group information
            // Parse the line field by field to get the information we need.
            std::string iface;
            ProtoAddress groupAddr;
            std::istringstream liness(line);
            std::string lpart;
            int field = 0;
            while(std::getline(liness, lpart, ' '))
            {
                if (!lpart.empty()) // Ignore extra white space between fields
                {
                    if (++field == 1)
                    { // This is the interface name
                        iface = lpart;
                    }
                    else if (field == 3)
                    { // This is the group address
                        groupAddr = ProtoAddress(lpart.c_str());
                    }
                    // We don't care about the rest of the fields, if the group is listed, then there is at least one interested receiver
                    // for that group on that interface.
                }
            }
            if (groupAddr.IsMulticast()) // Sanity check that we parsed a multicast group address
            {
                ++groupCnt;
                currentGroups[iface].emplace(groupAddr);
            }
        }
    }

    if (totalGroups != 0 && totalGroups != groupCnt) // Only check the total if we found that information in the output
    {
        PLOG(PL_ERROR, "SmfIgmp::DoUpdate() Total number of groups does not match the number parsed\n");
        return;
    }

    // Find difference between previous state and the current state
    // This function will set the group_changes if any differences are found
    // Returns true if there are changes to be handled
    if (FindChanges(currentGroups))
    { // There were changes, send a signal on the pipe
        char c;
        if (write(wpipe, &c, 1) == -1)
        {
            PLOG(PL_ERROR, "SmfIgmp::DoUpdate() Failed to write to pipe, %s\n", GetErrorString());
        }
    }
}

bool SmfIgmp::FindChanges(const GroupMap& currentGroups)
{
    auto pit = previous_groups.begin();
    auto cit = currentGroups.begin();
    while (true)
    {
        if (pit == previous_groups.end() && cit == currentGroups.end())
        { // Reached the end of both, break loop
            break;
        }
        else if (pit == previous_groups.end())
        { // End of previous groups, anything left in current groups is new
            unsigned int idx = GetInterfaceIndex(cit->first);
            if (idx == 0)
            {
                PLOG(PL_ERROR, "SmfIgmp::FindChanges() Failed to get index for interface %s\n", cit->first.c_str());
                cit = std::next(cit);
                continue;
            }

            for (const auto& i : cit->second)
            { // Add all groups as new for this interface
                group_changes.emplace_back(i, true, idx);
            }
            cit = std::next(cit);
        }
        else if (cit == currentGroups.end())
        { // End of current groups, anything left in previous groups is removed
            unsigned int idx = GetInterfaceIndex(pit->first);
            if (idx == 0)
            {
                PLOG(PL_ERROR, "SmfIgmp::FindChanges() Failed to get index for interface %s\n", pit->first.c_str());
                pit = std::next(pit);
                continue;
            }

            for (const auto& i : pit->second)
            { // Add all groups as removed for this interface
                group_changes.emplace_back(i, false, idx);
            }
            pit = std::next(pit);
        }
        else if (pit->first < cit->first)
        { // Previous iface is less than current, means the iface was removed
            unsigned int idx = GetInterfaceIndex(pit->first);
            if (idx == 0)
            {
                PLOG(PL_ERROR, "SmfIgmp::FindChanges() Failed to get index for interface %s\n", pit->first.c_str());
                pit = std::next(pit);
                continue;
            }

            for (const auto& i : pit->second)
            { // Add all groups as removed for this interface
                group_changes.emplace_back(i, false, idx);
            }
            pit = std::next(pit);
        }
        else if (pit->first > cit->first)
        { // Current iface is less than previous, means the iface was added
            unsigned int idx = GetInterfaceIndex(cit->first);
            if (idx == 0)
            {
                PLOG(PL_ERROR, "SmfIgmp::FindChanges() Failed to get index for interface %s\n", cit->first.c_str());
                cit = std::next(cit);
                continue;
            }

            for (const auto& i : cit->second)
            { // Add all groups as added for this interface
                group_changes.emplace_back(i, true, idx);
            }
            cit = std::next(cit);
        }
        else
        { // Same interface, look at groups to find differences
            unsigned int idx = GetInterfaceIndex(pit->first);
            if (idx == 0)
            {
                PLOG(PL_ERROR, "SmfIgmp::FindChanges() Failed to get index for interface %s\n", cit->first.c_str());
                pit = std::next(pit);
                cit = std::next(cit);
                continue;
            }

            auto pgit = pit->second.begin();
            auto cgit = cit->second.begin();
            while (true)
            {
                if (pgit == pit->second.end() && cgit == cit->second.end())
                {
                    break;
                }
                else if (pgit == pit->second.end())
                { // Anything left in current groups is new
                    group_changes.emplace_back(*cgit, true, idx);
                    cgit = std::next(cgit);
                }
                else if (cgit == cit->second.end())
                { // Anything left in previous groups is removed
                    group_changes.emplace_back(*pgit, false, idx);
                    pgit = std::next(pgit);
                }
                else if (*pgit < *cgit)
                { // Previous group is less than current, means previous group is removed
                    group_changes.emplace_back(*pgit, false, idx);
                    // Advance previous group only
                    pgit = std::next(pgit);
                }
                else if (*pgit > *cgit)
                { // Current group is less than previous, means current group is new
                    group_changes.emplace_back(*cgit, true, idx);
                    // Advance current group only
                    cgit = std::next(cgit);
                }
                else
                { // Last option is both are the same, nothing to do but advance both
                    pgit = std::next(pgit);
                    cgit = std::next(cgit);
                }
            }
            pit = std::next(pit);
            cit = std::next(cit);
        }
    }

    previous_groups = std::move(currentGroups);
    return !group_changes.empty();
}

unsigned int SmfIgmp::GetInterfaceIndex(const std::string& iface)
{
    auto it = iface_index_cache.find(iface);
    if (it == iface_index_cache.end())
    {
        // Not found, find the index for this interface and store it in the cache
        unsigned int idx = ProtoNet::GetInterfaceIndex(iface.c_str());
        if (idx == 0)
        {
            PLOG(PL_ERROR, "SmfIgmp::GetInterfaceIndex() Failed to get index for interface %s\n", iface.c_str());
            return 0;
        }
        it = iface_index_cache.emplace(iface, idx).first;
        it->second = idx; // Make sure it's set
    }
    return it->second;
}