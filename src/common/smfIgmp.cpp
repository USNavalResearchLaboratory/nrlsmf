#include "smfIgmp.h"
#include "frrVty.h"
#include <regex>
#include <set>
#include <protoJson.h>
#include <iostream>

SmfIgmp::SmfIgmp(ProtoTimerMgr& timerMgr, Smf& _smf) :
    ProtoChannel(),
    wpipe(INVALID_HANDLE),
    timer_mgr(timerMgr),
    smf(_smf),
    update_timer(),
    previous_groups(),
    group_changes(),
    active_interfaces()
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

    if (withFRR)
    { // Using FRR, so active the timer to check FRR
        if (!update_timer.IsActive())
        {
            timer_mgr.ActivateTimer(update_timer);
        }
    }
    else if (update_timer.IsActive())
    { // Not using FRR, so make sure the timer is inactive
        update_timer.Deactivate();
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
    UpdateInterfaces();
    UpdateMemberships();
}

void SmfIgmp::UpdateInterfaces()
{
    std::pair<std::string, std::int8_t> ret = FRR::FRRVty(FRR::PIM, {"enable","show ip igmp vrf all interface json"});
    if (ret.second != 0)
    {
       PLOG(PL_ERROR, "SmfIgmp::UpdateInterfaces() Failed to retrieve IGMP interface information from FRR-PIM\n");
       return;
    }

    PLOG(PL_DETAIL, "SmfIgmp::UpdateInterfaces() Current IGMP Interfaces\n%s\n", ret.first.c_str());

    // Example output from FRR-PIM
    // # show ip igmp vrf all interface json
    // {  
    //   "default": {
    //     "green1":{
    //       "name":"green1",
    //       "state":"up",
    //       "address":"192.168.30.1",
    //       "index":16,
    //       "flagMulticast":true,
    //       "flagBroadcast":true,
    //       "lanDelayEnabled":true,
    //       "upTime":"21:52:50",
    //       "version":3,
    //       "querier":true,
    //       "queryTimer":"00:00:12"
    //     }
    //   },
    //   "vblue": {
    //     "vblue":{
    //       "name":"vblue",
    //       "state":"up",
    //       "address":"192.168.34.1",
    //       "index":13,
    //       "lanDelayEnabled":true,
    //       "upTime":"38:17:49",
    //       "version":3,
    //       "mtraceOnly":true
    //     }
    //   }
    // }

    // First unmark all the current active interfaces so we can detect interfaces that get removed
    for (auto& i : active_interfaces)
    {
        i.second = false;
    }

    ProtoJson::Parser parser;
    ProtoJson::Document* doc = nullptr;
    switch (parser.ProcessInput(ret.first.c_str(), ret.first.size()))
    {
        case ProtoJson::Parser::PARSE_ERROR:
            PLOG(PL_ERROR, "SmfIgmp::UpdateInterfaces() Invalid JSON string\n");
            return;

        case ProtoJson::Parser::PARSE_MORE:
            PLOG(PL_ERROR, "SmfIgmp::UpdateInterfaces() Incomplete JSON string\n");
            return;

        case ProtoJson::Parser::PARSE_DONE:
            doc = parser.DetachDocument();
            if (!doc)
            {
                PLOG(PL_ERROR, "SmfIgmp::UpdateInterfaces() NULL document\n");
                return;
            }
            break;
    }

    ProtoJson::Document::Iterator dit(*doc);
    ProtoJson::Item* item = nullptr;
    while ((item = dit.GetNextItem()) != nullptr)
    { // Loop through all the items in the JSON document
        if (item->GetType() == ProtoJson::Item::OBJECT)
        { // Only process objects, we look specifically for the interface objects because we don't care about VRF info here
            ProtoJson::Object* obj = reinterpret_cast<ProtoJson::Object*>(item);
            if (!obj)
            {
                PLOG(PL_ERROR, "SmfIgmp::UpdateMemberships() Failed to cast item to object\n");
                continue;
            }
            // Look for the interface objects by first testing for the "state" key
            auto entry = obj->FindEntry("state");
            if (!entry)
            { // If the object doesn't contain the "state" key, then it's not an interface object so skip it
                continue;
            }

            // This is an interface, check and make sure it's up
            std::string state = static_cast<const ProtoJson::String*>(entry->GetValue())->GetText();
            if (state != "up")
            { // Not up, skip it
                continue;
            }

            // TODO: There appears to be an mtrace only interface added out of nowhere?? What to do with
            // that situation??
            entry = obj->FindEntry("mtraceOnly");
            bool mtraceOnly = false;
            if (entry && static_cast<const ProtoJson::Boolean*>(entry->GetValue())->GetValue())
            { // This is an mtrace only interface, what to do with it?
                mtraceOnly = true;
            }

            // This interface is up, so the rest of this information should be available and we should find at least one group
            // First we need the index for this interface
            entry = obj->FindEntry("index");
            if (!entry)
            {
                PLOG(PL_ERROR, "SmfIgmp::UpdateMemberships() Failed to find interface index\n");
                continue;
            }
            std::uint32_t iffidx = static_cast<const ProtoJson::Number*>(entry->GetValue())->GetInteger();
            auto iface = smf.GetInterface(iffidx);
            if (!iface)
            {
                if (!mtraceOnly)
                {
                    PLOG(PL_ERROR, "SmfIgmp::UpdateMemberships() Failed to find IGMP interface in the interface list, is it configured?\n");
                }
                continue;
            }
            iface->SetManaged(true);
            active_interfaces[iffidx] = true;
        }
    }

    // Now any interfaces not marked have been removed
    for (auto it = active_interfaces.begin(); it != active_interfaces.end();)
    {
        if (!it->second)
        {
            auto iface = smf.GetInterface(it->first);
            if (iface)
            {
                iface->SetManaged(false);
            }
            it = active_interfaces.erase(it);
        }
        else
        {
            it = std::next(it);
        }
    }
}

void SmfIgmp::UpdateMemberships()
{
    std::pair<std::string, std::int8_t> ret = FRR::FRRVty(FRR::PIM, {"enable","show ip igmp vrf all groups json"});
    if (ret.second != 0)
    {
       PLOG(PL_ERROR, "SmfIgmp::UpdateMemberships() Failed to retrieve group information from FRR-PIM\n");
       return;
    }

    PLOG(PL_DETAIL, "SmfIgmp::UpdateMemberships() Current IGMP Groups\n%s\n", ret.first.c_str());

    // Example output from FRR-PIM
    // # show ip igmp vrf all groups json
    // {
    //   "default": {
    //     "totalGroups":1,
    //     "watermarkLimit":0,
    //     "green1":{
    //       "name":"green1",
    //       "state":"up",
    //       "address":"192.168.30.1",
    //       "index":16,
    //       "flagMulticast":true,
    //       "flagBroadcast":true,
    //       "lanDelayEnabled":true,
    //       "groups":[
    //         {
    //           "source":"192.168.30.1",
    //           "group":"239.1.2.3",
    //           "mode":"EXCLUDE",
    //           "timer":"00:04:17",
    //           "sourcesCount":1,
    //           "version":3,
    //           "uptime":"00:00:03"
    //         }
    //       ]
    //     }
    //   },
    //   "vblue": {
    //     "totalGroups":0,
    //     "watermarkLimit":0
    //   },
    //   "vpurple": {
    //     "totalGroups":0,
    //     "watermarkLimit":0
    //   }
    // }

    ProtoJson::Parser parser;
    ProtoJson::Document* doc = nullptr;
    switch (parser.ProcessInput(ret.first.c_str(), ret.first.size()))
    {
        case ProtoJson::Parser::PARSE_ERROR:
            PLOG(PL_ERROR, "SmfIgmp::UpdateMemberships() Invalid JSON string\n");
            return;

        case ProtoJson::Parser::PARSE_MORE:
            PLOG(PL_ERROR, "SmfIgmp::UpdateMemberships() Incomplete JSON string\n");
            return;

        case ProtoJson::Parser::PARSE_DONE:
            doc = parser.DetachDocument();
            if (!doc)
            {
                PLOG(PL_ERROR, "SmfIgmp::UpdateMemberships() NULL document\n");
                return;
            }
            break;
    }

    GroupMap currentGroups;
    ProtoJson::Document::Iterator dit(*doc);
    ProtoJson::Item* item = nullptr;
    while ((item = dit.GetNextItem()) != nullptr)
    { // Loop through all the items in the JSON document
        if (item->GetType() == ProtoJson::Item::OBJECT)
        { // Only process objects, we look specifically for the interface objects because we don't care about VRF info here
            ProtoJson::Object* obj = reinterpret_cast<ProtoJson::Object*>(item);
            if (!obj)
            {
                PLOG(PL_ERROR, "SmfIgmp::UpdateMemberships() Failed to cast item to object\n");
                continue;
            }
            // Look for the interface objects by first testing for the "state" key
            auto entry = obj->FindEntry("state");
            if (!entry)
            { // If the object doesn't contain the "state" key, then it's not an interface object so skip it
                continue;
            }

            // This is an interface, check and make sure it's up
            std::string state = static_cast<const ProtoJson::String*>(entry->GetValue())->GetText();
            if (state != "up")
            { // Not up, skip it
                continue;
            }

            // This interface is up, so the rest of this information should be available and we should find at least one group
            // First we need the index for this interface
            entry = obj->FindEntry("index");
            if (!entry)
            {
                PLOG(PL_ERROR, "SmfIgmp::UpdateMemberships() Failed to find interface index\n");
                continue;
            }
            std::uint32_t iffidx = static_cast<const ProtoJson::Number*>(entry->GetValue())->GetInteger();

            // Now find all the groups that are joined on this interface
            entry = obj->FindEntry("groups");
            if (!entry || entry->GetValue()->GetType() != ProtoJson::Item::ARRAY)
            {
                PLOG(PL_ERROR, "SmfIgmp::UpdateMemberships() Failed to find groups array\n");
                continue;
            }

            const ProtoJson::Array* arr = static_cast<const ProtoJson::Array*>(entry->GetValue());
            for (unsigned int i = 0; i < arr->GetLength(); ++i)
            {
                entry = static_cast<const ProtoJson::Object*>(arr->GetValue(i))->FindEntry("group");
                if (!entry)
                {
                    PLOG(PL_ERROR, "SmfIgmp::UpdateMemberships() Failed to find group address\n");
                    break;
                }
                ProtoAddress grp(static_cast<const ProtoJson::String*>(entry->GetValue())->GetText());
                currentGroups[iffidx].emplace(grp);
            }
        }
    }

    // Find difference between previous state and the current state
    // This function will set the group_changes if any differences are found
    // Returns true if there are changes to be handled
    if (FindChanges(currentGroups))
    { // There were changes, send a signal on the pipe
        char c;
        if (write(wpipe, &c, 1) == -1)
        {
            PLOG(PL_ERROR, "SmfIgmp::UpdateMemberships() Failed to write to pipe, %s\n", GetErrorString());
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
            for (const auto& i : cit->second)
            { // Add all groups as new for this interface
                group_changes.emplace_back(i, true, cit->first);
            }
            cit = std::next(cit);
        }
        else if (cit == currentGroups.end())
        { // End of current groups, anything left in previous groups is removed
            for (const auto& i : pit->second)
            { // Add all groups as removed for this interface
                group_changes.emplace_back(i, false, pit->first);
            }
            pit = std::next(pit);
        }
        else if (pit->first < cit->first)
        { // Previous iface is less than current, means the iface was removed
            for (const auto& i : pit->second)
            { // Add all groups as removed for this interface
                group_changes.emplace_back(i, false, pit->first);
            }
            pit = std::next(pit);
        }
        else if (pit->first > cit->first)
        { // Current iface is less than previous, means the iface was added
            for (const auto& i : cit->second)
            { // Add all groups as added for this interface
                group_changes.emplace_back(i, true, cit->first);
            }
            cit = std::next(cit);
        }
        else
        { // Same interface, look at groups to find differences
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
                    group_changes.emplace_back(*cgit, true, pit->first);
                    cgit = std::next(cgit);
                }
                else if (cgit == cit->second.end())
                { // Anything left in previous groups is removed
                    group_changes.emplace_back(*pgit, false, pit->first);
                    pgit = std::next(pgit);
                }
                else if (*pgit < *cgit)
                { // Previous group is less than current, means previous group is removed
                    group_changes.emplace_back(*pgit, false, pit->first);
                    // Advance previous group only
                    pgit = std::next(pgit);
                }
                else if (*pgit > *cgit)
                { // Current group is less than previous, means current group is new
                    group_changes.emplace_back(*cgit, true, pit->first);
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