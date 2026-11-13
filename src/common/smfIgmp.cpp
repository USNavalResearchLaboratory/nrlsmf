#include "smfIgmp.h"
#include "frrVty.h"
#include <regex>
#include <set>
#include <chrono>
#include <utility>
#include <protoJson.h>
#include <iostream>

static const int IGMP_POLL_INTERVAL_MS = 5000;

SmfIgmp::SmfIgmp() :
    ProtoChannel(),
    wpipe(INVALID_HANDLE),
    membership_changes(),
    active_interfaces(),
    interface_changes(),
    mu(),
    cv(),
    stop(false),
    notify_armed(false),
    pending(),
    poll_thread()
{
}

SmfIgmp::~SmfIgmp()
{
    StopPollThread();
}

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

    // Register the read end before the poll thread can write it.
    if (!ProtoChannel::Open())
    {
        PLOG(PL_ERROR, "SmfIgmp::Open() Failed to open ProtoChannel\n");
        Close();
        return false;
    }

    if (withFRR)
        EnableFrrPolling();
    return true;
}

void SmfIgmp::EnableFrrPolling()
{
    if (poll_thread.joinable() || wpipe == INVALID_HANDLE)
        return;
    {
        std::lock_guard<std::mutex> lock(mu);
        stop = false;
    }
    poll_thread = std::thread(&SmfIgmp::PollLoop, this);
}

void SmfIgmp::StopPollThread()
{
    {
        std::lock_guard<std::mutex> lock(mu);
        stop = true;
    }
    cv.notify_all();
    if (poll_thread.joinable())
        poll_thread.join();
}

bool SmfIgmp::Stopping()
{
    std::lock_guard<std::mutex> lock(mu);
    return stop;
}

void SmfIgmp::Close()
{
    // Join the poll thread before closing the pipe it writes.
    StopPollThread();

    ProtoChannel::Close();

    if (descriptor != INVALID_HANDLE)
    {
        close(descriptor);
        descriptor = INVALID_HANDLE;
    }
    if (wpipe != INVALID_HANDLE)
    {
        close(wpipe);
        wpipe = INVALID_HANDLE;
    }
}

bool SmfIgmp::IsOpen() const
{
    return ProtoChannel::IsOpen() && wpipe != INVALID_HANDLE;
}

void SmfIgmp::PollLoop()
{
    InterfacesMap seenIfaces;
    MembershipMap seenGroups;
    bool haveIfaces = false;
    bool haveGroups = false;
    bool first = true;

    while (true)
    {
        {
            std::unique_lock<std::mutex> lock(mu);
            if (stop)
                return;
            if (!first &&
                cv.wait_for(lock, std::chrono::milliseconds(IGMP_POLL_INTERVAL_MS),
                            [this]() { return stop; }))
                return;
        }
        first = false;

        InterfacesMap ifaces;
        MembershipMap groups;
        InterfacesMap ifaceDelta;
        MembershipChangeArray groupDelta;
        const bool ifOk = CollectInterfaces(ifaces);
        if (Stopping())
            return;
        const bool grpOk = CollectMemberships(groups);
        if (ifOk && (!haveIfaces || ifaces != seenIfaces))
        {
            DiffInterfaces(haveIfaces ? seenIfaces : InterfacesMap(), ifaces, ifaceDelta);
            seenIfaces = ifaces;
            haveIfaces = true;
        }
        if (grpOk && (!haveGroups || groups != seenGroups))
        {
            DiffMemberships(seenGroups, groups, groupDelta);
            haveGroups = true;
        }
        if (ifaceDelta.empty() && groupDelta.empty())
            continue;

        bool wake = false;
        {
            std::lock_guard<std::mutex> lock(mu);
            if (stop)
                return;
            for (const auto& c : ifaceDelta)
                pending.interface_changes[c.first] = c.second;
            pending.membership_changes.insert(pending.membership_changes.end(),
                                              groupDelta.begin(), groupDelta.end());
            wake = !notify_armed;
            notify_armed = true;
        }
        if (!wake || wpipe == INVALID_HANDLE)
            continue;
        char c = 1;
        if (write(wpipe, &c, 1) != 1)
        {
            std::lock_guard<std::mutex> lock(mu);
            notify_armed = false;
        }
    }
}

void SmfIgmp::ProcessUpdates()
{
    char c;
    while (read(descriptor, &c, 1) > 0)
    {
    }

    Handoff handoff;
    {
        std::lock_guard<std::mutex> lock(mu);
        std::swap(handoff, pending);
        notify_armed = false;
    }
    for (const auto& c : handoff.interface_changes)
    {
        interface_changes[c.first] = c.second;
        if (c.second.second)
            active_interfaces[c.first] = c.second;
        else
            active_interfaces.erase(c.first);
    }
    membership_changes.insert(membership_changes.end(),
                              handoff.membership_changes.begin(),
                              handoff.membership_changes.end());
}

std::vector<std::tuple<std::string, std::string>> SmfIgmp::NewNetworkInterface(const std::string& ifaceName) const
{
    // Add a new push group with the new manet interface as the source, pushing to all the active host interfaces
    // Also add the new manet interface to all the rpush groups for each active host interface
    std::vector<std::tuple<std::string, std::string>> cmds;
    std::ostringstream os;
    os << "push," << ifaceName;
    for (const auto& i : active_interfaces)
    {
        os << "," << i.second.first;
        cmds.emplace_back(std::make_tuple("add", "rpush,"+i.second.first+","+ifaceName));
    }
    cmds.emplace_back(std::make_tuple("add", os.str()));
    return cmds;
}

bool SmfIgmp::CollectInterfaces(InterfacesMap& out)
{
    std::pair<std::string, std::int8_t> ret = FRR::FRRVty(FRR::PIM, {"enable","show ip igmp vrf all interface json"});
    if (ret.second != 0)
    {
       PLOG(PL_ERROR, "SmfIgmp::CollectInterfaces() Failed to retrieve IGMP interface information from FRR-PIM\n");
       return false;
    }

    PLOG(PL_DETAIL, "SmfIgmp::CollectInterfaces() Current IGMP Interfaces\n%s\n", ret.first.c_str());

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

    ProtoJson::Parser parser;
    ProtoJson::Document* doc = nullptr;
    switch (parser.ProcessInput(ret.first.c_str(), ret.first.size()))
    {
        case ProtoJson::Parser::PARSE_ERROR:
            PLOG(PL_ERROR, "SmfIgmp::CollectInterfaces() Invalid JSON string\n");
            return false;

        case ProtoJson::Parser::PARSE_MORE:
            PLOG(PL_ERROR, "SmfIgmp::CollectInterfaces() Incomplete JSON string\n");
            return false;

        case ProtoJson::Parser::PARSE_DONE:
            doc = parser.AccessDocument();
            if (!doc)
            {
                PLOG(PL_ERROR, "SmfIgmp::CollectInterfaces() NULL document\n");
                return false;
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
                PLOG(PL_ERROR, "SmfIgmp::CollectInterfaces() Failed to cast item to object\n");
                continue;
            }
            // Look for the interface objects by first testing for the "state" key
            auto entry = obj->FindEntry("state");
            if (!entry)
            { // If the object doesn't contain the "state" key, then it's not an interface object so skip it
                continue;
            }

            // This is an interface, make sure it's up
            std::string state = static_cast<const ProtoJson::String*>(entry->GetValue())->GetText();
            if (state != "up")
            {
                continue;
            }

            // Check for an mtrace only IGMP interface, which isn't actually configured for IGMP
            entry = obj->FindEntry("mtraceOnly");
            if (entry && static_cast<const ProtoJson::Boolean*>(entry->GetValue())->GetValue())
            {
                continue;
            }

            // This interface is up, so the rest of this information should be available and we should find at least one group

            // Get the name of the interface so we don't need to look it up if changing configuration during runtime
            entry = obj->FindEntry("name");
            if (!entry)
            {
                PLOG(PL_ERROR, "SmfIgmp::CollectInterfaces() Failed to parse Interface name from JSON output\n");
                continue;
            }
            std::string ifaceName = static_cast<const ProtoJson::String*>(entry->GetValue())->GetText();
            if (ifaceName.empty())
            {
                PLOG(PL_ERROR, "SmfIgmp::CollectInterfaces() Failed to parse Interface name from JSON output\n");
                continue;
            }

            // Now we need the index to look up the interface objct
            entry = obj->FindEntry("index");
            if (!entry)
            {
                PLOG(PL_ERROR, "SmfIgmp::CollectInterfaces() Failed to find interface index\n");
                continue;
            }
            std::uint32_t iffidx = static_cast<const ProtoJson::Number*>(entry->GetValue())->GetInteger();
            out[iffidx].first = ifaceName;
            out[iffidx].second = true;
        }
    }
    return true;
}

void SmfIgmp::DiffInterfaces(const InterfacesMap& previous, const InterfacesMap& current,
                             InterfacesMap& changes)
{
    for (const auto& c : current)
    {
        InterfacesMap::const_iterator it = previous.find(c.first);
        if (it == previous.end())
            changes[c.first] = c.second;
    }
    for (const auto& p : previous)
    {
        if (current.find(p.first) == current.end())
        {
            changes[p.first].first = p.second.first;
            changes[p.first].second = false;
        }
    }
}

bool SmfIgmp::CollectMemberships(MembershipMap& out)
{
    std::pair<std::string, std::int8_t> ret = FRR::FRRVty(FRR::PIM, {"enable","show ip igmp vrf all groups json"});
    if (ret.second != 0)
    {
       PLOG(PL_ERROR, "SmfIgmp::CollectMemberships() Failed to retrieve group information from FRR-PIM\n");
       return false;
    }

    PLOG(PL_DETAIL, "SmfIgmp::CollectMemberships() Current IGMP Groups\n%s\n", ret.first.c_str());

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
            PLOG(PL_ERROR, "SmfIgmp::CollectMemberships() Invalid JSON string\n");
            return false;

        case ProtoJson::Parser::PARSE_MORE:
            PLOG(PL_ERROR, "SmfIgmp::CollectMemberships() Incomplete JSON string\n");
            return false;

        case ProtoJson::Parser::PARSE_DONE:
            doc = parser.AccessDocument();
            if (!doc)
            {
                PLOG(PL_ERROR, "SmfIgmp::CollectMemberships() NULL document\n");
                return false;
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
                PLOG(PL_ERROR, "SmfIgmp::CollectMemberships() Failed to cast item to object\n");
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
                PLOG(PL_ERROR, "SmfIgmp::CollectMemberships() Failed to find interface index\n");
                continue;
            }
            std::uint32_t iffidx = static_cast<const ProtoJson::Number*>(entry->GetValue())->GetInteger();

            // Now find all the groups that are joined on this interface
            entry = obj->FindEntry("groups");
            if (!entry || entry->GetValue()->GetType() != ProtoJson::Item::ARRAY)
            {
                PLOG(PL_ERROR, "SmfIgmp::CollectMemberships() Failed to find groups array\n");
                continue;
            }

            const ProtoJson::Array* arr = static_cast<const ProtoJson::Array*>(entry->GetValue());
            for (unsigned int i = 0; i < arr->GetLength(); ++i)
            {
                entry = static_cast<const ProtoJson::Object*>(arr->GetValue(i))->FindEntry("group");
                if (!entry)
                {
                    PLOG(PL_ERROR, "SmfIgmp::CollectMemberships() Failed to find group address\n");
                    break;
                }
                ProtoAddress grp(static_cast<const ProtoJson::String*>(entry->GetValue())->GetText());
                out[iffidx].emplace(grp);
            }
        }
    }
    return true;
}

void SmfIgmp::DiffMemberships(MembershipMap& previous, const MembershipMap& current,
                               MembershipChangeArray& changes)
{
    // Find difference between previous state and the current state
    auto ait = previous.begin();
    auto cit = current.begin();
    while (true)
    {
        if (ait == previous.end() && cit == current.end())
        { // Reached the end of both, break loop
            break;
        }
        else if (ait == previous.end())
        { // End of previous groups, anything left in current groups is new
            for (const auto& i : cit->second)
            { // Add all groups as new for this interface
                changes.emplace_back(i, true, cit->first);
            }
            cit = std::next(cit);
        }
        else if (cit == current.end())
        { // End of current groups, anything left in previous groups is removed
            for (const auto& i : ait->second)
            { // Add all groups as removed for this interface
                changes.emplace_back(i, false, ait->first);
            }
            ait = std::next(ait);
        }
        else if (ait->first < cit->first)
        { // Previous iface is less than current, means the iface was removed
            for (const auto& i : ait->second)
            { // Add all groups as removed for this interface
                changes.emplace_back(i, false, ait->first);
            }
            ait = std::next(ait);
        }
        else if (ait->first > cit->first)
        { // Current iface is less than previous, means the iface was added
            for (const auto& i : cit->second)
            { // Add all groups as added for this interface
                changes.emplace_back(i, true, cit->first);
            }
            cit = std::next(cit);
        }
        else
        { // Same interface, look at groups to find differences
            auto agit = ait->second.begin();
            auto cgit = cit->second.begin();
            while (true)
            {
                if (agit == ait->second.end() && cgit == cit->second.end())
                {
                    break;
                }
                else if (agit == ait->second.end())
                { // Anything left in current groups is new
                    changes.emplace_back(*cgit, true, ait->first);
                    cgit = std::next(cgit);
                }
                else if (cgit == cit->second.end())
                { // Anything left in previous groups is removed
                    changes.emplace_back(*agit, false, ait->first);
                    agit = std::next(agit);
                }
                else if (*agit < *cgit)
                { // Previous group is less than current, means previous group is removed
                    changes.emplace_back(*agit, false, ait->first);
                    // Advance previous group only
                    agit = std::next(agit);
                }
                else if (*agit > *cgit)
                { // Current group is less than previous, means current group is new
                    changes.emplace_back(*cgit, true, ait->first);
                    // Advance current group only
                    cgit = std::next(cgit);
                }
                else
                { // Last option is both are the same, nothing to do but advance both
                    agit = std::next(agit);
                    cgit = std::next(cgit);
                }
            }
            ait = std::next(ait);
            cit = std::next(cit);
        }
    }

    previous = current;
}