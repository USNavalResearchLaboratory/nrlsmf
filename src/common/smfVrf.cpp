#include "smfVrf.h"
#include "frrVty.h"
#include "protoDebug.h"
#include "protoNet.h"
#include <iterator>
#include <sstream>
#include <string>
#include <chrono>
#include <stdlib.h>  // for atoi()
#include <unistd.h>

SmfVRF::SmfVRF(UINT32 vid) :
    ProtoQueue::Item(),
    vrf_id(vid) {}

SmfVRF::SmfVRF(UINT32 vid, const char *new_name):
    ProtoQueue::Item(),
    vrf_id(vid)
{
    SetName(new_name);
}

void SmfVRF::SetName(const char* new_name)
{
    strncpy(vrf_name, new_name, VRF_NAME_SIZE);
    vrf_name[VRF_NAME_SIZE]='\0';
}

bool SmfVRF::IsMemberInterface(const char *iface_name)
{
    if (iface_list.find(iface_name) != iface_list.end())
        return true;
    else
        return false;
}

bool SmfVRF::IsMemberInterface(unsigned int iface_index)
{
    if (iface_index_list.find(iface_index) != iface_index_list.end())
        return true;
    else
        return false;
}

bool SmfVRF::AddInterface(const char *iface)
{
    // iface_list.
    if (iface_list.find(iface) != iface_list.end())
    {
        //  The interface is already present
        return false;
    }
    else
    {
        unsigned int ifaceIndex = ProtoNet::GetInterfaceIndex(iface);
        if (0 == ifaceIndex)
        {
            PLOG(PL_ERROR, "SmfVRF::AddInterface error: invalid interface \"%s\"\n", iface);
            return false;
        }
        iface_list.insert(iface);
        iface_index_list.insert(ifaceIndex);
        return true;
    }
}

bool SmfVRF::SetIfaceList(std::unordered_set<std::string> new_iface_list)
{
    std::unordered_set<unsigned int> new_iface_index_list;
    for (auto it = new_iface_list.begin(); it != new_iface_list.end();)
    {
        char *iface = (char *) (*it).c_str();

        unsigned int ifaceIndex = ProtoNet::GetInterfaceIndex(iface);
        if (0 == ifaceIndex)
        {
            PLOG(PL_ERROR, "SmfVRF::SetIfaceList error: invalid interface \"%s\"\n", iface);
            it = new_iface_list.erase(it);
        }
        else
        {
            it=std::next(it);
            new_iface_index_list.insert(ifaceIndex);
        }
    }

    iface_list = new_iface_list;
    iface_index_list = new_iface_index_list;
    return true;
  }


static const int VRF_POLL_INTERVAL_MS = 5000;
/* Six unchanged reads means VRF config has settled. Later changes are
 * still picked up, just less often.
 */
static const int VRF_POLL_STABLE_COUNT = 6;
static const int VRF_POLL_SLOW_INTERVAL_MS = 15000;

SmfVrfUpdateChannel::SmfVrfUpdateChannel() :
    ProtoChannel(),
    wpipe(ProtoChannel::INVALID_HANDLE),
    mu(),
    armed(false)
{
}

SmfVrfUpdateChannel::~SmfVrfUpdateChannel()
{
    Close();
}

bool SmfVrfUpdateChannel::Open()
{
    if (IsOpen())
        return true;
    int p[2];
    if (pipe(p) < 0)
    {
        PLOG(PL_ERROR, "SmfVrfUpdateChannel::Open() pipe() error: %s\n", GetErrorString());
        return false;
    }
    descriptor = p[0];
    wpipe = p[1];
    if (!ProtoChannel::Open())
    {
        PLOG(PL_ERROR, "SmfVrfUpdateChannel::Open() Failed to open ProtoChannel\n");
        Close();
        return false;
    }
    return true;
}

void SmfVrfUpdateChannel::Close()
{
    ProtoChannel::Close();
    if (descriptor != ProtoChannel::INVALID_HANDLE)
    {
        close(descriptor);
        descriptor = ProtoChannel::INVALID_HANDLE;
    }
    if (wpipe != ProtoChannel::INVALID_HANDLE)
    {
        ::close(wpipe);
        wpipe = ProtoChannel::INVALID_HANDLE;
    }
    armed = false;
}

void SmfVrfUpdateChannel::Signal()
{
    {
        std::lock_guard<std::mutex> lock(mu);
        if (armed || wpipe == ProtoChannel::INVALID_HANDLE)
            return;
        armed = true;
    }
    char c = 1;
    if (write(wpipe, &c, 1) != 1)
    {
        std::lock_guard<std::mutex> lock(mu);
        armed = false;
    }
}

void SmfVrfUpdateChannel::Drain()
{
    char c;
    while (read(descriptor, &c, 1) > 0)
    {
    }
    std::lock_guard<std::mutex> lock(mu);
    armed = false;
}

SmfVRFList::SmfVRFList() :
    ProtoIndexedQueueTemplate<SmfVRF>(),
    update_channel(),
    poll_mu(),
    poll_cv(),
    stop(false),
    poll_thread(),
    pending_mu(),
    pending_updates(),
    last_snapshot(),
    policies(NULL)
{
}

SmfVRFList::~SmfVRFList()
{
    StopPollThread();
}

void SmfVRFList::StopPollThread()
{
    {
        std::lock_guard<std::mutex> lock(poll_mu);
        stop = true;
    }
    poll_cv.notify_all();
    if (poll_thread.joinable())
        poll_thread.join();
}

bool SmfVRFList::Stopping()
{
    std::lock_guard<std::mutex> lock(poll_mu);
    return stop;
}

void SmfVRFList::PollLoop()
{
    bool first = true;
    int intervalMs = VRF_POLL_INTERVAL_MS;
    int stable = 0;
    while (true)
    {
        {
            std::unique_lock<std::mutex> lock(poll_mu);
            if (stop)
                return;
            if (!first &&
                poll_cv.wait_for(lock, std::chrono::milliseconds(intervalMs),
                                 [this]() { return stop; }))
                return;
        }
        first = false;
        int result = Collect();
        if (result > 0)
        {
            update_channel.Signal();
            intervalMs = VRF_POLL_INTERVAL_MS;
            stable = 0;
        }
        else if (result == 0 && ++stable >= VRF_POLL_STABLE_COUNT)
            intervalMs = VRF_POLL_SLOW_INTERVAL_MS;
    }
}

void SmfVRFList::SmfVRFList::EnableFRRUpdates(bool enable)
{
    if (enable)
    {
        if (poll_thread.joinable())
            return;
        if (!update_channel.IsOpen() && !update_channel.Open())
        {
            PLOG(PL_ERROR, "SmfVRFList::EnableFRRUpdates() update channel open failed\n");
            return;
        }
        {
            std::lock_guard<std::mutex> lock(poll_mu);
            stop = false;
        }
        poll_thread = std::thread(&SmfVRFList::PollLoop, this);
    }
    else
    {
        StopPollThread();
    }
}

SmfVRF* SmfVRFList::AddVRF(const char *vrf_name, UINT32 vrf_id, int table_id)
{
    SmfVRF* vrf = GetVRFByName(vrf_name);
    static UINT32 vrf_id_pool = 100;
    if (NULL == vrf)
    {
        if (0 != strcmp(VRF_DEFAULT_NAME, vrf_name))
        {
            if (VRF_UKKNOWN == vrf_id || VRF_DEFAULT == vrf_id)
            {
                // automatic vrf id
                vrf_id = vrf_id_pool++;
            }
        }
        else if ( (0 == strcmp(VRF_DEFAULT_NAME, vrf_name)) && ( VRF_DEFAULT != vrf_id))
        {
            // make sure default vrf name and id are synced
            vrf_id = VRF_DEFAULT;
        }

        vrf = new SmfVRF(vrf_id, vrf_name);
        if (NULL == vrf)
        {
            PLOG(PL_ERROR, "SmfVRFList::AddVRF()) new SmfVRFList::SmfVRF error: %s\n", GetErrorString());
            return NULL;
        }

        if (-1 != table_id )
            vrf->SetTableID(table_id);
        else
            vrf->SetTableID(vrf_id);

        Insert(*vrf);
    }
    return vrf;
}
bool SmfVRFList::ParseShowVrf(const std::string& text, std::vector<VrfUpdate>& out)
{
    // FRR# show vrf
    // vrf blue id 13 table 10
    // vrf red id 19 table 11
    std::istringstream iss(text);
    std::string line;
    while (std::getline(iss, line))
    {
        std::string vrfName, vrfId, vrfTable;
        std::istringstream liness(line);
        std::string lpart;
        int field = 0;
        while (std::getline(liness, lpart, ' '))
        {
            if (lpart.empty())
                continue;
            field++;
            // Second, fourth, and sixth words are name, id, and table.
            switch (field)
            {
                case 2:
                    vrfName = lpart;
                    break;
                case 4:
                    vrfId = lpart;
                    break;
                case 6:
                    vrfTable = lpart;
                    break;
            }
        }
        if (vrfName.empty() || vrfId.empty() || vrfTable.empty())
            continue;
        VrfUpdate u;
        u.name = vrfName;
        u.id = (UINT32)atoi(vrfId.c_str());
        u.table_id = atoi(vrfTable.c_str());
        u.ifaces_valid = false;
        out.push_back(u);
    }
    return true;
}

void SmfVRFList::ParseIfaceBrief(const std::string& text, std::unordered_set<std::string>& out)
{
    // Interface       Status  VRF             Addresses
    // ---------       ------  ---             ---------
    // eth1            up      blue            192.168.20.1/24
    // A second address is a continuation line and has no interface name.
    std::istringstream iss(text);
    std::string line;
    int skip2lines = 2;
    while (std::getline(iss, line))
    {
        if (0 != skip2lines)
        {
            skip2lines--;
            continue;
        }
        std::string ifaceName;
        std::istringstream liness(line);
        std::string lpart;
        int field = 0;
        while (std::getline(liness, lpart, ' '))
        {
            if (lpart.empty())
                continue;
            field++;
            switch (field)
            {
                case 1:
                    if (lpart.find("/") == std::string::npos)
                        ifaceName = lpart;
                    break;
                case 2:
                    if (lpart == "down")
                        ifaceName.clear();
                    break;
            }
        }
        if (!ifaceName.empty())
            out.insert(ifaceName);
    }
}

int SmfVRFList::Collect()
{
    std::pair<std::string, std::int8_t> ret = FRR::FRRVty(FRR::Zebra, {"show vrf"});
    if (ret.second != 0)
        return -1;

    PLOG(PL_DETAIL,"SmfVRFList::Collect VRFs from FRR:\n%s\n", ret.first.c_str());

    std::vector<VrfUpdate> listed;
    ParseShowVrf(ret.first, listed);

    std::unordered_map<std::string, VrfSnap> now;
    VrfSnap deflt;
    deflt.id = 0;
    deflt.table_id = 254;
    deflt.have_ifaces = false;
    now["default"] = deflt;
    for (std::vector<VrfUpdate>::const_iterator it = listed.begin(); it != listed.end(); ++it)
    {
        VrfSnap snap;
        snap.id = it->id;
        snap.table_id = it->table_id;
        snap.have_ifaces = false;
        now[it->name] = snap;
    }

    for (std::unordered_map<std::string, VrfSnap>::iterator it = now.begin(); it != now.end(); ++it)
    {
        if (Stopping())
            return -1;
        std::string cmd = "show interface vrf " + it->first + " brief";
        std::pair<std::string, std::int8_t> iret = FRR::FRRVty(FRR::Zebra, {cmd});
        if (iret.second != 0)
            continue;
        ParseIfaceBrief(iret.first, it->second.ifaces);
        it->second.have_ifaces = true;
    }

    std::vector<VrfUpdate> delta;
    for (std::unordered_map<std::string, VrfSnap>::iterator it = now.begin(); it != now.end(); ++it)
    {
        std::unordered_map<std::string, VrfSnap>::iterator prev = last_snapshot.find(it->first);
        bool isNew = prev == last_snapshot.end();
        bool ifacesChanged = it->second.have_ifaces &&
            (isNew || !prev->second.have_ifaces || prev->second.ifaces != it->second.ifaces);
        if (!isNew && !ifacesChanged)
            continue;

        VrfUpdate update;
        update.name = it->first;
        update.id = it->second.id;
        update.table_id = it->second.table_id;
        update.ifaces_valid = it->second.have_ifaces;
        if (update.ifaces_valid)
            update.ifaces = it->second.ifaces;
        delta.push_back(update);

        if (isNew || it->second.have_ifaces)
            last_snapshot[it->first] = it->second;
    }
    if (delta.empty())
        return 0;

    std::lock_guard<std::mutex> lock(pending_mu);
    pending_updates.insert(pending_updates.end(), delta.begin(), delta.end());
    return 1;
}

void SmfVRFList::ApplyPending()
{
    update_channel.Drain();
    std::vector<VrfUpdate> batch;
    {
        std::lock_guard<std::mutex> lock(pending_mu);
        batch.swap(pending_updates);
    }
    bool dirty = false;
    for (std::vector<VrfUpdate>::const_iterator it = batch.begin(); it != batch.end(); ++it)
    {
        AddVRF(it->name.c_str(), it->id, it->table_id);
        if (!it->ifaces_valid)
            continue;
        SmfVRF* vrf = GetVRFByName(it->name.c_str());
        if (NULL == vrf)
            continue;
        if (it->ifaces != vrf->GetIfaceList())
        {
            vrf->SetIfaceList(it->ifaces);
            dirty = true;
        }
    }
    if (dirty)
    {
        DumpVRFs();
        if (policies)
            policies->DumpPolicies();
    }
}

SmfVRF* SmfVRFList::GetVRFByName(const char* vrf_name)
{
    SmfVRFList::Iterator vrfIterator(*this);
    SmfVRF* vrf;
    while (NULL != (vrf = vrfIterator.GetNextItem()))
    {
        if (0 == strcmp(vrf_name, vrf->GetName()))
            return vrf;
    }
    return NULL;
}

SmfVRF* SmfVRFList::GetVRFbyIfaceIndex(unsigned int iface_index)
{
    SmfVRFList::Iterator vrfIterator(*this);
    SmfVRF* vrf;
    while (NULL != (vrf = vrfIterator.GetNextItem()))
    {
        if (vrf->IsMemberInterface(iface_index))
            return vrf;
    }
    return nullptr;
}

void SmfVRFList::DumpVRFs()
{
    SmfVRFList::Iterator vrfIterator(*this);
    SmfVRF* vrf;
    PLOG(PL_DETAIL, "================ VRF table ================\n");
    while (NULL != (vrf = vrfIterator.GetNextItem()))
    {
        PLOG(PL_DETAIL, "vrf name = %s   vrf id =%u   table =%i\n", vrf->GetName(), vrf->GetID(), vrf->GetTableID());
        PLOG(PL_DETAIL, "    inerfaces:\n");
        for (std::string s : vrf->GetIfaceList())
            PLOG(PL_DETAIL, "             %s\n", s.c_str());
        //for (unsigned int i : vrf->GetIfaceIndexList())
        //    PLOG(PL_DEBUG, "             %u\n", i);
    }
    PLOG(PL_DETAIL, "===========================================\n");
}

void SmfVRFList::DeleteVRF(SmfVRF &vrf)
{

}

SmfVRFPolicies::SmfVRFPolicies() :
     policies(),
     dstpolicies(),
     srcpolicies(),
     wildcardpolicies()
{

}

SmfVRFPolicies::~SmfVRFPolicies()
{

}

SmfVRFPolicy* SmfVRFPolicies::AddPolicy(const std::string& srcvrf, const std::string& dstvrf)
{
    if (srcvrf == "all" && dstvrf == "all")
    {
        return &wildcardpolicies;
    }
    if (srcvrf == "all")
    {
        auto it = dstpolicies.emplace(dstvrf, SmfVRFPolicy{});
        return &(it.first->second);
    }
    if (dstvrf == "all")
    {
        auto it = srcpolicies.emplace(srcvrf, SmfVRFPolicy{});
        return &(it.first->second);
    }
    auto it = policies.emplace(srcvrf+":"+dstvrf, SmfVRFPolicy{});
    return &(it.first->second);
}

SmfVRFPolicy* SmfVRFPolicies:: FindPolicy(const std::string& srcvrf, const std::string& dstvrf)
{
    auto it = policies.find(srcvrf+":"+dstvrf);
    if (it != policies.end())
    {
        return &(it->second);
    }
    // No specific policy, check for wildcard dest
    auto sit = srcpolicies.find(srcvrf);
    if (sit != srcpolicies.end())
    {
        return &(sit->second);
    }
    // No specific or wildcard dest policy, check for wildcard src
    auto dit = dstpolicies.find(dstvrf);
    if (dit != dstpolicies.end())
    {
        return &(dit->second);
    }
    return &wildcardpolicies;
}

void SmfVRFPolicies::DumpPolicies()
{
    PLOG(PL_DEBUG, "-------- VRF Route Leaking Policies -------\n");
    PLOG(PL_DEBUG, "  all:all %s %s\n",
        wildcardpolicies.IsAllowed() ? "ALLOW" : "DENY",
        wildcardpolicies.HasWildcard() ? "all" : GetGroupList(wildcardpolicies.GetGroups()).c_str());
    for (auto& p : dstpolicies)
    {
        PLOG(PL_DEBUG, "  all:%s %s %s\n",
            p.first.c_str(),
            p.second.IsAllowed() ? "ALLOW" : "DENY",
            p.second.HasWildcard() ? "all" : GetGroupList(p.second.GetGroups()).c_str());
    }
    for (auto& p : srcpolicies)
    {
        PLOG(PL_DEBUG, "  %s:all %s %s\n",
            p.first.c_str(),
            p.second.IsAllowed() ? "ALLOW" : "DENY",
            p.second.HasWildcard() ? "all" : GetGroupList(p.second.GetGroups()).c_str());
    }
    for (auto& p : policies)
    {
        PLOG(PL_DEBUG, "  %s %s %s\n",
            p.first.c_str(),
            p.second.IsAllowed() ? "ALLOW" : "DENY",
            p.second.HasWildcard() ? "all" : GetGroupList(p.second.GetGroups()).c_str());
    }
    PLOG(PL_DEBUG, "------ END VRF Route Leaking Policies ------\n");
}

std::string SmfVRFPolicies::GetGroupList(ProtoAddressList& groups)
{
    std::ostringstream os;
    bool first = true;
    ProtoAddressList::Iterator iter(groups);
    ProtoAddress grp;
    while (iter.GetNextAddress(grp))
    {
        os << (!first ? "," : "") << grp.GetHostString();
        first = false;
    }
    return os.str();
}