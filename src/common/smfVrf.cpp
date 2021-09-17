#include "smfVrf.h"
#include "frrVty.h"
#include "protoDebug.h"
#include "protoNet.h"
#include <iterator>
#include <sstream>
#include <string>
#include <stdlib.h>  // for atoi()

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


SmfVRFList::SmfVRFList(ProtoTimerMgr& timerMgr) :
    ProtoIndexedQueueTemplate<SmfVRF>(),
    timer_mgr(timerMgr),
    update_timer(),
    policies(NULL)
{
    update_timer.SetInterval(5.0);
    update_timer.SetRepeat(-1);
    update_timer.SetListener(this, &SmfVRFList::DoUpdate);
}

SmfVRFList::~SmfVRFList()
{
    if (update_timer.IsActive())
    {
        update_timer.Deactivate();
    }
}

void SmfVRFList::SmfVRFList::EnableFRRUpdates(bool enable)
{
    if (enable)
    {
        QueryFRRVRFs();
        if (!update_timer.IsActive()) 
        {
            timer_mgr.ActivateTimer(update_timer);
        }
    } 
    else 
    {
        if (update_timer.IsActive()) 
        {
            timer_mgr.DeactivateTimer(update_timer);
        }
    }
}
void SmfVRFList::DoUpdate(ProtoTimer& theTimer)
{
    QueryFRRVRFs();
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
void SmfVRFList::QueryFRRVRFs()
{
    std::pair<std::string, std::int8_t> ret = FRR::FRRVty(FRR::Zebra, {"show vrf"});
    bool dirty = false;
    if (ret.second != 0)
    {
        // TODO: command failed
        return;
    }

    // There is always a default VRF mapped to table 254
    AddVRF("default", 0, 254);
    dirty = QueryFRRVRFInterface("default");
    //ret.first; // The string response to parse through
    PLOG(PL_DETAIL,"SmfVRFList::QueryFRRVRFs VRFs from FRR:\n%s\n", ret.first.c_str());

    // FRR# show vrf
    // vrf blue id 13 table 10
    // vrf red id 19 table 11

    std::istringstream iss(ret.first);
    std::string line;
    int totalVRFs = 0;
    while (std::getline(iss, line)) 
    {
        std::string vrfName, vrfId, vrfTable;
        std::istringstream liness(line);
        std::string lpart;
        int field = 0;
        while (std::getline(liness, lpart, ' ')) 
        {
            if (!lpart.empty()) // Ignore extra white space between fields
            {
                field++;
                // get the second, forth, and 6th words corresponding to vrf name, id,
                // and table
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
        }

        if(!vrfName.empty() && !vrfId.empty() && !vrfTable.empty())
        {
            AddVRF(vrfName.c_str(), atoi(vrfId.c_str()), atoi(vrfTable.c_str()));
            totalVRFs++;
            if (QueryFRRVRFInterface(vrfName))
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

bool SmfVRFList::QueryFRRVRFInterface(std::string vrf_name)
{
    SmfVRF * vrf = GetVRFByName(vrf_name.c_str());

    if (NULL == vrf)
    {
        PLOG(PL_ERROR,"SmfVRFList::QueryFRRVRFInterface:  No such VRF: %s\n", vrf_name.c_str());
        return false;
    }
    std::string cmd = "show interface vrf " + vrf_name + " brief";
    std::pair<std::string, std::int8_t> ret = FRR::FRRVty(FRR::Zebra, {cmd});
    if (ret.second != 0)
    {
        // TODO: command failed
        return false;
    }
    //ret.first; // The string response to parse through
    PLOG(PL_DETAIL,"SmfVRFList::QueryFRRVRFInterface: VRF FRR %s interface list:\n%s\n", vrf_name.c_str(), ret.first.c_str());

    // jtr# show  interface vrf  vblue brief
    // Interface       Status  VRF             Addresses
    //---------       ------  ---             ---------
    // eth1           up      blue           192.168.20.1/24
    // blue           up      blue

    std::istringstream iss(ret.first);
    std::string line;
    std::unordered_set<std::string> iface_list;
    int totalIfaces = 0;
    int skip2lines = 2;
    while (std::getline(iss, line)) 
    {
        if (0 != skip2lines) // skip the first two header lines
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
            if (!lpart.empty()) // Ignore extra white space between fields
            {
                field++;
                switch (field) 
                {
                    case 1:
                        // Interfaces with multiple IP addresses configured will
                        // have multiple lines, make sure to skip the extra lines
                        // ex:
                        // eth0          up      default         192.168.30.1/24
                        // eth1          up      default         192.168.35.1/32
                        //                                       192.168.45.1/32
                        if (lpart.find("/") == std::string::npos) 
                        {
                            ifaceName = lpart;
                        }
                        break;
                    case 2:
                        // Skip "down" interfaces
                        if (lpart == "down") 
                        {
                            ifaceName.clear();
                        }
                        break;
                }
            }
        }

        if (!ifaceName.empty())
        {
            totalIfaces++;
            iface_list.insert(ifaceName);
        }
    }

    if (iface_list != vrf->GetIfaceList() )
    {
        // we got some updates, reset the iface list.
        vrf->SetIfaceList(iface_list);
        return true;
    }
    return false;
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