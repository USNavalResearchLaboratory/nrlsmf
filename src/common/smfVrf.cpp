#include "smfVrf.h"
#include "frrVty.h"
#include "protoNet.h"
#include <sstream>
#include <string>
#include <stdlib.h>  // for atoi()

SmfVRF::SmfVRF(UINT32 vid):
    ProtoQueue::Item(),
    vrf_id(vid)
{
}

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

bool SmfVRF::AddInterface(const char *iface) {
  // iface_list.
  if (iface_list.find(iface) != iface_list.end())
  {
    //  The interface is already present
    return false;
  }
  else
  {
    unsigned int ifaceIndex = ProtoNet::GetInterfaceIndex(iface);
    if (0 == ifaceIndex) {
      PLOG(PL_ERROR, "SmfVRF::AddInterface error: invalid interface \"%s\"\n",
           iface);
      return false;
    }
    iface_list.insert(iface);
    iface_index_list.insert(ifaceIndex);
    return true;
  }
}

  bool SmfVRF::SetIfaceList(std::unordered_set<std::string> new_iface_list) {
    std::unordered_set<unsigned int> new_iface_index_list;
    for (auto it = new_iface_list.begin(); it != new_iface_list.end(); ++it)
    {
      char *iface = (char *) (*it).c_str();

      unsigned int ifaceIndex = ProtoNet::GetInterfaceIndex(iface);
      if (0 == ifaceIndex) {
        PLOG(PL_ERROR, "SmfVRF::AddInterface error: invalid interface \"%s\"\n",
             iface);
        new_iface_index_list.clear();
        return false;
      }
      new_iface_index_list.insert(ifaceIndex);
    }

    iface_list = new_iface_list;
    iface_index_list = new_iface_index_list;
    return true;
  }


SmfVRFList::SmfVRFList(ProtoTimerMgr& timerMgr) :
    ProtoIndexedQueueTemplate<SmfVRF>(),
    timer_mgr(timerMgr),
    update_timer()
{
    update_timer.SetInterval(15.0);
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
  if (enable) {
    if (!update_timer.IsActive()) {
      timer_mgr.ActivateTimer(update_timer);
    }
  } else {
    if (update_timer.IsActive()) {
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
        else  if ( (0 == strcmp(VRF_DEFAULT_NAME, vrf_name)) && ( VRF_DEFAULT != vrf_id))
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
    if (ret.second != 0)
    {
        // TODO: command failed
        return;
    }

    AddVRF("default", 0, 254);
    QueryFRRVRFInterface("default");
    //ret.first; // The string response to parse through
    PLOG(PL_DEBUG,"SmfVRFList::QueryFRRVRFs VRFs from FRR:\n%s\n", ret.first.c_str());

    // FRR# show vrf
    // vrf blue id 13 table 10
    // vrf red id 19 table 11

    std::istringstream iss(ret.first);
    std::string line;
    int totalVRFs = 0;
    while (std::getline(iss, line)) {
      std::string vrfName, vrfId, vrfTable;
      std::istringstream liness(line);
      std::string lpart;
      int field = 0;
      while (std::getline(liness, lpart, ' ')) {
        if (!lpart.empty()) // Ignore extra white space between fields
        {
          field++;
          // get the second, forth, and 6th words corresponding to vrf name, id,
          // and table
          switch (field) {
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
          QueryFRRVRFInterface(vrfName);
      }

    }
}

void SmfVRFList::QueryFRRVRFInterface(std::string vrf_name)
{
    SmfVRF * vrf = GetVRFByName(vrf_name.c_str());

    if (NULL == vrf)
    {
        PLOG(PL_ERROR,"SmfVRFList::QueryFRRVRFInterface:  No such VRF: %s\n", vrf_name.c_str());
        return;
    }
    std::string cmd = "show interface vrf " + vrf_name + " brief";
    std::pair<std::string, std::int8_t> ret = FRR::FRRVty(FRR::Zebra, {cmd});
    if (ret.second != 0)
    {
        // TODO: command failed
        return;
    }
    //ret.first; // The string response to parse through
    PLOG(PL_DEBUG,"SmfVRFList::QueryFRRVRFInterface: VRF FRR %s interface list:\n%s\n", vrf_name.c_str(), ret.first.c_str());

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
    while (std::getline(iss, line)) {
      if (0 != skip2lines) // skip the first two header lines
      {
        skip2lines--;
        continue;
      }
      std::string ifaceName;
      std::istringstream liness(line);
      std::string lpart;
      int field = 0;
      while (std::getline(liness, lpart, ' ')) {
        if (!lpart.empty()) // Ignore extra white space between fields
        {
          field++;
          switch (field) {
          case 1:
            ifaceName = lpart;
            continue; // we only need the interface name for  now.
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
    PLOG(PL_DEBUG, "================ VRF table ================\n");
    while (NULL != (vrf = vrfIterator.GetNextItem()))
    {
        PLOG(PL_DEBUG, "vrf name = %s   vrf id =%u   table =%i\n", vrf->GetName(), vrf->GetID(), vrf->GetTableID());
        PLOG(PL_DEBUG, "    inerfaces:\n");
        for (std::string s : vrf->GetIfaceList())
            PLOG(PL_DEBUG, "             %s\n", s.c_str());
        //for (unsigned int i : vrf->GetIfaceIndexList())
        //    PLOG(PL_DEBUG, "             %u\n", i);
    }
    PLOG(PL_DEBUG, "===========================================\n");
}

void SmfVRFList::DeleteVRF(SmfVRF &vrf)
{

}