#include "protoDefs.h"
#include "protoQueue.h"
#include "protoTimer.h"
#include <unordered_set>

#define VRF_NAME_SIZE 36
#define VRF_DEFAULT 0
#define VRF_DEFAULT_NAME "default"
#define VRF_UKKNOWN UINT32_MAX

class SmfVRF : public ProtoQueue::Item {

public:
  SmfVRF(UINT32 vid);
  SmfVRF(UINT32 vid, const char *new_name);
  ~SmfVRF()
  { iface_list.clear(); iface_index_list.clear();}

  void SetID(UINT32 vid) { vrf_id = vid; }
  UINT32 GetID() { return vrf_id; }

  void SetTableID(UINT32 tid) { table_id = tid; }
  UINT32 GetTableID() { return table_id; }

  void SetName(const char *new_name);
  const char *GetName() const { return vrf_name; }

  // Used for SmfVRFList required ProtoIndexedQueue overrides
  const char *GetKey() const { return ((const char *)&vrf_id); }
  unsigned int GetKeysize() const { return (8 * sizeof(UINT32)); }

  bool IsMemberInterface(const char *iface_name);
  bool IsMemberInterface(unsigned int iface_index);

  bool AddInterface(const char *iface);
  bool SetIfaceList(std::unordered_set<std::string> new_iface_list);

  std::unordered_set<std::string> GetIfaceList() { return iface_list; }
  std::unordered_set<unsigned int> GetIfaceIndexList() { return iface_index_list; }

private:
  UINT32 vrf_id;
  int table_id;
  char vrf_name[VRF_NAME_SIZE + 1];
  std::unordered_set<std::string> iface_list;
  std::unordered_set<unsigned int> iface_index_list;
};// end class SmfVRF

class SmfVRFList : public ProtoIndexedQueueTemplate<SmfVRF> {
public:
  SmfVRFList(ProtoTimerMgr& timerMgr);
  ~SmfVRFList();

  SmfVRF *FindVRF(UINT32 vid) const {
    return Find((const char *)&vid, 8 * sizeof(UINT32));
  }

  class Iterator : public ProtoIndexedQueueTemplate<SmfVRF>::Iterator {
  public:
    Iterator(SmfVRFList &vrfList)
        : ProtoIndexedQueueTemplate<SmfVRF>::Iterator(vrfList) {}
    SmfVRF *GetNextVRF() {
      return ProtoIndexedQueueTemplate<SmfVRF>::Iterator::GetNextItem();
    }
  }; // end class SmfVRFList::Iterator

SmfVRF *AddVRF(const char *vrf_name, UINT32 vrf_id, int table_id);
void DeleteVRF(SmfVRF &vrf);
void DumpVRFs();
SmfVRF *GetVRFByName(const char *vrf_name);
void QueryFRRVRFs();
void EnableFRRUpdates(bool enable);
void QueryFRRVRFInterface(std::string vrf_name);
SmfVRF *GetVRF(UINT32 vrf_id) const { return FindVRF(vrf_id); }
SmfVRF *GetVRFbyIfaceIndex(unsigned int iface_index);
void DoUpdate(ProtoTimer& theTimer);

private:
  ProtoTimerMgr& timer_mgr;
  ProtoTimer update_timer;
  const char *GetKey(const Item &item) const {
    return static_cast<const SmfVRF &>(item).GetKey();
  }
  unsigned int GetKeysize(const Item &item) const {
    return static_cast<const SmfVRF &>(item).GetKeysize();
  }
};// end class SmfVRFList

