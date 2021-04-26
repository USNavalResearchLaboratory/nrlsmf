
#include "smfConfig.h"
#include "protoString.h"  // for ProtoTokenator
#include "protoNet.h"
#include "protoDebug.h"

SmfConfig::SmfConfig()
{
}

SmfConfig::~SmfConfig()
{
    Destroy();
}

const char* SmfConfig::GetRelayTypeString(Smf::RelayType relayType)
{
    switch (relayType)
    {
        case Smf::CF:
            return "cf";
        case Smf::S_MPR:
            return "smpr";
        case Smf::E_CDS:
            return "ecds";
        case Smf::MPR_CDS:   
            return "mprcds";     
        case Smf::NS_MPR:
            return "nsmpr";
        default:
            return NULL;    
    }
}  // end SmfConfig::GetRelayTypeString()

bool SmfConfig::Init()
{
    ProtoJson::Object* config = static_cast<ProtoJson::Object*>(item_list.GetHead());
    if (NULL == config)
    {
        if (NULL == (config = new ProtoJson::Object()))
        {
            PLOG(PL_ERROR, "SmfConfig::Init() new config_object error: %s\n", GetErrorString());
            return false;
        }
        if (!AddItem(*config))
        {
            PLOG(PL_ERROR, "SmfConfig::Init() AddItem() error: %s\n", GetErrorString());
            delete config;
            return false;
        }
    }
    else
    {
        config->Destroy();
    }
    return true;
}  // end SmfConfig::Init()

bool SmfConfig::AddInterface(const char*        ifaceName, 
                             ProtoAddressList*  addrList,
                             const char*        deviceName,
                             bool               reliable,
                             bool               layered,
                             bool               shadow,
                             bool               blockIGMP)
{
    if (!Initialized() && !Init()) return false;
    // First, find or create "interface" object
    ProtoJson::Object* config = static_cast<ProtoJson::Object*>(item_list.GetHead());
    ProtoJson::Object* iface = FindInterface(ifaceName);
    if (NULL == iface)
    {
        iface = new ProtoJson::Object();
        if ((NULL == iface) || !config->InsertEntry("interface", *iface))
        {
            PLOG(PL_ERROR, "SmfConfig::AddInterface() error adding new interface: %s\n", GetErrorString());
            if (NULL != iface) delete iface;
            return false;
        }      
    }
    else
    {
        iface->Destroy();
    }
    if (!iface->InsertString("name", ifaceName))
    {
        PLOG(PL_ERROR, "SmfConfig::AddInterface() error setting 'name' attribute: %s\n", GetErrorString());
        return false;
    }  
    if (NULL != deviceName)
    {
        if (!iface->InsertString("device", deviceName))
        {
            PLOG(PL_ERROR, "SmfConfig::AddInterface() error adding 'device' attribute: %s\n", GetErrorString());
            return false;
        }
    }
    if ((NULL != addrList) && !addrList->IsEmpty())
    {
        ProtoJson::Array* array;
        if (((NULL == (array = new ProtoJson::Array())) || !iface->InsertEntry("addresses", *array)))
        {
            PLOG(PL_ERROR, "SmfConfig::AddInterface() error setting 'addresses' attribute: %s\n", GetErrorString());
            return false;
        }
        ProtoAddressList::Iterator iterator(*addrList);
        ProtoAddress addr;
        while (iterator.GetNextAddress(addr))
        {
            unsigned int maskLen = ProtoNet::GetInterfaceAddressMask(ifaceName, addr);
            if (0 == maskLen)
            {
                PLOG(PL_ERROR, "SmfConfig::AddInterface() error getting interface address mask: %s\n", GetErrorString());
                continue;
            }
            char addrString[256];
            sprintf(addrString, "%s/%u", addr.GetHostString(), maskLen);
            if (!array->AppendString(addrString))
            {
                PLOG(PL_ERROR, "SmfConfig::AddInterface() error adding 'address' item: %s\n", GetErrorString());
                return false;
            }
        }
    }
    // Should we skip 'false' items, since the default is 'false' for these?
    if (!iface->InsertBoolean("reliable", reliable))
    {
        PLOG(PL_ERROR, "SmfConfig::AddInterface() error adding 'reliable' attribute: %s\n", GetErrorString());
        return false;
    }
    if (!iface->InsertBoolean("layered", layered))
    {
        PLOG(PL_ERROR, "SmfConfig::AddInterface() error adding 'layered' attribute: %s\n", GetErrorString());
        return false;
    }
    if (!iface->InsertBoolean("shadow", shadow))
    {
        PLOG(PL_ERROR, "SmfConfig::AddInterface() error adding 'shadow' attribute: %s\n", GetErrorString());
        return false;
    }
    if (!iface->InsertBoolean("blockIGMP", blockIGMP))
    {
        PLOG(PL_ERROR, "SmfConfig::AddInterface() error adding 'shadow' attribute: %s\n", GetErrorString());
        return false;
    }
    return true;
    
}  // end SmfConfig:AddInterface()

bool SmfConfig::AddInterfaceGroup(const char*           groupName,
                                  Smf::RelayType        relayType,
                                  Smf::InterfaceList&   ifaceList,  // comma-delimited list of interfaces
                                  bool                  elastic,
                                  bool                  unicast,
                                  bool                  etx)
{
    if (!Initialized() && !Init()) return false;
    // First, find or create "group" object
    ProtoJson::Object* config = static_cast<ProtoJson::Object*>(item_list.GetHead());
    ProtoJson::Object* group = FindInterfaceGroup(groupName);
    if (NULL != group)
    {
        // Existing group, remove existing attributes
        group->Destroy();
    }
    else 
    {
        // Create entry to contain new group
        group =  new ProtoJson::Object();
        if ((NULL == group) || !config->InsertEntry("group", *group))
        {
            PLOG(PL_ERROR, "SmfConfig::AddInterfaceGroup() error adding new group: %s\n", GetErrorString());
            if (NULL != group) delete group;
            return false;
        }
    }  
    bool error = false;
    if (!group->InsertString("name", groupName))
    {
        PLOG(PL_ERROR, "SmfConfig::AddInterfaceGroup() error setting 'name' attribute: %s\n", GetErrorString());
        error = true;
    }
    const char* relayTypeString = GetRelayTypeString(relayType);
    if (!error && (NULL == relayTypeString))
    {
        PLOG(PL_ERROR, "SmfConfig::AddInterfaceGroup() error: invalid relayType\n");
        error = true;
    }
    if (!error && !group->InsertString("type", relayTypeString))
    {
        PLOG(PL_ERROR, "SmfConfig::AddInterfaceGroup() error setting 'relayType' attribute: %s\n", GetErrorString());
        error = true;
    }
    ProtoJson::Array* array = NULL;
    if (!error && ((NULL == (array = new ProtoJson::Array())) || !group->InsertEntry("interfaces", *array)))
    {
        PLOG(PL_ERROR, "SmfConfig::AddInterfaceGroup() error setting 'interfsces' attribute: %s\n", GetErrorString());
        error = true;
    }
    if (!error)
    {
        // Parse "ifaceList" to build JSON Array
        Smf::InterfaceList::Iterator iterator(ifaceList);
        Smf::Interface* iface;
        while (NULL != (iface = iterator.GetNextInterface()))
        {
            char ifaceName[Smf::IF_NAME_MAX + 1];
            ifaceName[Smf::IF_NAME_MAX] = '\0';
            if (!ProtoNet::GetInterfaceName(iface->GetIndex(), ifaceName, Smf::IF_NAME_MAX))
            {
                PLOG(PL_ERROR, "SmfConfig::AddInterfaceGroup() GetInterfaceName() error: %s\n", GetErrorString());
                continue;
            }
            if (!array->AppendString(ifaceName))
            {
                PLOG(PL_ERROR, "SmfConfig::AddInterfaceGroup() error adding 'interfsces' item: %s\n", GetErrorString());
                error = true;
                break;
            }
        }
    }
    if (!error && !group->InsertBoolean("elastic", elastic))
    {
        PLOG(PL_ERROR, "SmfConfig::AddInterfaceGroup() error setting 'elastic' attribute: %s\n", GetErrorString());
        error = true;
    }
    if (!error && !group->InsertBoolean("unicast", unicast))
    {
        PLOG(PL_ERROR, "SmfConfig::AddInterfaceGroup() error setting 'unicast' attribute: %s\n", GetErrorString());
        error = true;
    }
    if (!error && !group->InsertBoolean("etx", etx))
    {
        PLOG(PL_ERROR, "SmfConfig::AddInterfaceGroup() error setting 'etx' attribute: %s\n", GetErrorString());
        error = true;
    }
    if (error)
    {
        ProtoJson::Entry* entry = static_cast<ProtoJson::Entry*>(group->AccessParent());
        config->RemoveEntry(*entry);
        delete group;
        return false;
    }
    return true;
}  // end SmfConfig::AddInterfaceGroup()


bool SmfConfig::SetGroupAttribute(const char* groupName, const char* attrName, bool state)
{
    ProtoJson::Object* group = FindInterfaceGroup(groupName);
    if (NULL == group)
    {
        PLOG(PL_ERROR, "SmfConfig::SetGroupAttribute() error: unknown group name!\n");
        return false;
    }
    ProtoJson::Entry* attr = group->FindEntry(attrName);
    if (NULL == attr)
    {
        if (!group->InsertBoolean(attrName, state))
        {
            PLOG(PL_ERROR, "SmfConfig::SetGroupAttribute() error setting '%s' attribute: %s\n", attrName, GetErrorString());
            return false;
        }
    }
    else
    {
        ProtoJson::Item* item = attr->AccessValue();
        if ((NULL == item) && 
            (ProtoJson::Item::TRUE != item->GetType())  && 
            (ProtoJson::Item::FALSE != item->GetType())) 
        {
            PLOG(PL_ERROR, "SmfConfig::SetGroupAttribute() error: '%s' already set as non-boolean attribute?!\n", attrName);
            return false;
        }
        else
        {
            static_cast<ProtoJson::Boolean*>(item)->SetValue(state);
        }
    }
    return true;
}  // end SmfConfig::SetGroupAttribute(bool)

ProtoJson::Object* SmfConfig::FindInterface(const char* ifaceName)
{
    if (!Initialized()) return NULL;
    ProtoJson::Object* config = static_cast<ProtoJson::Object*>(item_list.GetHead());
    ProtoJson::Object::Iterator iterator(*config);
    iterator.Reset(false, "interface");
    ProtoJson::Entry* entry;
    while (NULL != (entry = iterator.GetNextEntry()))
    {
        ProtoJson::Object* iface = static_cast<ProtoJson::Object*>(entry->AccessValue());
        ProtoJson::Entry* name = iface->FindEntry("name");
        if ((NULL != name) && (0 == strcmp(ifaceName, static_cast<const ProtoJson::String*>(name->GetValue())->GetText())))
            return iface;
    }
    return NULL;
}  // end SmfConfig::FindInterface()

ProtoJson::Object* SmfConfig::FindInterfaceGroup(const char* groupName)
{
    if (!Initialized()) return NULL;
    ProtoJson::Object* config = static_cast<ProtoJson::Object*>(item_list.GetHead());
    ProtoJson::Object::Iterator iterator(*config);
    iterator.Reset(false, "group");
    ProtoJson::Entry* entry;
    while (NULL != (entry = iterator.GetNextEntry()))
    {
        ProtoJson::Object* group = static_cast<ProtoJson::Object*>(entry->AccessValue());
        ProtoJson::Entry* name = group->FindEntry("name");
        if ((NULL != name) && (0 == strcmp(groupName, static_cast<const ProtoJson::String*>(name->GetValue())->GetText())))
            return group;
    }
    return NULL;
}  // end SmfConfig::FindInterfaceGroup()
