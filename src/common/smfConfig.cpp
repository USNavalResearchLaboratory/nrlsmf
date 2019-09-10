
#include "smfConfig.h"
#include "protoString.h"  // for ProtoTokenator
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

bool SmfConfig::AddInterfaceGroup(const char*      groupName,
                                  Smf::RelayType   relayType,
                                  const char*      ifaceList,  // comma-delimited list of interfaces
                                  bool             elastic,
                                  bool             unicast)
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
    if (!error && !group->InsertString("relayType", relayTypeString))
    {
        PLOG(PL_ERROR, "SmfConfig::AddInterfaceGroup() error setting 'relayType' attribute: %s\n", GetErrorString());
        error = true;
    }
    ProtoJson::Array* array;
    if (!error && ((NULL == (array = new ProtoJson::Array())) || !group->InsertEntry("interfaceList", *array)))
    {
        PLOG(PL_ERROR, "SmfConfig::AddInterfaceGroup() error setting 'interfaceList' attribute: %s\n", GetErrorString());
        error = true;
    }
    if (!error)
    {
        // Parse comma-delimited "ifaceList" to build JSON Array
        ProtoTokenator tk(ifaceList, ',');
        const char* ifaceName;
        while (NULL != (ifaceName = tk.GetNextItem()))
        {
            if (!array->AppendString(ifaceName))
            {
                PLOG(PL_ERROR, "SmfConfig::AddInterfaceGroup() error adding 'interfaceList' item: %s\n", GetErrorString());
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
        if ((NULL != name) || (0 == strcmp(groupName, static_cast<const ProtoJson::String*>(name->GetValue())->GetText())))
            return group;
    }
    return NULL;
}  // end SmfConfig::FindInterfaceGroup()
