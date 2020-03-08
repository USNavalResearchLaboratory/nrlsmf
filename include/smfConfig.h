
#ifndef _SMF_CONFIG
#define _SMF_CONFIG

#include "protoJson.h"
#include "smf.h"

/*
Ccurrnet config schema
group : 
{
    name            : <string>
    type            : <string>  // CF, ECDS, SMPR,        
    interfaces      : <array> of <string> // interface names
    elastic         : {TRUE | FALSE}   // FALSE is default upon omission
    unicast         : {TRUE | FALSE}   // FALSE is default upon omission
    
    reliable        : {TRUE | FALSE} // FALSE is default upon omission
    layered         : {TRUE | FALSE} // FALSE is default upon omission
    shadow          : {TRUE | FALSE} // FALSE is default upon omission
}

interface
{
    name            : <string>  // name of virtual interface device to be created
    device          : <string>  // name of physical interface to map a virtual (if null, then "name" == device)
    addresses       : <array> of <string> // items of format "<address>[/<maskLength>]
    reliable        : {TRUE | FALSE} // FALSE is default upon omission
    layered         : {TRUE | FALSE} // FALSE is default upon omission
    shadow          : {TRUE | FALSE} // FALSE is default upon omission
}

*/

class SmfConfig : public ProtoJson::Document
{
    public:
        SmfConfig();
        ~SmfConfig();
        
        bool Init();
        bool Initialized() const
            {return (NULL != item_list.GetHead());}
        void Destroy()
            {item_list.Destroy();}
        
        // Normally we will use this class to load and parse config files
        // but the methods here can be used to programmatically build
        // up a config document.
        bool AddInterface(const char*           ifaceName, 
                          ProtoAddressList*     addrList = NULL,
                          const char*           deviceName = NULL,
                          bool                  reliable = false,
                          bool                  layered = false,
                          bool                  shadow = false);
        
        bool AddInterfaceGroup(const char*          groupName,
                               Smf::RelayType       relayType,
                               Smf::InterfaceList&  ifaceList,  // comma-delimited list of interfaces
                               bool                 elastic = false,
                               bool                 unicast = false);
        
        bool SetElastic(const char* groupName,  bool state)
            {return SetGroupAttribute(groupName, "elastic", state);}
        
        bool SetUnicast(const char* groupName,  bool state)
            {return SetGroupAttribute(groupName, "unicast", state);}
        
        ProtoJson::Object* FindInterface(const char* ifaceName);
        
        ProtoJson::Object* FindInterfaceGroup(const char* groupName);
        
        ProtoJson::Object* AccessConfigurationObject()
            {return static_cast<ProtoJson::Object*>(item_list.GetHead());}
        
        // TBD - add an Iterator class to return specific config items (e.g., 'group', 'device', etc)
        
    private:
        const char* GetRelayTypeString(Smf::RelayType relayType);
        bool SetGroupAttribute(const char* groupName, const char* attrName, bool state);
            
};  // end SmfConfig

    
#endif // !_SMF_CONFIG
