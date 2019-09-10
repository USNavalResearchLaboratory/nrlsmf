#ifndef _SMF_DEVICE
#define _SMF_DEVICE

#include "protoVif.h"

// This class creates a virtual interface device that is bound to another interface.  
// The initial purpose of this is to provide a couple of capabilities for nrlsmf: 
//
// 1) This puts SMF in the path of outbound packets so they can be mirrored to other interfaces.
//
// 2) For our experimental wireless flow control project, we implement per-neighbor queuing 
//    within the interface and manage scheduling (transmission) of traffic 
//    (This approach enables locally sourced as well as SMF-forwarded packets
//     to be managed by SMF)

class SmfDevice
{
    public:
        SmfDevice();
        ~SmfDevice();
        
        bool Open(const char* vifName, const char* ifaceName);
        void Close();
                  
    private:
        ProtoVif*   vif;
        ProtoCap*   cap;
        char        vif_name[ProtoVif::VIF_NAME_MAX];
        char        iface_name[ProtoVif::VIF_NAME_MAX];
        
};  // end class SmfDevice


#endif // _SMF_DEVICE
