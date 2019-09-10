#ifndef _MANET_NHDP
#define _MANET_NHDP

#include "protoSocket.h"
#include "protoTimer.h"

#include "manetMsg.h"
#include "manetGraph.h"

class Nhdp
{
    public:
        
        // Message types and TLVs of ietf:manet:nhdp namespace    
        enum MsgType
        {
            HELLO   = 1
        };
        
        enum AddressBlockTlvType
        {
            LOCAL_IF,
            LINK_STATUS,
            OTHER_NEIGHB
        };    
            
        enum LocalIfType
        {
            IF_THIS     = 0,
            IF_OTHER    = 1
        };
            
        enum LinkStatus
        {
            LINK_LOST       = 0,
            LINK_SYMMETRIC  = 1,
            LINK_HEARD      = 2,
            LINK_PENDING         // value doesn't matter since never transmitted
        };
            
        Nhdp(ProtoSocket::Notifier& socketNotifier,
             ProtoTimerMgr&         timerMgr);
        ~Nhdp();
        
        bool IsRunning() const
            {return (nhdp_socket.IsOpen());}
        
        // Local interface to which this Nhdp instance applies
        enum {NHDP_NAME_MAX = 63};
        void SetNhdpInterface(const char* ifaceName);
        const char* GetNhdpInterface() const
            {return nhdp_iface;}
    
        void SetNhdpAddress(const ProtoAddress& theAddr)
            {nhdp_addr = theAddr;}
        const ProtoAddress& GetNhdpAddress() const
            {return nhdp_addr;}
        int GetNhdpPort() const
            {return (nhdp_addr.IsValid() ? nhdp_addr.GetPort() : -1);}
        
        // Use these to manage the "local_if_addr_list"
        bool InsertLocalAddress(ProtoAddress& theAddr)
            {return local_iface_addr_list.Insert(theAddr);}
        void RemoveLocalAddress(ProtoAddress& theAddr)
            {local_iface_addr_list.Remove(theAddr);}
        
        bool Start();
        void Stop();
        
        
        // NHDP message construction and parsing methods
        bool BuildHelloPkt(ManetPkt& helloPkt) const;
        bool BuildHelloMsg(ManetMsg& helloMsg) const;
        
        // Note: Here we define the Nhdp::Graph class
        //       used to maintain neighborhood state
        //       (links to neighbors and their neighbors)
        
        class Graph : public ManetGraph
        {
            public:
                Graph();
                ~Graph();
            
                class Interface : public ManetGraph::Interface
                {
                    // TBD - add NHDP-specific members/methods 
                    public:
                        Interface();
                        ~Interface();
                        
                        
                    private:
                        
                    
                    
                    
                };  // end class Nhdp::Graph::Interface

                class Link : public ManetGraph::Link
                {
                    // TBD - add NHDP-specific members/methods 
                };  // end class Nhdp::Graph::Link     

                class Node : public ManetGraph::Node
                {
                    public:
                        Node();
                        ~Node();
                        
                    // TBD - add NHDP-specific members/methods 

                }; // end class Nhdp::Graph::Node
                
                
                class AddressAssociation
                
                
            protected:
                // Override of ProtoGraph::CreateEdge()
                Edge* CreateEdge() const 
                    {return static_cast<Edge*>(new Link);}
            
        };  // end class Nhdp::Graph
        
    private:
        bool OnHelloTimeout(ProtoTimer& theTimer);
        void OnSocketEvent(ProtoSocket&       theSocket, 
                           ProtoSocket::Event theEvent);
        
        ProtoTimerMgr&      timer_mgr;
        
        ProtoSocket         nhdp_socket;
        ProtoTimer          hello_timer; 
        
        char                nhdp_iface[NHDP_NAME_MAX];
        ProtoAddress        nhdp_addr;
        ProtoAddressList    local_iface_addr_list;
        
        Graph               nhdp_graph;
        Graph::Node*        local_node;
    
}; // end class Nhdp


/**
 * @class NhdpInstance
 *
 * @brief This class manages a real-world instance
 * of the NHDP protocol.  It contains a "class Nhdp"
 * member that has the core algorithms for NHDP while
 * the "NhdpInstance" provides the additional state
 * and mechanism for the real-world (as opposed to 
 * simulation) implementation. Most of this additional
 * state relates to dealing with a real-world network
 * interface.
 */
class NhdpInstance
{
    public:
        NhdpInstance(ProtoSocket::Notifier& socketNotifier,
                     ProtoTimerMgr&         timerMgr,
                     const char*            ifaceName, 
                     ProtoAddress::Type     ssaddrType = ProtoAddress::IPv4);
        ~NhdpInstance();
        
        void SetNhdpAddress(const ProtoAddress& theAddr)
            {nhdp.SetNhdpAddress(theAddr);}
        int GetNhdpPort() const
            {return (nhdp.GetNhdpPort());}
        
        bool Start();
        void Stop();
        bool IsRunning() const
            {return nhdp.IsRunning();}
            
    private:
        Nhdp    nhdp;
        bool    ipv6;
            
};  // end class NhdpInstance

    
#endif // _MANET_NHDP
