#include "nhdp.h"

Nhdp::Graph::Graph()
{
}

Nhdp::Graph::~Graph()
{
}

Nhdp::Nhdp(ProtoSocket::Notifier& socketNotifier,
           ProtoTimerMgr&         timerMgr)
  : nhdp_socket(ProtoSocket::UDP), timer_mgr(timerMgr)
{    
    nhdp_iface[0] = '\0';
    
    nhdp_socket.SetNotifier(&socketNotifier);   
    nhdp_socket.SetListener(this, &Nhdp::OnSocketEvent);
    
    hello_timer.SetListener(this, &Nhdp::OnHelloTimeout);
    hello_timer.SetRepeat(-1);
}


Nhdp::~Nhdp()
{
    Stop();
}

void Nhdp::SetNhdpInterface(const char* ifaceName)
{
    nhdp_iface[NHDP_NAME_MAX] = '\0';
    strncpy(nhdp_iface, ifaceName, NHDP_NAME_MAX);
}  // end Nhdp::SetNhdpInterface()

bool Nhdp::Start()
{
    if (nhdp_addr.IsValid())
    {
        if (!nhdp_socket.Open(nhdp_addr.GetPort()))
        {
            PLOG(PL_ERROR, "Nhdp::Start() error: couldn't open socket on desired port number\n");
            return false;
        }
        if (nhdp_addr.IsMulticast())
        {
            TRACE("joining group %s\n", nhdp_addr.GetHostString());
            if (!nhdp_socket.JoinGroup(nhdp_addr, nhdp_iface))
            {
                PLOG(PL_ERROR, "Nhdp::Start() error: couldn't join NHDP group on specified interface\n");
                nhdp_socket.Close();
                return false;
            }
            TRACE("setting mcast iface ...\n");
            nhdp_socket.SetMulticastInterface(nhdp_iface);
        }
        
    }
    else
    {
        PLOG(PL_ERROR, "Nhdp::Start() error: invalid address\n");
        return false;
    }
    
   timer_mgr.ActivateTimer(hello_timer);
   
   return true;
}  // end Nhdp::Start()

void Nhdp::Stop()
{
    if (nhdp_socket.IsOpen())
        nhdp_socket.Close();
    if (hello_timer.IsActive())
        hello_timer.Deactivate();   
}  // end Nhdp::Stop()


bool Nhdp::OnHelloTimeout(ProtoTimer& /*theTimer*/)
{
    TRACE("Nhdp::OnHelloTimeout() ...\n");
    
    // 1) Build an NHDP_HELLO packet and send it
    
    return true;
}  // end Nhdp::OnHelloTimeout()


void Nhdp::OnSocketEvent(ProtoSocket& /*theSocket*/, 
                         ProtoSocket::Event theEvent)
{
    TRACE("Nhdp::OnSocketEvent() ...\n");
}  // end Nhdp::OnSocketEvent()

bool Nhdp::BuildHelloPkt(ManetPkt& helloPkt) const
{
    // 1) Init the ManetPkt buffer
    if (!helloPkt.InitIntoBuffer())
    {
        PLOG(PL_ERROR, "Nhdp::BuildHelloPkt() ManetPkt::InitIntoBuffer() error\n");
        return false;
    }
    // 2) Append/build NHDP HELLO message
    ManetMsg* helloMsg = helloPkt.AppendMessage();
    if (NULL == helloMsg)
    {
        PLOG(PL_ERROR, "Nhdp::BuildHelloPkt() ManetPkt::AppendMessage() error\n");
        return false;
    }
    if (BuildHelloMsg(*helloMsg))
    {
        helloPkt.Pack();
        return true;
    }
    else
    {
        PLOG(PL_ERROR, "Nhdp::BuildHelloPkt() error: message building failure!\n");
        return false;
    }
}  // end Nhdp::BuildHelloPkt()

bool Nhdp::BuildHelloMsg(ManetMsg& helloMsg) const
{
    // 1) Set NHDP HELLO msg type
    helloMsg.SetType(HELLO);
    
    // 2) TBD - add option set "originator" ???
    //helloMsg.SetOriginator(xxx);  
    
    // 3) Add address block containing LOCAL_IF interfaces
    
    ManetAddrBlock* addrBlk = helloMsg.AppendAddressBlock();
    if (NULL == addrBlk)
    {
        TRACE("Nhdp::BuildHelloMsg() error: AppendAddressBlock() failure!\n");
        return false;
    }

    // TBD - support option for addr prefix &| tail
    
    
    return true;
}  // end Nhdp::BuildHelloMsg()


NhdpInstance::NhdpInstance(ProtoSocket::Notifier& socketNotifier,
                           ProtoTimerMgr&         timerMgr,
                           const char*            ifaceName, 
                           ProtoAddress::Type     addrType)
 : nhdp(socketNotifier, timerMgr), ipv6(ProtoAddress::IPv4 == addrType ? false : true) 
{
    nhdp.SetNhdpInterface(ifaceName);
}

NhdpInstance::~NhdpInstance()
{
    if (IsRunning()) Stop();
}

bool NhdpInstance::Start()
{
    nhdp.Stop();
    ProtoAddressList ifaceAddrList;
    ProtoAddress::Type addrType = ipv6 ? ProtoAddress::IPv6 : ProtoAddress::IPv4;
    if (!ProtoSocket::GetInterfaceAddressList(nhdp.GetNhdpInterface(), addrType, ifaceAddrList))
    {
        PLOG(PL_ERROR, "NhdpInstance::Start() error: failed to get interface address list\n");
        return false;
    }
    // We provide this iteration to possibly filter out some addresses in the future
    ProtoAddressList::Iterator it(ifaceAddrList);
    ProtoAddress addr;
    while (it.GetNextAddress(addr))
    {
        if (!nhdp.InsertLocalAddress(addr))
        {
            PLOG(PL_ERROR, "NhdpInstance::Start() error: local_addr_list.Insert() failure!\n");
            return false;
        }
    }
    return nhdp.Start();
}  // end NhdpInstance::Start()

void NhdpInstance::Stop()
{
    
}  // end NhdpInstance::Stop()
