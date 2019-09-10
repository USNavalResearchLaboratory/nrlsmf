
#ifdef SIMULATE
#include "nsProtoSimAgent.h"
#else
#include "protoApp.h"
#endif  // if/else SIMULATE

#include "nhdp.h"

#include <stdlib.h>  // for atoi()
#include <stdio.h>   // for stdout/stderr printouts
#include <string.h>

class NhdpTest :
#ifdef SIMULATE
                     public NsProtoSimAgent
#else
                     public ProtoApp
#endif  // if/else SIMULATE
                     
{
public:
  NhdpTest();
  ~NhdpTest();
  
  // Overrides from ProtoApp or NsProtoSimAgent base
  bool OnStartup(int argc, const char*const* argv);
  bool ProcessCommands(int argc, const char*const* argv);
  void OnShutdown();
  virtual bool HandleMessage(unsigned int len, const char* txBuffer,const ProtoAddress& srcAddr) {return true;}

private:
  enum CmdType {CMD_INVALID, CMD_ARG, CMD_NOARG};
  static CmdType GetCmdType(const char* string);
  bool OnCommand(const char* cmd, const char* val);        
  void Usage();
  
  static const char* const CMD_LIST[];
  
  NhdpInstance* nhdp_instance;  // ptr to an NhdpInstance, currently just for one iface
  
}; // end class NhdpTest


// (TBD) Note this #if/else code could be replaced with something like
// a PROTO_INSTANTIATE(NhdpTest) macro defined differently
// in "protoApp.h" and "nsProtoSimAgent.h"
#ifdef SIMULATE
#ifdef NS2
static class NsNhdpTestClass : public TclClass
{
	public:
		NsNhdpTestClass() : TclClass("Agent/NHDP") {}
	 	TclObject *create(int argc, const char*const* argv) 
			{return (new NhdpTest());}
} class_nhdp_test;	
#endif // NS2


#else

// Our application instance 
PROTO_INSTANTIATE_APP(NhdpTest) 

#endif  // SIMULATE

NhdpTest::NhdpTest()
: nhdp_instance(NULL)
{        
}

NhdpTest::~NhdpTest()
{
    if (NULL != nhdp_instance)
    {
        delete nhdp_instance;
        nhdp_instance = NULL;
    }
}

void NhdpTest::Usage()
{
    fprintf(stderr, "nhdpTest [addr <addr>/<port>] interface <ifaceName>\n");
}  // end NhdpTest::Usage()


const char* const NhdpTest::CMD_LIST[] =
{
    "+address",       // Specify addr/port for NHDP operation
    "+interface",     // Specify which interface our test nhdp instance is working on
    NULL
};

NhdpTest::CmdType NhdpTest::GetCmdType(const char* cmd)
{
    if (!cmd) return CMD_INVALID;
    unsigned int len = strlen(cmd);
    bool matched = false;
    CmdType type = CMD_INVALID;
    const char* const* nextCmd = CMD_LIST;
    while (*nextCmd)
    {
        if (!strncmp(cmd, *nextCmd+1, len))
        {
            if (matched)
            {
                // ambiguous command (command should match only once)
                return CMD_INVALID;
            }
            else
            {
                matched = true;   
                if ('+' == *nextCmd[0])
                    type = CMD_ARG;
                else
                    type = CMD_NOARG;
            }
        }
        nextCmd++;
    }
    return type; 
}  // end NhdpTest::GetCmdType()


bool NhdpTest::OnStartup(int argc, const char*const* argv)
{
    if (!ProcessCommands(argc, argv))
    {
        PLOG(PL_ERROR, "NhdpTest::OnStartup() error: bad command line!\n");
        return false;
    }  
    
    if (NULL != nhdp_instance)
    {
        if (!nhdp_instance->Start())
        {
            PLOG(PL_ERROR, "NhdpTest::OnStartup() error: NhdpInstance::Start failure!\n");
            return false;
        }
    }
    else
    {
        PLOG(PL_ERROR, "NhdpTest::OnStartup() error: no interface assigned?!\n");
        return false;
    }
    return true;
}  // end NhdpTest::OnStartup()

void NhdpTest::OnShutdown()
{
    if (NULL != nhdp_instance)
    {
        nhdp_instance->Stop();   
        delete nhdp_instance;
        nhdp_instance = NULL;
    }
    PLOG(PL_ERROR, "nhdpTest: Done.\n");
    CloseDebugLog();
}  // end NhdpTest::OnShutdown()

bool NhdpTest::ProcessCommands(int argc, const char*const* argv)
{
    // Dispatch command-line commands to our OnCommand() method
    int i = 1;
    while ( i < argc)
    {
        // Is it a class NhdpTest command?
        switch (GetCmdType(argv[i]))
        {
            case CMD_INVALID:
            {
#ifndef SIMULATE
                PLOG(PL_ERROR, "NhdpTest::ProcessCommands() Invalid command:%s\n", 
                        argv[i]);
#endif // SIMULATE
                return false;
            }
            case CMD_NOARG:
                if (!OnCommand(argv[i], NULL))
                {
                    PLOG(PL_ERROR, "NhdpTest::ProcessCommands() ProcessCommand(%s) error\n", 
                            argv[i]);
                    return false;
                }
                i++;
                break;
            case CMD_ARG:
                if (!OnCommand(argv[i], argv[i+1]))
                {
                    PLOG(PL_ERROR, "NhdpTest::ProcessCommands() ProcessCommand(%s, %s) error\n", 
                            argv[i], argv[i+1]);
                    return false;
                }
                i += 2;
                break;
        }
    }
    return true;  
}  // end NhdpTest::ProcessCommands()

bool NhdpTest::OnCommand(const char* cmd, const char* val)
{

    // (TBD) move command processing into Mgen class ???
    CmdType type = GetCmdType(cmd);
    ASSERT(CMD_INVALID != type);
    unsigned int len = strlen(cmd);
    if ((CMD_ARG == type) && !val)
    {
        PLOG(PL_ERROR, "NhdpTest::OnCommand(%s) missing argument\n", cmd);
        return false;
    }
    else if (!strncmp("interface", cmd, len))
    {     
        if (NULL != nhdp_instance)
        {
            PLOG(PL_WARN, "nhdpTest::OnCommand(interface) shutting down old NhdpInstance ...\n");
            delete nhdp_instance;
        }
        if (NULL == (nhdp_instance = new NhdpInstance(GetSocketNotifier(), GetTimerMgr(), val)))
        {
            PLOG(PL_ERROR, "NhdpTest::OnCommand(interface) error: new NhdpInstance failure!\n");
            return false;
        }
        if (IsRunning() && !nhdp_instance->Start())
            PLOG(PL_ERROR, "Nhdp::OnCommand(interface) error: couldn't restart nhdp after interface change\n");
    }
    else if (!strncmp("address", cmd, len))
    {
        if (NULL == nhdp_instance)
        {
            PLOG(PL_ERROR, "NhdpTest::OnCommand(address) error: no interface specified!\n");
            return false;
        }
        // (TBD) should we have a default addr/port for NHDP set in class Nhdp
        char* ptr = strchr(val, '/');
        int port = (NULL == ptr) ? nhdp_instance->GetNhdpPort() : atoi(ptr+1);
        if ((port < 0) || (port > 65535))
        {
            PLOG(PL_ERROR, "NhdpTest::OnCommand(address) error: invalid port\n");
            return false;
        }
        unsigned int addrStrLen = ptr - val;
        if (addrStrLen > 255)
        {
            PLOG(PL_ERROR, "NhdpTest::OnCommand(address) error: address string tool long\n");
            return false;
        }
        char addrStr[256];
        addrStr[addrStrLen] = '\0';
        strncpy(addrStr, val, addrStrLen);
        ProtoAddress addr;
        if (!addr.ResolveFromString(addrStr))
        {
            PLOG(PL_ERROR, "NhdpTest::OnCommand(address) error: invalid address: %s\n", addrStr);
            return false;
        }
        addr.SetPort(port);
        nhdp_instance->SetNhdpAddress(addr);
    }
    else
    {
        PLOG(PL_ERROR, "NhdpTest::OnCommand() error: unknown command: %s\n", cmd);
        return false;
    }
    return true;
}  // end NhdpTest::OnCommand()
