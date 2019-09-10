#ifndef _OPNET_SMF_PROCESS
#define _OPNET_SMF_PROCESS

/* Design OpnetSmfProcess to be the equivalent of OpnetOlsrProcess */
/* Therefore, it is renamed to OpnetSmfProcess and no longer       */
/* inherits from ProtoApp but from OpnetProtoSimProcess, instead.  */

#include "smfDupTree.h"
#include "opnetProtoSimProcess.h"
#include "smf_ipc.h"

class OpnetSmfProcess : public OpnetProtoSimProcess
{
    public:
	
        OpnetSmfProcess();
        ~OpnetSmfProcess();

        // OpnetProtoSimProcess's virtual functions
        bool OnStartup(int argc, const char*const* argv);
        bool ProcessCommands(int argc, const char*const* argv);
        void OnShutdown();
	
	
		void OnPktReceive(smfT_wlan_mem* mem);      
        void OnControlMsg(char* msg, int evcode);       
        void OnPktIntercept(Packet* pktptr);
	
    private:
        enum {SELECTOR_LIST_LEN_MAX = 600};  // 600 bytes = 100 MAC addresses max
        enum CmdType {CMD_INVALID, CMD_ARG, CMD_NOARG};
        static const char* const CMD_LIST[];
        static CmdType GetCmdType(const char* string);
        bool OnCommand(const char* cmd, const char* val);        
        void Usage();
        
        // Timeout handlers
        bool OnPruneTimeout(ProtoTimer& theTimer);

        // Async I/O handlers	    
        bool IsSelector(const char* macAddr) const;
        
#ifdef MNE_SUPPORT
        bool MneIsBlocking(const char* macAddr) const;
#endif // MNE_SUPPORT
        
        bool OpenIPv6Detour();
        
        // Packet manipulation methods
        //bool GetPktSequence(int version, unsigned char* ipPkt, UINT32& sequence);
        //unsigned short InsertPktSequence(int              version, 
        //                                 unsigned char*   pktBuffer,  // includes MAC header
        //                                 unsigned int     pktLen,     // includes MAC header
        //                                 unsigned int     maxBufferLen,
        //                                 UINT32           seqValue);
		
		
        //unsigned char DecrementPktTTL(int version, unsigned char* ipPkt);
		
        
        // Debug helper methods
        void PrintPacket(FILE* filePtr, u_char *pkt, unsigned int pktLen);
        
        // Member variables
        ProtoAddress        my_mac_addr;
        ProtoAddress        my_ip_addr;
#ifdef HAVE_IPV6
        bool                ipv6_enabled;
        ProtoAddress        my_ip6_addr;
#endif // HAVE_IPV6
        
#ifdef _PROTO_DETOUR
        ProtoDetour*        detour_ipv4;  // for interception and "fixing" outbound packets
#ifdef HAVE_IPV6
        ProtoDetour*        detour_ipv6;
#endif // HAVE_IPV6
#endif // _PROTO_DETOUR
                
        
        SmfDuplicateTree  duplicate_tree; // state for duplicate packet detection
        ProtoTimer          prune_timer;
        unsigned int        update_age_max;  // max staleness allowed for flows
        unsigned int        current_update_time;
        
        char                selector_list[SELECTOR_LIST_LEN_MAX];  
        unsigned int        selector_list_len;

        char                symetric_list[SELECTOR_LIST_LEN_MAX]; 
        unsigned int        symetric_list_len;
#ifdef MNE_SUPPORT        
        char                mne_block_list[SELECTOR_LIST_LEN_MAX];  
        unsigned int        mne_block_list_len;
#endif // MNE_SUPPORT        
        bool                default_forward;
        bool                resequence; // set to "true" to fix locally generated mcast packets
        UINT16              my_seq;         // (TBD) keep per source seq state!!!
        
        unsigned int        recv_count;
        unsigned int        mrcv_count;
        unsigned int        dups_count;
        unsigned int        sent_count;
        unsigned int        serr_count;
       
}; // end class OpnetSmfProcess

		
#endif  // !_OPNET_SMF_PROCESS

