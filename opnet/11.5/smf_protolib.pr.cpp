/* Process model C++ form file: smf_protolib.pr.cpp */
/* Portions of this file copyright 1992-2006 by OPNET Technologies, Inc. */



/* This variable carries the header into the object file */
const char smf_protolib_pr_cpp [] = "MIL_3_Tfile_Hdr_ 115A 30A op_runsim 7 4540BC74 4540BC74 1 apocalypse Jim@Hauser 0 0 none none 0 0 none 0 0 0 0 0 0 0 0 d50 3                                                                                                                                                                                                                                                                                                                                                                                                   ";
#include <string.h>



/* OPNET system definitions */
#include <opnet.h>



/* Header Block */

#include <OpnetSmfProcess.h>
#include <protoTree.h>
#include <oms_pr.h>
#include <oms_tan.h>
#include <smf_ipc.h>
#include <wlan_support.h>
#include <ip_dgram_sup.h>
#include <smfVersion.h>
#include <udp_dgram_sup.h>


/*	Define a transition conditions              	*/

#define	SELF_NOTIF		intrpt_type == OPC_INTRPT_SELF

/*	Define a transition condition corresponding 	*/
/*	to capture of an inbound or an outbound packet  */
#define PACKET_CAPTURE	intrpt_type == OPC_INTRPT_STRM

/*	Define a transition condition corresponding 	*/
/*  to arrival of a command from another process.   */
#define COMMAND			intrpt_type == OPC_INTRPT_REMOTE


#define IPV4_ADDR_SIZE 4
#define IPV6_ADDR_SIZE 16
//#define MAC_ADDR_LEN 6 - JPH  Opnet uses an int for mac addr
#define MAC_ADDR_LEN 4  

const char* const OpnetSmfProcess::CMD_LIST[] =
{
    "-version",        // show version and exit
    "-ipv6",           // enable IPv6 support (must be first on command-line)
    "+interface",      // recv/forward raw packets on given interface name
    "+defaultForward", // {on | off] (off is default) to forward all mcast packets once
    "+resequence",     // {on | off} (off is default) to "correct" local sequence numbers (add IPv6 header option)
    "+smfServer",      // connect to this server, and send "smfClientStart <myName>"
    "+instance",       // sets our instance (control_pipe) name 
    "+debug",          // set debug level
    "+log",            // <logFile> debug log file
    NULL
};

/* End of Header Block */

#if !defined (VOSD_NO_FIN)
#undef	BIN
#undef	BOUT
#define	BIN		FIN_LOCAL_FIELD(_op_last_line_passed) = __LINE__ - _op_block_origin;
#define	BOUT	BIN
#define	BINIT	FIN_LOCAL_FIELD(_op_last_line_passed) = 0; _op_block_origin = __LINE__;
#else
#define	BINIT
#endif /* #if !defined (VOSD_NO_FIN) */



/* State variable definitions */
class smf_protolib_state
	{
	public:
		smf_protolib_state (void);

		/* Destructor contains Termination Block */
		~smf_protolib_state (void);

		/* State Variables */
		OpnetSmfProcess	        		smf                                             ;	/* SMF application object for this IP module */
		Objid	                  		my_id                                           ;	/* Variable for storing objid of the surrounding	 */
		                        		                                                	/* ARP processor, and the surr. node objid.		     */
		Objid	                  		my_node_id                                      ;
		Objid	                  		my_olsr_id                                      ;
		Prohandle	              		own_prohandle                                   ;
		OmsT_Pr_Handle	         		own_process_record_handle                       ;
		char	                   		pid_string [512]                                ;	/* State variables for use while tracing/debugging.	 */
		Objid	                  		my_pro_id                                       ;
		Stathandle	             		bits_rcvd_stathandle                            ;
		Stathandle	             		pkts_rcvd_stathandle                            ;
		Stathandle	             		bits_frwd_stathandle                            ;
		Stathandle	             		pkts_frwd_stathandle                            ;
		Boolean	                		olsr_packet_capture                             ;
		Prohandle	              		invoke_prohandle                                ;
		int	                    		seq_word_size                                   ;
		int	                    		window_size                                     ;
		int	                    		window_past_max                                 ;
		Boolean	                		duplicate_filtering                             ;

		/* FSM code */
		void smf_protolib (OP_SIM_CONTEXT_ARG_OPT);
		/* Diagnostic Block */
		void _op_smf_protolib_diag (OP_SIM_CONTEXT_ARG_OPT);

#if defined (VOSD_NEW_BAD_ALLOC)
		void * operator new (size_t) throw (VOSD_BAD_ALLOC);
#else
		void * operator new (size_t);
#endif
		void operator delete (void *);

		/* Memory management */
		static VosT_Obtype obtype;

	private:
		/* Internal state tracking for FSM */
		FSM_SYS_STATE
	};

VosT_Obtype smf_protolib_state::obtype = (VosT_Obtype)OPC_NIL;

#define pr_state_ptr            		((smf_protolib_state*) (OP_SIM_CONTEXT_PTR->_op_mod_state_ptr))
#define smf                     		pr_state_ptr->smf
#define my_id                   		pr_state_ptr->my_id
#define my_node_id              		pr_state_ptr->my_node_id
#define my_olsr_id              		pr_state_ptr->my_olsr_id
#define own_prohandle           		pr_state_ptr->own_prohandle
#define own_process_record_handle		pr_state_ptr->own_process_record_handle
#define pid_string              		pr_state_ptr->pid_string
#define my_pro_id               		pr_state_ptr->my_pro_id
#define bits_rcvd_stathandle    		pr_state_ptr->bits_rcvd_stathandle
#define pkts_rcvd_stathandle    		pr_state_ptr->pkts_rcvd_stathandle
#define bits_frwd_stathandle    		pr_state_ptr->bits_frwd_stathandle
#define pkts_frwd_stathandle    		pr_state_ptr->pkts_frwd_stathandle
#define olsr_packet_capture     		pr_state_ptr->olsr_packet_capture
#define invoke_prohandle        		pr_state_ptr->invoke_prohandle
#define seq_word_size           		pr_state_ptr->seq_word_size
#define window_size             		pr_state_ptr->window_size
#define window_past_max         		pr_state_ptr->window_past_max
#define duplicate_filtering     		pr_state_ptr->duplicate_filtering

/* These macro definitions will define a local variable called	*/
/* "op_sv_ptr" in each function containing a FIN statement.	*/
/* This variable points to the state variable data structure,	*/
/* and can be used from a C debugger to display their values.	*/
#undef FIN_PREAMBLE_DEC
#undef FIN_PREAMBLE_CODE
#  define FIN_PREAMBLE_DEC	smf_protolib_state *op_sv_ptr;
#if defined (OPD_PARALLEL)
#  define FIN_PREAMBLE_CODE	\
		op_sv_ptr = ((smf_protolib_state *)(sim_context_ptr->_op_mod_state_ptr));
#else
#  define FIN_PREAMBLE_CODE	op_sv_ptr = pr_state_ptr;
#endif


/* Function Block */

#if !defined (VOSD_NO_FIN)
enum { _op_block_origin = __LINE__ + 2};
#endif

/* Forward declrations */
void smf_connected_arp_find (Objid*);
Boolean smf_connected_mac_find (Objid*, int*);
void smf_warn (const char*);


static void smf_init ()
	{
	FIN (smf_init ());
	/* Get value of toggle which indicates if captured packets should be forwarded to OLSR */
	op_ima_obj_attr_get_toggle(my_id,"OLSR Packet Capture",&olsr_packet_capture);
	op_ima_obj_attr_get_int32(my_id,"Sequence Word Size",&seq_word_size);
	op_ima_obj_attr_get_int32(my_id,"Window Size",&window_size);
	op_ima_obj_attr_get_int32(my_id,"Window Past Max",&window_past_max);
	op_ima_obj_attr_get_toggle(my_id,"Duplicate Filtering",&duplicate_filtering);
	
	if (olsr_packet_capture)
		{
		/* Obtain a pointer to the process record handle list of any
        neighboring OLSR processes. */
		List* proc_record_handle_list_ptr = op_prg_list_create();
		oms_pr_process_discover(my_id, proc_record_handle_list_ptr,
	                        "protocol", OMSC_PR_STRING, "OLSR_NRL", OPC_NIL);

		/* An error should be created if there are zero or more than
		one OLSR process connected to the SMF module. */
		int record_handle_list_size = op_prg_list_size(proc_record_handle_list_ptr);
		if (1 != record_handle_list_size)
			{
			/* Generate an error and end simulation. */
			op_sim_end("Error: either zero or more than one OLSR process connected to SMF.", "", "", "");
			}
		else
			{
			/* Obtain the process record handle of the neighboring OLSR process. */
			OmsT_Pr_Handle process_record_handle = (OmsT_Pr_Handle) op_prg_list_access(proc_record_handle_list_ptr, OPC_LISTPOS_HEAD);
			/* Obtain the object id of the OLSR module. */
			oms_pr_attr_get(process_record_handle, "module objid", OMSC_PR_OBJID, &my_olsr_id);
			}

		/* Deallocate the list pointer. */
		while (op_prg_list_size(proc_record_handle_list_ptr) > 0)
			op_prg_list_remove(proc_record_handle_list_ptr, OPC_LISTPOS_HEAD);
		op_prg_mem_free(proc_record_handle_list_ptr);
		}

	
	/* Register the statistics that will be saved by this model. */
	bits_rcvd_stathandle = op_stat_reg ("SMF.MAC Traffic Received (bits)",	OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	pkts_rcvd_stathandle = op_stat_reg ("SMF.MAC Traffic Received (packets)",OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	bits_frwd_stathandle = op_stat_reg ("SMF.MAC Traffic Forwarded (bits)",		OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	pkts_frwd_stathandle = op_stat_reg ("SMF.MAC Traffic Forwarded (packets)",	OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	FOUT;
	}


static void smf_error (const char *msg)
	{
	FIN (smf_error (msg));
	op_sim_end ("Error in SMF process model (smf_protolib):",
		msg, OPC_NIL, OPC_NIL);
	FOUT;
	}

static void
smf_warn (const char *msg)
	{
	FIN (smf_warn (msg))
	op_sim_message ("Warning from SMF process model (smf_protolib):", msg);
	FOUT;
	}



static void smf_packet_handle ()
	{
	smfT_wlan_mem*	mem;
	double			pk_size;
	
	FIN (smf_packet_handle ());
	
	if (!olsr_packet_capture) FOUT;  // JPH 9/12/06 - Fix recoverable error if SMF is disabled.

	/* get pointer to smf/wlan common memory */
	mem = (smfT_wlan_mem*)op_pro_argmem_access ();
	
	/* Caclulate metrics to be updated.		*/
	pk_size = (double) op_pk_total_size_get (mem->pkptr);

	/* Update local statistics.				*/
	op_stat_write (bits_rcvd_stathandle, 		pk_size);
	op_stat_write (pkts_rcvd_stathandle, 		1.0);

	/* call SMF OnPktReceive member function */
	smf.OnPktReceive(mem);
	FOUT;
	}

static void smf_command_handle()
	{
	Ici*	ici_ptr;
	char*	buffer;
	int		len;
	
	FIN (smf_command_handle());
			
	ici_ptr = op_intrpt_ici();
	
	if (ici_ptr == OPC_NIL)
		smf_error("smf_command_handle failed to get smfControlMsg ici.");
	if (op_ici_attr_exists (ici_ptr, "cmdbuf"))
		{
		if (op_ici_attr_get_ptr (ici_ptr, "cmdbuf", (void**)&buffer) == OPC_COMPCODE_FAILURE)
			smf_error("smf_command_handle failed to get cmdbuf.");
		}
	if (op_ici_attr_exists (ici_ptr, "len"))
		{
		if (op_ici_attr_get_int32 (ici_ptr, "len", &len) == OPC_COMPCODE_FAILURE)
			smf_error("smf_command_handle failed to get len.");
		}
	smf.OnControlMsg(buffer, len);
	op_ici_destroy(ici_ptr);
	FOUT;
	}



/* Define OpnetSmfProcess member functions */


OpnetSmfProcess::OpnetSmfProcess()
	: 
#ifdef HAVE_IPV6
    ipv6_enabled(false),	  
#endif // HAVE_IPV6 
	update_age_max(10), current_update_time(0),
	selector_list_len(0),
#ifdef MNE_SUPPORT
    mne_block_list_len(0),
#endif // MNE_SUPPORT
    default_forward(false), resequence(false), my_seq(65533), 
    recv_count(0), mrcv_count(0), dups_count(0),
    sent_count(0), serr_count(0) 
	  
	{ 
	prune_timer.SetInterval(5.0);
	prune_timer.SetRepeat(-1);
	prune_timer.SetListener(this, &OpnetSmfProcess::OnPruneTimeout);
	}


OpnetSmfProcess::~OpnetSmfProcess()
	{
    duplicate_tree.Destroy();
	}


bool OpnetSmfProcess::OnStartup(int argc, const char*const* argv)
	{
		
    if (!duplicate_tree.Init(seq_word_size, window_size, window_past_max))
		{
        DMSG(0, "nrlsmf: error initializing duplicate_tree\n");
        FRET (OPC_FALSE);
		}
     
    ActivateTimer(prune_timer);
    
    FRET (OPC_TRUE);
	}


bool OpnetSmfProcess::ProcessCommands(int argc, const char*const* argv)
	{
	/* virtual functions of the OpnetProtosimProcess class */
	bool t_val = OPC_FALSE;
	return t_val;
	}



void OpnetSmfProcess::OnShutdown()
	{
	duplicate_tree.Destroy();
	if (prune_timer.IsActive()) 
		prune_timer.Deactivate();
   
	DMSG(0, "nrlsmf: Done.\n"); 
	CloseDebugLog();
	}


void OpnetSmfProcess::OnPktReceive(smfT_wlan_mem* mem)
	{
	/* Code extracted from nrlsmf while loop that processes captured packets */
	/* Preserve some of the orginal code as comments */
		
	//const int BUFFER_MAX = 2048;
    //unsigned char buffer[BUFFER_MAX];
    //unsigned int numBytes = BUFFER_MAX;
	//OpnetSmfProcess::Direction direction;
	
	char						pk_format [128];
	IpT_Dgram_Fields*			ip_dgram_fd_ptr;
	InetT_Address				src_netaddr = INETC_ADDRESS_INVALID;
	InetT_Address				dest_netaddr = INETC_ADDRESS_INVALID;
	IpT_Address					src_ip4addr;
	IpT_Address					dest_ip4addr;
	int							version = 0;
	Packet*						ip_pkptr;
	
	FIN (OpnetSmfProcess::OnPktReceive(mem));
	
    // Only forward inbound packets (unless we're "fixing" outbound packet seq num
    //if ((ProtoCap::INBOUND != direction) && !resequence) continue;
	
	mem->forward = OPC_FALSE;	
	mem->is_duplicate = OPC_FALSE;	
	if ((INBOUND != mem->direction) && !resequence) FOUT;
        
    // Only forward IPv4 or IPv6 packets
    //UINT16 type;
    //memcpy(&type, buffer+12, 2);
    //type = ntohs(type);
    //if ((type != 0x0800) && (type != 0x86dd)) continue;
				
    recv_count++;  // increment total IP packets recvd stat count
	
	ip_pkptr = op_pk_copy(mem->pkptr);
        
    // 1) Get IP protocol version
    //unsigned char version = buffer[IP_HDR_OFFSET]  >> 4;
	// JPH - Use packet format as a substitute for protocol type
	op_pk_format (ip_pkptr, pk_format);	
	if (strcmp (pk_format, "ip_dgram_v4") == 0)
		{
		version = 4;        
		/*	Get the fields structure from the packet.			*/
		op_pk_nfd_access (ip_pkptr, "fields", &ip_dgram_fd_ptr);
		/* Determine the source address of the data.			*/
		src_netaddr = inet_address_copy (ip_dgram_fd_ptr->src_addr);
		if (InetC_Addr_Family_v6 == inet_address_family_get (&src_netaddr))
			version = 6;
		/* Store the destinaton address also.					*/
		dest_netaddr = inet_address_copy (ip_dgram_fd_ptr->dest_addr);
		}
	
    // 2) Get IP packet dst and src addresses
    ProtoAddress srcIp, dstIp;
	src_ip4addr = inet_ipv4_address_get (src_netaddr);
	//srcIp.SetRawHostAddress(ProtoAddress::SIM, (char*)&src_ip4addr, IPV4_ADDR_SIZE);
	srcIp.SimSetAddress(src_ip4addr);
	dest_ip4addr = inet_ipv4_address_get (dest_netaddr);
	//dstIp.SetRawHostAddress(ProtoAddress::SIM, (char*)&dest_ip4addr, IPV4_ADDR_SIZE);
	dstIp.SimSetAddress(dest_ip4addr);
	
	// JPH - Forward broadcast packets to OLSR process
	if (dstIp.IsBroadcast())
		{
		//  JPH - Don't send packets to OLSR that will be dropped by OLSR anyway.
		if (ip_dgram_fd_ptr->protocol != IpC_Protocol_Udp)
			{
			op_pk_destroy(ip_pkptr);
			FOUT;  // Don't send non-UDP packets.
			}
		UdpT_Dgram_Fields* udp_dgram_fd_ptr;
		Packet* udp_pkptr = ip_dgram_data_pkt_get(ip_pkptr);
		op_pk_nfd_access (udp_pkptr, "fields", &udp_dgram_fd_ptr);
		if (udp_dgram_fd_ptr->dest_port != 698)
			{
			op_pk_destroy(ip_pkptr);
			op_pk_destroy(udp_pkptr);
			FOUT;  // Don't send non-OLSR packets.
			}
		const unsigned int OLSR_OFFSET_TYPE = 4;    // OLSR packet type is 5th byte of OLSR msg
		Packet* olsr_pkptr;
		char* buffer;
		op_pk_nfd_get (udp_pkptr, "data", &olsr_pkptr);  // must use op_pk_nfd_get for ownership of olsr packet
	    op_pk_fd_get(olsr_pkptr, 0, &buffer);
		if (1 != buffer[OLSR_OFFSET_TYPE])
			{
			op_pk_destroy(ip_pkptr);
			op_pk_destroy(udp_pkptr);
			op_pk_destroy(olsr_pkptr);
			FOUT;  // Don't send non-Hello packets
			}
		smfT_olsr_ipc pcap;
		pcap.src_ip4addr = src_ip4addr;
		pcap.direction = mem->direction;
		pcap.version = version;
		pcap.tx_addr = mem->tx_addr;
		Ici* pcap_ici = op_ici_create("smfPcap");
		op_ici_attr_set_ptr(pcap_ici,"pcap",&pcap);
		op_ici_install(pcap_ici);
		op_intrpt_schedule_remote(op_sim_time(),PACKET_CAPTURE_EVENT,my_olsr_id);
		op_pk_destroy(ip_pkptr);
		op_pk_destroy(udp_pkptr);
		op_pk_destroy(olsr_pkptr);
		FOUT;
		}

    // 3) Only forward multicast packets
    if (!dstIp.IsMulticast())
		{
		op_pk_destroy(ip_pkptr);
		FOUT;
		}
        
    mrcv_count++;  // increment multicast received count

    // 4) Get source MAC address
    ProtoAddress srcMac;
    //srcMac.SetRawHostAddress(ProtoAddress::ETH, (char*)buffer+MAC_ADDR_LEN, MAC_ADDR_LEN);
    //srcMac.SetRawHostAddress(ProtoAddress::SIM, (char*)&mem->tx_addr, MAC_ADDR_LEN);
	srcMac.SimSetAddress(mem->tx_addr);
	// JPH 3/2/06 - receive side duplicate filtering
	UINT32 sequence = ip_dgram_fd_ptr->ident;
	bool hasSeq = OPC_TRUE;
	if (duplicate_filtering)
		mem->is_duplicate = duplicate_tree.IsDuplicate(srcIp, sequence, current_update_time);
        
    // 5) Should we forward this packet? (Based on source MAC addr and forwarding policy)
    bool forward = default_forward;
    if (forward)
		{
        //if (fwd_exception_list.Find((char*)buffer+MAC_ADDR_LEN, MAC_ADDR_LEN))
        //    forward = false;
		}
    else
		{
		SIMADDR macaddr = srcMac.SimGetAddress();
        if (IsSelector((char*)&macaddr))
            forward = OPC_TRUE;  
		}
        
    // 6) Forward the packet as needed
    if (forward)
		{
        // A) Get the packet sequence number  JPH 3/2/06 - moved to outer block 
        //UINT32 sequence;
        //bool hasSeq = GetPktSequence(version, buffer+IP_HDR_OFFSET, sequence);
            
        //bool locallyGeneratedPkt = 
        //    (0 == memcmp(srcMac.GetRawHostAddress(), my_mac_addr.GetRawHostAddress(), srcMac.GetLength()));
		bool locallyGeneratedPkt = (srcMac.SimGetAddress() == mem->rx_addr);
        if (!locallyGeneratedPkt)
			{
            // We might hear someone else forwarding our own packets ...
            if (4 == version)
				{
				my_ip_addr.SimSetAddress(mem->tx_ip_addr);
                if (srcIp.HostIsEqual(my_ip_addr))
                    locallyGeneratedPkt = OPC_TRUE; 
#ifdef HAVE_IPV6
				}
            else
				{
                if (srcIp.HostIsEqual(my_ip6_addr)) 
                    locallyGeneratedPkt = OPC_TRUE; 
#endif // HAVE_IPV6                    
				}     
			}
            
        if (hasSeq)
			{
            if (locallyGeneratedPkt)
				{
                // don't forward our own packets
 		        op_pk_destroy(ip_pkptr);
				// JPH 3/2/06 - filter own packets
				if (duplicate_filtering)
					mem->is_duplicate = OPC_TRUE;
                FOUT;
				}
            //else if (0 == DecrementPktTTL(version, buffer + IP_HDR_OFFSET))
		    else if (0 == (--(ip_dgram_fd_ptr->ttl)))  // JPH - Opnet doesn't model header checksum
				{
				// We decrement the TTL first so we don't have to 
				// bother checking for dups of TTL = 0 packets
		        op_pk_destroy(ip_pkptr);
				FOUT;  // don't forward packets with TTL == 1
				}
			else if (duplicate_filtering)  // JPH 3/2/06 - Use previously computed value
				{
				if (mem->is_duplicate)
					{
					dups_count++;
					op_pk_destroy(ip_pkptr);  // don't forward duplicate packets
					FOUT;
					}
				}
			else if (duplicate_tree.IsDuplicate(srcIp, sequence, current_update_time))
				{
                dups_count++;
	        	op_pk_destroy(ip_pkptr);  // don't forward duplicate packets
                FOUT;
				}
			}
        else if (locallyGeneratedPkt && resequence)
			{
            //numBytes = InsertPktSequence(version, buffer, numBytes, BUFFER_MAX, my_seq++);
			ip_dgram_fd_ptr->ident = my_seq++;
			}
        else
			{
            DMSG(0, "SmfApp::OnPktReceive() received packet with no sequence field\n");
		    op_pk_destroy(ip_pkptr);
            FOUT;       
			}
            
        // C) Send it along its way
        //if (cap_rcvr->Forward((char*)buffer, numBytes))
		//	{
        //    sent_count++;
		//	}
        //else
		//	{
        //    DMSG(0, "SmfApp::OnPktReceive() error forwarding packet\n");
        //    serr_count++;
		//	}
		/* Update local statistics.				*/
		op_stat_write (bits_frwd_stathandle, op_pk_total_size_get(mem->pkptr));
		op_stat_write (pkts_frwd_stathandle, 1.0);

		sent_count++;	// This counts packets that SMF attempts to forward.
		mem->forward = forward;  // JPH - Let wlan_mac_smf parent process do forwarding.
		op_pk_destroy(ip_pkptr);
		FOUT;
		}
	}


void OpnetSmfProcess::OnControlMsg(char* buffer, int len)
	{
	buffer[len] = '\0';
    // Parse received message from controller and populate
    // our forwarding table
    //if (len)
    //    TRACE("SmfApp::OnControlMsg() recv'd %d byte message from controller\n", len);            
            
    char* cmd = buffer;
    char* arg = NULL;
    for (unsigned int i = 0; i < len; i++)
		{
        if ('\0' == buffer[i])
            {
            break;
            }
        else if (isspace(buffer[i]))
            {
            buffer[i] = '\0';
            arg = buffer+i+1;
            break;
            }
        }
    unsigned int cmdLen = strlen(cmd);
    unsigned int argLen = len - (arg - cmd);
    // Check for a pipe only command first
    if (!strncmp(cmd, "smfServerStart", cmdLen))
        {
        smf_warn("SmfApp::OnControlMsg(smfServerStart) not expected");
        //if (server_pipe.IsOpen()) server_pipe.Close();
        //if (!server_pipe.Connect(arg))
        //    DMSG(0, "SmfApp::OnControlMsg(smfServerStart) error connecting to smf server\n");
        }
    else if (!strncmp(cmd, "forwardMac", cmdLen))
        {
        // The "arg" points to the current set of MPR selector MAC addresses
        // Overwrite our current selector list
        if (argLen > SELECTOR_LIST_LEN_MAX)
            {
            DMSG(0, "SmfApp::OnControlMsg(forwardMac) error: selector list too long!\n");
            // (TBD) record this error indication permanently
            argLen = SELECTOR_LIST_LEN_MAX;
            }
        memcpy(selector_list, arg, argLen);
        selector_list_len = argLen;
        //TRACE("SmfApp::OnControlMsg(forwardMac:%u) ", argLen);
        //for (unsigned int i = 0; i < argLen; i += MAC_ADDR_LEN)
        //    {
        //    for (int j = 0; j< MAC_ADDR_LEN; j++)
        //        TRACE("%02x", ((unsigned char) arg[i+j]));
        //    TRACE("|");
        //    }
        //TRACE("\n");
        }  
    else if (!strncmp(cmd, "symetricMac", cmdLen))
        {
        // The "arg" points to the current set of symetric neighbor MAC addresses
        // Overwrite our current symmetric list
        if (argLen > SELECTOR_LIST_LEN_MAX)
			{
            DMSG(0, "SmfApp::OnControlMsg(symetricMac) error: symmetric list too long!\n");
            // (TBD) record this error indication permanently
            argLen = SELECTOR_LIST_LEN_MAX;
			}
        memcpy(symetric_list, arg, argLen);
        symetric_list_len = argLen;
        }  
#ifdef MNE_SUPPORT
    else if (!strncmp(cmd, "mneBlock", cmdLen))
        {
        // The "arg" points to the current set of MPR selector MAC addresses
        // Overwrite our current selector list
        if (argLen > SELECTOR_LIST_LEN_MAX)
            {
            DMSG(0, "SmfApp::OnControlMsg(mneBlock) error: mac list too long!\n");
            // (TBD) record this error indication permanently
            argLen = SELECTOR_LIST_LEN_MAX;
            }
        memcpy(mne_block_list, arg, argLen);
        mne_block_list_len = argLen;
        }  
#endif // MNE_SUPPORT
    else
        {
        // Maybe it's a regular command
        if (!OnCommand(cmd, arg))
            DMSG(0, "SmfApp::OnControlMsg() invalid command: \"%s\"\n", cmd);
        }
    }   


bool OpnetSmfProcess::IsSelector(const char* macAddr) const
	{
    const char *ptr = selector_list;
    const char* endPtr = selector_list + selector_list_len;
    while (ptr < endPtr)
		{
        if (!memcmp(macAddr, ptr, MAC_ADDR_LEN))
            return true;   
        ptr += MAC_ADDR_LEN;
		}
    return false;
	}  // end SmfApp::IsSelector()

#ifdef MNE_SUPPORT
bool OpnetSmfProcess::MneIsBlocking(const char* macAddr) const
	{
    const char *ptr = mne_block_list;
    const char* endPtr = mne_block_list + mne_block_list_len;
    while (ptr < endPtr)
		{
        if (!memcmp(macAddr, ptr, MAC_ADDR_LEN))
            return true;   
        ptr += MAC_ADDR_LEN;
		}
    return false;
	}  // end SmfApp::MneIsBlocking()
#endif // MNE_SUPPORT


bool OpnetSmfProcess::OnPruneTimeout(ProtoTimer& theTimer)
	{
    current_update_time += (unsigned int)prune_timer.GetInterval();
    // The SmfDuplicateTree::Prune() method removes
    // entries which are stale for more than "update_age_max"
    duplicate_tree.Prune(current_update_time, update_age_max);
    
    
    DMSG(0, "flows:%u recv:%u mrcv:%u uniq:%u sent:%u serr:%u\n",
            duplicate_tree.GetCount(), recv_count, mrcv_count,
            mrcv_count - dups_count, sent_count, serr_count); 
    return true;
	}  // end SmfApp::OnPruneTimeout()



void OpnetSmfProcess::PrintPacket(FILE* filePtr, u_char *pkt, unsigned int len)
	{
    for(unsigned int i = 0; i < len; i++) 
		{
        if ((i > 0) && (0 == (i | 0x0f))) fprintf(filePtr, "\n");
        fprintf(filePtr, "%02x ", pkt[i]);
		}
    if (len) fprintf(filePtr, "\n");
	}  // end SmfApp::PrintPacket()




bool OpnetSmfProcess::OnCommand(const char* cmd, const char* val)
{
    CmdType type = GetCmdType(cmd);
    if(CMD_INVALID == type)
    {
        DMSG(0, "SmfApp::OnCommand() invalid command: %s\n", cmd);
        return false;   
    }
    unsigned int len = strlen(cmd);
    if ((CMD_ARG == type) && !val)
    {
        DMSG(0, "SmfApp::OnCommand(%s) missing argument\n", cmd);
        return false;
    }
    else if (!strncmp("version", cmd, len))
    {
	    fprintf(stderr, "%s\n", _SMF_VERSION);
        return false;
    }
#ifdef HAVE_IPV6 // JPH
    else if (!strncmp("ipv6", cmd, len))
    {
#ifdef _PROTO_DETOUR
	    if (resequence && !OpenIPv6Detour())
        {
            DMSG(0, "SmfApp::OnCommand(ipv6) error opening IPv6 detour\n");
            return false;
        }
#endif // _PROTO_DETOUR
        ipv6_enabled = true;
    }
#endif // HAVE_IPV6
    else if (!strncmp("interface", cmd, len))
    {
        // Make sure "val" is an interface name
        int ifIndex = ProtoSocket::GetInterfaceIndex(val);
        char ifName[256];
        ifName[255] = '\0';
        if (!ProtoSocket::GetInterfaceName(ifIndex, ifName, 255))
        {
            DMSG(0, "nrlsmf: invalid <interfaceName>\n");
            return false;
        }
        if (!ProtoSocket::GetInterfaceAddress(ifName, ProtoAddress::ETH, my_mac_addr))
        {
            DMSG(0, "nrlsmf: error getting interface MAC address\n");
            return false;
        }
        // Here we get our locally-assigned address for the interface
        // (TBD) We should create a list of all addresses when multiple
        //       addresses are assigned to the interface
        my_ip_addr.Invalidate();
        ProtoSocket::GetInterfaceAddress(ifName, ProtoAddress::IPv4, my_ip_addr);
#ifdef HAVE_IPV6        
        my_ip6_addr.Invalidate();
        ProtoRouteMgr* routeMgr = ProtoRouteMgr::Create();
        if (NULL != routeMgr)
        {
            if (routeMgr->Open())
            {
                if (routeMgr->GetInterfaceAddress(ifIndex, ProtoAddress::IPv6, my_ip6_addr))
                    DMSG(1, "SmfApp::OnCommand() ProtoSocket::GetInterfaceAddress(IPv6) failed\n");
                routeMgr->Close();
            }
            else
            {
                DMSG(1, "SmfApp::OnCommand() ProtoRouteMgr::OPen() failed\n");
            }
            delete routeMgr;
        }
        else if (!ProtoSocket::GetInterfaceAddress(ifName, ProtoAddress::IPv6, my_ip6_addr))
        {
            DMSG(1, "SmfApp::OnCommand() ProtoSocket::GetInterfaceAddress(IPv6) failed\n");
        }
#endif // HAVE_IPV6
        // Open packet sniffing on the given interface
#ifndef OPNET  // JPH
	    if (!cap_rcvr->IsOpen())
        {
	        if (!cap_rcvr->Open(ifName))
            {
                DMSG(0, "nrlsmf: error opening ProtoCap rcvr\n");
                return false;
	        }
            DMSG(0, "nrlsmf: listening on interface \"%s\" ...\n", ifName);
	    }
#endif  // OPNET
    }
    else if (!strncmp("smfServer", cmd, len))
    {
		smf_warn ("smfServer command not supported in Opnet simulation.");
    }
    else if (!strncmp("instance", cmd, len))
    {
		smf_warn ("instance command not supported in Opnet simulation.");
    }      
    else if (!strncmp("resequence", cmd, len))
    {
        if (!strcmp("on", val))
        {
#ifdef _PROTO_DETOUR
            if (NULL == (detour_ipv4 = ProtoDetour::Create()))
            {
                DMSG(0, "SmfApp::OnCommand(resequence) new ProtoDetour error: %s\n",
                        GetErrorString());
                return false;
            }
            detour_ipv4->SetNotifier(static_cast<ProtoChannel::Notifier*>(&dispatcher));
            detour_ipv4->SetListener(this, &SmfApp::OnPktIntercept);
            ProtoAddress srcFilter;
            ProtoAddress dstFilter;
            unsigned int dstFilterMask;
            srcFilter.Reset(ProtoAddress::IPv4);  // unspecified address
            dstFilter.ResolveFromString("224.0.0.0");
            dstFilterMask = 4;
            if (!detour_ipv4->Open(ProtoDetour::OUTPUT, srcFilter, 0, dstFilter, dstFilterMask))
            {
                DMSG(0, "SmfApp::OnCommand(resequence) error opening IPv4 detour\n");
                return false;
            }
#ifdef HAVE_IPV6
            if (ipv6_enabled && !OpenIPv6Detour())
            {
                DMSG(0,  "SmfApp::OnCommand(resequence) error opening IPv6 detour\n"); 
                return false; 
            }
#endif // HAVE_IPV6
#endif // _PROTO_DETOUR
            resequence = true;
        }
        else if (!strcmp("off", val))
        {
#ifdef _PROTO_DETOUR
            if (NULL != detour_ipv4)
            {
                detour_ipv4->Close();
                delete detour_ipv4;
                detour_ipv4 = NULL;
            }
#ifdef HAVE_IPV6
            if (NULL != detour_ipv6)
            {
                detour_ipv6->Close();
                delete detour_ipv6;
                detour_ipv6 = NULL;
            }
#endif // HAVE_IPV6
#endif // _PROTO_DETOUR
            resequence = false;
        }
        else
        {
            DMSG(0, "SmfApp::OnCommand(resequence) invalid argument: %s\n", val);
            return false;
        }
    }      
    else if (!strncmp("defaultForward", cmd, len))
    {
        if (!strcmp("on", val))
        {
            default_forward = true;
        }
        else if (!strcmp("off", val))
        {
            default_forward = false;
        }
        else
        {
            DMSG(0, "SmfApp::OnCommand(defaultForward) invalid argument: %s\n", val);
            return false;
        }
    }    
    else if (!strncmp("debug", cmd, len))
    {
        SetDebugLevel(atoi(val));  // set protolib debug level
    }    
    else if (!strncmp("log", cmd, len))
    {
        if (!OpenDebugLog(val))  // set protolib debug log file
        {
            DMSG(0, "SmfApp::OnCommand(log) error opening file:\n", GetErrorString());
            return false;
        }
    }
    return true;
}  // end OpnetSmfProcess::OnCommand()


OpnetSmfProcess::CmdType OpnetSmfProcess::GetCmdType(const char* cmd)
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
};  // end OpnetSmfProcess::GetCmdType()

/* End of Function Block */

/* Undefine optional tracing in FIN/FOUT/FRET */
/* The FSM has its own tracing code and the other */
/* functions should not have any tracing.		  */
#undef FIN_TRACING
#define FIN_TRACING

#undef FOUTRET_TRACING
#define FOUTRET_TRACING

/* Undefine shortcuts to state variables because the */
/* following functions are part of the state class */
#undef smf
#undef my_id
#undef my_node_id
#undef my_olsr_id
#undef own_prohandle
#undef own_process_record_handle
#undef pid_string
#undef my_pro_id
#undef bits_rcvd_stathandle
#undef pkts_rcvd_stathandle
#undef bits_frwd_stathandle
#undef pkts_frwd_stathandle
#undef olsr_packet_capture
#undef invoke_prohandle
#undef seq_word_size
#undef window_size
#undef window_past_max
#undef duplicate_filtering

/* Access from C kernel using C linkage */
extern "C"
{
	VosT_Obtype _op_smf_protolib_init (int * init_block_ptr);
	VosT_Address _op_smf_protolib_alloc (VOS_THREAD_INDEX_ARG_COMMA VosT_Obtype, int);
	void smf_protolib (OP_SIM_CONTEXT_ARG_OPT)
		{
		((smf_protolib_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr))->smf_protolib (OP_SIM_CONTEXT_PTR_OPT);
		}

	void _op_smf_protolib_svar (void *, const char *, void **);

	void _op_smf_protolib_diag (OP_SIM_CONTEXT_ARG_OPT)
		{
		((smf_protolib_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr))->_op_smf_protolib_diag (OP_SIM_CONTEXT_PTR_OPT);
		}

	void _op_smf_protolib_terminate (OP_SIM_CONTEXT_ARG_OPT)
		{
		/* The destructor is the Termination Block */
		delete (smf_protolib_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr);
		}


	VosT_Obtype Vos_Define_Object_Prstate (const char * _op_name, unsigned int _op_size);
	VosT_Address Vos_Alloc_Object_MT (VOS_THREAD_INDEX_ARG_COMMA VosT_Obtype _op_ob_hndl);
	VosT_Fun_Status Vos_Poolmem_Dealloc_MT (VOS_THREAD_INDEX_ARG_COMMA VosT_Address _op_ob_ptr);
} /* end of 'extern "C"' */




/* Process model interrupt handling procedure */


void
smf_protolib_state::smf_protolib (OP_SIM_CONTEXT_ARG_OPT)
	{
#if !defined (VOSD_NO_FIN)
	int _op_block_origin = 0;
#endif
	FIN_MT (smf_protolib_state::smf_protolib ());
	try
		{
		/* Temporary Variables */
		/* used for transition selection */
		int						intrpt_type;
		int						invoke_mode;
		int						intrpt_code;
		
		/* End of Temporary Variables */


		FSM_ENTER ("smf_protolib")

		FSM_BLOCK_SWITCH
			{
			/*---------------------------------------------------------*/
			/** state (init) enter executives **/
			FSM_STATE_ENTER_UNFORCED_NOLABEL (0, "init", "smf_protolib [init enter execs]")
				FSM_PROFILE_SECTION_IN ("smf_protolib [init enter execs]", state0_enter_exec)
				{
				
				/* Obtain the object ID of the surrounding wireless_lan_mac processor. 	*/
				my_id = op_id_self ();
				
				/* Also obtain the object ID of the surrounding node.		*/
				my_node_id = op_topo_parent (my_id);
				
				/* Obtain the prohandle for this process.					*/
				own_prohandle = op_pro_self ();
				
				/**	Register the process in the model-wide registry.				**/
				own_process_record_handle = (OmsT_Pr_Handle) oms_pr_process_register 
					(my_node_id, my_id, own_prohandle, "SMF");
				
				/*	Register the protocol attribute in the registry. No other	*/
				/*	process should use the string "smf" as the value for its	*/
				/*	"protocol" attribute!										*/
				oms_pr_attr_set (own_process_record_handle, 
					"protocol", 	OMSC_PR_STRING, 	"smf",
					OPC_NIL);
				
				/*	Initialize the state variable used to keep track of the	*/
				/*	SMF module object ID and to generate trace/debugging 	*/
				/*	string information. Obtain process ID of this process. 	*/
				my_pro_id = op_pro_id (op_pro_self ());
				
				/* 	Set the process ID string, to be later used for trace	*/
				/*	and debugging information.								*/
				sprintf (pid_string, "SMF PID (%d)", my_pro_id);
				
				/* 	Schedule a self interrupt to allow the olsr to 			*/
				/*	perform additional initialization.  			   		*/
				op_intrpt_schedule_self (op_sim_time (), 0);
				
				}
				FSM_PROFILE_SECTION_OUT (state0_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (1,"smf_protolib")


			/** state (init) exit executives **/
			FSM_STATE_EXIT_UNFORCED (0, "init", "smf_protolib [init exit execs]")
				FSM_PROFILE_SECTION_IN ("smf_protolib [init exit execs]", state0_exit_exec)
				{
				smf_init();
				smf.OnStartup(0,NULL);
				}
				FSM_PROFILE_SECTION_OUT (state0_exit_exec)


			/** state (init) transition processing **/
			FSM_TRANSIT_FORCE (1, state1_enter_exec, ;, "default", "", "init", "idle", "smf_protolib [init -> idle : default / ]")
				/*---------------------------------------------------------*/



			/** state (idle) enter executives **/
			FSM_STATE_ENTER_UNFORCED (1, "idle", state1_enter_exec, "smf_protolib [idle enter execs]")

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (3,"smf_protolib")


			/** state (idle) exit executives **/
			FSM_STATE_EXIT_UNFORCED (1, "idle", "smf_protolib [idle exit execs]")
				FSM_PROFILE_SECTION_IN ("smf_protolib [idle exit execs]", state1_exit_exec)
				{
				/* determine the interrupt type */
				intrpt_type = op_intrpt_type ();
				intrpt_code = op_intrpt_code ();
				
				invoke_prohandle = op_pro_invoker (own_prohandle, &invoke_mode);
				if ((invoke_mode != OPC_PROINV_INDIRECT) && (invoke_mode != OPC_PROINV_DIRECT))
					{
					smf_error ("Unable to determine how SMF process got invoked."); 	
					}
				if (intrpt_type == OPC_INTRPT_ENDSIM)
					smf.OnShutdown();
				}
				FSM_PROFILE_SECTION_OUT (state1_exit_exec)


			/** state (idle) transition processing **/
			FSM_PROFILE_SECTION_IN ("smf_protolib [idle trans conditions]", state1_trans_conds)
			FSM_INIT_COND (PACKET_CAPTURE)
			FSM_TEST_COND (COMMAND)
			FSM_DFLT_COND
			FSM_TEST_LOGIC ("idle")
			FSM_PROFILE_SECTION_OUT (state1_trans_conds)

			FSM_TRANSIT_SWITCH
				{
				FSM_CASE_TRANSIT (0, 1, state1_enter_exec, smf_packet_handle();, "PACKET_CAPTURE", "smf_packet_handle()", "idle", "idle", "smf_protolib [idle -> idle : PACKET_CAPTURE / smf_packet_handle()]")
				FSM_CASE_TRANSIT (1, 1, state1_enter_exec, smf_command_handle();, "COMMAND", "smf_command_handle()", "idle", "idle", "smf_protolib [idle -> idle : COMMAND / smf_command_handle()]")
				FSM_CASE_TRANSIT (2, 1, state1_enter_exec, ;, "default", "", "idle", "idle", "smf_protolib [idle -> idle : default / ]")
				}
				/*---------------------------------------------------------*/



			}


		FSM_EXIT (0,"smf_protolib")
		}
	catch (...)
		{
		Vos_Error_Print (VOSC_ERROR_ABORT,
			(const char *)VOSC_NIL,
			"Unhandled C++ exception in process model (smf_protolib)",
			(const char *)VOSC_NIL, (const char *)VOSC_NIL);
		}
	}




void
smf_protolib_state::_op_smf_protolib_diag (OP_SIM_CONTEXT_ARG_OPT)
	{
	/* No Diagnostic Block */
	}

void
smf_protolib_state::operator delete (void* ptr)
	{
	FIN (smf_protolib_state::operator delete (ptr));
	Vos_Poolmem_Dealloc_MT (OP_SIM_CONTEXT_THREAD_INDEX_COMMA ptr);
	FOUT
	}

smf_protolib_state::~smf_protolib_state (void)
	{

	FIN (smf_protolib_state::~smf_protolib_state ())


	/* No Termination Block */


	FOUT
	}


#undef FIN_PREAMBLE_DEC
#undef FIN_PREAMBLE_CODE

#define FIN_PREAMBLE_DEC
#define FIN_PREAMBLE_CODE

void *
smf_protolib_state::operator new (size_t)
#if defined (VOSD_NEW_BAD_ALLOC)
		throw (VOSD_BAD_ALLOC)
#endif
	{
	void * new_ptr;

	FIN_MT (smf_protolib_state::operator new ());

	new_ptr = Vos_Alloc_Object_MT (VOS_THREAD_INDEX_UNKNOWN_COMMA smf_protolib_state::obtype);
#if defined (VOSD_NEW_BAD_ALLOC)
	if (new_ptr == VOSC_NIL) throw VOSD_BAD_ALLOC();
#endif
	FRET (new_ptr)
	}

/* State constructor initializes FSM handling */
/* by setting the initial state to the first */
/* block of code to enter. */

smf_protolib_state::smf_protolib_state (void) :
		_op_current_block (0)
	{
#if defined (OPD_ALLOW_ODB)
		_op_current_state = "smf_protolib [init enter execs]";
#endif
	}

VosT_Obtype
_op_smf_protolib_init (int * init_block_ptr)
	{
	FIN_MT (_op_smf_protolib_init (init_block_ptr))

	smf_protolib_state::obtype = Vos_Define_Object_Prstate ("proc state vars (smf_protolib)",
		sizeof (smf_protolib_state));
	*init_block_ptr = 0;

	FRET (smf_protolib_state::obtype)
	}

VosT_Address
_op_smf_protolib_alloc (VOS_THREAD_INDEX_ARG_COMMA VosT_Obtype, int)
	{
#if !defined (VOSD_NO_FIN)
	int _op_block_origin = 0;
#endif
	smf_protolib_state * ptr;
	FIN_MT (_op_smf_protolib_alloc ())

	/* New instance will have FSM handling initialized */
#if defined (VOSD_NEW_BAD_ALLOC)
	try {
		ptr = new smf_protolib_state;
	} catch (const VOSD_BAD_ALLOC &) {
		ptr = VOSC_NIL;
	}
#else
	ptr = new smf_protolib_state;
#endif
	FRET ((VosT_Address)ptr)
	}



void
_op_smf_protolib_svar (void * gen_ptr, const char * var_name, void ** var_p_ptr)
	{
	smf_protolib_state		*prs_ptr;

	FIN_MT (_op_smf_protolib_svar (gen_ptr, var_name, var_p_ptr))

	if (var_name == OPC_NIL)
		{
		*var_p_ptr = (void *)OPC_NIL;
		FOUT
		}
	prs_ptr = (smf_protolib_state *)gen_ptr;

	if (strcmp ("smf" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->smf);
		FOUT
		}
	if (strcmp ("my_id" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->my_id);
		FOUT
		}
	if (strcmp ("my_node_id" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->my_node_id);
		FOUT
		}
	if (strcmp ("my_olsr_id" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->my_olsr_id);
		FOUT
		}
	if (strcmp ("own_prohandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->own_prohandle);
		FOUT
		}
	if (strcmp ("own_process_record_handle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->own_process_record_handle);
		FOUT
		}
	if (strcmp ("pid_string" , var_name) == 0)
		{
		*var_p_ptr = (void *) (prs_ptr->pid_string);
		FOUT
		}
	if (strcmp ("my_pro_id" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->my_pro_id);
		FOUT
		}
	if (strcmp ("bits_rcvd_stathandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->bits_rcvd_stathandle);
		FOUT
		}
	if (strcmp ("pkts_rcvd_stathandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->pkts_rcvd_stathandle);
		FOUT
		}
	if (strcmp ("bits_frwd_stathandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->bits_frwd_stathandle);
		FOUT
		}
	if (strcmp ("pkts_frwd_stathandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->pkts_frwd_stathandle);
		FOUT
		}
	if (strcmp ("olsr_packet_capture" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->olsr_packet_capture);
		FOUT
		}
	if (strcmp ("invoke_prohandle" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->invoke_prohandle);
		FOUT
		}
	if (strcmp ("seq_word_size" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->seq_word_size);
		FOUT
		}
	if (strcmp ("window_size" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->window_size);
		FOUT
		}
	if (strcmp ("window_past_max" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->window_past_max);
		FOUT
		}
	if (strcmp ("duplicate_filtering" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->duplicate_filtering);
		FOUT
		}
	*var_p_ptr = (void *)OPC_NIL;

	FOUT
	}

