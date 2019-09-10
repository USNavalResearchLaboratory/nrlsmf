/* Process model C form file: wlan_dispatch_smf.pr.c */
/* Portions of this file copyright 1992-2006 by OPNET Technologies, Inc. */



/* This variable carries the header into the object file */
const char wlan_dispatch_smf_pr_c [] = "MIL_3_Tfile_Hdr_ 115A 30A op_runsim 7 4540BC74 4540BC74 1 apocalypse Jim@Hauser 0 0 none none 0 0 none 0 0 0 0 0 0 0 0 d50 3                                                                                                                                                                                                                                                                                                                                                                                                   ";
#include <string.h>



/* OPNET system definitions */
#include <opnet.h>



/* Header Block */

#include "wlan_support.h"

/** Define the WLAN global variables, which are declared in wlan_support.h.	**/

/* Global linked list of AP position info.									*/
WlanT_AP_Position_Info* 			global_ap_pos_info_head = OPC_NIL;

/* Global variable to keep note of the nature of the subnet.				*/
/* This variable is initialized to not set.									*/
WlanT_Bss_Identification_Approach	bss_id_type = WlanC_Not_Set;

/* Read-only array of the minimum frequencies of the 12 operational 802.11a	*/
/* WLAN channels.															*/
double	WLANC_11a_CHNL_MIN_FREQ_ARRAY [WLANC_11a_OPER_CHNL_COUNT] = 
			{5170.0, 5190.0, 5210.0, 5230.0, 5250.0, 5270.0, 5290.0, 5310.0, 5735.0, 5755.0, 5775.0, 5795.0};

/* Read-only arrays for mandatory 802.11a and 802.11g data rates.			*/
double	WLANC_11a_MANDATORY_DRATE_ARRAY [3] = {24000000.0, 12000000.0, 6000000.0};
double	WLANC_11g_MANDATORY_DRATE_ARRAY [7] = {24000000.0, 12000000.0, 11000000.0, 6000000.0, 5500000.0, 2000000.0, 1000000.0};

/* Reset one of the packet field index global variables so its value can be	*/
/* checked to determine whether all of those variables are initialized or	*/
/* not.																		*/
int		WLANC_DATA_TYPE_FD = OPC_FIELD_INDEX_INVALID;
int		WLANC_DATA_HEADER_FD, WLANC_DATA_QOS_FD, WLANC_DATA_BODY_FD, WLANC_DATA_ACCEPT_FD, WLANC_DATA_PKID_FD;
int		WLANC_CNTL_TYPE_FD, WLANC_CNTL_HEADER_FD, WLANC_CNTL_ACCEPT_FD;
int		WLANC_BEACON_BODY_FD;

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
typedef struct
	{
	/* Internal state tracking for FSM */
	FSM_SYS_STATE
	} wlan_dispatch_smf_state;

#define pr_state_ptr            		((wlan_dispatch_smf_state*) (OP_SIM_CONTEXT_PTR->_op_mod_state_ptr))

/* These macro definitions will define a local variable called	*/
/* "op_sv_ptr" in each function containing a FIN statement.	*/
/* This variable points to the state variable data structure,	*/
/* and can be used from a C debugger to display their values.	*/
#undef FIN_PREAMBLE_DEC
#undef FIN_PREAMBLE_CODE
#  define FIN_PREAMBLE_DEC	wlan_dispatch_smf_state *op_sv_ptr;
#if defined (OPD_PARALLEL)
#  define FIN_PREAMBLE_CODE	\
		op_sv_ptr = ((wlan_dispatch_smf_state *)(sim_context_ptr->_op_mod_state_ptr));
#else
#  define FIN_PREAMBLE_CODE	op_sv_ptr = pr_state_ptr;
#endif


/* No Function Block */

#if !defined (VOSD_NO_FIN)
enum { _op_block_origin = __LINE__ };
#endif

/* Undefine optional tracing in FIN/FOUT/FRET */
/* The FSM has its own tracing code and the other */
/* functions should not have any tracing.		  */
#undef FIN_TRACING
#define FIN_TRACING

#undef FOUTRET_TRACING
#define FOUTRET_TRACING

#if defined (__cplusplus)
extern "C" {
#endif
	void wlan_dispatch_smf (OP_SIM_CONTEXT_ARG_OPT);
	VosT_Obtype _op_wlan_dispatch_smf_init (int * init_block_ptr);
	VosT_Address _op_wlan_dispatch_smf_alloc (VOS_THREAD_INDEX_ARG_COMMA VosT_Obtype, int);
	void _op_wlan_dispatch_smf_diag (OP_SIM_CONTEXT_ARG_OPT);
	void _op_wlan_dispatch_smf_terminate (OP_SIM_CONTEXT_ARG_OPT);
	void _op_wlan_dispatch_smf_svar (void *, const char *, void **);


	VosT_Obtype Vos_Define_Object_Prstate (const char * _op_name, unsigned int _op_size);
	VosT_Address Vos_Alloc_Object_MT (VOS_THREAD_INDEX_ARG_COMMA VosT_Obtype _op_ob_hndl);
	VosT_Fun_Status Vos_Poolmem_Dealloc_MT (VOS_THREAD_INDEX_ARG_COMMA VosT_Address _op_ob_ptr);
#if defined (__cplusplus)
} /* end of 'extern "C"' */
#endif




/* Process model interrupt handling procedure */


void
wlan_dispatch_smf (OP_SIM_CONTEXT_ARG_OPT)
	{
#if !defined (VOSD_NO_FIN)
	int _op_block_origin = 0;
#endif
	FIN_MT (wlan_dispatch_smf ());

		{
		/* Temporary Variables */
		Objid		comp_attr_objid, comp_attr_row_objid;
		int			hcf_support_int;
		Prohandle	mac_prohandle;
		/* End of Temporary Variables */


		FSM_ENTER_NO_VARS ("wlan_dispatch_smf")

		FSM_BLOCK_SWITCH
			{
			/*---------------------------------------------------------*/
			/** state (spawn) enter executives **/
			FSM_STATE_ENTER_UNFORCED_NOLABEL (0, "spawn", "wlan_dispatch_smf [spawn enter execs]")
				FSM_PROFILE_SECTION_IN ("wlan_dispatch_smf [spawn enter execs]", state0_enter_exec)
				{
				/* Find out whether the surrounding WLAN MAC module		*/
				/* supports Hybrid Coordination Function (HCF),			*/
				/* specified in the IEEE 802.11e standard. Access the	*/
				/* WLAN configuration attribute.						*/
				op_ima_obj_attr_get (op_id_self (), "Wireless LAN Parameters", &comp_attr_objid);
				comp_attr_row_objid = op_topo_child (comp_attr_objid, OPC_OBJTYPE_GENERIC, 0);
				
				/* Read the value of the corresponding attribute under	*/
				/* HCF Parameters.										*/
				op_ima_obj_attr_get (comp_attr_row_objid, "HCF Parameters", &comp_attr_objid);
				comp_attr_row_objid = op_topo_child (comp_attr_objid, OPC_OBJTYPE_GENERIC, 0);
				op_ima_obj_attr_get (comp_attr_row_objid, "Status", &hcf_support_int);
				
				/* Create the appropriate MAC process model.			*/
				mac_prohandle = (hcf_support_int == OPC_BOOLINT_ENABLED) ?
									op_pro_create ("wlan_mac_hcf", OPC_NIL) :
									//op_pro_create ("wlan_mac"    , OPC_NIL);    // JPH SMF
									op_pro_create ("wlan_mac_smf"    , OPC_NIL);  // JPH SMF
				
				/* Make the child process the recipient of the			*/
				/* interrupts of the module.							*/
				op_intrpt_type_register (OPC_INTRPT_STRM,   mac_prohandle);
				op_intrpt_type_register (OPC_INTRPT_STAT,   mac_prohandle);
				op_intrpt_type_register (OPC_INTRPT_REMOTE, mac_prohandle);
				
				/* Spawn the MAC child process.							*/
				op_pro_invoke (mac_prohandle, OPC_NIL);
				
				}
				FSM_PROFILE_SECTION_OUT (state0_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (1,"wlan_dispatch_smf")


			/** state (spawn) exit executives **/
			FSM_STATE_EXIT_UNFORCED (0, "spawn", "wlan_dispatch_smf [spawn exit execs]")
				FSM_PROFILE_SECTION_IN ("wlan_dispatch_smf [spawn exit execs]", state0_exit_exec)
				{
				
				}
				FSM_PROFILE_SECTION_OUT (state0_exit_exec)


			/** state (spawn) transition processing **/
			FSM_TRANSIT_MISSING ("spawn")
				/*---------------------------------------------------------*/



			}


		FSM_EXIT (0,"wlan_dispatch_smf")
		}
	}




void
_op_wlan_dispatch_smf_diag (OP_SIM_CONTEXT_ARG_OPT)
	{
	/* No Diagnostic Block */
	}




void
_op_wlan_dispatch_smf_terminate (OP_SIM_CONTEXT_ARG_OPT)
	{
#if !defined (VOSD_NO_FIN)
	int _op_block_origin = __LINE__;
#endif

	FIN_MT (_op_wlan_dispatch_smf_terminate ())

	if (1)
		{

		/* Termination Block */

		BINIT
		{
		
		}

		/* End of Termination Block */

		}
	Vos_Poolmem_Dealloc_MT (OP_SIM_CONTEXT_THREAD_INDEX_COMMA pr_state_ptr);

	FOUT
	}


#undef FIN_PREAMBLE_DEC
#undef FIN_PREAMBLE_CODE

#define FIN_PREAMBLE_DEC
#define FIN_PREAMBLE_CODE

VosT_Obtype
_op_wlan_dispatch_smf_init (int * init_block_ptr)
	{
	VosT_Obtype obtype = OPC_NIL;
	FIN_MT (_op_wlan_dispatch_smf_init (init_block_ptr))

	obtype = Vos_Define_Object_Prstate ("proc state vars (wlan_dispatch_smf)",
		sizeof (wlan_dispatch_smf_state));
	*init_block_ptr = 0;

	FRET (obtype)
	}

VosT_Address
_op_wlan_dispatch_smf_alloc (VOS_THREAD_INDEX_ARG_COMMA VosT_Obtype obtype, int init_block)
	{
#if !defined (VOSD_NO_FIN)
	int _op_block_origin = 0;
#endif
	wlan_dispatch_smf_state * ptr;
	FIN_MT (_op_wlan_dispatch_smf_alloc (obtype))

	ptr = (wlan_dispatch_smf_state *)Vos_Alloc_Object_MT (VOS_THREAD_INDEX_COMMA obtype);
	if (ptr != OPC_NIL)
		{
		ptr->_op_current_block = init_block;
#if defined (OPD_ALLOW_ODB)
		ptr->_op_current_state = "wlan_dispatch_smf [spawn enter execs]";
#endif
		}
	FRET ((VosT_Address)ptr)
	}



void
_op_wlan_dispatch_smf_svar (void * gen_ptr, const char * var_name, void ** var_p_ptr)
	{

	FIN_MT (_op_wlan_dispatch_smf_svar (gen_ptr, var_name, var_p_ptr))

	*var_p_ptr = (void *)OPC_NIL;

	FOUT
	}

