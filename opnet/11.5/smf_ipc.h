/** smf_ipc.h         **/

/****************************************/
/*  Define a common block of memory     */
/*  to be shared between the Wlan       */
/*  process model and the Smf child   	*/
/*  process.  							*/
/*										*/
/*  Define an ici structure for passing */
/*  info from smf to olsr.              */
/****************************************/

/* Protect against multiple includes. 	*/
#ifndef	_SMF_IPC_INCLUDED_
#define _SMF_IPC_INCLUDED_

#define PACKET_CAPTURE_EVENT			77


typedef enum Direction
	{
	UNSPECIFIED,
	INBOUND,
	OUTBOUND   
	} Direction;

typedef struct
	{
	Packet*		pkptr;		/* captured defragmented packet */
	Direction	direction;	/* packet direction - INBOUND/OUTBOUND */
	int			tx_addr;    /* MAC addr of station xmitting packet */
	int			rx_addr;	/* MAC addr of station rcving packet */
	int			tx_ip_addr; /* IP addr of station xmitting packet */
	Boolean		forward;	/* Should the packet be retransmitted? */
	Boolean		is_duplicate;	/* Is this multicast packet a duplicate? */
	} smfT_wlan_mem;

typedef struct
	{
	Direction	direction;	/* packet direction - INBOUND/OUTBOUND */
	int			version;	/* protocol version - IPv4 or IPv6 */
	int			tx_addr;    /* MAC addr of station xmiting packet */
	IpT_Address	src_ip4addr;/* source addr of IP packet */
	} smfT_olsr_ipc;

/* End if for protection against multiple includes. */
#endif /* _SMF_WLAN_MEM_INCLUDED_ */
