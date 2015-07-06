#include <stdio.h>
#include <string.h>
#include <osmocom/core/utils.h>
#include <assert.h>

#include "lte_nas_eps.h"
#include "lte_nas_eps_mm.h"

/* Parse a NAS/EPS security message (preceding message to set security options) */
static naseps_msg_t *parse_naseps_mm_msg_sec(uint8_t *raw_message, uint8_t uplink)
{
	nas_eps_message_spec spec;

	/* Setup specification */
	spec.type[0]=ELEMENT_TYPE_1V;
	spec.len[0]=-1;
	spec.tag[0]=-1;
	spec.type[1]=ELEMENT_TYPE_3V;
	spec.len[1]=4;
	spec.tag[1]=-1;
	spec.type[2]=ELEMENT_TYPE_3V;
	spec.len[2]=1;
	spec.tag[2]=-1;

	spec.n=3;
	spec.msg_type=PROTOCOL_EPS_MM;
	spec.msg_uplink=uplink;
	
	/* Parse message */
	return parse_naseps_msg_generic(raw_message,6,&spec);
}

/* Parse a NAS/EPS Tracking area update request message */
static naseps_msg_t *parse_naseps_mm_msg_taur(uint8_t *raw_message, int len, uint8_t uplink)
{
	/* See also: ETSI TS 124 301 V12.7.0 (2015-01), page 240, 
                     Table 8.2.29.1: TRACKING AREA UPDATE REQUEST message content */

	nas_eps_message_spec spec;

	/* Mandatory fields */
	spec.type[0]=ELEMENT_TYPE_1V;	/* Protocol discriminator and Security header type */
	spec.len[0]=-1;
	spec.tag[0]=-1;
	spec.type[1]=ELEMENT_TYPE_3V;	/* Message type */
	spec.len[1]=1;
	spec.tag[1]=-1;
	spec.type[2]=ELEMENT_TYPE_1V;	/* EPS update type and NAS key set identifier */
	spec.len[2]=-1;
	spec.tag[2]=-1;
	spec.type[3]=ELEMENT_TYPE_4LV;	/* EPS mobile identity */
	spec.len[3]=12;
	spec.tag[3]=-1;

	/* Optional fields */
	spec.type[4]=ELEMENT_TYPE_1TV;	/* NAS key set identifier */
	spec.len[4]=-1;
	spec.tag[4]=0x0b;
	spec.type[5]=ELEMENT_TYPE_1TV;	/* Ciphering key sequence number */
	spec.len[5]=-1;
	spec.tag[5]=0x8;
	spec.type[6]=ELEMENT_TYPE_3TV;	/* Old P-TMSI signature */
	spec.len[6]=4;
	spec.tag[6]=0x19;
	spec.type[7]=ELEMENT_TYPE_4TLV;	/* Additional GUTI */
	spec.len[7]=13;
	spec.tag[7]=0x50;
	spec.type[8]=ELEMENT_TYPE_3TV;	/* NonceUE */
	spec.len[8]=5;
	spec.tag[8]=0x55;
	spec.type[9]=ELEMENT_TYPE_4TLV;	/* UE network capability */
	spec.len[9]=15;
	spec.tag[9]=0x58;
	spec.type[10]=ELEMENT_TYPE_3TV;	/* Last visited registered TAI */
	spec.len[10]=6;
	spec.tag[10]=0x52;
	spec.type[11]=ELEMENT_TYPE_3TV;	/* DRX parameter */
	spec.len[11]=3;
	spec.tag[11]=0x5c;
	spec.type[12]=ELEMENT_TYPE_1TV;	/* UE radio capability information information update needed */
	spec.len[12]=-1;
	spec.tag[12]=0xa;
	spec.type[13]=ELEMENT_TYPE_4TLV;/* EPS bearer context status */
	spec.len[13]=4;
	spec.tag[13]=0x57;
	spec.type[14]=ELEMENT_TYPE_4TLV;/* MS network capability */
	spec.len[14]=10;
	spec.tag[14]=0x31;
	spec.type[15]=ELEMENT_TYPE_3TV;	/* Old location area identification */
	spec.len[15]=6;
	spec.tag[15]=0x13;
	spec.type[16]=ELEMENT_TYPE_1TV;	/* TMSI status */
	spec.len[16]=-1;
	spec.tag[16]=0x9;
	spec.type[17]=ELEMENT_TYPE_4TLV;/* Mobile station classmark 2 */
	spec.len[17]=5;
	spec.tag[17]=0x11;
	spec.type[18]=ELEMENT_TYPE_4TLV;/* Mobile station classmark 3 */
	spec.len[18]=34;
	spec.tag[18]=0x20;
	spec.type[18]=ELEMENT_TYPE_4TLV;/* Supported Codecs */
	spec.len[18]=-1;
	spec.tag[18]=0x40;
	spec.type[19]=ELEMENT_TYPE_1TV;	/* Additional update type */
	spec.len[19]=-1;
	spec.tag[19]=0xf;
	spec.type[20]=ELEMENT_TYPE_4TLV;/* Voice domain preference and UE's usage setting */
	spec.len[20]=3;
	spec.tag[20]=0x5d;
	spec.type[21]=ELEMENT_TYPE_1TV;	/* Old GUTI type */
	spec.len[21]=-1;
	spec.tag[21]=0xe;
	spec.type[22]=ELEMENT_TYPE_1TV;	/* Device properties */
	spec.len[22]=-1;
	spec.tag[22]=0xd;
	spec.type[23]=ELEMENT_TYPE_1TV;	/* MS network feature support */
	spec.len[23]=-1;
	spec.tag[23]=0xc;
	spec.type[24]=ELEMENT_TYPE_4TLV;/* TMSI based NRI container */
	spec.len[24]=4;
	spec.tag[24]=0x10;
	spec.type[25]=ELEMENT_TYPE_4TLV;/* T3324 value */
	spec.len[25]=3;
	spec.tag[25]=0x6a;

	spec.n=26;
	spec.msg_subtype=EPS_MM_TAUR_MSG;
	spec.msg_type=PROTOCOL_EPS_MM;
	spec.msg_uplink=uplink;
	return parse_naseps_msg_generic(raw_message,len,&spec);
}

/* Parse a NAS/EPS Authentication request message */
static naseps_msg_t *parse_naseps_mm_msg_areq(uint8_t *raw_message, int len, uint8_t uplink)
{
	/* See also: ETSI TS 124 301 V12.7.0 (2015-01), page 224, 
                     Table 8.2.7.1: AUTHENTICATION REQUEST message content */

	nas_eps_message_spec spec;

	/* Mandatory fields */
	spec.type[0]=ELEMENT_TYPE_1V;	/* Protocol discriminator and Security header type */
	spec.len[0]=-1;
	spec.tag[0]=-1;
	spec.type[1]=ELEMENT_TYPE_3V;	/* Message type */
	spec.len[1]=1;
	spec.tag[1]=-1;
	spec.type[2]=ELEMENT_TYPE_1V;	/* NAS key set identifier and a Spare half octet */
	spec.len[2]=-1;
	spec.tag[2]=-1;
	spec.type[3]=ELEMENT_TYPE_3V;	/* Authentication parameter RAND */
	spec.len[3]=16;
	spec.tag[3]=-1;
	spec.type[4]=ELEMENT_TYPE_4LV;	/* Authentication parameter AUTN */
	spec.len[4]=17;
	spec.tag[4]=-1;

	spec.n=5;
	spec.msg_subtype=EPS_MM_AREQ_MSG;
	spec.msg_type=PROTOCOL_EPS_MM;
	spec.msg_uplink=uplink;
	return parse_naseps_msg_generic(raw_message,len,&spec);
}

/* Parse a NAS/EPS Authentication reponse message */
static naseps_msg_t *parse_naseps_mm_msg_ares(uint8_t *raw_message, int len, uint8_t uplink)
{
	/* See also: ETSI TS 124 301 V12.7.0 (2015-01), page 224, 
                     Table 8.2.8.1: AUTHENTICATION RESPONSE message content */

	nas_eps_message_spec spec;

	/* Mandatory fields */
	spec.type[0]=ELEMENT_TYPE_1V;	/* Protocol discriminator and Security header type */
	spec.len[0]=-1;
	spec.tag[0]=-1;
	spec.type[1]=ELEMENT_TYPE_3V;	/* Message type */
	spec.len[1]=1;
	spec.tag[1]=-1;
	spec.type[2]=ELEMENT_TYPE_4LV;	/* Authentication response parameter */
	spec.len[2]=17;
	spec.tag[2]=-1;

	spec.n=3;
	spec.msg_subtype=EPS_MM_ARES_MSG;
	spec.msg_type=PROTOCOL_EPS_MM;
	spec.msg_uplink=uplink;
	return parse_naseps_msg_generic(raw_message,len,&spec);
}

/* Parse a NAS/EPS security mode command message */
static naseps_msg_t *parse_naseps_mm_msg_scmd(uint8_t *raw_message, int len, uint8_t uplink)
{
	/* See also: ETSI TS 124 301 V12.7.0 (2015-01), page 233, 
                     Table 8.2.20.1: SECURITY MODE COMMAND message content */

	nas_eps_message_spec spec;

	/* Mandatory fields */
	spec.type[0]=ELEMENT_TYPE_1V;	/* Protocol discriminator and Security header type */
	spec.len[0]=-1;
	spec.tag[0]=-1;
	spec.type[1]=ELEMENT_TYPE_3V;	/* Message type */
	spec.len[1]=1;
	spec.tag[1]=-1;
	spec.type[2]=ELEMENT_TYPE_3V;	/* NAS security algorithms */
	spec.len[2]=1;
	spec.tag[2]=-1;
	spec.type[3]=ELEMENT_TYPE_1V;	/* NAS key set identifier and a Spare half octet */
	spec.len[3]=-1;
	spec.tag[3]=-1;
	spec.type[4]=ELEMENT_TYPE_4LV;	/* Replayed UE security capabilities */
	spec.len[4]=6;
	spec.tag[4]=-1;

	/* Optional fields */
	spec.type[5]=ELEMENT_TYPE_1TV;	/* IMEISV request */
	spec.len[5]=-1;
	spec.tag[5]=0xc;
	spec.type[6]=ELEMENT_TYPE_3TV;	/* Replayed nonceUE */
	spec.len[6]=6;
	spec.tag[6]=0x55;
	spec.type[7]=ELEMENT_TYPE_3TV;	/* Nonce MME */
	spec.len[7]=6;
	spec.tag[7]=0x56;

	spec.n=8;
	spec.msg_subtype=EPS_MM_SCMD_MSG;
	spec.msg_type=PROTOCOL_EPS_MM;
	spec.msg_uplink=uplink;
	return parse_naseps_msg_generic(raw_message,len,&spec);
}

/* Parse a NAS/EPS security mode complete message */
static naseps_msg_t *parse_naseps_mm_msg_scpl(uint8_t *raw_message, int len, uint8_t uplink)
{
	/* See also: ETSI TS 124 301 V12.7.0 (2015-01), page 233, 
                     Table 8.2.21.1: SECURITY MODE COMPLETE message content */

	nas_eps_message_spec spec;

	/* Mandatory fields */
	spec.type[0]=ELEMENT_TYPE_1V;	/* Protocol discriminator and Security header type */
	spec.len[0]=-1;
	spec.tag[0]=-1;
	spec.type[1]=ELEMENT_TYPE_3V;	/* Message type */
	spec.len[1]=1;
	spec.tag[1]=-1;

	/* Optional fields */
	spec.type[2]=ELEMENT_TYPE_4TLV;	/* IMEISV */
	spec.len[2]=23;
	spec.tag[2]=0x11;

	spec.n=3;
	spec.msg_subtype=EPS_MM_SCPL_MSG;
	spec.msg_type=PROTOCOL_EPS_MM;
	spec.msg_uplink=uplink;
	return parse_naseps_msg_generic(raw_message,len,&spec);
}

/* Parse a NAS/EPS tracking area update accept message */
static naseps_msg_t *parse_naseps_mm_msg_taua(uint8_t *raw_message, int len, uint8_t uplink)
{
	/* See also: ETSI TS 124 301 V12.7.0 (2015-01), page 236, 
                     Table 8.2.26.1: TRACKING AREA UPDATE ACCEPT message content */

	nas_eps_message_spec spec;

	/* Mandatory fields */
	spec.type[0]=ELEMENT_TYPE_1V;	/* Protocol discriminator and Security header type */
	spec.len[0]=-1;
	spec.tag[0]=-1;
	spec.type[1]=ELEMENT_TYPE_3V;	/* Message type */
	spec.len[1]=1;
	spec.tag[1]=-1;
	spec.type[2]=ELEMENT_TYPE_1V;	/* EPS update result and a Spare half octet */
	spec.len[2]=-1;
	spec.tag[2]=-1;

	/* Optional fields */
	spec.type[3]=ELEMENT_TYPE_3TV;	/* T3412 value */
	spec.len[3]=2;
	spec.tag[3]=0x5A;
	spec.type[4]=ELEMENT_TYPE_4TLV;	/* GUTI */
	spec.len[4]=13;
	spec.tag[4]=0x50;
	spec.type[5]=ELEMENT_TYPE_4TLV;	/* TAI list */
	spec.len[5]=98;
	spec.tag[5]=0x54;
	spec.type[6]=ELEMENT_TYPE_4TLV;	/* EPS bearer context status */
	spec.len[6]=4;
	spec.tag[6]=0x57;
	spec.type[7]=ELEMENT_TYPE_3TV;	/* Location area identification */
	spec.len[7]=6;
	spec.tag[7]=0x13;
	spec.type[8]=ELEMENT_TYPE_4TLV;	/* MS identity */
	spec.len[8]=10;
	spec.tag[8]=0x23;
	spec.type[9]=ELEMENT_TYPE_3TV;	/* EMM cause */
	spec.len[9]=2;
	spec.tag[9]=0x53;
	spec.type[10]=ELEMENT_TYPE_3TV;	/* T3402 value */
	spec.len[10]=2;
	spec.tag[10]=0x17;
	spec.type[11]=ELEMENT_TYPE_3TV;	/* T3423 value */
	spec.len[11]=2;
	spec.tag[11]=0x59;
	spec.type[12]=ELEMENT_TYPE_4TLV;/* Equivalent PLMNs */
	spec.len[12]=47;
	spec.tag[12]=0x4a;
	spec.type[13]=ELEMENT_TYPE_4TLV;/* Emergency number list */
	spec.len[13]=50;
	spec.tag[13]=0x34;
	spec.type[14]=ELEMENT_TYPE_4TLV;/* EPS network feature support */
	spec.len[14]=3;
	spec.tag[14]=0x64;
	spec.type[15]=ELEMENT_TYPE_1TV;	/* Additional update result */
	spec.len[15]=-1;
	spec.tag[15]=0xf;
	spec.type[16]=ELEMENT_TYPE_4TLV;/* T3412 extended value */
	spec.len[16]=3;
	spec.tag[16]=0x5e;
	spec.type[17]=ELEMENT_TYPE_4TLV;/* T3324 value */
	spec.len[17]=3;
	spec.tag[17]=0x6a;

	spec.n=18;
	spec.msg_subtype=EPS_MM_TAUA_MSG;
	spec.msg_type=PROTOCOL_EPS_MM;
	spec.msg_uplink=uplink;
	return parse_naseps_msg_generic(raw_message,len,&spec);
}

/* Parse a NAS/EPS tracking area update complete message */
static naseps_msg_t *parse_naseps_mm_msg_tauc(uint8_t *raw_message, int len, uint8_t uplink)
{
	/* See also: ETSI TS 124 301 V12.7.0 (2015-01), page 238, 
                     Table 8.2.27.1: TRACKING AREA UPDATE COMPLETE message content */

	nas_eps_message_spec spec;

	/* Mandatory fields */
	spec.type[0]=ELEMENT_TYPE_1V;	/* Protocol discriminator and Security header type */
	spec.len[0]=-1;
	spec.tag[0]=-1;
	spec.type[1]=ELEMENT_TYPE_3V;	/* Message type */
	spec.len[1]=1;
	spec.tag[1]=-1;

	spec.n=2;
	spec.msg_subtype=EPS_MM_TAUC_MSG;
	spec.msg_type=PROTOCOL_EPS_MM;
	spec.msg_uplink=uplink;
	return parse_naseps_msg_generic(raw_message,len,&spec);
}


/* Parse a NAS/EPS attach request message */
static naseps_msg_t *parse_naseps_mm_msg_arq(uint8_t *raw_message, int len, uint8_t uplink)
{
	/* See also: ETSI TS 124 301 V12.7.0 (2015-01), page 221, 
                     Table 8.2.4.1: ATTACH REQUEST message content */

	nas_eps_message_spec spec;

	/* Mandatory fields */
	spec.type[0]=ELEMENT_TYPE_1V;	/* Protocol discriminator and Security header type */
	spec.len[0]=-1;
	spec.tag[0]=-1;
	spec.type[1]=ELEMENT_TYPE_3V;	/* Message type */
	spec.len[1]=1;
	spec.tag[1]=-1;
	spec.type[2]=ELEMENT_TYPE_1V;	/* EPS attach type and NAS key set identifier */
	spec.len[2]=-1;
	spec.tag[2]=-1;
	spec.type[3]=ELEMENT_TYPE_4LV;	/* EPS mobile identity */
	spec.len[3]=12;
	spec.tag[3]=-1;
	spec.type[4]=ELEMENT_TYPE_4LV;	/* UE network capability */
	spec.len[4]=14;
	spec.tag[4]=-1;
	spec.type[5]=ELEMENT_TYPE_6LVE;	/* ESM message container */
	spec.len[5]=-1;
	spec.tag[5]=-1;

	/* Optional fields */
	spec.type[6]=ELEMENT_TYPE_3TV;	/* Old P-TMSI signature */
	spec.len[6]=4;
	spec.tag[6]=0x19;
	spec.type[7]=ELEMENT_TYPE_4TLV;	/* Additional GUTI */
	spec.len[7]=13;
	spec.tag[7]=0x50;
	spec.type[8]=ELEMENT_TYPE_3TV;	/* Last visited registered TAI */
	spec.len[8]=6;
	spec.tag[8]=0x52;
	spec.type[9]=ELEMENT_TYPE_3TV;	/* DRX parameter */
	spec.len[9]=3;
	spec.tag[9]=0x5c;
	spec.type[10]=ELEMENT_TYPE_4TLV;/* MS network capability */
	spec.len[10]=10;
	spec.tag[10]=0x31;
	spec.type[11]=ELEMENT_TYPE_3TV;	/* Old location area identification */
	spec.len[11]=6;
	spec.tag[11]=0x13;
	spec.type[12]=ELEMENT_TYPE_1TV;	/* TMSI status */
	spec.len[12]=-1;
	spec.tag[12]=0x9;
	spec.type[13]=ELEMENT_TYPE_4TLV;/* Mobile station classmark 2 */
	spec.len[13]=5;
	spec.tag[13]=0x11;
	spec.type[14]=ELEMENT_TYPE_4TLV;/* Mobile station classmark 3 */
	spec.len[14]=34;
	spec.tag[14]=0x20;
	spec.type[15]=ELEMENT_TYPE_4TLV;/* Supported Codecs */
	spec.len[15]=-1;
	spec.tag[15]=0x40;
	spec.type[16]=ELEMENT_TYPE_1TV;	/* Additional update type */
	spec.len[16]=-1;
	spec.tag[16]=0xf;
	spec.type[17]=ELEMENT_TYPE_4TLV;/* Voice domain preference and UE's usage setting */
	spec.len[17]=3;
	spec.tag[17]=0x5d;
	spec.type[18]=ELEMENT_TYPE_1TV;	/* Device properties */
	spec.len[18]=-1;
	spec.tag[18]=0xd;
	spec.type[19]=ELEMENT_TYPE_1TV;	/* Old GUTI type */
	spec.len[19]=-1;
	spec.tag[19]=0xe;
	spec.type[20]=ELEMENT_TYPE_1TV;	/* MS network feature support */
	spec.len[20]=-1;
	spec.tag[20]=0xc;
	spec.type[21]=ELEMENT_TYPE_4TLV;/* TMSI based NRI containerg */
	spec.len[21]=3;
	spec.tag[21]=0x10;
	spec.type[22]=ELEMENT_TYPE_4TLV;/* T3324 value */
	spec.len[22]=3;
	spec.tag[22]=0x6a;
	spec.type[23]=ELEMENT_TYPE_4TLV;/* T3412 extended value */
	spec.len[23]=3;
	spec.tag[23]=0x5e;

	spec.n=24;
	spec.msg_subtype=EPS_MM_ARQ_MSG;
	spec.msg_type=PROTOCOL_EPS_MM;
	spec.msg_uplink=uplink;
	return parse_naseps_msg_generic(raw_message,len,&spec);
}


/* Parse a NAS/EPS attach accept message */
static naseps_msg_t *parse_naseps_mm_msg_aac(uint8_t *raw_message, int len, uint8_t uplink)
{
	/* See also: ETSI TS 124 301 V12.7.0 (2015-01), page 221, 
                     Table 8.2.4.1: ATTACH REQUEST message content */

	nas_eps_message_spec spec;

	/* Mandatory fields */
	spec.type[0]=ELEMENT_TYPE_1V;	/* Protocol discriminator and Security header type */
	spec.len[0]=-1;
	spec.tag[0]=-1;
	spec.type[1]=ELEMENT_TYPE_3V;	/* Message type */
	spec.len[1]=1;
	spec.tag[1]=-1;
	spec.type[2]=ELEMENT_TYPE_1V;	/* EPS attach result and Spare half octet */
	spec.len[2]=-1;
	spec.tag[2]=-1;
	spec.type[3]=ELEMENT_TYPE_3V;	/* T3412 value */
	spec.len[3]=1;
	spec.tag[3]=-1;
	spec.type[4]=ELEMENT_TYPE_4LV;	/* TAI list */
	spec.len[4]=97;
	spec.tag[4]=-1;
	spec.type[5]=ELEMENT_TYPE_6LVE;	/* ESM message container */
	spec.len[5]=-1;
	spec.tag[5]=-1;

	/* Optional fields */
	spec.type[6]=ELEMENT_TYPE_4TLV;	/* GUTI */
	spec.len[6]=13;
	spec.tag[6]=0x50;
	spec.type[7]=ELEMENT_TYPE_3TV;	/* Old location area identification */
	spec.len[7]=6;
	spec.tag[7]=0x13;
	spec.type[8]=ELEMENT_TYPE_4TLV;	/* MS identity */
	spec.len[8]=10;
	spec.tag[8]=0x23;
	spec.type[9]=ELEMENT_TYPE_3TV;	/* EMM cause */
	spec.len[9]=2;
	spec.tag[9]=0x53;
	spec.type[10]=ELEMENT_TYPE_3TV;	/* T3402 value */
	spec.len[10]=2;
	spec.tag[10]=0x17;
	spec.type[11]=ELEMENT_TYPE_3TV;	/* T3423 value */
	spec.len[11]=2;
	spec.tag[11]=0x59;
	spec.type[12]=ELEMENT_TYPE_4TLV;/* Equivalent PLMNs */
	spec.len[12]=47;
	spec.tag[12]=0x4a;
	spec.type[13]=ELEMENT_TYPE_4TLV;/* Emergency number list */
	spec.len[13]=50;
	spec.tag[13]=0x34;
	spec.type[14]=ELEMENT_TYPE_4TLV;/* EPS network feature support */
	spec.len[14]=3;
	spec.tag[14]=0x64;
	spec.type[15]=ELEMENT_TYPE_1TV;	/* Additional update result */
	spec.len[15]=-1;
	spec.tag[15]=0xf;
	spec.type[16]=ELEMENT_TYPE_4TLV;/* T3412 extended value */
	spec.len[16]=3;
	spec.tag[16]=0x5e;
	spec.type[17]=ELEMENT_TYPE_4TLV;/* T3324 value */
	spec.len[17]=3;
	spec.tag[17]=0x6a;

	spec.n=18;
	spec.msg_subtype=EPS_MM_AAC_MSG;
	spec.msg_type=PROTOCOL_EPS_MM;
	spec.msg_uplink=uplink;
	return parse_naseps_msg_generic(raw_message,len,&spec);


}


/* Parse a NAS/EPS tracking area update reject message */
static naseps_msg_t *parse_naseps_mm_msg_tauj(uint8_t *raw_message, int len, uint8_t uplink)
{
	/* See also: ETSI TS 124 301 V12.7.0 (2015-01), page 238, 
                     Table 8.2.28.1: TRACKING AREA UPDATE REJECT message content */

	nas_eps_message_spec spec;

	/* Mandatory fields */
	spec.type[0]=ELEMENT_TYPE_1V;	/* Protocol discriminator and Security header type */
	spec.len[0]=-1;
	spec.tag[0]=-1;
	spec.type[1]=ELEMENT_TYPE_3V;	/* Message type */
	spec.len[1]=1;
	spec.tag[1]=-1;
	spec.type[2]=ELEMENT_TYPE_3V;	/* EMM cause */
	spec.len[2]=1;
	spec.tag[2]=-1;

	/* Optional fields */
	spec.type[3]=ELEMENT_TYPE_4TLV;/* T3346 value */
	spec.len[3]=3;
	spec.tag[3]=0x5f;
	spec.type[4]=ELEMENT_TYPE_1TV;	/* Extended EMM cause */
	spec.len[4]=-1;
	spec.tag[4]=0xa;

	spec.n=5;
	spec.msg_subtype=EPS_MM_TAUJ_MSG;
	spec.msg_type=PROTOCOL_EPS_MM;
	spec.msg_uplink=uplink;
	return parse_naseps_msg_generic(raw_message,len,&spec);
}


/* Parse a NAS/EPS detach request */
static naseps_msg_t *parse_naseps_mm_msg_drq(uint8_t *raw_message, int len, uint8_t uplink)
{

	nas_eps_message_spec spec;

	/* Specification for uplink message (UE => NETWORK) */
	if(uplink)
	{
		/* See also: ETSI TS 124 301 V12.7.0 (2015-01), page 226, 
		             Table 8.2.11.1.1: DETACH REQUEST message content */

		/* Mandatory fields */
		spec.type[0]=ELEMENT_TYPE_1V;	/* Protocol discriminator and Security header type */
		spec.len[0]=-1;
		spec.tag[0]=-1;
		spec.type[1]=ELEMENT_TYPE_3V;	/* Message type */
		spec.len[1]=1;
		spec.tag[1]=-1;
		spec.type[2]=ELEMENT_TYPE_1V;	/* Detach type and NAS key set identifier */
		spec.len[2]=-1;
		spec.tag[2]=-1;
		spec.type[3]=ELEMENT_TYPE_4LV;	/* EPS mobile identity */
		spec.len[3]=12;
		spec.tag[3]=-1;
		spec.n=4;
	}
	/* Specification for downlink message (NETWORK => UE) */
	else
	{
		/* See also: ETSI TS 124 301 V12.7.0 (2015-01), page 227, 
		             Table 8.2.11.2.1: DETACH REQUEST message content */

		/* Mandatory fields */
		spec.type[0]=ELEMENT_TYPE_1V;	/* Protocol discriminator and Security header type */
		spec.len[0]=-1;
		spec.tag[0]=-1;
		spec.type[1]=ELEMENT_TYPE_3V;	/* Message type */
		spec.len[1]=1;
		spec.tag[1]=-1;
		spec.type[2]=ELEMENT_TYPE_1V;	/* Detach type and spare hald octet */
		spec.len[2]=-1;
		spec.tag[2]=-1;

		/* Optional fields */
		spec.type[3]=ELEMENT_TYPE_3TV;	/* EMM cause */
		spec.len[3]=2;
		spec.tag[3]=0x5f;
		spec.n=4;
	}

	spec.msg_subtype=EPS_MM_DRQ_MSG;
	spec.msg_type=PROTOCOL_EPS_MM;
	spec.msg_uplink=uplink;
	return parse_naseps_msg_generic(raw_message,len,&spec);
}

/* Parse a NAS/EPS uplink NAS transport message */
static naseps_msg_t *parse_naseps_mm_msg_unt(uint8_t *raw_message, int len, uint8_t uplink)
{
	/* See also: ETSI TS 124 301 V12.7.0 (2015-01), page 243, 
		     Table 8.2.30.1: UPLINK NAS TRANSPORT message content */

	nas_eps_message_spec spec;

	/* Mandatory fields */
	spec.type[0]=ELEMENT_TYPE_1V;	/* Protocol discriminator and Security header type */
	spec.len[0]=-1;
	spec.tag[0]=-1;
	spec.type[1]=ELEMENT_TYPE_3V;	/* Message type */
	spec.len[1]=1;
	spec.tag[1]=-1;
	spec.type[2]=ELEMENT_TYPE_4LV;	/* NAS message container */
	spec.len[2]=253;
	spec.tag[2]=-1;

	spec.n=3;
	spec.msg_subtype=EPS_MM_UNT_MSG;
	spec.msg_type=PROTOCOL_EPS_MM;
	spec.msg_uplink=uplink;
	return parse_naseps_msg_generic(raw_message,len,&spec);
}

/* Parse a NAS/EPS downlink NAS transport message */
static naseps_msg_t *parse_naseps_mm_msg_dnt(uint8_t *raw_message, int len, uint8_t uplink)
{
	/* See also: ETSI TS 124 301 V12.7.0 (2015-01), page 227, 
		     Table 8.2.12.1: DOWNLINK NAS TRANSPORT message content */

	nas_eps_message_spec spec;

	/* Mandatory fields */
	spec.type[0]=ELEMENT_TYPE_1V;	/* Protocol discriminator and Security header type */
	spec.len[0]=-1;
	spec.tag[0]=-1;
	spec.type[1]=ELEMENT_TYPE_3V;	/* Message type */
	spec.len[1]=1;
	spec.tag[1]=-1;
	spec.type[2]=ELEMENT_TYPE_4LV;	/* NAS message container */
	spec.len[2]=253;
	spec.tag[2]=-1;

	spec.n=3;
	spec.msg_subtype=EPS_MM_DNT_MSG;
	spec.msg_type=PROTOCOL_EPS_MM;
	spec.msg_uplink=uplink;
	return parse_naseps_msg_generic(raw_message,len,&spec);
}

/* Generate a dummy message */
static naseps_msg_t *parse_naseps_msg_minimum(uint8_t *raw_message, int len, int type, int subtype, uint8_t uplink)
{
	/* Note, this parsing function setups a minimal message specification that
           is common for all mobility management messages. It is intended to be used when
           no approriate parsing function is available to get at least the first 3 header
           fields */

	nas_eps_message_spec spec;

	/* Setup specification */
	spec.type[0]=ELEMENT_TYPE_1V;	/* Protocol discriminator and Security header type */
	spec.len[0]=-1;
	spec.tag[0]=-1;
	spec.type[1]=ELEMENT_TYPE_3V;	/* Message type */
	spec.len[1]=1;
	spec.tag[1]=-1;

	spec.n=2;
	spec.msg_type=type;
	spec.msg_subtype=subtype;
	spec.msg_uplink=uplink;
	
	/* Parse message */
	return parse_naseps_msg_generic(raw_message,len,&spec);
}

/* Dispatch and parse a regular NAS/EPS mobility mananagement message */
static naseps_msg_t *parse_naseps_mm_msg_normal(uint8_t *raw_message, int len, uint8_t uplink)
{
	naseps_msg_t* msg;
	uint8_t message_type;

	/* Lookup the message identity */
	if(len >= 2)
		message_type = raw_message[1];
	else
		return NULL;
	

	/* Look at the protocol discriminator and decide what to do */
	switch(message_type)
	{
		/* Tracking area update request message */
		case EPS_MM_TAUR_MSG:
			msg = parse_naseps_mm_msg_taur(raw_message,len,uplink);
		break;

		/* Authentication request message */
		case EPS_MM_AREQ_MSG:
			msg = parse_naseps_mm_msg_areq(raw_message,len,uplink);
		break;

		/* Security mode command message */
		case EPS_MM_SCMD_MSG:
			msg = parse_naseps_mm_msg_scmd(raw_message,len,uplink);
		break;

		/* Authentication reponse message */
		case EPS_MM_ARES_MSG:
			msg = parse_naseps_mm_msg_ares(raw_message,len,uplink);
		break;

		/* Security mode complete message */
		case EPS_MM_SCPL_MSG:
			msg = parse_naseps_mm_msg_scpl(raw_message,len,uplink);
		break;

		/* Tracking area update accept message */
		case EPS_MM_TAUA_MSG:
			msg = parse_naseps_mm_msg_taua(raw_message,len,uplink);
		break;

		/* Tracking area update complete message */
		case EPS_MM_TAUC_MSG:
			msg = parse_naseps_mm_msg_tauc(raw_message,len,uplink);
		break;

		/* Attach request message */
		case EPS_MM_ARQ_MSG:
			msg = parse_naseps_mm_msg_arq(raw_message,len,uplink);
		break;

		/* Attach accept message */
		case EPS_MM_AAC_MSG:
			msg = parse_naseps_mm_msg_aac(raw_message,len,uplink);
		break;

		/* Tracking area update reject message */
		case EPS_MM_TAUJ_MSG:
			msg = parse_naseps_mm_msg_tauj(raw_message,len,uplink);
		break;

		/* Detach request message */
		case EPS_MM_DRQ_MSG:
			msg = parse_naseps_mm_msg_drq(raw_message,len,uplink);
		break;

		/* Uplink NAS transport message */
		case EPS_MM_UNT_MSG:
			msg = parse_naseps_mm_msg_unt(raw_message,len,uplink);
		break;

		/* Downlink NAS transport message */
		case EPS_MM_DNT_MSG:
			msg = parse_naseps_mm_msg_dnt(raw_message,len,uplink);
		break;

		/* Return a message marked as unknown */
		default:
			msg = parse_naseps_msg_minimum(raw_message, len, PROTOCOL_EPS_MM, message_type & 0xFF,uplink);
		break;
	}

	return msg;
}

/* Parse a NAS/EPS Mobility management message */
naseps_msg_t *parse_naseps_mm_msg(uint8_t *raw_message, int len, uint8_t uplink)
{
	uint8_t protocol_discriminator;	
	uint8_t header_type;
	naseps_msg_t *message = NULL;

	/* Sanity check */
	protocol_discriminator = raw_message[0] & 0x0F;
	if (protocol_discriminator != PROTOCOL_EPS_MM) {
		return NULL;
	}

	header_type = (raw_message[0] >> 4) & 0x0F;

	switch (header_type) {
	case EPS_MM_SECHDR_TYPE_PLAIN:
		message = parse_naseps_mm_msg_normal(raw_message, len, uplink);
		break;

	case EPS_MM_SECHDR_TYPE_INTEGRITY:
	case EPS_MM_SECHDR_TYPE_INTEGRITY_NEW:
		message = parse_naseps_mm_msg_sec(raw_message, uplink);

		/* Be sure that we got a result from the parsing functions */
		if(!message) {
			break;
		}

		/* Move on to the message part */
		raw_message += message->raw_len;
		len -= message->raw_len;

		/* Stop if all input buffer bytes are consumed */
		if(len <= 0) {
			break;
		}

		/* Sanity check (again) */
		protocol_discriminator = raw_message[0] & 0x0F;
		if (protocol_discriminator != PROTOCOL_EPS_MM) {
			break;
		}

		/* We are ready to parse the actual message */
		free(message);
		message = parse_naseps_mm_msg_normal(raw_message, len, uplink);
		if (message ) {
			message->flags = EPS_MM_SEC_INTEGRITY;
		}
		break;

	case EPS_MM_SECHDR_TYPE_INTEGRITY_CIPHERED:
	case EPS_MM_SECHDR_TYPE_INTEGRITY_CIPHERED_NEW:
		message = parse_naseps_msg_dummy(raw_message, len, PROTOCOL_EPS_MM, 0, uplink);
		if (message ) {
			message->flags = EPS_MM_SEC_INTEGRITY | EPS_MM_SEC_CIPHERED;
		}
		break;

	case EPS_MM_SECHDR_TYPE_SERVICE_REQUEST:
		message = parse_naseps_mm_msg_sec(raw_message, uplink);
		if (message ) {
			message->flags = EPS_MM_SEC_INTEGRITY;
		}
		break;

	default:
		/* Unhandled */
		break;
	}

	return message;
}

