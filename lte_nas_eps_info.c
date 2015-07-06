#include "lte_nas_eps_mm.h"
#include "lte_nas_eps_sm.h"
#include "l3_handler.h"
#include <arpa/inet.h>
#include "bit_func.h"

/* Structure to hold an EPS Mobile identity */
typedef struct
{
	uint8_t odd_even_ind;
	uint8_t type_of_identity; /* 1=IMSI, 6=GUTI, 3=IMEI */
	uint16_t mcc;
	uint16_t mnc;
	uint16_t mme_group_id;
	uint8_t mme_code;
	uint8_t identity_len;
	uint8_t identity[255]; /* GUTI, IMEI, or IMSI */ 
} eps_mobile_identity_t;

/* Three different EPS MI types are possible: */
#define EPS_MI_TYPE_GUTI 6
#define EPS_MI_TYPE_IMSI 1
#define EPS_MI_TYPE_IMEI 3

/* Parse a NAS mobile identity field */
int parse_naseps_mi(naseps_msg_string_t *elm, eps_mobile_identity_t *mi)
{
	struct gsm48_loc_area_id *lai;

	/* Only continue if the element is there */
	if(elm == NULL)
		return -1;

	/* Check if the element is really valid */
	if (!(elm->valid))
		return -1;

	mi->odd_even_ind = (elm->data[0] >> 3) & 0x1; /* Get Odd/Even indicator */
	mi->type_of_identity = (elm->data[0]) & 0x07; /* Get type of identity */

	/* EPS mobile identity information element for type of identity "GUTI" */
	if(mi->type_of_identity == EPS_MI_TYPE_GUTI)
	{
		/* See also: 3GPP TS 24.301 version 12.7.0 Release 12, ETSI TS 124 301 V12.7.0 (2015-01), page 278 
		             Figure 9.9.3.12.1: EPS mobile identity information element for type of identity "GUTI" */

		/* Extract MCC/MNC fields */
		lai = (struct gsm48_loc_area_id *) &(elm->data[1]);
		mi->mcc = get_mcc(lai->digits);
		mi->mnc = get_mnc(lai->digits);

		/* Extract MME Group ID */
		mi->mme_group_id = (elm->data[5] |  elm->data[4] << 8);

		/* Extract MME code */
		mi->mme_code = elm->data[6];

		/* Extract identity (GUTI) */
		mi->identity_len = 4;
		memcpy(mi->identity,&(elm->data[7]),mi->identity_len);
		return 0;
	}

	/* EPS mobile identity information element for type of identity "IMSI" or "IMEI" */
	else if((mi->type_of_identity == EPS_MI_TYPE_IMSI)||(mi->type_of_identity == EPS_MI_TYPE_IMEI))
	{
		/* See also: 3GPP TS 24.301 version 12.7.0 Release 12, ETSI TS 124 301 V12.7.0 (2015-01), page 278 
		             Figure 9.9.3.12.2: EPS mobile identity information element for type of identity "IMSI" or "IMEI" */

		/* Note: Caller functions will expect a BCD encoded string where the length is set to the real
			 buffer length (6 digits, buffer length = 3) see also handle_mi() from l3_handler.c */
		return -1;
	}
	
	return -1;
}

/* Handle EPS Mobile identity */
void handle_eps_mi(struct session_info *s, naseps_msg_string_t *elm, uint8_t new_tmsi)
{	
	/* Note: The new_tmsi flag is usually only set on an accept transaction,
		 on all other transactions the flag is not set. */

	int rc;
	eps_mobile_identity_t mi;
	char tmsi_str[9];

	/* Parse EPS Mobile identity field */
	rc = parse_naseps_mi(elm, &mi);

	/* Only continue if parsing was successful */
	if (rc == 0)
	{
		switch (mi.type_of_identity)
		{
			case EPS_MI_TYPE_GUTI:
				assert(mi.identity_len == 4);
				hex_bin2str(mi.identity, tmsi_str, 4);
				tmsi_str[8] = 0;
				assert(s->new_msg);
				APPEND_MSG_INFO(s, ", TMSI %s", tmsi_str); 

				if (new_tmsi) {
					if (!not_zero(s->new_tmsi, 4)) {
						memcpy(s->new_tmsi, mi.identity, 4);
					}
				} else {
					if (!not_zero(s->old_tmsi, 4)) {
						memcpy(s->old_tmsi, mi.identity, 4);
						s->use_tmsi = 1;
					}
				}
			break;
			case EPS_MI_TYPE_IMSI:
				s->use_imsi = 1;
				/* TODO: Not fully implemented yet! */
			break;
			case EPS_MI_TYPE_IMEI:
				/* TODO: Not implemented yet! */
			break;
			default:
				SET_MSG_INFO(s, "FAILED SANITY CHECKS (MI_TYPE)");
			return;
		}
	}
}

/* Extract MCC, MNC, LAC from a location ara identification field */
void parse_naseps_lai(struct session_info *s, naseps_msg_t *msg, uint8_t new_lai)
{
	/* See also 3GPP TS 24.008 version 8.6.0 Release 8 / ETSI TS 124 008 V8.6.0 (2009-07), page 356 */
	struct gsm48_loc_area_id *lai;
	naseps_msg_string_t *elm;

	/* Try to find LAI_IEI */
	elm = get_naseps_msg_field_by_iei(msg, 0x13);

	/* Only continue if the element is there */
	if(elm == NULL)
		return;

	/* And if the length is exactly 5 octets */
	if(elm->len != 5)
		return;

	/* Extract LAI fields */
	lai = (struct gsm48_loc_area_id *) elm->data;

	if (new_lai) {
		s->mcc = get_mcc(lai->digits);
		s->mnc = get_mnc(lai->digits);
		s->lac = htons(lai->lac);
	} else {
		s->lu_mcc = get_mcc(lai->digits);
		s->lu_mnc = get_mnc(lai->digits);
		s->lu_lac = htons(lai->lac);
	}
}

/* Extract the IMS-flag from the network feature support field */
void parse_naseps_nfs(struct session_info *s, naseps_msg_t *msg)
{
	naseps_msg_string_t *elm;

	/* Try to find NFS_IEI */
	elm = get_naseps_msg_field_by_iei(msg, 0x64);

	/* Only continue if the element is there */
	if(elm == NULL)
		return;

	/* And if the length is at least 1 octet */
	if(elm->len < 1)
		return;

	/* Mask the IMS flag (last bit in the first octet) */
	s->have_ims = elm->data[0] & 1; 
}


/* Handle tracking area update request */
void handle_taur(struct session_info *s, naseps_msg_t *msg)
{
	naseps_msg_string_t *mobile_identity;

	session_reset(s, 1);

	s->mo = 1;
	s->locupd = 1;
	s->started = 1;
	s->closed = 0;

	parse_naseps_lai(s, msg, 0);
	mobile_identity = get_naseps_msg_field_by_pos(msg, 5);
	handle_eps_mi(s, mobile_identity, 0);
}

/* Handle attach request */
void handle_arq(struct session_info *s, naseps_msg_t *msg)
{
	naseps_msg_string_t *mobile_identity;

	session_reset(s, 1);

	s->mo = 1;
	s->attach = 1;
	s->started = 1;
	s->closed = 0;

	parse_naseps_lai(s, msg, 0);
	mobile_identity = get_naseps_msg_field_by_pos(msg, 5);
	handle_eps_mi(s, mobile_identity, 0);
}

/* Handle attach accept */
void handle_aac(struct session_info *s, naseps_msg_t *msg)
{
	naseps_msg_string_t *mobile_identity;
	s->mo = 1;
	s->attach = 1;

	parse_naseps_lai(s, msg, 1);
	parse_naseps_nfs(s, msg);

	mobile_identity = get_naseps_msg_field_by_iei(msg, 0x50);
	handle_eps_mi(s, mobile_identity, 1);
}

/* Handle Tracking area update accept */
void handle_taua(struct session_info *s, naseps_msg_t *msg)
{
	naseps_msg_string_t *mobile_identity;
	s->locupd = 1;
	s->mo = 1;
	s->lu_acc = 1;

	parse_naseps_lai(s, msg, 1);
	parse_naseps_nfs(s, msg);

	mobile_identity = get_naseps_msg_field_by_iei(msg, 0x50);
	handle_eps_mi(s, mobile_identity, 1);
}

/* Handle Tracking area update reject */
void handle_tauj(struct session_info *s, naseps_msg_t *msg)
{
	naseps_msg_string_t* reject_cause;

	s->locupd = 1;
	s->mo = 1;
	s->lu_acc = 0;
	s->lu_reject = 1;

	reject_cause = get_naseps_msg_field_by_pos(msg, 3);
	if(reject_cause && reject_cause->data)
		s->lu_rej_cause = reject_cause->data[0];
}

/* Handle Authentication request */
void handle_areq(struct session_info *s, naseps_msg_t *msg)
{
	s->auth = 2;
}

/* Handle Authentication response */
void handle_ares(struct session_info *s, naseps_msg_t *msg)
{
	s->auth = 2;
}

/* Handle security mode command */
void handle_scmd(struct session_info *s, naseps_msg_t *msg)
{
	naseps_msg_string_t* selected_nas_security_alogirthms;

	/* Find out which ciphering algorithms where selected */
	selected_nas_security_alogirthms = get_naseps_msg_field_by_pos(msg, 3);
	if(selected_nas_security_alogirthms && selected_nas_security_alogirthms->data)
	{
		s->cipher_nas = ((selected_nas_security_alogirthms->data[0]) >> 4) & 0x7;
		s->integrity_nas = (selected_nas_security_alogirthms->data[0]) & 0x7;
	}
}

/* Handle detach request */
void handle_drq(struct session_info *s, naseps_msg_t *msg)
{
	naseps_msg_string_t *mobile_identity;

	session_reset(s, 1);
	s->detach = 1;

	/* Only for mobile originated detach do: */
	if(msg->uplink)
	{
		mobile_identity = get_naseps_msg_field_by_pos(msg, 5);
		handle_eps_mi(s, mobile_identity, 0);
	}
}

/* Handle uplink NAS transport message */
void handle_unt(struct session_info *s, naseps_msg_t *msg)
{
	naseps_msg_string_t* nas_mc;

	nas_mc = get_naseps_msg_field_by_pos(msg, 3);
	if(nas_mc && nas_mc->data)
		handle_dtap(s, nas_mc->data, nas_mc->len, 0, 1);
}

/* Handle downlink NAS transport message */
void handle_dnt(struct session_info *s, naseps_msg_t *msg)
{
	naseps_msg_string_t* nas_mc;

	nas_mc = get_naseps_msg_field_by_pos(msg, 3);
	if(nas_mc && nas_mc->data)
		handle_dtap(s, nas_mc->data, nas_mc->len, 0, 0);
}

/* Session management types */
static void naseps_set_msg_info_sm(struct session_info *s, naseps_msg_t *msg)
{
	switch (msg->subtype) {
	case EPS_SM_ADBCR_MSG:	SET_MSG_INFO(s, "ACTIVATE DEFAULT EPS BEARER CONTEXT REQUEST"); break;
	case EPS_SM_ADBCA_MSG:	SET_MSG_INFO(s, "ACTIVATE DEFAULT EPS BEARER CONTEXT ACCEPT"); break;
	case EPS_SM_ADBCJ_MSG:	SET_MSG_INFO(s, "ACTIVATE DEFAULT EPS BEARER CONTEXT REJECT"); break;
	case EPS_SM_AEBCR_MSG:	SET_MSG_INFO(s, "ACTIVATE DEDICATED EPS BEARER CONTEXT REQUEST"); break;
	case EPS_SM_AEBCA_MSG:	SET_MSG_INFO(s, "ACTIVATE DEDICATED EPS BEARER CONTEXT ACCEPT"); break;
	case EPS_SM_AEBCJ_MSG:	SET_MSG_INFO(s, "ACTIVATE DEDICATED EPS BEARER CONTEXT REJECT"); break;
	case EPS_SM_MBCR_MSG:	SET_MSG_INFO(s, "MODIFY EPS BEARER CONTEXT REQUEST"); break;
	case EPS_SM_MBCA_MSG:	SET_MSG_INFO(s, "MODIFY EPS BEARER CONTEXT ACCEPT"); break;
	case EPS_SM_MBCJ_MSG:	SET_MSG_INFO(s, "MODIFY EPS BEARER CONTEXT REJECT"); break;
	case EPS_SM_DBCR_MSG:	SET_MSG_INFO(s, "DEACTIVATE EPS BEARER CONTEXT REQUEST"); break;
	case EPS_SM_DBCA_MSG:	SET_MSG_INFO(s, "DEACTIVATE EPS BEARER CONTEXT ACCEPT"); break;
	case EPS_SM_PCR_MSG:	SET_MSG_INFO(s, "PDN CONNECTIVITY REQUEST"); break;
	case EPS_SM_PCJ_MSG:	SET_MSG_INFO(s, "PDN CONNECTIVITY REJECT"); break;
	case EPS_SM_PDR_MSG:	SET_MSG_INFO(s, "PDN DISCONNECT REQUEST"); break;
	case EPS_SM_PDJ_MSG:	SET_MSG_INFO(s, "PDN DISCONNECT REJECT"); break;
	case EPS_SM_BRAR_MSG:	SET_MSG_INFO(s, "BEARER RESOURCE ALLOCATION REQUEST"); break;
	case EPS_SM_BRAJ_MSG:	SET_MSG_INFO(s, "BEARER RESOURCE ALLOCATION REJECT"); break;
	case EPS_SM_BRMR_MSG:	SET_MSG_INFO(s, "BEARER RESOURCE MODIFICATION REQUEST"); break;
	case EPS_SM_BRMJ_MSG:	SET_MSG_INFO(s, "BEARER RESOURCE MODIFICATION REJECT"); break;
	case EPS_SM_EIR_MSG:	SET_MSG_INFO(s, "ESM INFORMATION REQUEST"); break;
	case EPS_SM_EIP_MSG:	SET_MSG_INFO(s, "ESM INFORMATION RESPONSE"); break;
	case EPS_SM_NT_MSG:	SET_MSG_INFO(s, "NOTIFICATION"); break;
	case EPS_SM_ES_MSG:	SET_MSG_INFO(s, "ESM STATUS"); break;
	default:		SET_MSG_INFO(s, "UNKNOWN ESM TYPE 0x%02x", msg->subtype); break;
	}
}

/* Mobility management types */
static void naseps_set_msg_info_mm(struct session_info *s, naseps_msg_t *msg)
{
	if (msg->flags & EPS_MM_SEC_CIPHERED) {
		SET_MSG_INFO(s, "[ENCRYPTED]");
		s->new_msg->flags &= ~MSG_DECODED;
		return;
	}

	if (msg->flags & EPS_MM_SEC_INTEGRITY) {
		SET_MSG_INFO(s, "[INTEGRITY PROTECTED]");
		s->new_msg->flags &= ~MSG_DECODED;
		return;
	}


	switch (msg->subtype) {
	case EPS_MM_ARQ_MSG: 	
		SET_MSG_INFO(s, "ATTACH REQUEST");
		handle_arq(s,msg);
	break;
	case EPS_MM_AAC_MSG: 	
		SET_MSG_INFO(s, "ATTACH ACCEPT");
		handle_aac(s,msg);
	break;
	case EPS_MM_ACP_MSG: 	SET_MSG_INFO(s, "ATTACH COMPLETE"); break;
	case EPS_MM_ARE_MSG: 	SET_MSG_INFO(s, "ATTACH REJECT"); break;
	case EPS_MM_DRQ_MSG:
		SET_MSG_INFO(s, "DETACH REQUEST");
		handle_drq(s,msg);
	break;
	case EPS_MM_DAC_MSG: 	SET_MSG_INFO(s, "DETACH ACCEPT"); break;
	case EPS_MM_TAUR_MSG: 	
		SET_MSG_INFO(s, "TRACKING AREA UPDATE REQUEST"); 
		handle_taur(s,msg);
	break;
	case EPS_MM_TAUA_MSG:
		SET_MSG_INFO(s, "TRACKING AREA UPDATE ACCEPT"); 
		handle_taua(s,msg);
	break;
	case EPS_MM_TAUC_MSG: 	SET_MSG_INFO(s, "TRACKING AREA UPDATE COMPLETE"); break;
	case EPS_MM_TAUJ_MSG:
		SET_MSG_INFO(s, "TRACKING AREA UPDATE REJECT");
		handle_tauj(s,msg);
	break;
	case EPS_MM_ESR_MSG: 	SET_MSG_INFO(s, "EXTENDED SERVICE REQUEST"); break;
	case EPS_MM_SR_MSG: 	SET_MSG_INFO(s, "SERVICE REJECT"); break;
	case EPS_MM_GRAC_MSG: 	SET_MSG_INFO(s, "GUTI REALLOCATION COMMAND"); break;
	case EPS_MM_GRAP_MSG: 	SET_MSG_INFO(s, "GUTI REALLOCATION COMPLETE"); break;
	case EPS_MM_AREQ_MSG:
		SET_MSG_INFO(s, "AUTHENTICATION REQUEST");
		handle_areq(s,msg);
	break;
	case EPS_MM_ARES_MSG:
		SET_MSG_INFO(s, "AUTHENTICATION RESPONSE");
		handle_ares(s,msg);
	break;
	case EPS_MM_AREJ_MSG: 	SET_MSG_INFO(s, "AUTHENTICATION REJECT"); break;
	case EPS_MM_ARFL_MSG: 	SET_MSG_INFO(s, "AUTHENTICATION FAILURE"); break;
	case EPS_MM_IRQ_MSG: 	SET_MSG_INFO(s, "IDENTITY REQUEST"); break;
	case EPS_MM_IRP_MSG: 	SET_MSG_INFO(s, "IDENTITY RESPONSE"); break;
	case EPS_MM_SCMD_MSG:
		SET_MSG_INFO(s, "SECURITY MODE COMMAND");
		handle_scmd(s,msg);
	break;
	case EPS_MM_SCPL_MSG: 	SET_MSG_INFO(s, "SECURITY MODE COMPLETE"); break;
	case EPS_MM_SCRJ_MSG: 	SET_MSG_INFO(s, "SECURITY MODE REJECT"); break;
	case EPS_MM_EST_MSG: 	SET_MSG_INFO(s, "EMM STATUS"); break;
	case EPS_MM_EIF_MSG: 	SET_MSG_INFO(s, "EMM INFORMATION"); break;
	case EPS_MM_DNT_MSG:
		SET_MSG_INFO(s, "DOWNLINK NAS TRANSPORT");
		handle_dnt(s,msg);
	break;
	case EPS_MM_UNT_MSG:
		SET_MSG_INFO(s, "UPLINK NAS TRANSPORT");
		handle_unt(s,msg);
	break;
	case EPS_MM_CSSN_MSG: 	SET_MSG_INFO(s, "CS SERVICE NOTIFICATION"); break;
	case EPS_MM_DGNT_MSG: 	SET_MSG_INFO(s, "DOWNLINK GENERIC NAS TRANSPORT"); break;
	case EPS_MM_UGNT_MSG: 	SET_MSG_INFO(s, "UPLINK GENERIC NAS TRANSPORT"); break;
	default:		SET_MSG_INFO(s, "UNKNOWN EMM TYPE 0x%02x", msg->subtype); break;
	}
}

/* Set message description according to proto_disc/subtype */
void naseps_set_msg_info(struct session_info *s, naseps_msg_t *msg)
{
	switch (msg->type)
	{
		case PROTOCOL_EPS_MM: 
			naseps_set_msg_info_mm(s, msg);
			break;
		case PROTOCOL_EPS_SM: 
			naseps_set_msg_info_sm(s, msg);
			break;
		default:
			SET_MSG_INFO(s, "Unknown protocol 0x%02x", msg->type);
			break;
	}
}
