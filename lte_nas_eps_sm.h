#ifndef LTE_NAS_EPS_SM_H
#define LTE_NAS_EPS_SM_H

#include "lte_nas_eps.h"

/* Protocol discriminator for EPS Mobititly management messages (message type) */
#define	PROTOCOL_EPS_SM 0x02	

/* Message types as defined in ETSI TS 124 301 V12.7.0, page 268: */
#define EPS_SM_ADBCR_MSG 0xC1		/* Activate default EPS bearer context request */
#define EPS_SM_ADBCA_MSG 0xC2		/* Activate default EPS bearer context accept */
#define EPS_SM_ADBCJ_MSG 0xC3		/* Activate default EPS bearer context reject */
#define EPS_SM_AEBCR_MSG 0xC5		/* Activate dedicated EPS bearer context request */
#define EPS_SM_AEBCA_MSG 0xC6		/* Activate dedicated EPS bearer context accept */
#define EPS_SM_AEBCJ_MSG 0xC7		/* Activate dedicated EPS bearer context reject */
#define EPS_SM_MBCR_MSG 0xC9		/* Modify EPS bearer context request */
#define EPS_SM_MBCA_MSG 0xCA		/* Modify EPS bearer context accept */
#define EPS_SM_MBCJ_MSG 0xCB		/* Modify EPS bearer context reject */
#define EPS_SM_DBCR_MSG 0xCD		/* Deactivate EPS bearer context request */
#define EPS_SM_DBCA_MSG 0xCE		/* Deactivate EPS bearer context accept */
#define EPS_SM_PCR_MSG 0xD0		/* PDN connectivity request */
#define EPS_SM_PCJ_MSG 0xD1		/* PDN connectivity reject */
#define EPS_SM_PDR_MSG 0xD2		/* PDN disconnect request */
#define EPS_SM_PDJ_MSG 0xD3		/* PDN disconnect reject */
#define EPS_SM_BRAR_MSG 0xD4		/* Bearer resource allocation request */
#define EPS_SM_BRAJ_MSG 0xD5		/* Bearer resource allocation reject */
#define EPS_SM_BRMR_MSG 0xD6		/* Bearer resource modification request */
#define EPS_SM_BRMJ_MSG 0xD7		/* Bearer resource modification reject */
#define EPS_SM_EIR_MSG 0xD9		/* ESM information request */
#define EPS_SM_EIP_MSG 0xDA		/* ESM information response */
#define EPS_SM_NT_MSG 0xDB		/* Notification */
#define EPS_SM_ES_MSG 0xE8		/* ESM status */



/* Note: The type definition is always located in the 4th message element (3rd byte) */


/* Parse a NAS/EPS Session management message */
naseps_msg_t *parse_naseps_sm_msg(uint8_t *raw_message, int len, uint8_t uplink);

#endif
