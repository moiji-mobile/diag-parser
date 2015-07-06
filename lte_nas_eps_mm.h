#ifndef LTE_NAS_EPS_MM_H
#define LTE_NAS_EPS_MM_H

#include "lte_nas_eps.h"

/* Protocol discriminator for EPS Mobititly management messages (message type) */
#define	PROTOCOL_EPS_MM 0x07	

/* Security headers for EPS Mobilitiy messages */
#define EPS_MM_SECHDR_TYPE_PLAIN 0x00 			/* Plain, No security */
#define EPS_MM_SECHDR_TYPE_INTEGRITY 0x01 		/* Integrity protected */
#define EPS_MM_SECHDR_TYPE_INTEGRITY_CIPHERED 0x02	/* Integrity protected and ciphered */
#define EPS_MM_SECHDR_TYPE_INTEGRITY_NEW 0x03		/* Integrity protected with new EPS security context */
#define EPS_MM_SECHDR_TYPE_INTEGRITY_CIPHERED_NEW 0x04	/* Integrity protected and ciphered with new EPS security context */
#define EPS_MM_SECHDR_TYPE_SERVICE_REQUEST 0x0c		/* Special value for SERVICE REQUESTs */

/* Message security flags */
#define EPS_MM_SEC_NONE		0x00	/* No security header */
#define EPS_MM_SEC_INTEGRITY	0x01	/* Message is integrity protected */
#define EPS_MM_SEC_CIPHERED	0x02	/* Message is ciphered */

/* Message types as defined in ETSI TS 124 301 V12.7.0, page 267: */
#define EPS_MM_ARQ_MSG 0x41		/* Attach request */
#define EPS_MM_AAC_MSG 0x42		/* Attach accept */
#define EPS_MM_ACP_MSG 0x43		/* Attach complete */
#define EPS_MM_ARE_MSG 0x44		/* Attach reject */
#define EPS_MM_DRQ_MSG 0x45		/* Detach request */
#define EPS_MM_DAC_MSG 0x46		/* Detach accept */
#define EPS_MM_TAUR_MSG 0x48		/* Tracking area update request  */
#define EPS_MM_TAUA_MSG 0x49		/* Tracking area update accept */
#define EPS_MM_TAUC_MSG 0x4A		/* Tracking area update complete */
#define EPS_MM_TAUJ_MSG 0x4B		/* Tracking area update reject */
#define EPS_MM_ESR_MSG 0x4C		/* Extended service request */
#define EPS_MM_SR_MSG 0x4E		/* Service reject */
#define EPS_MM_GRAC_MSG 0x50		/* GUTI reallocation command */
#define EPS_MM_GRAP_MSG 0x51		/* GUTI reallocation complete */
#define EPS_MM_AREQ_MSG 0x52		/* Authentication request */
#define EPS_MM_ARES_MSG 0x53		/* Authentication response */
#define EPS_MM_AREJ_MSG 0x54		/* Authentication reject */
#define EPS_MM_ARFL_MSG 0x5C		/* Authentication failure */
#define EPS_MM_IRQ_MSG 0x55		/* Identity request */
#define EPS_MM_IRP_MSG 0x56		/* Identity response */
#define EPS_MM_SCMD_MSG 0x5D		/* Security mode command */
#define EPS_MM_SCPL_MSG 0x5E		/* Security mode complete */
#define EPS_MM_SCRJ_MSG 0x5F		/* Security mode reject */
#define EPS_MM_EST_MSG 0x60		/* EMM status */
#define EPS_MM_EIF_MSG 0x61		/* EMM information */
#define EPS_MM_DNT_MSG 0x62		/* Downlink NAS transport */
#define EPS_MM_UNT_MSG 0x63		/* Uplink NAS transport */
#define EPS_MM_CSSN_MSG 0x64		/* CS Service notification */
#define EPS_MM_DGNT_MSG 0x68		/* Downlink generic NAS transport */
#define EPS_MM_UGNT_MSG 0x69		/* Uplink generic NAS transport */

/* Note: The type definition is always located in the 3rd message element,
         (2nd byte) except for EPS_MM_SECURITY_MSG */

/* Parse a NAS/EPS Mobility management message */
naseps_msg_t *parse_naseps_mm_msg(uint8_t *raw_message, int len, uint8_t uplink);

#endif
