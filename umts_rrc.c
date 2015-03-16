#include <stdio.h>
#include <osmocom/rrc/UL-DCCH-Message.h>
#include <osmocom/rrc/DL-DCCH-Message.h>
#include <osmocom/rrc/UL-CCCH-Message.h>
#include <osmocom/rrc/DL-CCCH-Message.h>
#include <osmocom/rrc/BCCH-BCH-Message.h>
#include <osmocom/rrc/SysInfoType1.h>
#include <osmocom/rrc/SysInfoType3.h>
#include <osmocom/rrc/SysInfoType5.h>
#include <osmocom/rrc/SysInfoType7.h>
#include <osmocom/rrc/SysInfoType11.h>
#include <osmocom/rrc/MasterInformationBlock.h>
#include <osmocom/rrc/MCC.h>
#include <osmocom/rrc/MNC.h>
#include <osmocom/core/bits.h>
#include <BIT_STRING.h>

#include "umts_rrc.h"
#include "l3_handler.h"
#include "session.h"

int handle_dcch_ul(struct session_info *s, uint8_t *msg, size_t len)
{
	uint8_t msg_type;
	int need_to_parse = 0;

	UL_DCCH_Message_t *dcch = NULL;
	asn_dec_rval_t rv;
	//MessageAuthenticationCode_t *mac;

	uint8_t *nas = NULL;
	int nas_len;
	int domain = -1;

	assert(s != NULL);
	assert(msg != NULL);

	if (!len) {
		return 1;
	}

	s[0].rat = RAT_UMTS;
	s[1].rat = RAT_UMTS;

	/* Decode message type */
	if (msg[0] & 0x80) {
		/* Integrity present */
		if (len < 6) {
			SET_MSG_INFO(s, "SANITY CHECK FAILED (HMAC_LEN)");
			return 1;
		}
		msg_type = ((msg[4] & 0x07) << 2) | (msg[5] >> 6);
	} else {
		msg_type = (msg[0] & 0x7c) >> 2;
	}

	/* Attach description and discard unsupported types */
	switch (msg_type) {
	case (UL_DCCH_MessageType_PR_rrcConnectionSetupComplete-1):
		SET_MSG_INFO(s, "RRC Setup Complete");
		session_reset(&s[0], 1);
		s[1].new_msg = NULL;
		session_reset(&s[1], 1);
		break;

	case (UL_DCCH_MessageType_PR_rrcConnectionReleaseComplete-1):
		SET_MSG_INFO(s, "RRC Release Complete");
		s[0].release = 1;
		session_reset(&s[0], 0);
		s[1].new_msg = NULL;
		s[1].release = 1;
		session_reset(&s[1], 0);
		break;

	case (UL_DCCH_MessageType_PR_securityModeComplete-1):
		SET_MSG_INFO(s, "RRC Security Mode Complete");

		//TODO try to handle domains
		if (s->cipher_missing < 0) {
			s->cipher_missing = 0;
		} else {
			s->cipher_missing = 1;
		}
		break;

	case (UL_DCCH_MessageType_PR_initialDirectTransfer-1):
		SET_MSG_INFO(s, "RRC InitialDirectTransfer");

		need_to_parse = 1;
		break;

	case (UL_DCCH_MessageType_PR_uplinkDirectTransfer-1):
		SET_MSG_INFO(s, "RRC UplinkDirectTransfer");

		need_to_parse = 1;
		break;

	default:
		SET_MSG_INFO(s, "UL-DCCH type=%d", msg_type);
		s->new_msg->flags &= ~MSG_DECODED;
	}


	/* Apply ASN.1 decoder to extract needed information */
	if (need_to_parse) {
		rv = uper_decode(NULL, &asn_DEF_UL_DCCH_Message, (void **) &dcch, msg, len, 0, 0);
		if ((rv.code != RC_OK) || !dcch) {
			SET_MSG_INFO(s, "ASN.1 PARSING ERROR");
			return 1;
		}

		switch(dcch->message.present) {
		case UL_DCCH_MessageType_PR_initialDirectTransfer:
			domain = dcch->message.choice.initialDirectTransfer.cn_DomainIdentity;
			nas = dcch->message.choice.initialDirectTransfer.nas_Message.buf;
			nas_len = dcch->message.choice.initialDirectTransfer.nas_Message.size;
			break;

		case UL_DCCH_MessageType_PR_uplinkDirectTransfer:
			domain = dcch->message.choice.initialDirectTransfer.cn_DomainIdentity;
			nas = dcch->message.choice.uplinkDirectTransfer.nas_Message.buf;
			nas_len = dcch->message.choice.uplinkDirectTransfer.nas_Message.size;
			break;

		default:
			assert(0 && "This message is not meant to be parsed, error!");
			break;
		}

		if (domain >= 0) {
			s->new_msg->domain = domain;
		}

		if (nas) {
			handle_dtap(s, nas, nas_len, 0, 1);
		}

		ASN_STRUCT_FREE(asn_DEF_UL_DCCH_Message, dcch);
	}

#if 0
	if (dcch->integrityCheckInfo) {
		mac = &dcch->integrityCheckInfo->messageAuthenticationCode;
		//SET_MSG_INFO(s, " [I:%s/%lu]", osmo_hexdump_nospc(mac->buf, mac->size),
		//	 dcch->integrityCheckInfo->rrc_MessageSequenceNumber);
	}
#endif

	return 0;
}

int handle_dcch_dl(struct session_info *s, uint8_t *msg, size_t len)
{
	uint8_t msg_type;
	int need_to_parse = 0;
	int error = 0;
	DL_DCCH_Message_t *dcch = NULL;
	asn_dec_rval_t rv;
	//MessageAuthenticationCode_t *mac = NULL;
	//SecurityCapability_t *cap = NULL; 
	CipheringModeInfo_t *cipher = NULL;
	CipheringModeInfo_r7_t *cipher7 = NULL;
	IntegrityProtectionModeInfo_t *integrity= NULL;	
	IntegrityProtectionModeInfo_r7_t *integrity7 = NULL;
	uint8_t *nas = NULL;
	int nas_len = 0;
	int domain;
	uint8_t msg_rel;
	int c_algo = 0;
	int i_algo = 0;

	assert(s != NULL);
	assert(msg != NULL);

	if (!len) {
		return 1;
	}

	s[0].rat = RAT_UMTS;
	s[1].rat = RAT_UMTS;

	/* Pre-decode message type */
	if (msg[0] & 0x80) {
		if (len < 6) {
			SET_MSG_INFO(s, "SANITY CHECK FAILED (HMAC_LEN)");
			return 1;
		}
		msg_type = ((msg[4] & 0x07) << 2) | (msg[5] >> 6);
	} else {
		msg_type = (msg[0] & 0x7c) >> 2;
	}

	/* Attach description and discard unsupported types */
	switch (msg_type) {
		case (DL_DCCH_MessageType_PR_signallingConnectionRelease-1):
			SET_MSG_INFO(s, "RRC Signalling Connection Release");
			/* Extract fields skipping integrity if needed */
			if (msg[0] & 0x80) {
				msg_rel = (msg[5] & 0x3f) >> 4;
				domain = (msg[5] >> 1) & 1;
			} else {
				msg_rel = msg[0] & 0x3;
				domain = (msg[1] >> 5) & 1;
			}
			/* we only support message r3 */
			if (msg_rel == 0) {
				s[domain].release = 1;
				//TODO: also reset single domain?
			}
			break;

		case (DL_DCCH_MessageType_PR_rrcConnectionRelease-1):
			SET_MSG_INFO(s, "RRC Connection Release");
			s[0].release = 1;
			session_reset(&s[0], 0);
			s[1].new_msg = NULL;
			s[1].release = 1;
			session_reset(&s[1], 0);
			break;

		case (DL_DCCH_MessageType_PR_securityModeCommand-1):
			need_to_parse = 1;
			break;

		case (DL_DCCH_MessageType_PR_downlinkDirectTransfer-1):
			SET_MSG_INFO(s, "RRC DownlinkDirectTransfer");

			need_to_parse = 1;
			break;

		default:
			SET_MSG_INFO(s, "DL-DCCH type=%d", msg_type);
			s->new_msg->flags &= ~MSG_DECODED;
			break;
	}

	if (need_to_parse) {
		/* Call ASN.1 decoder */
		rv = uper_decode(NULL, &asn_DEF_DL_DCCH_Message, (void **) &dcch, msg, len, 0, 0);
		if ((rv.code != RC_OK) || !dcch) {
			SET_MSG_INFO(s, "ASN.1 PARSING ERROR");
			return 1;
		}

		/* Process contents by message type */
		switch(dcch->message.present) {
		case DL_DCCH_MessageType_PR_securityModeCommand:
			switch(dcch->message.choice.securityModeCommand.present) {
			case SecurityModeCommand_PR_r3:
				domain = dcch->message.choice.securityModeCommand.choice.r3.securityModeCommand_r3.cn_DomainIdentity;
				//cap = &dcch->message.choice.securityModeCommand.choice.r3.securityModeCommand_r3.securityCapability;
				cipher = dcch->message.choice.securityModeCommand.choice.r3.securityModeCommand_r3.cipheringModeInfo;
				integrity = dcch->message.choice.securityModeCommand.choice.r3.securityModeCommand_r3.integrityProtectionModeInfo;
				if (cipher && (cipher->cipheringModeCommand.present == CipheringModeCommand_PR_startRestart)) {
					c_algo = cipher->cipheringModeCommand.choice.startRestart;
				}
				if (integrity && integrity->integrityProtectionAlgorithm) {
					i_algo = 1 + *(integrity->integrityProtectionAlgorithm);
				}
				break;
			case SecurityModeCommand_PR_later_than_r3:
				switch(dcch->message.choice.securityModeCommand.choice.later_than_r3.criticalExtensions.present) {
				case SecurityModeCommand__later_than_r3__criticalExtensions_PR_r7:
					domain = dcch->message.choice.securityModeCommand.choice.later_than_r3.criticalExtensions.choice.r7.securityModeCommand_r7.cn_DomainIdentity;
					//cap = &dcch->message.choice.securityModeCommand.choice.later_than_r3.criticalExtensions.choice.r7.securityModeCommand_r7.securityCapability;
					cipher7 = dcch->message.choice.securityModeCommand.choice.later_than_r3.criticalExtensions.choice.r7.securityModeCommand_r7.cipheringModeInfo;
					integrity7 = dcch->message.choice.securityModeCommand.choice.later_than_r3.criticalExtensions.choice.r7.securityModeCommand_r7.integrityProtectionModeInfo;
					if (cipher7) {
						c_algo = cipher7->cipheringModeCommand.startRestart;
					}
					if (integrity7 && integrity7->integrityProtectionAlgorithm) {
						i_algo = 1 + *(integrity7->integrityProtectionAlgorithm);
					}
					break;
				default:
					SET_MSG_INFO(&s[0], "RRC Security Mode Command / Not supported");
					error = 1;
					goto dl_end;
				}
				break;
			default:
				SET_MSG_INFO(&s[0], "RRC Security Mode Command / Not supported");
				error = 1;
				goto dl_end;
			}

			if (s[domain].cipher) {
				printf("Transaction was already ciphered!\n");
				error = 1;
				goto dl_end;
			}
			SET_MSG_INFO(&s[domain], "RRC Security Mode Command (%s), UEA/%d UIA/%d", (domain ? "PS" : "CS"), c_algo, i_algo);
			s[domain].cipher = c_algo;
			s[domain].integrity = i_algo;
			s[domain].cipher_missing = -1;
			break;

		case DL_DCCH_MessageType_PR_downlinkDirectTransfer:
			switch(dcch->message.choice.downlinkDirectTransfer.present) {
			case DownlinkDirectTransfer_PR_r3:
				domain = dcch->message.choice.downlinkDirectTransfer.choice.r3.downlinkDirectTransfer_r3.cn_DomainIdentity;
				nas = dcch->message.choice.downlinkDirectTransfer.choice.r3.downlinkDirectTransfer_r3.nas_Message.buf;
				nas_len = dcch->message.choice.downlinkDirectTransfer.choice.r3.downlinkDirectTransfer_r3.nas_Message.size;
				break;
			case DownlinkDirectTransfer_PR_later_than_r3:
				SET_MSG_INFO(s, "DDT > r3 is not supported!");
				break;
			default:
				SET_MSG_INFO(s, "DDT / Not supported");
				error = 1;
				goto dl_end;
			}
			break;

		default:
			assert(0 && "This message is not meant to be parsed, error!");
			break;
		}

		if (nas) {
			handle_dtap(s, nas, nas_len, 0, 0);
		}

dl_end:
		ASN_STRUCT_FREE(asn_DEF_DL_DCCH_Message, dcch);
	}

	#if 0
	if (dcch->integrityCheckInfo) {
		mac = &dcch->integrityCheckInfo->messageAuthenticationCode;
		//SET_MSG_INFO(s, " [I:%s/%lu]", osmo_hexdump_nospc(mac->buf, mac->size),
		//	 dcch->integrityCheckInfo->rrc_MessageSequenceNumber);
	}
	#endif

	return error;
}

int handle_ccch_ul(struct session_info *s, uint8_t *msg, size_t len)
{
	uint8_t msg_type;

	assert(s != NULL);
	assert(msg != NULL);

	if (!len) {
		return 1;
	}

	s[0].rat = RAT_UMTS;
	s[1].rat = RAT_UMTS;

	/* Pre-decode message type */
	if (msg[0] & 0x80) {
		if (len < 5) {
			SET_MSG_INFO(s, "SANITY CHECK FAILED (HMAC_LEN)");
			return 1;
		}
		msg_type = (msg[4] & 0x07);
	} else {
		msg_type = (msg[0] & 0x70) >> 4;
	}

	/* Attach description and discard unsupported types */
	switch(msg_type) {
	case 3:
		SET_MSG_INFO(s, "RRC Connection Request");
		break;
	default:
		/* no other messages accepted */
		SET_MSG_INFO(s, "UL-CCCH type=%d", msg_type);
		s->new_msg->flags &= ~MSG_DECODED;
	}

	return 0;
}

int handle_ccch_dl(struct session_info *s, uint8_t *msg, size_t len)
{
	uint8_t msg_type;

	assert(s != NULL);
	assert(msg != NULL);

	if (!len) {
		return 1;
	}

	s[0].rat = RAT_UMTS;
	s[1].rat = RAT_UMTS;

	/* Pre-decode message type */
	if (msg[0] & 0x80) {
		if (len < 5) {
			SET_MSG_INFO(s, "SANITY CHECK FAILED (HMAC_LEN)");
			return 1;
		}
		msg_type = (msg[4] & 0x07);
	} else {
		msg_type = (msg[0] & 0x70) >> 4;
	}

	/* Attach description and discard unsupported types */
	switch(msg_type) {
	case (DL_CCCH_MessageType_PR_rrcConnectionSetup-1):
		SET_MSG_INFO(s, "RRC Connection Setup");
		break;
	case (DL_CCCH_MessageType_PR_rrcConnectionRelease-1):
		SET_MSG_INFO(s, "RRC Connection Release");
		break;
	case (DL_CCCH_MessageType_PR_rrcConnectionReject-1):
		SET_MSG_INFO(s, "RRC Connection Reject");
		break;
	default:
		/* no other messages accepted */
		SET_MSG_INFO(s, "DL-CCCH type=%d", msg_type);
		s->new_msg->flags &= ~MSG_DECODED;
	}
	
	return 0;
}

/* Analyze system information type 0 (MIB) frame */
void handle_umts_sib_0_frame(struct session_info *s, BIT_STRING_t *frame)
{
	unsigned len, i;
	MasterInformationBlock_t *sib = NULL;
	asn_dec_rval_t rv;
	len = frame->size;
	MCC_t *mcc = NULL;
	MNC_t *mnc = NULL;
	int n_mcc = 0;
	int n_mnc = 0;

	rv = uper_decode(NULL, &asn_DEF_MasterInformationBlock, (void **) &sib, frame->buf, len, 0, 0);
	if ((rv.code != RC_OK) || !sib) {
		return;
	}

	/* Extract MCC and MNC */
	switch (sib->plmn_Type.present) {
	case PLMN_Type_PR_gsm_MAP:
		mcc = &sib->plmn_Type.choice.gsm_MAP.plmn_Identity.mcc;
		mnc = &sib->plmn_Type.choice.gsm_MAP.plmn_Identity.mnc;
		break;
	case PLMN_Type_PR_gsm_MAP_and_ANSI_41:
		mcc = &sib->plmn_Type.choice.gsm_MAP_and_ANSI_41.plmn_Identity.mcc;
		mnc = &sib->plmn_Type.choice.gsm_MAP_and_ANSI_41.plmn_Identity.mnc;
		break;
	default:
		return;
	}

	for (i = 0; i < mcc->list.count; i++) {
		n_mcc = n_mcc*10 + (int)*mcc->list.array[i];
	}

	for (i=0; i< mnc->list.count; i++) {
		n_mnc = n_mnc*10 + (int)*mnc->list.array[i];
	}

	APPEND_MSG_INFO(s, " MIB MCC %d MNC %d", n_mcc, n_mnc);
	s->mcc = n_mcc;
	s->mnc = n_mnc;

	/* FIXME: When freeing, the whole program exits. */
	//ASN_STRUCT_FREE(asn_DEF_MasterInformationBlock, sib);
}

/* Analyze system information type 1 frame */
void handle_umts_sib_1_frame(struct session_info *s, BIT_STRING_t *frame)
{
	unsigned len, i;
	SysInfoType1_t *sib = NULL;
	asn_dec_rval_t rv;
	len = frame->size;
	int lac = 0;

	rv = uper_decode(NULL, &asn_DEF_SysInfoType1, (void **) &sib, frame->buf, len, 0, 0);
	if ((rv.code != RC_OK) || !sib) {
		return;
	}

	/* Extract LAC */
	for (i=0; i<sib->cn_CommonGSM_MAP_NAS_SysInfo.size; i++) {
		lac = lac*256+sib->cn_CommonGSM_MAP_NAS_SysInfo.buf[i];
	}

	APPEND_MSG_INFO(s, " SIB1 LAC %d", lac);
	s->lac = lac;

	//ASN_STRUCT_FREE(asn_DEF_SysInfoType1, sib);
}

/* Analyze system information type 3 frame */
void handle_umts_sib_3_frame(struct session_info *s, BIT_STRING_t *frame)
{
	unsigned len;
	SysInfoType3_t *sib = NULL;
	asn_dec_rval_t rv;
	len = frame->size;
	int cid;

	rv = uper_decode(NULL, &asn_DEF_SysInfoType3, (void **) &sib, frame->buf, len, 0, 0);
	if ((rv.code != RC_OK) || !sib) {
		return;
	}

	/* Extract CID */
	cid = sib->cellIdentity.buf[0] & 0x0f;
	cid = cid * 16 + (sib->cellIdentity.buf[1] >> 4);
	cid = cid * 16 + (sib->cellIdentity.buf[1] & 0x0f);
	cid = cid * 256 + (sib->cellIdentity.buf[2]);
	cid = cid * 16 + (sib->cellIdentity.buf[3] >> 4);
	APPEND_MSG_INFO(s, " SIB3 CID %d", cid);
	s->cid = cid;

	//ASN_STRUCT_FREE(asn_DEF_SysInfoType3, sib);
}

/* Analyze system information type 5 frame */
void handle_umts_sib_5_frame(struct session_info *s, BIT_STRING_t *frame)
{
	unsigned len;
	SysInfoType5_t *sib = NULL;
	asn_dec_rval_t rv;
	len = frame->size;

	rv = uper_decode(NULL, &asn_DEF_SysInfoType5, (void **) &sib, frame->buf, len, 0, 0);
	if ((rv.code != RC_OK) || !sib) {
		return;
	}

	APPEND_MSG_INFO(s, " SIB5");

	ASN_STRUCT_FREE(asn_DEF_SysInfoType5, sib);
}

/* Analyze system information type 7 frame */
void handle_umts_sib_7_frame(struct session_info *s, BIT_STRING_t *frame)
{
	unsigned len;
	SysInfoType7_t *sib = NULL;
	asn_dec_rval_t rv;
	len = frame->size;

	rv = uper_decode(NULL, &asn_DEF_SysInfoType7, (void **) &sib, frame->buf, len, 0, 0);
	if ((rv.code != RC_OK) || !sib) {
		return;
	}

	APPEND_MSG_INFO(s, " SIB7");

	//ASN_STRUCT_FREE(asn_DEF_SysInfoType7, sib);
}

/* Analyze system information type 11 frame */
void handle_umts_sib_11_frame(struct session_info *s, BIT_STRING_t *frame)
{
	unsigned len;
	SysInfoType11_t *sib = NULL;
	asn_dec_rval_t rv;
	len = frame->size;

	rv = uper_decode(NULL, &asn_DEF_SysInfoType11, (void **) &sib, frame->buf, len, 0, 0);
	if ((rv.code != RC_OK) || !sib) {
		return;
	}

	APPEND_MSG_INFO(s, " SIB11");

	//ASN_STRUCT_FREE(asn_DEF_SysInfoType11, sib);
}

void handle_umts_sib(struct session_info *s, CompleteSIBshort_t *sib)
{
	switch (sib->sib_Type) {
	case 0: /* SIB0 (MIB) */
		handle_umts_sib_0_frame(s, &sib->sib_Data_variable);
		break;

	case 1: /* SIB1 */
		handle_umts_sib_1_frame(s, &sib->sib_Data_variable);
		break;
	
	case 3: /* SIB3 */
		handle_umts_sib_3_frame(s, &sib->sib_Data_variable);
		break;
			
	case 7: /* SIB7 */
		handle_umts_sib_7_frame(s, &sib->sib_Data_variable);
		break;
	default:
		APPEND_MSG_INFO(s, " SIB%d", sib->sib_Type);
	}
}

void handle_umts_sib_list(struct session_info *s, CompleteSIB_List_t *sib_list)
{
	int i;

	for (i = 0; i < sib_list->list.count; i++) {
		handle_umts_sib(s, sib_list->list.array[i]);
	}
}

int handle_umts_bcch(struct session_info *s, uint8_t *msg, size_t len)
{
	BCCH_BCH_Message_t *bcch = NULL;
        asn_dec_rval_t rv;

	/* Decode */
        rv = uper_decode(NULL, &asn_DEF_BCCH_BCH_Message, (void **) &bcch, msg, len, 0, 0);
        if ((rv.code != RC_OK) || !bcch) {
		SET_MSG_INFO(s, "ASN.1 PARSING ERROR");
		return -1;
	}
	
	SET_MSG_INFO(s, "BCCH");

	// check sequence and reset buffer on jumps
	// bcch->message.sfn_Prime;

	/* Inspect decoding results */
	switch (bcch->message.payload.present) {
		/* Frames that include only a single segment (simple case) */
		case SystemInformation_BCH__payload_PR_firstSegment:
			/* First */
			APPEND_MSG_INFO(s, " SIB%d [0/%d]",
				bcch->message.payload.choice.firstSegment.sib_Type,
				bcch->message.payload.choice.firstSegment.seg_Count
				);
/*
			&bcch->message.payload.choice.firstSegment.sib_Data_fixed,
			bcch->message.payload.choice.firstSegment.sib_Type,
			0,
			bcch->message.payload.choice.firstSegment.seg_Count
*/
			break;

		case SystemInformation_BCH__payload_PR_subsequentSegment:
			/* Subsequent */
			APPEND_MSG_INFO(s, " SIB%d [%d/-]",
				bcch->message.payload.choice.firstSegment.sib_Type,
				bcch->message.payload.choice.subsequentSegment.segmentIndex
				);
/*
			&bcch->message.payload.choice.subsequentSegment.sib_Data_fixed,
			bcch->message.payload.choice.firstSegment.sib_Type,
			bcch->message.payload.choice.subsequentSegment.segmentIndex,
			0
*/
			break;

		case SystemInformation_BCH__payload_PR_lastSegmentShort:
			/* Last short */
			APPEND_MSG_INFO(s, " SIB%d [%d/-]",
				bcch->message.payload.choice.firstSegment.sib_Type,
				bcch->message.payload.choice.subsequentSegment.segmentIndex
				);
/*
			&bcch->message.payload.choice.lastSegmentShort.sib_Data_variable,
			bcch->message.payload.choice.firstSegment.sib_Type,
			bcch->message.payload.choice.subsequentSegment.segmentIndex,
			0
*/
			break;

		case SystemInformation_BCH__payload_PR_lastSegment:
			/* Last */
			APPEND_MSG_INFO(s, " SIB%d [%d/-]",
				bcch->message.payload.choice.lastSegment.sib_Type,
				bcch->message.payload.choice.lastSegment.segmentIndex
				);
/*
			&bcch->message.payload.choice.lastSegment.sib_Data_fixed,
			bcch->message.payload.choice.lastSegment.sib_Type,
			bcch->message.payload.choice.lastSegment.segmentIndex,
			0
*/
			break;

		/* Frames that combine multiple segements and lists */	
		case SystemInformation_BCH__payload_PR_lastAndFirst:
			/* Last */
			APPEND_MSG_INFO(s, " SIB%d [%d/-]",
				bcch->message.payload.choice.lastAndFirst.lastSegmentShort.sib_Type,
				bcch->message.payload.choice.lastAndFirst.lastSegmentShort.segmentIndex
				);
/*
			&bcch->message.payload.choice.lastAndFirst.lastSegmentShort.sib_Data_variable,
			bcch->message.payload.choice.lastAndFirst.lastSegmentShort.sib_Type,
			bcch->message.payload.choice.lastAndFirst.lastSegmentShort.segmentIndex,
			0
*/
			
			/* First */
			APPEND_MSG_INFO(s, " SIB%d [0/%d]",
				bcch->message.payload.choice.lastAndFirst.firstSegment.sib_Type,
				bcch->message.payload.choice.lastAndFirst.firstSegment.seg_Count
				);
/*
			&bcch_sib_5_data,&bcch->message.payload.choice.lastAndFirst.firstSegment.sib_Data_variable,
			bcch->message.payload.choice.lastAndFirst.firstSegment.sib_Type,
			0,
			bcch->message.payload.choice.lastAndFirst.firstSegment.seg_Count
*/
			break;

		case SystemInformation_BCH__payload_PR_lastAndComplete:
			/* Last */
			APPEND_MSG_INFO(s, " SIB%d [%d/-]",
				bcch->message.payload.choice.lastAndComplete.lastSegmentShort.sib_Type,
				bcch->message.payload.choice.lastAndComplete.lastSegmentShort.segmentIndex
				);
/*
			&bcch->message.payload.choice.lastAndComplete.lastSegmentShort.sib_Data_variable,
			bcch->message.payload.choice.lastAndComplete.lastSegmentShort.sib_Type,
			bcch->message.payload.choice.lastAndComplete.lastSegmentShort.segmentIndex,
			0
*/

			/* Complete */
			handle_umts_sib_list(s, &bcch->message.payload.choice.lastAndComplete.completeSIB_List);
			break;

		case SystemInformation_BCH__payload_PR_lastAndCompleteAndFirst:
			/* Last */
			APPEND_MSG_INFO(s, " SIB%d [%d/-]",
				bcch->message.payload.choice.lastAndCompleteAndFirst.lastSegmentShort.sib_Type,
				bcch->message.payload.choice.lastAndCompleteAndFirst.lastSegmentShort.segmentIndex
				);
/*
			&bcch->message.payload.choice.lastAndCompleteAndFirst.lastSegmentShort.sib_Data_variable,
			bcch->message.payload.choice.lastAndCompleteAndFirst.lastSegmentShort.sib_Type,
			bcch->message.payload.choice.lastAndCompleteAndFirst.lastSegmentShort.segmentIndex,
			0
*/

			/* Complete, list */
			handle_umts_sib_list(s, &bcch->message.payload.choice.lastAndCompleteAndFirst.completeSIB_List);

			/* First */
			APPEND_MSG_INFO(s, " SIB%d [0/%d]",
				bcch->message.payload.choice.lastAndCompleteAndFirst.firstSegment.sib_Type,
				bcch->message.payload.choice.lastAndCompleteAndFirst.firstSegment.seg_Count
				);
/*
			&bcch->message.payload.choice.lastAndCompleteAndFirst.firstSegment.sib_Data_variable,
			bcch->message.payload.choice.lastAndCompleteAndFirst.firstSegment.sib_Type,
			0,
			bcch->message.payload.choice.lastAndCompleteAndFirst.firstSegment.seg_Count
*/
			break;

		case SystemInformation_BCH__payload_PR_completeSIB_List:
			/* Complete, list */
			handle_umts_sib_list(s, &bcch->message.payload.choice.completeSIB_List);
			break;

		case SystemInformation_BCH__payload_PR_completeAndFirst:
			/* Complete, list */
			handle_umts_sib_list(s, &bcch->message.payload.choice.completeAndFirst.completeSIB_List);

			/* First */
			APPEND_MSG_INFO(s, " SIB%d [0/%d]",
				bcch->message.payload.choice.completeAndFirst.firstSegment.sib_Type,
				bcch->message.payload.choice.completeAndFirst.firstSegment.seg_Count
				);
/*
			&bcch->message.payload.choice.completeAndFirst.firstSegment.sib_Data_variable,
			bcch->message.payload.choice.completeAndFirst.firstSegment.sib_Type,
			0,
			bcch->message.payload.choice.completeAndFirst.firstSegment.seg_Count
*/
			break;

		case SystemInformation_BCH__payload_PR_completeSIB:
			/* Complete, single */
			handle_umts_sib(s, &bcch->message.payload.choice.completeSIB);
			break;

		/* No data */
		case SystemInformation_BCH__payload_PR_noSegment:
		case SystemInformation_BCH__payload_PR_NOTHING:
		default:
			APPEND_MSG_INFO(s, " <empty>");
			break;
	}
	
	/* Missing ASN.1 free() */

	return 0;
}
