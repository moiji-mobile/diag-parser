#include <stdio.h>
#include <osmocom/rrc/UL-DCCH-Message.h>
#include <osmocom/rrc/DL-DCCH-Message.h>
#include <osmocom/rrc/UL-CCCH-Message.h>
#include <osmocom/rrc/DL-CCCH-Message.h>

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
