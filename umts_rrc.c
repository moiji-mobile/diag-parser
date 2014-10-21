#include <stdio.h>
#include <osmocom/rrc/DL-DCCH-Message.h>
#include <osmocom/rrc/UL-DCCH-Message.h>

#include "umts_rrc.h"
#include "l3_handler.h"

int handle_dcch_ul(struct session_info *s, uint8_t *msg, size_t len)
{
	UL_DCCH_Message_t *dcch = NULL;
	asn_dec_rval_t rv;

	MessageAuthenticationCode_t *mac;
	uint8_t *nas = NULL;
	int nas_len;
	int domain = -1;

	assert(s != NULL);
	assert(msg != NULL);
	assert(len > 0);

        rv = uper_decode(NULL, &asn_DEF_UL_DCCH_Message, (void **) &dcch, msg, len, 0, 0);
        if ((rv.code != RC_OK) || !dcch) {
                SET_MSG_INFO(s, "ASN.1 PARSING ERROR");
		return 1;
        }

	s[0].rat = RAT_UMTS;
	s[1].rat = RAT_UMTS;

	switch(dcch->message.present) {
	case UL_DCCH_MessageType_PR_rrcConnectionSetupComplete:
		SET_MSG_INFO(s, "RRC Setup Complete");
		session_reset(&s[0], 1);
		s[1].new_msg = NULL;
		session_reset(&s[1], 1);
		break;
	case UL_DCCH_MessageType_PR_rrcConnectionReleaseComplete:
		SET_MSG_INFO(s, "RRC Release Complete");
		session_reset(&s[0], 0);
		s[1].new_msg = NULL;
		session_reset(&s[1], 0);
		break;
	case UL_DCCH_MessageType_PR_securityModeComplete:
		SET_MSG_INFO(s, "RRC Security Mode Complete");
		//TODO try to handle domains
		if (s->cipher_missing < 0) {
			s->cipher_missing = 0;
		} else {
			s->cipher_missing = 1;
		}
		break;
	case UL_DCCH_MessageType_PR_initialDirectTransfer:
		SET_MSG_INFO(s, "RRC InitialDirectTransfer");
		domain = dcch->message.choice.initialDirectTransfer.cn_DomainIdentity;
		nas = dcch->message.choice.initialDirectTransfer.nas_Message.buf;
		nas_len = dcch->message.choice.initialDirectTransfer.nas_Message.size;
		break;
	case UL_DCCH_MessageType_PR_uplinkDirectTransfer:
		SET_MSG_INFO(s, "RRC UplinkDirectTransfer");
		domain = dcch->message.choice.initialDirectTransfer.cn_DomainIdentity;
		nas = dcch->message.choice.uplinkDirectTransfer.nas_Message.buf;
		nas_len = dcch->message.choice.uplinkDirectTransfer.nas_Message.size;
		break;
	default:
		SET_MSG_INFO(s, "UL-DCCH type=%d", dcch->message.present);
		s->new_msg->flags &= ~MSG_DECODED;
	}

	if (domain >= 0) {
		s->new_msg->domain = domain;
	}

	if (nas) {
		handle_dtap(s, nas, nas_len, 0, 1);
	}

#if 0
	if (dcch->integrityCheckInfo) {
		mac = &dcch->integrityCheckInfo->messageAuthenticationCode;
		//SET_MSG_INFO(s, " [I:%s/%lu]", osmo_hexdump_nospc(mac->buf, mac->size),
		//	 dcch->integrityCheckInfo->rrc_MessageSequenceNumber);
	}
#endif

	ASN_STRUCT_FREE(asn_DEF_UL_DCCH_Message, dcch);

	return 0;
}

int handle_dcch_dl(struct session_info *s, uint8_t *msg, size_t len)
{
	DL_DCCH_Message_t *dcch = NULL;
	asn_dec_rval_t rv;
	int error = 0;
	uint8_t *nas = NULL;
	int nas_len = 0;
	int domain;
	MessageAuthenticationCode_t *mac = NULL;
	SecurityCapability_t *cap = NULL; 
	CipheringModeInfo_t *cipher = NULL;
	CipheringModeInfo_r7_t *cipher7 = NULL;
	IntegrityProtectionModeInfo_t *integrity= NULL;	
	IntegrityProtectionModeInfo_r7_t *integrity7 = NULL;
	int c_algo = 0;
	int i_algo = 0;

	assert(s != NULL);
	assert(msg != NULL);
	assert(len > 0);

	/* sanity check */
	if (len > 90) {
                SET_MSG_INFO(s, "RRC Message too long: %d", len);
		return 1;
	}

    rv = uper_decode(NULL, &asn_DEF_DL_DCCH_Message, (void **) &dcch, msg, len, 0, 0);
    if ((rv.code != RC_OK) || !dcch) {
            SET_MSG_INFO(s, "ASN.1 PARSING ERROR");
	return 1;
    }

	s[0].rat = RAT_UMTS;
	s[1].rat = RAT_UMTS;

	switch(dcch->message.present) {
	case DL_DCCH_MessageType_PR_radioBearerSetup:
		SET_MSG_INFO(s, "RRC Radio Bearer Setup");
		break;
	case DL_DCCH_MessageType_PR_signallingConnectionRelease:
		SET_MSG_INFO(s, "RRC Signalling Connection Release");
		break;
	case DL_DCCH_MessageType_PR_rrcConnectionRelease:
		SET_MSG_INFO(s, "RRC Connection Release");
		session_reset(&s[0], 0);
		s[1].new_msg = NULL;
		session_reset(&s[1], 0);
		break;
	case DL_DCCH_MessageType_PR_securityModeCommand:
		switch(dcch->message.choice.securityModeCommand.present) {
		case SecurityModeCommand_PR_r3:
			domain = dcch->message.choice.securityModeCommand.choice.r3.securityModeCommand_r3.cn_DomainIdentity;
			cap = &dcch->message.choice.securityModeCommand.choice.r3.securityModeCommand_r3.securityCapability;
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
				cap = &dcch->message.choice.securityModeCommand.choice.later_than_r3.criticalExtensions.choice.r7.securityModeCommand_r7.securityCapability;
				domain = dcch->message.choice.securityModeCommand.choice.later_than_r3.criticalExtensions.choice.r7.securityModeCommand_r7.cn_DomainIdentity;
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
				SET_MSG_INFO(&s[domain], "RRC Security Mode Command / Not supported");
				error = 1;
				goto dl_end;
			}
			break;
		default:
			SET_MSG_INFO(&s[domain], "RRC Security Mode Command / Not supported");
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
		SET_MSG_INFO(s, "RRC DownlinkDirectTransfer");
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
	/* Buggy structures that cannot be freed */
	case DL_DCCH_MessageType_PR_measurementControl:
		SET_MSG_INFO(s, "RRC MeasurementControl");
		goto dl_no_free;
	case DL_DCCH_MessageType_PR_radioBearerRelease:
		SET_MSG_INFO(s, "RRC RadioBearerRelease");
		goto dl_no_free;
	case DL_DCCH_MessageType_PR_utranMobilityInformation:
		SET_MSG_INFO(s, "RRC utranMobilityInformation");
		goto dl_no_free;
	case DL_DCCH_MessageType_PR_radioBearerReconfiguration:
		SET_MSG_INFO(s, "RRC RadioBearerReconfig");
		goto dl_no_free;
	default:
		SET_MSG_INFO(s, "DL-DCCH type=%d", dcch->message.present);
		s->new_msg->flags &= ~MSG_DECODED;
	}

	if (nas) {
		handle_dtap(s, nas, nas_len, 0, 0);
	}

#if 0
	if (dcch->integrityCheckInfo) {
		mac = &dcch->integrityCheckInfo->messageAuthenticationCode;
		//SET_MSG_INFO(s, " [I:%s/%lu]", osmo_hexdump_nospc(mac->buf, mac->size),
		//	 dcch->integrityCheckInfo->rrc_MessageSequenceNumber);
	}
#endif

dl_end:
	//ASN_STRUCT_FREE(asn_DEF_DL_DCCH_Message, dcch);
dl_no_free:
	return error;
}
