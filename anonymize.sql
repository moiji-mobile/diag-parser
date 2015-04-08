

-- Anonymize session_info
update session_info set imsi=substr(imsi,1,6);	-- Strip IMSIs
update session_info set imei=substr(imei,1,6);	-- Strip IMEIs
update session_info set msisdn=substr(msisdn,1,6);-- Strip phone numbers

-- Anonymize sms_meta
update sms_meta set data = "" where (alphabet = 1 or alphabet = 2) and length > 0 and ota = 0 and src_port = 0 and dst_port = 0 and (dcs < 192 or dcs >= 208); -- Strip everything thats not binary or silent sms
update sms_meta set data = "" where udh_length > 6 and dst_port = 2948 and from_network; -- Strip MMS anouncement SMS
update sms_meta set msisdn = substr(msisdn,1,6); -- Strip phone numbers

