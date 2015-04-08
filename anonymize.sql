-- Anonymize sensible fields in session_info

update session_info set imsi=substr(imsi,1,6);		-- Strip IMSIs

update session_info set imei=substr(imei,1,6);		-- Strip IMEIs

update session_info set msisdn=substr(msisdn,1,6);	-- Strip phone numbers

-- Anonymize sensible fields in sms_meta

update sms_meta set msisdn = substr(msisdn,1,6);	-- Strip phone numbers

update sms_meta set data = ""				-- Strip data if
where	(alphabet = 1 or alphabet = 2) and		-- text SMS only
	length > 0 and ota = 0 and			-- not empty or OTA
	src_port = 0 and dst_port = 0 and		-- no port addressing
	(dcs < 192 or dcs >= 208);			-- not silent sms

update sms_meta set data = ""				-- Strip data if
where	from_network and				-- message comes from network
	dst_port = 2948 and				-- addresses WAP-PUSH
	length > 6;					-- not empty
