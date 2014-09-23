# security metrics v2.4

# operators to be listed ("valid")
drop table if exists va;
create table va(
	mcc SMALLINT UNSIGNED NOT NULL,
	mnc SMALLINT UNSIGNED NOT NULL,
	country CHAR(32) NOT NULL,
	network CHAR(32) NOT NULL,
	oldest DATE NOT NULL,
	latest DATE NOT NULL,
	cipher TINYINT UNSIGNED NOT NULL
) ENGINE=MyISAM;

# operator risk, main score (level 1)
drop table if exists risk_category;
create table risk_category(
	mcc SMALLINT UNSIGNED NOT NULL,
	mnc SMALLINT UNSIGNED NOT NULL,
	lac SMALLINT UNSIGNED NOT NULL,
	month CHAR(7) NOT NULL,
	intercept FLOAT(1),
	impersonation FLOAT(1),
	tracking FLOAT(1)
) ENGINE=MyISAM;

# operator risk, intercept sub-score (level 2)
drop table if exists risk_intercept;
create table risk_intercept(
	mcc SMALLINT UNSIGNED NOT NULL,
	mnc SMALLINT UNSIGNED NOT NULL,
	lac SMALLINT UNSIGNED NOT NULL,
	month CHAR(7) NOT NULL,
	voice FLOAT(1),
	sms FLOAT(1)
) ENGINE=MyISAM;

# operator risk, impersonation sub-score (level 2)
drop table if exists risk_impersonation;
create table risk_impersonation(
	mcc SMALLINT UNSIGNED NOT NULL,
	mnc SMALLINT UNSIGNED NOT NULL,
	lac SMALLINT UNSIGNED NOT NULL,
	month CHAR(7) NOT NULL,
	make_calls FLOAT(1),
	recv_calls FLOAT(1)
) ENGINE=MyISAM;

# operator risk, tracking  sub-score (level 2)
drop table if exists risk_tracking;
create table risk_tracking(
	mcc SMALLINT UNSIGNED NOT NULL,
	mnc SMALLINT UNSIGNED NOT NULL,
	lac SMALLINT UNSIGNED NOT NULL,
	month CHAR(7) NOT NULL,
	local_track FLOAT(1),
	global_track FLOAT(1)
) ENGINE=MyISAM;

# operator risk, attack components (level 3) 
drop table if exists attack_component;
create table attack_component(
	mcc SMALLINT UNSIGNED NOT NULL,
	mnc SMALLINT UNSIGNED NOT NULL,
	lac SMALLINT UNSIGNED NOT NULL,
	month CHAR(7) NOT NULL,
	realtime_crack FLOAT(1),
	offline_crack FLOAT(1),
	key_reuse_mt FLOAT(1),
	key_reuse_mo FLOAT(1),
	track_tmsi FLOAT(1),
	hlr_inf FLOAT(1),
	freq_predict FLOAT(1),
	PRIMARY KEY (mcc,mnc,lac,month)
) ENGINE=MyISAM;

drop table if exists attack_component_x4;
create table attack_component_x4(
	mcc SMALLINT UNSIGNED NOT NULL,
	mnc SMALLINT UNSIGNED NOT NULL,
	lac SMALLINT UNSIGNED NOT NULL,
	month CHAR(7) NOT NULL,
	cipher SMALLINT UNSIGNED,
	call_perc FLOAT(1),
	sms_perc FLOAT(1),
	loc_perc FLOAT(1),
	realtime_crack FLOAT(1),
	offline_crack FLOAT(1),
	key_reuse_mt FLOAT(1),
	key_reuse_mo FLOAT(1),
	track_tmsi FLOAT(1),
	hlr_inf FLOAT(1),
	freq_predict FLOAT(1),
	PRIMARY KEY (mcc,mnc,lac,month,cipher)
) ENGINE=MyISAM;

# operator security metrics (level 4)
drop table if exists sec_params;
create table sec_params(
	mcc SMALLINT UNSIGNED NOT NULL,
	mnc SMALLINT UNSIGNED NOT NULL,
	country CHAR(32) NOT NULL,
	network CHAR(32) NOT NULL,
	lac SMALLINT UNSIGNED NOT NULL,
	month CHAR(7) NOT NULL,
	cipher SMALLINT UNSIGNED NOT NULL,
	call_count INTEGER UNSIGNED,
	call_mo_count INTEGER UNSIGNED,
	sms_count INTEGER UNSIGNED,
	sms_mo_count INTEGER UNSIGNED,
	loc_count INTEGER UNSIGNED,
	call_success REAL,
	sms_success REAL,
	loc_success REAL,
	call_null_rand REAL,
	sms_null_rand REAL,
	loc_null_rand REAL,
	call_si_rand REAL,
	sms_si_rand REAL,
	loc_si_rand REAL,
	call_nulls REAL,
	sms_nulls REAL,
	loc_nulls REAL,
	call_pred REAL,
	sms_pred REAL,
	loc_pred REAL,
	call_imeisv REAL,
	sms_imeisv REAL,
	loc_imeisv REAL,
	pag_auth_mt REAL,
	call_auth_mo REAL,
	sms_auth_mo REAL,
	loc_auth_mo REAL,
	call_tmsi REAL,
	sms_tmsi REAL,
	loc_tmsi REAL,
	call_imsi REAL,
	sms_imsi REAL,
	loc_imsi REAL,
	ma_len REAL,
	var_len REAL,
	var_hsn REAL,
	var_maio REAL,
	var_ts REAL,
	rand_imsi REAL,
	home_routing REAL,
	PRIMARY KEY (mcc,mnc,lac,month,cipher)
) ENGINE=MyISAM;
	
# operator hlr query information (level 4+)
# !! manually populated !!

#create table hlr_info(
#	mcc SMALLINT UNSIGNED NOT NULL,
#	mnc SMALLINT UNSIGNED NOT NULL,
#	rand_imsi BOOLEAN,
#	home_routing BOOLEAN
#) ENGINE=MyISAM;

#--

# "va" population
delete from va;

insert into va
 select session_info.mcc,
	session_info.mnc,
	c_src.name,
	n_src.name,
	date(min(timestamp)),
	date(max(timestamp)),
	0
 from session_info, mnc as n_src, mcc as c_src
 where c_src.mcc = n_src.mcc and n_src.mcc = session_info.mcc and n_src.mnc = session_info.mnc
 and ((t_locupd and (lu_acc or cipher > 1)) or
      (t_sms and (t_release or cipher > 1)) or
      (t_call and (assign or cipher > 1)))
 and (cipher > 0 or duration > 350) and rat = 0
 group by mcc, mnc
 order by mcc, mnc;

delete from va
 where mcc >= 1000 or mnc >= 1000
 or (mcc = 262 and mnc = 10)
 or (mcc = 262 and mnc = 42)
 or (mcc = 204 and mnc = 21)
 or (mcc = 222 and mnc = 30)
 or (mcc = 228 and mnc = 6)
 or (mcc = 244 and mnc = 17)
 or (mcc = 208 and mnc = 14)
 or (mcc = 901);

insert into va (select distinct mcc,mnc,country,network,oldest,latest,1 from va);
insert into va (select distinct mcc,mnc,country,network,oldest,latest,2 from va);
insert into va (select distinct mcc,mnc,country,network,oldest,latest,3 from va);

--

# "sec_params" population
delete from sec_params;

insert into sec_params
 select va.mcc as mcc, va.mnc as mnc,
		 va.country as country, va.network as network,
		 c.lac as lac, c.month as month, va.cipher as cipher,
		 c.count, c.mo_count, s.count, s.mo_count, l.count,
		 c.success, s.success, l.success,
		 c.rand_null_perc, s.rand_null_perc, l.rand_null_perc,
		 c.rand_si_perc, s.rand_si_perc, l.rand_si_perc,
		 c.nulls, s.nulls, l.nulls,
		 c.pred, s.pred, l.pred,
		 c.imeisv, s.imeisv, l.imeisv,
		 avg_of_2(c.auth_mt, s.auth_mt),
		 c.auth_mo, s.auth_mo, l.auth_mo,
		 c.tmsi, s.tmsi, l.tmsi,
		 c.imsi, s.imsi, l.imsi,
		 e.ma_len, e.var_len, e.var_hsn, e.var_maio, e.var_ts,
		 h.rand_imsi,
		 h.home_routing
 from va left outer join (
  select mcc, mnc, lac, date_format(timestamp, "%Y-%m") as month, cipher,
	 count(*) as count,
	 sum(if(mobile_orig,1,0)) as mo_count,
	 avg(cracked) as success,
	 avg(if(enc_null, enc_null_rand/enc_null, NULL)) as rand_null_perc,
	 avg(if(enc_si, enc_si_rand/enc_si, NULL)) as rand_si_perc,
	 avg(enc_null-enc_null_rand) as nulls,
	 avg(predict) as pred,
	 avg(cmc_imeisv) as imeisv,
	 avg(if(mobile_term, auth, NULL)) as auth_mt,
	 avg(if(mobile_orig, auth, NULL)) as auth_mo,
	 avg(t_tmsi_realloc) as tmsi,
	 avg(iden_imsi_bc) as imsi
  from session_info
  where rat = 0 and ((t_call or (mobile_term and !t_sms)) and
	(call_presence or (cipher=1 and cracked=0) or cipher>1)) and
	(cipher > 0 or duration > 350)
  group by mcc, mnc, lac, month, cipher
  order by mcc, mnc, lac, month, cipher) as c
 on (va.mcc = c.mcc and va.mnc = c.mnc and va.cipher = c.cipher)
 left outer join (
  select mcc, mnc, lac, date_format(timestamp, "%Y-%m") as month, cipher,
	 count(*) as count,
	 sum(if(mobile_orig,1,0)) as mo_count,
	 avg(cracked) as success,
	 avg(if(enc_null, enc_null_rand/enc_null, NULL)) as rand_null_perc,
	 avg(if(enc_si, enc_si_rand/enc_si, NULL)) as rand_si_perc,
	 avg(enc_null-enc_null_rand) as nulls,
	 avg(predict) as pred,
	 avg(cmc_imeisv) as imeisv,
	 avg(if(mobile_term, auth, NULL)) as auth_mt,
	 avg(if(mobile_orig, auth, NULL)) as auth_mo,
	 avg(t_tmsi_realloc) as tmsi,
	 avg(iden_imsi_bc) as imsi
  from session_info
  where rat = 0 and (t_sms and (sms_presence or (cipher=1 and cracked=0) or cipher>1))
  group by mcc, mnc, lac, month, cipher
  order by mcc, mnc, lac, month, cipher) as s
 on (va.mcc = s.mcc and va.mnc = s.mnc and va.cipher = s.cipher
     and c.lac = s.lac and c.month = s.month)
 left outer join (
  select mcc, mnc, lac, date_format(timestamp, "%Y-%m") as month, cipher,
	 count(*) as count,
	 avg(cracked) as success,
	 avg(if(enc_null, enc_null_rand/enc_null, NULL)) as rand_null_perc,
	 avg(if(enc_si, enc_si_rand/enc_si, NULL)) as rand_si_perc,
	 avg(enc_null-enc_null_rand) as nulls,
	 avg(predict) as pred,
	 avg(cmc_imeisv) as imeisv,
	 avg(if(mobile_term, auth, NULL)) as auth_mt,
	 avg(if(mobile_orig, auth, NULL)) as auth_mo,
	 avg(t_tmsi_realloc) as tmsi,
	 avg(iden_imsi_bc) as imsi
  from session_info
  where rat = 0 and t_locupd and (lu_acc or cipher > 1)
  group by mcc, mnc, lac, month, cipher
  order by mcc, mnc, lac, month, cipher) as l
 on (va.mcc = l.mcc and va.mnc = l.mnc and va.cipher = l.cipher
     and c.lac = l.lac and c.month = l.month)
 left outer join
  (select mcc, mnc, lac, month, cipher,
	 avg(a_len) as ma_len,
	 avg(v_len) as var_len,
	 avg(v_hsn) as var_hsn,
	 avg(v_maio) as var_maio,
	 avg(v_ts) as var_ts,
	 avg(v_tsc) as var_tsc
  from (
  	select mcc, mnc, lac, cid, date_format(timestamp, "%Y-%m") as month, cipher,
	 	avg(a_ma_len + 1 - a_hopping) as a_len,
	 	variance((a_ma_len + 1 - a_hopping)/64) as v_len,
	 	variance(a_hsn/64) as v_hsn,
	 	variance(a_maio/64) as v_maio,
	 	variance(a_timeslot/8) as v_ts,
	 	variance(a_tsc/8) as v_tsc
 	from session_info
 	where rat = 0 and (assign or handover) and
	(cipher > 0 or duration > 350)
 	group by mcc, mnc, lac, cid, month, cipher) as en
  group by mcc, mnc, lac, month, cipher
  order by mcc, mnc, lac, month, cipher) as e
 on (va.mcc = e.mcc and va.mnc = e.mnc and va.cipher = e.cipher
     and c.lac = e.lac and c.month = e.month)
 left outer join hlr_info as h
 on (va.mcc = h.mcc and va.mnc = h.mnc) 
 where c.lac <> 0 and c.month <> ""
 order by mcc, mnc, lac, month, cipher; 

--

# "attack_component" population

delete from attack_component_x4;
insert into attack_component_x4
 select s.mcc, s.mnc, s.lac, s.month, s.cipher,

	s.call_count / t.call_tot as call_perc,

	s.sms_count  / t.sms_tot  as sms_perc,

	s.loc_count  / t.loc_tot  as loc_perc,

	avg_of_2
        (
                CASE WHEN call_nulls >  5 THEN 0 ELSE 1 - call_nulls /  5 END,
                CASE WHEN sms_nulls  > 10 THEN 0 ELSE 1 - sms_nulls  / 10 END
        )
        as realtime_crack,

	avg_of_2
        (
                CASE WHEN call_pred > 10 THEN 0 ELSE 1 - call_pred / 10 END,
                CASE WHEN sms_pred  > 15 THEN 0 ELSE 1 - sms_pred  / 15 END
        ) as offline_crack,

	pag_auth_mt as key_reuse_mt,

	avg_of_2(call_auth_mo,sms_auth_mo) as key_reuse_mo,

        --  FIXME: This value won't exceed 0.6 - is this on purpose?
	0.4 * avg_of_3 (call_tmsi, sms_tmsi, loc_tmsi) +
        0.2 * CASE WHEN loc_imsi < 0.05 THEN 1 - loc_imsi * 20 ELSE 0 END
           as track_tmsi,

	0.5 * rand_imsi + 0.5 * home_routing as hlr_inf,

	( if(ma_len<8, ma_len/8, 1) + if(var_len<0.01, var_len*100, 1)
	+ if(var_hsn<0.01, var_hsn*100, 1)
	+ if(var_maio<0.1, var_maio*10, 1)
	+ if(var_ts<0.1, var_ts*10, 1) )/5 as freq_predict

  from sec_params as s, lac_session_type_count as t
  where s.mcc = t.mcc and s.mnc = t.mnc and
	s.lac = t.lac and s.month = t.month
  order by s.mcc,s.mnc,s.lac,s.month,s.cipher;

delete from attack_component;
insert into attack_component
 select mcc, mnc, lac, month,

        sum(CASE
               WHEN cipher=3 THEN
                  (1.0 / 2 + realtime_crack / 2)
               WHEN cipher=2 THEN
                  0.2 / 2
               WHEN cipher=1 THEN
                  (0.5 / 2 + realtime_crack / 2)
               ELSE
                  0
            END * avg_of_2(call_perc,sms_perc)) as realtime_crack,

        sum(CASE
               WHEN cipher=3 THEN
                  (1.0 / 2 + offline_crack / 2)
               WHEN cipher=2 THEN
                   0.2 / 2
               WHEN cipher=1 THEN
                  (0.5 / 2 + offline_crack / 2)
               ELSE
                  0
            END * avg_of_2(call_perc,sms_perc)) as offline_crack,

        sum(avg_of_2(call_perc,sms_perc)*key_reuse_mt) as key_reuse_mt,

        sum(avg_of_2(call_perc,sms_perc)*key_reuse_mo) as key_reuse_mo,

        sum(CASE
               WHEN cipher=3 THEN
                    1 * 0.4 * avg_of_2(call_perc,sms_perc)
               WHEN cipher=2 THEN
                  0.2 * 0.4 * avg_of_2(call_perc,sms_perc)
               WHEN cipher=1 THEN
                  0.5 * 0.4 * avg_of_2(call_perc,sms_perc) + track_tmsi
               ELSE
                  0
            END) as track_imsi,

        avg(hlr_inf) as hlr_info,

        sum(call_perc * freq_predict) as freq_predict

 from attack_component_x4
 group by mcc, mnc, lac, month
 order by mcc, mnc, lac, month;

--

# "risk_intercept" population
delete from risk_intercept;
insert into risk_intercept
 select mcc, mnc, lac, month,
	(realtime_crack*0.4
	+ offline_crack*0.25
	+ avg_of_2(key_reuse_mt, key_reuse_mo)*0.20
	+ freq_predict*0.15) as voice,
	offline_crack as sms
 from attack_component
 order by mcc, mnc, lac, month;

--

# "risk_impersonation" population
delete from risk_impersonation;

insert into risk_impersonation
 select mcc, mnc, lac, month,
	avg_of_2(offline_crack, key_reuse_mo) as make_calls,
	avg_of_2(offline_crack, key_reuse_mt) as recv_calls
 from attack_component
 order by mcc, mnc, lac, month;

--

# "risk_tracking" population
delete from risk_tracking;

insert into risk_tracking
 select mcc, mnc, lac, month,
	track_tmsi as local_track,
	hlr_inf as global_track
 from attack_component
 order by mcc, mnc, lac, month;

--

# "risk_category" population
delete from risk_category;

insert into risk_category
 select inter.mcc, inter.mnc, inter.lac, inter.month,
	(inter.voice*0.8+inter.sms*0.2) as intercept,
	(imper.make_calls*0.7+imper.recv_calls*0.3) as impersonation,
	(track.local_track*0.3+track.global_track*0.7) as tracking
 from	risk_intercept as inter,
	risk_impersonation as imper,
	risk_tracking as track
 where inter.mcc = imper.mcc and imper.mcc = track.mcc
   and inter.mnc = imper.mnc and imper.mnc = track.mnc
   and inter.lac = imper.lac and imper.lac = track.lac
   and inter.month = imper.month and imper.month = track.month
 order by inter.mcc, inter.mnc, inter.lac, inter.month;

--
exit
# definition of views

drop view lac_session_type_count;
create view lac_session_type_count as
 select mcc, mnc, lac, month,
	sum(call_count) as call_tot,
	sum(sms_count) as sms_tot,
	sum(loc_count) as loc_tot
 from sec_params
 group by mcc,mnc,lac,month;

drop view a53_in_use;
create view a53_in_use as
 select mcc, mnc, lac, month,
	if((call_count+sms_count+loc_count)>0, if(cipher = 3, 1, 0), 0) as in_use
 from sec_params
 group by mcc,mnc,lac,month;

select r.mcc as mcc, r.mnc as mnc, r.lac as lac, r.month as month,
 if(call_tot, call_tot, 9)+if(sms_tot, sms_tot, 0)+if(loc_tot, loc_tot, 0) as samples,
 intercept as intercept_avg, impersonation as impersonation_avg, tracking as tracking_avg
from risk_category as r, session_type_count as s
where r.mcc = s.mcc and r.mnc = s.mnc
  and r.lac = s.lac and r.month = s.month;

