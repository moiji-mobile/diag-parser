DROP TABLE IF EXISTS cell_info;
CREATE TABLE cell_info (
  id integer PRIMARY KEY,		-- Unique cell index
  first_seen datetime NOT NULL,		-- First seen timestamp
  last_seen datetime NOT NULL,		-- Last seen timestamp
  mcc smallint NOT NULL,		-- Mobile country code
  mnc smallint NOT NULL,		-- Mobile network code
  lac smallint NOT NULL,		-- Location area code
  cid int NOT NULL,			-- Cell ID
  rat tinyint NOT NULL,			-- Radio access technology (GSM=0, UMTS=1, LTE=2)
  bcch_arfcn int DEFAULT NULL,		-- Main ARFCN for this cell
  ba_len int DEFAULT NULL,		-- Number of ARFCNs belonging to this cell
  power_sum int DEFAULT NULL,		-- Power measurement accumulator
  power_count int DEFAULT NULL,		-- Power measurement count
  gps_lon float DEFAULT NULL,		-- GPS longitude
  gps_lat float DEFAULT NULL,		-- GPS latitude
  neigh_2 smallint DEFAULT NULL,	-- Neighboring cell count derived from SI2
  neigh_2b smallint DEFAULT NULL,	-- Neighboring cell count derived from SI2bis
  neigh_2t smallint DEFAULT NULL,	-- Neighboring cell count derived from SI2ter
  neigh_2q smallint DEFAULT NULL,	-- Neighboring cell count derived from SI2quater
  combined smallint DEFAULT NULL,	-- Cell uses BCCH combined mode
  t3212 smallint DEFAULT NULL,		-- Location update timer
  cro smallint DEFAULT NULL,		-- Cell reselection offset
  c1 smallint DEFAULT NULL,		-- C1 parameter
  c2 smallint DEFAULT NULL,		-- C2 parameter
  agch_blocks smallint DEFAULT NULL,	-- # of blocks reserved to AGCH
  si1 binary(23) DEFAULT NULL,		-- Binary message SI1
  si2 binary(23) DEFAULT NULL,		-- Binary message SI2
  si2b binary(23) DEFAULT NULL,		-- Binary message SI2bis
  si2t binary(23) DEFAULT NULL,		-- Binary message SI2ter
  si2q binary(23) DEFAULT NULL,		-- Binary message SI2quater
  si3 binary(23) DEFAULT NULL,		-- Binary message SI3
  si4 binary(23) DEFAULT NULL,		-- Binary message SI4
  si5 binary(23) DEFAULT NULL,		-- Binary message SI5
  si5b binary(23) DEFAULT NULL,		-- Binary message SI5bis
  si5t binary(23) DEFAULT NULL,		-- Binary message SI5ter
  si6 binary(23) DEFAULT NULL,		-- Binary message SI6
  si13 binary(23) DEFAULT NULL		-- Binary message SI113
);


DROP TABLE IF EXISTS neigh_info;
CREATE TABLE neigh_info (
  id integer NOT NULL,			-- Unique cell index
  arfcn integer	NOT NULL		-- Neighboring ARFCN
);
