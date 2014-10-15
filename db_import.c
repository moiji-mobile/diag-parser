#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mysql.h>
#include <omp.h>
#define __USE_XOPEN 1
#include <time.h>

#include "l3_handler.h"
#include "bit_func.h"
#include "assignment.h"
#include "session.h"
#include "process.h"

#define START_ID 585179

int explore_session(int id)
{
	MYSQL r_conn, w_conn, *test;
	MYSQL_RES *result;
	MYSQL_ROW row;
	int ret;
	char *cret;
	int mcc, mnc, lac, cid, cracked;
	char hex_tmp[9];
	char query[4096];
	struct session_info *s;
	struct tm tm;

	memset(&r_conn, 0, sizeof(r_conn));

	test = mysql_real_connect(&r_conn, "10.0.0.1", "luca", "nooHah1Aes", "celldb", 3306, 0, 0);
	if (test == 0) {
		printf("Cannot connect to R-database\n");
		return -1;
	}

	snprintf(query, sizeof(query),	"select mcc, mnc, lac, cid, timestamp, success from session"
				 	" where id = %d order by mcc, mnc, lac, cid", id );

	ret = mysql_query(&r_conn, query);
	if (ret != 0) {
		printf("Cannot execute query: %s\n", query);
		return -1;
	}

	result = mysql_use_result(&r_conn);
	if (result == 0) {
		printf("Cannot get query result\n");
		return -1;
	}

	row = mysql_fetch_row(result);
	if (row[0] == 0) {
		printf("Error reading row from result\n");
		return -1;
	}

	mcc = atoi(row[0]);
	mnc = atoi(row[1]);
	lac = atoi(row[2]);
	cid = atoi(row[3]);
	cracked = atoi(row[5]);

	memset(&tm, 0, sizeof(tm));
	cret = strptime(row[4], "%Y-%m-%d %T", &tm);
	if (!cret || cret[0]) {
		printf("Error parsing timestamp at %s\n", cret);
		return -1;
	}

	mysql_free_result(result);

	s = session_create(id, NULL, NULL, mcc, mnc, lac, cid, NULL);
	if (s == NULL) {
		printf("Cannot allocate session structure\n");
		return -1;
	}

	s->timestamp.tv_sec = mktime(&tm);
	s->cracked = cracked;
	s->started = 1;

	s->sql_callback = _s[0].sql_callback;

	snprintf(query, sizeof(query),	"select frameno, channel, uplink, data from session_frame"
					" where session = %d order by frameno, channel, uplink", id);

	ret = mysql_query(&r_conn, query);
	if (ret != 0) {
		printf("Cannot execute query: %s\n", query);
		return -1;
	}

	result = mysql_use_result(&r_conn);
	if (result == 0) {
		printf("Cannot get query result\n");
		return -1;
	}

	while ((row = mysql_fetch_row(result)) && row[0]) {
		int fn = atoi(row[0]);
		int channel = atoi(row[1]);
		int uplink = atoi(row[2]);
		uint8_t *data = row[3];
		struct radio_message *m;

		m = (struct radio_message *) malloc(sizeof(struct radio_message));
		if (m == 0)
			return 0;

		memset(m, 0, sizeof(struct radio_message));

		m->rat = RAT_GSM;
		m->domain = DOMAIN_CS;

		switch(channel) {
		case 100:
			m->flags = MSG_SDCCH;
			m->chan_nr = 0x41;
			memcpy(m->msg, data, 23);
			break;
		case 97:
			m->flags = MSG_SACCH;
			m->chan_nr = 0x41;
			memcpy(m->msg, data, 23);
			break;
		default:
			printf("unhandled channel %d in session %d\n", channel, id);
			fflush(stdout);
			free(m);
			continue;
		}
		m->msg_len = 23;
		m->flags |= MSG_DECODED;
		m->bb.fn[0] = fn;
		m->bb.arfcn[0] = (uplink ? ARFCN_UPLINK : 0);

		handle_radio_msg(s, m);
	}

	mysql_free_result(result);

	mysql_close(&r_conn);

	memset(&w_conn, 0, sizeof(w_conn));

	test = mysql_real_connect(&w_conn, "127.0.0.1", "root", "moth*echo5Sigma", "session_meta_test", 3306, 0, 0);
	if (test == 0) {
		printf("Cannot connect to W-database\n");
		return -1;
	}

	snprintf(query, sizeof(query), "delete from session_info where id = %d", id);

	ret = mysql_query(&w_conn, query);
	if (ret != 0) {
		printf("Cannot execute query: %s\n", query);
		return -1;
	}

	snprintf(query, sizeof(query), "delete from sms_meta where id = %d", id);

	ret = mysql_query(&w_conn, query);
	if (ret != 0) {
		printf("Cannot execute query: %s\n", query);
		return -1;
	}

	/* Write to database */
	session_close(s);

	session_free(s);

	mysql_close(&w_conn);
}

int main(int argc, char **argv)
{
	MYSQL conn, *test;
	MYSQL_RES *result;
	MYSQL_ROW row;
	int ret, i, s_id;
	unsigned int row_count;
	char query[128];

	session_init(0, 0, 0, 0, CALLBACK_MYSQL);
	auto_reset = 0;

	if (argc == 2) {
		msg_verbose = 1;

		s_id = atoi(argv[1]);

		printf("Session %d\n", s_id);

		explore_session(s_id);

		return 0;
	}

	memset(&conn, 0, sizeof(conn));

	test = mysql_real_connect(&conn, "10.0.0.1", "luca", "nooHah1Aes", "celldb", 3306, 0, 0);
	if (test == 0) {
		printf("Cannot connect to database\n");
		return -1;
	}

	snprintf(query, sizeof(query), "select id from session where id > %d order by id;", START_ID);

	ret = mysql_query(&conn, query);
	if (ret != 0) {
		printf("Cannot execute query: %s\n", query);
		return -1;
	}

	result = mysql_store_result(&conn);
	if (result == 0) {
		printf("Cannot get query result\n");
		return -1;
	}

	row_count = mysql_num_rows(result);

//	#pragma omp parallel for private(row) shared(result) num_threads (10)

	for (i = 1; i < row_count; i++) {
		row = mysql_fetch_row(result);
		if (row[0] == 0) {
			printf("Error read row from result\n");
			return -1;
		}

		s_id = atoi(row[0]);

		printf("Session %d\n", s_id);

		explore_session(s_id);
	}

	cell_and_paging_dump(1);

	mysql_free_result(result);
	mysql_close(&conn);

	return 0;
}
