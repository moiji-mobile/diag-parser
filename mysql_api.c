#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <mysql.h>
#include <assert.h>

#include "mysql_api.h"

#ifndef MYSQL_USER
#define MYSQL_USER "root"
#endif
#ifndef MYSQL_PASS
#define MYSQL_PASS ""
#endif
#ifndef MYSQL_DBNAME
#define MYSQL_DBNAME "celldb"
#endif

static MYSQL *meta_db;

void mysql_api_query_cb(const char *input)
{
	const char *ptr = input;
	char query[4096];
	int ret;

	assert(input != NULL);

	if (input[0] == 0) {
		return;
	}

	while (sgets(query, sizeof(query), &ptr)) {
		ret = mysql_query(meta_db, query);
		if (ret) {
			printf("Error executing query:\n%s\n", query);
			printf("MySQL error: %s\n", mysql_error(meta_db));
			exit(1);
		}
	}
}

void mysql_api_init(struct session_info *s)
{	
	int ret, one = 1;
	MYSQL *conn_check;

	/* Connect to database */
	meta_db = mysql_init(NULL);

	ret = mysql_options(meta_db, MYSQL_OPT_RECONNECT, &one);
	if (ret) {
		printf("Cannot set database options\n");
		exit(1);
	}

	conn_check = mysql_real_connect(meta_db, "localhost", MYSQL_USER, MYSQL_PASS, MYSQL_DBNAME, 3306, 0, 0);
	if (!conn_check) {
		printf("Cannot open database\n");
		exit(1);
	}

	s->sql_callback = mysql_api_query_cb;
}

void mysql_api_destroy()
{
	mysql_close(meta_db);
}
