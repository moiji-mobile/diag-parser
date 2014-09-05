#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>

#include "sqlite_api.h"

static sqlite3 *meta_db;

void sqlite_api_query_cb(const char *query)
{
	int ret;

	ret = sqlite3_exec(meta_db, query, 0, 0, 0);
	if (ret != SQLITE_OK) {
		printf("Error executing query:\n%s\n", query);
		exit(1);
	}
}

void sqlite_api_init(struct session_info *s)
{	
	int ret;

	//TODO check if db file exists, init new db with schema

	ret = sqlite3_open("metadata.db", &meta_db);
	if (ret) {
		printf("Cannot open database\n");
		sqlite3_close(meta_db);
		exit(1);
	}

	s->sql_callback = sqlite_api_query_cb;
}

void sqlite_api_destroy()
{
	sqlite3_close(meta_db);
}
