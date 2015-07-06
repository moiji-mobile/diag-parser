#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sqlite3.h>

#include "sqlite_api.h"
#include "bit_func.h"

static sqlite3 *meta_db;

void sqlite_api_query_cb(const char *input)
{
	const char *ptr = input;
	char query[4096];
	int ret;

	assert(input != NULL);

	if (input[0] == 0) {
		return;
	}

	while (sgets(query, sizeof(query), &ptr)) {
		ret = sqlite3_exec(meta_db, query, 0, 0, 0);
		if (ret != SQLITE_OK) {
			printf("Error executing query:\n%s\n", query);
			exit(1);
		}
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

	ret = sqlite3_exec(meta_db, "BEGIN TRANSACTION;", 0, 0, 0);
	if (ret) {
		printf("Cannot begin transaction\n");
	}

	s->sql_callback = sqlite_api_query_cb;
}

void sqlite_api_destroy()
{
	int ret;

	ret = sqlite3_exec(meta_db, "COMMIT TRANSACTION;", 0, 0, 0);
	if (ret) {
		printf("Cannot commit transaction\n");
	}
	sqlite3_close(meta_db);
}
