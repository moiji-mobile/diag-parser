#ifndef META_MYSQL_API_H
#define META_MYSQL_API_H

#include "session.h"

void mysql_api_init(struct session_info *s);
void mysql_api_destroy();

#endif
