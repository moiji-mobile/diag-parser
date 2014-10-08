#ifndef META_SQLITE_API_H
#define META_SQLITE_API_H

#include "session.h"

void sqlite_api_init(struct session_info *s);
void sqlite_api_close();

#endif
