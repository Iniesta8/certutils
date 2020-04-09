#ifndef HELPER_H
#define HELPER_H

#include "certutils.h"

typedef enum { CU_RE_MATCH, CU_RE_NOMATCH, CU_RE_OK, CU_RE_ERR } CU_RE_STATUS;

CU_RE_STATUS match_regex(const char *regex, const char *to_match);

void free_cert(CU_CERT **cert);
void free_crl(CU_CRL **crl);

#endif // HELPER_H
