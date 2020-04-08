#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "helper.h"

#define MAX_ERR_MSG_LEN 0x1000

// Compile a regular expression
static CU_RE_STATUS compile_regex(regex_t *preg, const char *regex) {
    int rc = regcomp(preg, regex, REG_EXTENDED | REG_NEWLINE);
    if (rc != 0) {
        char err_msg[MAX_ERR_MSG_LEN];
        regerror(rc, preg, err_msg, MAX_ERR_MSG_LEN);
        fprintf(stderr, "Failed to compile regex '%s': %s\n", regex, err_msg);
        return CU_RE_ERR;
    }
    return CU_RE_OK;
}

// Match a string against a compiled regular expression
static CU_RE_STATUS exec_regex(regex_t *preg, const char *to_match) {
    CU_RE_STATUS rc = CU_RE_NOMATCH;
    const char *p = to_match;

    rc = (regexec(preg, p, 0, NULL, 0) != 0) ? CU_RE_MATCH : CU_RE_NOMATCH;

    if (rc == CU_RE_MATCH) {
        regfree(preg);
    }

    return rc;
}

CU_RE_STATUS match_regex(const char *regex, const char *to_match) {
    CU_RE_STATUS rc = CU_RE_NOMATCH;
    regex_t preg;

    rc = compile_regex(&preg, regex);
    if (rc != CU_RE_OK) {
        return rc;
    }

    return exec_regex(&preg, to_match);
}

inline void free_cert(X509 **cert) {
    X509_free(*cert);
    *cert = NULL;
}

inline void free_crl(X509_CRL **crl) {
    X509_CRL_free(*crl);
    *crl = NULL;
}
