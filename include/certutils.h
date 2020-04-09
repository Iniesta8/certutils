#ifndef CERTUTILS_H
#define CERTUTILS_H

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CU_OK = 0,     ///< Success / No error
    CU_STREAM_ERR, ///< Stream error
    CU_MEM_ERR,    ///< Memory error
    CU_PARAM_ERR,  ///< Parameter error
    CU_OSSL_ERR,   ///< OpenSSL error
    CU_UNKNOWN_ERR ///< Unknown error
} CU_STATUS;

typedef enum {
    CU_FTYPE_CERT,    ///< X509 Certificate
    CU_FTYPE_CRL,     ///< X509 Certificate revocation list
    CU_FTYPE_CSR,     ///< X509 Certificate signing request
    CU_FTYPE_NEW_CSR, ///< X509 New certificate signing request
    CU_FTYPE_PKCS7,   ///< PKCS7
    CU_FTYPE_PRIVKEY, ///< Private Key
    CU_FTYPE_PUBKEY,  ///< Public Key
    CU_FTYPE_UNKNOWN  ///< Unknown file type
} CU_FILETYPE;

typedef X509 CU_CERT;
typedef X509_CRL CU_CRL;

// clang-format off
#define CU_NID_basic_constraints          NID_basic_constraints        ///< Basic Constraints
#define CU_NID_key_usage                  NID_key_usage                ///< Key Usage
#define CU_NID_ext_key_usage              NID_ext_key_usage            ///< Extended Key Usage
#define CU_NID_subject_key_identifier     NID_subject_key_identifier   ///< Subject Key Identifier
#define CU_NID_authority_key_identifier   NID_authority_key_identifier ///< Authority Key Identifier
#define CU_NID_private_key_usage_period   NID_private_key_usage_period ///< Private Key Usage Period
#define CU_NID_subject_alt_name           NID_subject_alt_name         ///< Subject Alternative Name
#define CU_NID_issuer_alt_name            NID_issuer_alt_name          ///< Issuer Alternative Name
#define CU_NID_info_access                NID_info_access              ///< Authority Information Access
#define CU_NID_sinfo_access               NID_sinfo_access             ///< Subject Information Access
#define CU_NID_name_constraints           NID_name_constraints         ///< Name Constraints
#define CU_NID_certificate_policies       NID_certificate_policies     ///< Certificate Policies
#define CU_NID_policy_mappings            NID_policy_mappings          ///< Policy Mappings
#define CU_NID_policy_constraints         NID_policy_constraints       ///< Policy Constraints
#define CU_NID_inhibit_any_policy         NID_inhibit_any_policy       ///< Inhibit Any Policy
#define CU_NID_tlsfeature                 NID_tlsfeature               ///< TLS Feature
#define CU_NID_crl_distribution_points    NID_crl_distribution_points  ///< CRL Distribution Points
// clang-format on

CU_FILETYPE cu_get_file_type(const char *filename);

CU_STATUS cu_read_cert(const char *filename, CU_CERT **cert);
CU_STATUS cu_read_crl(const char *filename, CU_CRL **crl);
CU_STATUS cu_read_file(const char *filename, char **buf, size_t *buf_len);

CU_STATUS cu_cert_conv_pem2der(const char *pem_cert, const char *der_cert);
CU_STATUS cu_cert_conv_der2pem(const char *der_cert, const char *pem_cert);

CU_STATUS cu_cert_get_subject_name(const CU_CERT *cert, char **subject_name);
CU_STATUS cu_cert_get_issuer_name(const CU_CERT *cert, char **issuer_name);
CU_STATUS cu_cert_get_serial_number(const CU_CERT *cert, char **serial_number);
CU_STATUS cu_cert_get_not_before(const CU_CERT *cert, char **not_before);
CU_STATUS cu_cert_get_not_after(const CU_CERT *cert, char **not_after);
CU_STATUS cu_cert_get_extension(const CU_CERT *cert, int nid, char **ext_data);
CU_STATUS cu_cert_get_fingerprint(const CU_CERT *cert, const EVP_MD *digest_alg,
                                  char **fingerprint);

CU_STATUS cu_crl_get_issuer_name(const CU_CRL *crl, char **issuer_name);
CU_STATUS cu_crl_get_last_update(const CU_CRL *crl, char **last_update);
CU_STATUS cu_crl_get_next_update(const CU_CRL *crl, char **next_update);

#ifdef __cplusplus
}
#endif

#endif // CERTUTILS_H
