#include <getopt.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "certutils.h"
#include "helper.h"

typedef enum { CU_SUBCMD_NONE, CU_SUBCMD_CERT, CU_SUBCMD_CRL } CU_SUBCMD;

typedef enum {
    CU_INFO_NONE,
    CU_INFO_SUBJECT,
    CU_INFO_ISSUER,
    CU_INFO_EXTENSION
} CU_INFO;

struct global_args {
    int subcmd_flag;
    int info_flag;
    char *input_file;
    char *output_file;
};

static inline void display_usage() {
    printf("Usage: ./certutils --cert|--crl\n");
    exit(EXIT_FAILURE);
}

static inline void display_result(char *result) {
    if (result) {
        printf("%s\n", result);
    }
}

static inline void not_implemented() { fprintf(stderr, "Not implemented.\n"); }

int main(int argc, char **argv) {

    int c;

    char *result = NULL;

    static struct global_args args = {
        .subcmd_flag = CU_SUBCMD_NONE,
        .info_flag = CU_INFO_NONE,
        .input_file = NULL,
        .output_file = NULL,
    };

    if (argc == 1) {
        display_usage();
        exit(EXIT_FAILURE);
    }

    while (1) {
        static struct option long_options[] = {
            {"cert", no_argument, &args.subcmd_flag, CU_SUBCMD_CERT},
            {"crl", no_argument, &args.subcmd_flag, CU_SUBCMD_CRL},
            {"in", required_argument, NULL, 'i'},
            {"out", required_argument, NULL, 'o'},
            {"subject", no_argument, &args.info_flag, CU_INFO_SUBJECT},
            {"issuer", no_argument, &args.info_flag, CU_INFO_ISSUER},
            {"ext", no_argument, &args.info_flag, CU_INFO_EXTENSION},
            {"help", no_argument, NULL, 'h'},
            {NULL, no_argument, NULL, 0}};

        // getopt_long stores the option index here
        int option_index = 0;

        c = getopt_long(argc, argv, "i:o:h?", long_options, &option_index);

        // Detect the end of the options
        if (c == -1)
            break;

        switch (c) {
        case 0:
            // If this option set a flag, do nothing else now
            if (long_options[option_index].flag != 0)
                break;
            printf("test option %s", long_options[option_index].name);
            if (optarg)
                printf(" with arg %s", optarg);
            printf("\n");
            break;

        case 'i':
            args.input_file = optarg;
            break;

        case 'o':
            args.output_file = optarg;
            break;

        case 'h':
        case '?':
            display_usage();
            break;

        default:
            abort();
        }
    }

    if (optind < argc) {
        printf("non-option arguments: ");
        while (optind < argc)
            printf("%s ", argv[optind++]);
        putchar('\n');
    }

    X509 *cert = NULL;
    X509_CRL *crl = NULL;

    switch (args.subcmd_flag) {
    case CU_SUBCMD_CERT:
        if (!args.input_file || (args.info_flag == CU_INFO_NONE)) {
            display_usage();
        }

        switch (args.info_flag) {
        case CU_INFO_SUBJECT:
            cu_read_cert(args.input_file, &cert);
            cu_cert_get_subject_name(cert, &result);
            break;
        case CU_INFO_ISSUER:
            cu_read_cert(args.input_file, &cert);
            cu_cert_get_issuer_name(cert, &result);
            break;
        case CU_INFO_EXTENSION:
            not_implemented();
            break;
        }

        break;
    case CU_SUBCMD_CRL:
        if (!args.input_file || (args.info_flag == CU_INFO_NONE)) {
            display_usage();
        }

        switch (args.info_flag) {
        case CU_INFO_SUBJECT:
            not_implemented();
            break;
        case CU_INFO_ISSUER:
            cu_read_crl(args.input_file, &crl);
            cu_crl_get_issuer_name(crl, &result);
            break;
        case CU_INFO_EXTENSION:
            not_implemented();
            break;
        }

        break;
    case CU_SUBCMD_NONE:
    default:
        display_usage();
    }

    display_result(result);
    free(result);

    free_cert(&cert);
    free_crl(&crl);

    return EXIT_SUCCESS;
}
