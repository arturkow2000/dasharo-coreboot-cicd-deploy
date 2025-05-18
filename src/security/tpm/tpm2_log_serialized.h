/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef __TPM2_LOG_SERIALIZED_H__
#define __TPM2_LOG_SERIALIZED_H__

#include <commonlib/bsd/tpm_log_defs.h>

#define TPM_20_SPEC_ID_EVENT_SIGNATURE "Spec ID Event03"
#define TPM_20_LOG_DATA_MAX_LENGTH 50

#define TPM_20_LOG_VI_MAGIC 0x32544243 /* "CBT2" in LE */
#define TPM_20_LOG_VI_MAJOR 2
#define TPM_20_LOG_VI_MINOR 0

/*
 * TPM2.0 log entries can't be generally represented as C structures due to
 * varying number of digests and their sizes. However, it works as long as
 * we're only using single kind of digests.
 */
#if CONFIG(TPM_LOG_TCG) || CONFIG(TPM_LOG_TPM2)
#  if CONFIG(TPM_HASH_SHA512)
#    define TPM_20_LOG_DIGEST_MAX_LENGTH SHA512_DIGEST_SIZE
#  elif CONFIG(TPM_HASH_SHA384)
#    define TPM_20_LOG_DIGEST_MAX_LENGTH SHA384_DIGEST_SIZE
#  elif CONFIG(TPM_HASH_SHA256)
#    define TPM_20_LOG_DIGEST_MAX_LENGTH SHA256_DIGEST_SIZE
#  elif CONFIG(TPM_HASH_SHA1)
#    define TPM_20_LOG_DIGEST_MAX_LENGTH SHA1_DIGEST_SIZE
#  endif

#  ifndef TPM_20_LOG_DIGEST_MAX_LENGTH
#    error "Misconfiguration: failed to determine TPM hashing algorithm"
#  endif
#else
#  define TPM_20_LOG_DIGEST_MAX_LENGTH 1 /* To avoid compilation error */
#endif

#define TPM_20_VENDOR_INFO_SIZE (sizeof(struct tpm_2_log_bottom) - sizeof(uint8_t))

/* This log table has two variable-sized portions one of which is in the middle.  For this
 * reason the declaration is split in two each ending on a variable-sized portion. */
struct tpm_2_log_table {
	struct tcg_efi_spec_id_event header; /* TCG_PCR_EVENT actually */
	// struct tpm_digest_sizes digest_sizes[header.num_of_algorithms];
	// struct tpm_2_log_bottom bottom;
} __packed;

/* The bottom part of the log which follows its first variable-sized portion (list of digest
   sizes). */
struct tpm_2_log_bottom {
	/* Size of the following set of fields. */
	uint8_t vendor_info_size;

	/* This is vendor info/data. */
	uint8_t reserved;
	uint8_t version_major;
	uint8_t version_minor;
	uint32_t magic;
	uint16_t next_offset; /* Offset within `events` array */
	uint16_t max_offset;  /* Maximum within `events` array */

	/* Events follow. */
	uint8_t events[];
} __packed;

#endif
