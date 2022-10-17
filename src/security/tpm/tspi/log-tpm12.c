/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Unlike log.c this implements TCPA log according to TPM1.2 specification
 * rather then using coreboot-specific log format.
 */

#include <endian.h>
#include <console/console.h>
#include <security/tpm/tspi.h>
#include <string.h>
#include <symbols.h>
#include <cbmem.h>
#include <bootstate.h>
#include <vb2_sha.h>

static struct tpm_1_log_table *tpm1_log_cbmem_init(void)
{
	static struct tpm_1_log_table *tclt;
	if (tclt)
		return tclt;

	if (cbmem_possibly_online()) {
		size_t tcpa_log_len;
		struct spec_id_event_data *hdr;

		tclt = cbmem_find(CBMEM_ID_TCPA_SPEC_LOG);
		if (tclt)
			return tclt;

		tcpa_log_len = sizeof(*tclt) + MAX_TCPA_LOG_ENTRIES * sizeof(tclt->entries[0]);
		tclt = cbmem_add(CBMEM_ID_TCPA_SPEC_LOG, tcpa_log_len);
		if (!tclt)
			return NULL;

		memset(tclt, 0, sizeof(*tclt));
		hdr = &tclt->spec_id;

		/* Fill in first "header" entry. */
		tclt->event_type = htole32(EV_NO_ACTION);
		tclt->event_data_size = htole32(sizeof(*hdr) + hdr->vendor_info_size);
		strcpy(hdr->signature, TCPA_SPEC_ID_EVENT_SIGNATURE);
		hdr->platform_class = htole32(0x00); // client platform
		hdr->spec_version_minor = 0x02;
		hdr->spec_version_major = 0x01;
		hdr->spec_errata = 0x01;
		hdr->vendor_info_size = sizeof(tclt->max_entries) + sizeof(tclt->num_entries);

		tclt->max_entries = MAX_TCPA_LOG_ENTRIES;
		tclt->num_entries = 0;
	}

	return tclt;
}

struct tpm_1_log_table *tcpa_log_init(void)
{
	static struct tpm_1_log_table *tclt;

	/* We are dealing here with pre CBMEM environment.
	 * If cbmem isn't available use CAR or SRAM */
	if (!cbmem_possibly_online() &&
		!CONFIG(VBOOT_RETURN_FROM_VERSTAGE)) {
		return (struct tpm_1_log_table *)_tpm_tcpa_log;
	} else if (ENV_ROMSTAGE &&
		!CONFIG(VBOOT_RETURN_FROM_VERSTAGE)) {
		tclt = tpm1_log_cbmem_init();
		if (!tclt)
			return (struct tpm_1_log_table *)_tpm_tcpa_log;
	} else {
		tclt = tpm1_log_cbmem_init();
	}

	return tclt;
}

void tcpa_log_dump(void *unused)
{
	int i, j;
	struct tpm_1_log_table *tclt;

	tclt = tpm_log_init();
	if (!tclt)
		return;

	printk(BIOS_INFO, "coreboot TCPA measurements:\n\n");
	for (i = 0; i < tclt->num_entries; i++) {
		struct tcpa_entry *tce = &tclt->entries[i];

		printk(BIOS_INFO, " PCR-%u ", le32toh(tce->pcr));

		for (j = 0; j < TPM_1_LOG_DIGEST_MAX_LENGTH; j++)
			printk(BIOS_INFO, "%02x", tce->digest[j]);

		printk(BIOS_INFO, " %s [%s]\n", "SHA1", tce->name);
	}
	printk(BIOS_INFO, "\n");
}

void tcpa_log_add_table_entry(const char *name, uint32_t pcr, const struct tpm_digest *digests)
{
	struct tpm_1_log_table *tclt;
	struct tpm_1_log_entry *tce;

	tclt = tpm_log_init();
	if (!tclt) {
		printk(BIOS_WARNING, "TPM LOG: non-existent!\n");
		return;
	}

	if (!name) {
		printk(BIOS_WARNING, "TPM LOG: entry name not set\n");
		return;
	}

	if (digests[0].hash_type != VB2_HASH_SHA1 || digests[1].hash_type != VB2_HASH_INVALID) {
		printk(BIOS_WARNING, "TPM LOG: digest is of unsupported type: %s\n",
		       vb2_get_hash_algorithm_name(digests[0].hash_type));
		return;
	}

	if (le16toh(tclt->vendor.num_entries) >= le16toh(tclt->vendor.max_entries)) {
		printk(BIOS_WARNING, "TPM LOG: log table is full\n");
		return;
	}

	tce = &tclt->entries[tclt->num_entries++];

	tce->pcr = htole32(pcr);
	tce->event_type = htole32(EV_ACTION);

	memcpy(tce->digest, digests[0].hash, TPM_1_LOG_DIGEST_MAX_LENGTH);

	tce->name_length = htole32(TCPA_PCR_HASH_NAME);
	strncpy(tce->name, name, TCPA_PCR_HASH_NAME - 1);
}

void tcpa_preram_log_clear(void)
{
	printk(BIOS_INFO, "TPM LOG: clearing the log\n");
	struct tpm_1_log_table *tclt = (struct tpm_1_log_table *)_tpm_tcpa_log;
	tclt->max_entries = MAX_TCPA_LOG_ENTRIES;
	tclt->num_entries = 0;
}

#if !CONFIG(VBOOT_RETURN_FROM_VERSTAGE)
static void recover_tcpa_log(int is_recovery)
{
	struct tpm_1_log_table *preram_log = (struct tpm_1_log_table *)_tpm_tcpa_log;
	struct tpm_1_log_table *ram_log = NULL;
	int i;

	if (preram_log->num_entries > MAX_PRERAM_TCPA_LOG_ENTRIES) {
		printk(BIOS_WARNING,
		       "TCPA: Pre-RAM TCPA log is too full, possible corruption\n");
		return;
	}

	ram_log = tpm1_log_cbmem_init();
	if (!ram_log) {
		printk(BIOS_WARNING, "TCPA: CBMEM not available something went wrong\n");
		return;
	}

	for (i = 0; i < preram_log->num_entries; i++) {
		struct tcpa_entry *tce = &ram_log->entries[ram_log->num_entries++];

		tce->pcr = preram_log->entries[i].pcr;
		tce->event_type = preram_log->entries[i].event_type;

		memcpy(tce->digest, preram_log->entries[i].digest, TPM_1_LOG_DIGEST_MAX_LENGTH);

		tce->name_length = htole32(TCPA_PCR_HASH_NAME);
		strncpy(tce->name, preram_log->entries[i].name, TCPA_PCR_HASH_NAME - 1);
	}
}
CBMEM_CREATION_HOOK(recover_tcpa_log);
#endif

BOOT_STATE_INIT_ENTRY(BS_PAYLOAD_BOOT, BS_ON_ENTRY, tcpa_log_dump, NULL);
