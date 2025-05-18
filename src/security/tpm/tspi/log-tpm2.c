/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Unlike log.c this implements TPM log according to TPM2.0 specification
 * rather then using coreboot-specific log format.
 *
 * First entry is in TPM1.2 format and serves as a header, the rest are in
 * a newer (agile) format which supports SHA256 and multiple hashes, but we
 * store only one hash.
 *
 * This is defined in "TCG EFI Protocol Specification".
 */

#include <endian.h>
#include <console/console.h>
#include <security/tpm/tspi.h>
#include <security/tpm/tspi/crtm.h>
#include <security/tpm/tspi/logs.h>
#include <region_file.h>
#include <string.h>
#include <symbols.h>
#include <cbmem.h>
#include <vb2_sha.h>

struct log_event {
	uint32_t pcr;
	uint32_t event_type;
	uint32_t digest_count;
	struct {
		uint16_t hash_type;
		uint8_t *hash;
	} digests[ENABLED_TPM_ALGS_NUM];
	uint32_t name_len;
	char *name;
};

struct pcr_banks_info {
	int active_count;
	bool is_active[ENABLED_TPM_ALGS_NUM];
};

static enum vb2_hash_algorithm tpmalg_to_vb2_hash(uint16_t hash_type)
{
	switch (hash_type) {
	case TPM2_ALG_SHA1:
		return VB2_HASH_SHA1;
	case TPM2_ALG_SHA256:
		return VB2_HASH_SHA256;
	case TPM2_ALG_SHA384:
		return VB2_HASH_SHA384;
	case TPM2_ALG_SHA512:
		return VB2_HASH_SHA512;

	default:
		return VB2_HASH_INVALID;
	}
}

static uint16_t tpmalg_from_vb2_hash(enum vb2_hash_algorithm hash_type)
{
	switch (hash_type) {
	case VB2_HASH_SHA1:
		return TPM2_ALG_SHA1;
	case VB2_HASH_SHA256:
		return TPM2_ALG_SHA256;
	case VB2_HASH_SHA384:
		return TPM2_ALG_SHA384;
	case VB2_HASH_SHA512:
		return TPM2_ALG_SHA512;

	default:
		return 0xFF;
	}
}

static int find_alg_index(enum vb2_hash_algorithm alg)
{
	unsigned int i;
	for (i = 0; i < ENABLED_TPM_ALGS_NUM; i++) {
		if (enabled_tpm_algs[i] == alg)
			return i;
	}

	return -1;
}

static bool is_all_zeroes(const void *buffer, size_t size)
{
	const uint8_t *p = buffer;
	while (size-- != 0) {
		if (*p++ != 0)
			return false;
	}
	return true;
}

static struct pcr_banks_info *get_pcr_banks_info(void)
{
	static bool initialized;
	static struct pcr_banks_info info;

	unsigned int i;

	if (initialized)
		return &info;

	TPML_PCR_SELECTION pcrs;
	tpm_result_t rc = tlcl2_get_capability_pcrs(&pcrs);
	if (rc != TPM_SUCCESS) {
		for (i = 0; i < ENABLED_TPM_ALGS_NUM; ++i)
			info.is_active[i] = true;
		info.active_count = ENABLED_TPM_ALGS_NUM;
	} else {
		for (i = 0; i < pcrs.count; i++) {
			TPMS_PCR_SELECTION *selection = &pcrs.pcrSelections[i];

			enum vb2_hash_algorithm alg = tpmalg_to_vb2_hash(selection->hash);
			if (alg == VB2_HASH_INVALID) {
				printk(BIOS_DEBUG, "%s(): unsupported PCR bank: %#x\n",
				       __func__, selection->hash);
				continue;
			}

			int alg_index = find_alg_index(alg);
			if (alg_index < 0) {
				printk(BIOS_DEBUG,
				       "%s(): skipping PCR bank disabled at build-time: %s\n",
				       __func__, vb2_get_hash_algorithm_name(alg));
				continue;
			}

			bool active = !is_all_zeroes(selection->pcrSelect,
						     selection->sizeofSelect);
			if (active) {
				info.is_active[alg_index] = active;
				++info.active_count;
			}
		}
	}

	initialized = true;
	return &info;
}

bool tpm2_log_alg_active(enum vb2_hash_algorithm alg)
{
	int alg_index = find_alg_index(alg);
	if (alg_index < 0)
		return false;

	return get_pcr_banks_info()->is_active[alg_index];
}

void *tpm2_log_cbmem_init(void)
{
	static struct tpm_2_log_table *tclt;
	if (tclt)
		return tclt;

	if (ENV_HAS_CBMEM) {
		int i, j;
		size_t tpm_log_len;
		struct tcg_efi_spec_id_event *hdr;
		struct pcr_banks_info *pcr_banks_info;

		tclt = cbmem_find(CBMEM_ID_TPM2_TCG_LOG);
		if (tclt)
			return tclt;

		tpm_log_len = 4 * KiB;
		tclt = cbmem_add(CBMEM_ID_TPM2_TCG_LOG, tpm_log_len);
		if (!tclt)
			return NULL;

		memset(tclt, 0, tpm_log_len);
		hdr = &tclt->header;

		hdr->event_type = htole32(EV_NO_ACTION);
		hdr->event_size = htole32(33 + sizeof(tclt->vendor));
		strcpy((char *)hdr->signature, TPM_20_SPEC_ID_EVENT_SIGNATURE);
		hdr->platform_class = htole32(0x00); // client platform
		hdr->spec_version_minor = 0x00;
		hdr->spec_version_major = 0x02;
		hdr->spec_errata = 0x00;
		hdr->uintn_size = 0x02; // 64-bit UINT

		pcr_banks_info = get_pcr_banks_info();
		hdr->num_of_algorithms = htole32(pcr_banks_info->active_count);
		for (i = 0, j = 0; i < le32toh(hdr->num_of_algorithms); ++i) {
			/* Find the next active bank. */
			while (!pcr_banks_info->is_active[j])
				++j;

			hdr->digest_sizes[i].alg_id =
				htole16(tpmalg_from_vb2_hash(enabled_tpm_algs[j]));
			hdr->digest_sizes[i].digest_size =
				htole16(vb2_digest_size(enabled_tpm_algs[j]));
		}

		tclt->vendor_info_size = sizeof(tclt->vendor);
		tclt->vendor.reserved = 0;
		tclt->vendor.version_major = TPM_20_LOG_VI_MAJOR;
		tclt->vendor.version_minor = TPM_20_LOG_VI_MINOR;
		tclt->vendor.magic = htole32(TPM_20_LOG_VI_MAGIC);
		tclt->vendor.next_offset = 0;
	}

	return tclt;
}

static uint16_t get_uint16(uint8_t **data)
{
	uint16_t value;
	memcpy(&value, *data, sizeof(value));
	*data += sizeof(uint16_t);
	return le16toh(value);
}

static uint32_t get_uint32(uint8_t **data)
{
	uint32_t value;
	memcpy(&value, *data, sizeof(value));
	*data += sizeof(uint32_t);
	return le32toh(value);
}

/* Returns non-zero if an event was parsed. */
static bool parse_log_event(struct tpm_2_log_table *tclt,
			    struct log_event *ev,
			    uint16_t *offset)
{
	uint8_t *tce;
	uint32_t i;

	if (*offset == tclt->vendor.next_offset)
		return false;

	tce = &tclt->events[*offset];

	ev->pcr = get_uint32(&tce);
	ev->event_type = get_uint32(&tce);
	ev->digest_count = get_uint32(&tce);

	for (i = 0; i < ev->digest_count; ++i) {
		ev->digests[i].hash_type = get_uint16(&tce);

		ev->digests[i].hash = tce;
		tce += vb2_digest_size(tpmalg_to_vb2_hash(ev->digests[i].hash_type));
	}

	ev->name_len = get_uint32(&tce);

	ev->name = (char *)tce;
	tce += ev->name_len;

	*offset = tce - tclt->events;
	return true;
}

void tpm2_log_dump(void)
{
	uint16_t offset;
	struct log_event ev;
	struct tpm_2_log_table *tclt;

	tclt = tpm_log_init();
	if (!tclt)
		return;

	offset = 0;
	while (parse_log_event(tclt, &ev, &offset)) {
		uint32_t i;

		printk(BIOS_INFO, " PCR-%u [%s]:\n", ev.pcr, ev.name);

		for (i = 0; i < ev.digest_count; ++i) {
			enum vb2_hash_algorithm hash_type;
			int digest_size, j;

			hash_type = tpmalg_to_vb2_hash(ev.digests[i].hash_type);
			digest_size = vb2_digest_size(hash_type);

			printk(BIOS_INFO, "  %6s: ", vb2_get_hash_algorithm_name(hash_type));
			for (j = 0; j < digest_size; ++j)
				printk(BIOS_INFO, "%02x", ev.digests[i].hash[j]);
			printk(BIOS_INFO, "\n");
		}
	}
	printk(BIOS_INFO, "\n");
}

void tpm2_log_add_table_entry(const char *name, uint32_t pcr, const struct tpm_digest *digests)
{
	struct tpm_2_log_table *tclt;
	uint16_t name_len, needed_size;
	uint8_t *tce;
	int i, digest_count;

	tclt = tpm_log_init();
	if (!tclt) {
		printk(BIOS_WARNING, "TPM LOG: non-existent!\n");
		return;
	}

	if (!name) {
		printk(BIOS_WARNING, "TPM LOG: entry name not set\n");
		return;
	}

	name_len = strlen(name) + 1;
	needed_size = 4 * sizeof(uint32_t) + name_len;
	for (i = 0; digests[i].hash_type != VB2_HASH_INVALID; ++i)
		needed_size += sizeof(uint16_t) + vb2_digest_size(digests[i].hash_type);

	digest_count = i;

	if (sizeof(*tclt) + tclt->vendor.next_offset + needed_size > MAX_TCPA_LOG_SIZE) {
		printk(BIOS_WARNING, "TCPA: TCPA log table is full\n");
		return;
	}

	tce = &tclt->events[tclt->vendor.next_offset];

	*(uint32_t *)tce = htole32(pcr);
	tce += sizeof(uint32_t);
	*(uint32_t *)tce = htole32(EV_ACTION);
	tce += sizeof(uint32_t);
	*(uint32_t *)tce = htole32(digest_count);
	tce += sizeof(uint32_t);

	for (i = 0; digests[i].hash_type != VB2_HASH_INVALID; ++i) {
		int hash_size = vb2_digest_size(digests[i].hash_type);

		*(uint16_t *)tce = htole16(tpmalg_from_vb2_hash(digests[i].hash_type));
		tce += sizeof(uint16_t);
		memcpy(tce, digests[i].hash, hash_size);
		tce += hash_size;
	}

	*(uint32_t *)tce = htole32(name_len);
	tce += sizeof(uint32_t);
	memcpy(tce, name, name_len);

	tclt->vendor.next_offset += needed_size;
}

int tpm2_log_get(int entry_idx, int *pcr, struct tpm_digest *digests, const char **event_name)
{
	uint16_t offset;
	struct log_event ev;
	int idx;
	struct tpm_2_log_table *tclt;

	tclt = tpm_log_init();
	if (!tclt)
		return 1;

	offset = 0;
	idx = 0;
	while (parse_log_event(tclt, &ev, &offset)) {
		if (idx != entry_idx) {
			++idx;
			continue;
		}

		int i;
		for (i = 0; i < ev.digest_count; ++i) {
			digests[i].hash_type = tpmalg_to_vb2_hash(ev.digests[i].hash_type);
			digests[i].hash = ev.digests[i].hash;
		}
		digests[ev.digest_count].hash_type = VB2_HASH_INVALID;

		*pcr = ev.pcr;
		*event_name = ev.name;
		return 0;
	}

	return 1;
}

uint16_t tpm2_log_get_size(const void *log_table)
{
	const struct tpm_2_log_table *tclt = log_table;
	return sizeof(*tclt) + le16toh(tclt->vendor.next_offset);
}

void tpm2_preram_log_clear(void)
{
	printk(BIOS_INFO, "TPM LOG: clearing the log\n");
	/*
	 * Pre-RAM log is only for internal use and isn't exported anywhere, hence it's header
	 * is not initialized.
	 */
	struct tpm_2_log_table *tclt = (struct tpm_2_log_table *)_tpm_log;
	tclt->vendor.next_offset = 0;
}

void tpm2_log_copy_entries(const void *from, void *to)
{
	const struct tpm_2_log_table *from_log = from;
	struct tpm_2_log_table *to_log = to;

	// TODO: check  for enough room via vendor.max_offset  
	memcpy(to_log->events, from_log->events, from_log->vendor.next_offset);
	to_log->vendor.next_offset = from_log->vendor.next_offset;
}
