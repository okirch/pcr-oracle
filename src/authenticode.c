/*
 *   Copyright (C) 2022 SUSE LLC
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Written by Olaf Kirch <okir@suse.com>
 *
 * This file contains functions to build the Authenticode digest
 * of a PECOFF executable. The defails are described in
 * "Windows Authenticode Portable Executable Signature Format"
 * (sorry, you need to google for this).
 *
 * Information on the layout of PECOFF files, consult
 * https://docs.microsoft.com/windows/win32/debug/pe-format
 *
 * Another good resource is the pesign package, which has code
 * to do this as well.
 */

#include <stdint.h>

#include "oracle.h"
#include "authenticode.h"
#include "bufparser.h"
#include "digest.h"
#include "runtime.h"

#if 1
# define pe_debug(args ...) \
	do { \
		if (opt_debug > 2) debug(args); \
	} while (0)
#else
# define pe_debug(args ...) \
	do { } while (0)
#endif

typedef struct pecoff_placement {
	uint32_t	addr;
	uint32_t	size;
} pecoff_placement_t;

typedef pecoff_placement_t	pecoff_image_datadir_t;

#define PECOFF_MAX_HOLES	10
#define PECOFF_MAX_AREAS	64

typedef struct authenticode_image_info {
	/* authenticated range of file */
	pecoff_placement_t	auth_range;

	unsigned int		hashed_bytes;

	unsigned int		num_holes;
	pecoff_placement_t	hole[PECOFF_MAX_HOLES];

	unsigned int		num_areas;
	pecoff_placement_t	area[PECOFF_MAX_AREAS];
} authenticode_image_info_t;


typedef struct pecoff_section {
	char			name[8];

	/* virtual addr of section */
	pecoff_placement_t	virtual;

	/* position within file */
	pecoff_placement_t	raw;
} pecoff_section_t;

typedef struct pecoff_image_info {
	authenticode_image_info_t *auth_info;

	unsigned int		format;

	struct {
		uint32_t	offset;
		uint16_t	machine_id;
		uint16_t	num_sections;
		uint32_t	symtab_offset;
		uint16_t	optional_hdr_size;
		uint32_t	optional_hdr_offset;

		uint32_t	section_table_offset;
	} pe_hdr;

	struct {
		uint32_t	size_of_headers;
		uint32_t	data_dir_count;
	} pe_optional_header;

	unsigned int		num_data_dirs;
	pecoff_image_datadir_t *data_dirs;

	unsigned int		num_sections;
	pecoff_section_t *	section;
} pecoff_image_info_t;

#define MSDOS_STUB_PE_OFFSET	0x3c

#define PECOFF_IMAGE_FILE_MACHINE_AMD64		0x8664

#define PECOFF_HEADER_LENGTH				20
#define PECOFF_HEADER_MACHINE_OFFSET			0x0000
#define PECOFF_HEADER_NUMBER_OF_SECTIONS_OFFSET		0x0002
#define PECOFF_HEADER_SYMTAB_POS_OFFSET			0x0008
#define PECOFF_HEADER_SYMTAB_CNT_OFFSET			0x000c
#define PECOFF_HEADER_OPTIONAL_HDR_SIZE_OFFSET		0x0010

#define PECOFF_OPTIONAL_HDR_MAGIC_OFFSET		0x0000
#define PECOFF_OPTIONAL_HDR_SIZEOFHEADERS_OFFSET	0x003c
#define PECOFF_OPTIONAL_HDR_CHECKSUM_OFFSET		0x0040

#define PECOFF_FORMAT_PE32				0x10b
#define PECOFF_FORMAT_PE32_PLUS				0x20b
#define PECOFF_DATA_DIRECTORY_CERTTBL_INDEX		4

static void
authenticode_set_range(authenticode_image_info_t *info, unsigned int offset, unsigned int len)
{
	info->auth_range.addr = offset;
	info->auth_range.size = len;
}

static void
authenticode_exclude_range(authenticode_image_info_t *info, unsigned int offset, unsigned int len)
{
	pecoff_placement_t *h;

	pe_debug("  Authenticode: Excluding %u bytes at offset %u\n", len, offset);
	if (info->num_holes >= PECOFF_MAX_HOLES)
		fatal("%s: cannot punch more than %d holes into a file\n", __func__, PECOFF_MAX_HOLES);

	h = info->hole + info->num_holes++;
	h->addr = offset;
	h->size = len;
}

static void
authenticode_add_range(authenticode_image_info_t *info, unsigned int offset, unsigned int len)
{
	pecoff_placement_t *h;

	pe_debug("  Authenticode: Including %u bytes at offset %u\n", len, offset);
	if (info->num_areas >= PECOFF_MAX_AREAS)
		fatal("%s: cannot cover more than %d areas of a PE executable\n", __func__, PECOFF_MAX_AREAS);

	h = info->area + info->num_areas++;
	h->addr = offset;
	h->size = len;
}

static unsigned int
authenticode_skip(authenticode_image_info_t *info, unsigned int last_offset, unsigned int hole_offset, unsigned int hole_len)
{
	authenticode_add_range(info, last_offset, hole_offset - last_offset);
	return hole_offset + hole_len;
}


static int
pecoff_placement_compare(const void *a, const void *b)
{
	const pecoff_placement_t *pa = a;
	const pecoff_placement_t *pb = b;

	return (int) pa->addr - (int) pb->addr;
}

static void
authenticode_finalize(authenticode_image_info_t *info)
{
	unsigned int i, j, range_end;
	pecoff_placement_t *area, *hole;

	for (i = 0, hole = info->hole; i < info->num_holes; ++i, ++hole) {
		unsigned int hole_end;

		pe_debug("  Hole %2u: 0x%x->0x%x\n", i, hole->addr, hole->addr + hole->size);
		hole_end = hole->addr + hole->size;

		for (j = 0, area = info->area; j < info->num_areas; ++j, ++area) {
			unsigned int area_end = area->addr + area->size;

			if (hole_end <= area->addr || area_end <= hole->addr)
				continue;

			pe_debug("  Area %u: 0x%x->0x%x overlaps hole %u\n", j, area->addr, area->addr + area->size, i);

			if (area->addr < hole->addr) {
				area->size = hole->addr - area->addr;
			} else {
				area->size = 0;
			}

			if (hole_end < area_end)
				authenticode_add_range(info, hole_end, area_end - hole_end);
		}
	}

	qsort(info->hole, info->num_holes, sizeof(info->hole[0]), pecoff_placement_compare);
	qsort(info->area, info->num_areas, sizeof(info->area[0]), pecoff_placement_compare);

	range_end = info->auth_range.addr + info->auth_range.size;
	for (i = 0, area = info->area; i < info->num_areas; ++i, ++area) {
		pe_debug("  Area %u: 0x%x->0x%x\n", i, area->addr, area->addr + area->size);
		if (i && area->addr < area[-1].addr + area[-1].size)
			fatal("PECOFF: area %u of PE image overlaps area %u\n",
					i, i - 1);

		if (area->addr >= range_end) {
			pe_debug("** Area %u is beyond the end of the auth range **\n", i);
			info->num_areas = i;
			break;
		}

		if (area->addr + area->size > range_end) {
			pe_debug("** Area %u extends beyond the end of the auth range **\n", i);
			area->size = range_end - area->addr;
		}
	}

	for (i = 0, hole = info->hole; i < info->num_holes; ++i, ++hole) {
		pe_debug("  Hole %2u: 0x%x->0x%x\n", i, hole->addr, hole->addr + hole->size);
	}
}

static tpm_evdigest_t *
authenticode_compute(authenticode_image_info_t *info, buffer_t *in, digest_ctx_t *digest)
{
	unsigned int area_index;
	static tpm_evdigest_t md;

	authenticode_finalize(info);

	for (area_index = 0; area_index < info->num_areas; ++area_index) {
		pecoff_placement_t *area = &info->area[area_index];

		if (!buffer_seek_read(in, area->addr)
		 || buffer_available(in) < area->size) {
			error("area %u points outside file data?!\n", area_index);
			return NULL;
		}

		pe_debug("  Hashing range 0x%x->0x%x\n", area->addr, area->addr + area->size);
		digest_ctx_update(digest, buffer_read_pointer(in), area->size);
	}

	return digest_ctx_final(digest, &md);
}

static inline bool
__pecoff_seek(buffer_t *in, const pecoff_image_info_t *img, unsigned int offset)
{
	return buffer_seek_read(in, img->pe_hdr.offset + offset);
}

static inline bool
__pecoff_get_u16(buffer_t *in, const pecoff_image_info_t *img, unsigned int offset, uint16_t *vp)
{
	return __pecoff_seek(in, img, offset) && buffer_get_u16le(in, vp);
}

static inline bool
__pecoff_get_u32(buffer_t *in, const pecoff_image_info_t *img, unsigned int offset, uint32_t *vp)
{
	return __pecoff_seek(in, img, offset) && buffer_get_u32le(in, vp);
}

static const char *
__pecoff_get_machine(const pecoff_image_info_t *img)
{
	static struct {
		unsigned int	id;
		const char *	name;
	} pe_machine_ids[] = {
		{ 0,		"unknown"	},
		{ 0x1c0,	"arm"		},
		{ 0xaa64,	"aarch64"	},
		{ 0x8664,	"x86_64"	},
		{ 0, NULL }
	}, *p;

	pe_debug("  Machine ID 0x%x\n", img->pe_hdr.machine_id);
	for (p = pe_machine_ids; p->name; ++p) {
		if (p->id == img->pe_hdr.machine_id)
			return p->name;
	}

	pe_debug("PE/COFF image has unsupported machine ID 0x%x\n", img->pe_hdr.machine_id);
	return "unsupported";
}

static bool
__pecoff_process_header(buffer_t *in, pecoff_image_info_t *img)
{
	if (!buffer_seek_read(in, MSDOS_STUB_PE_OFFSET)
	 || !buffer_get_u32le(in, &img->pe_hdr.offset))
		return false;

	if (!buffer_seek_read(in, img->pe_hdr.offset)
	 || memcmp(buffer_read_pointer(in), "PE\0\0", 4))
		return false;

	/* PE header starts immediately after the PE signature */
	img->pe_hdr.offset += 4;

	if (!__pecoff_get_u16(in, img, PECOFF_HEADER_MACHINE_OFFSET, &img->pe_hdr.machine_id))
		return NULL;

	if (!__pecoff_get_u16(in, img, PECOFF_HEADER_NUMBER_OF_SECTIONS_OFFSET, &img->pe_hdr.num_sections))
		return false;

	if (!__pecoff_get_u32(in, img, PECOFF_HEADER_SYMTAB_POS_OFFSET, &img->pe_hdr.symtab_offset))
		return false;

	img->pe_hdr.optional_hdr_offset = img->pe_hdr.offset + PECOFF_HEADER_LENGTH;
	if (!__pecoff_get_u16(in, img, PECOFF_HEADER_OPTIONAL_HDR_SIZE_OFFSET, &img->pe_hdr.optional_hdr_size))
		return false;

	img->pe_hdr.section_table_offset = img->pe_hdr.optional_hdr_offset + img->pe_hdr.optional_hdr_size;

	return true;
}

static bool
__pecoff_process_optional_header(buffer_t *in, pecoff_image_info_t *info)
{
	unsigned int hdr_offset = info->pe_hdr.optional_hdr_offset;
	unsigned int hdr_size = info->pe_hdr.optional_hdr_size;
	buffer_t hdr;
	uint16_t magic;
	unsigned int data_dir_offset, i, hash_base = 0;

	if (hdr_size == 0) {
		error("Invalid PE image: OptionalHdrSize can't be 0\n");
		return false;
	}

	/* Create a buffer that provides access to the PE header but not beyond */
	if (!buffer_seek_read(in, hdr_offset)
	 || !buffer_get_buffer(in, hdr_size, &hdr))
		return false;

	if (!buffer_seek_read(&hdr, PECOFF_OPTIONAL_HDR_MAGIC_OFFSET)
	 || !buffer_get_u16le(&hdr, &magic))
		return false;

	switch (magic) {
	case PECOFF_FORMAT_PE32:
		/* We do not point to the Data Directory itself as defined in the
		 * PE spec, but to NumberOfRvaAndSizes which is the 32bit word
		 * immediately preceding the Data Directory. */
		data_dir_offset = 92;
		break;

	case PECOFF_FORMAT_PE32_PLUS:
		/* We do not point to the Data Directory itself as defined in the
		 * PE spec, but to NumberOfRvaAndSizes which is the 32bit word
		 * immediately preceding the Data Directory. */
		data_dir_offset = 108;
		break;

	default:
		error("Unexpected magic number 0x%x in PECOFF optional header\n", magic);
		return false;
	}

	info->format = magic;

	if (!buffer_seek_read(&hdr, PECOFF_OPTIONAL_HDR_SIZEOFHEADERS_OFFSET)
	 || !buffer_get_u32le(&hdr, &info->pe_optional_header.size_of_headers))
		return false;

	/* Skip the checksum field when computing the digest.
	 * The offset of the checksum is the same for PE32 and PE32+ */
	hash_base = authenticode_skip(info->auth_info, hash_base,
			hdr_offset + PECOFF_OPTIONAL_HDR_CHECKSUM_OFFSET, 4);

	if (!buffer_seek_read(&hdr, data_dir_offset)
	 || !buffer_get_u32le(&hdr, &info->pe_optional_header.data_dir_count))
		return false;

	if (info->pe_optional_header.data_dir_count <= PECOFF_DATA_DIRECTORY_CERTTBL_INDEX) {
		error("PECOFF data directory too small - cannot find Certificate Table (expected at index %u)\n", PECOFF_DATA_DIRECTORY_CERTTBL_INDEX);
		return false;
	}

	info->data_dirs = calloc(info->pe_optional_header.data_dir_count, sizeof(info->data_dirs[0]));
	info->num_data_dirs = info->pe_optional_header.data_dir_count;

	for (i = 0; i < info->pe_optional_header.data_dir_count; ++i) {
		pecoff_image_datadir_t *de = info->data_dirs + i;

		if (!buffer_get_u32le(&hdr, &de->addr)
		 || !buffer_get_u32le(&hdr, &de->size))
			return false;
	}

	/* Exclude the data directory entry pointing to the certificate table */
	hash_base = authenticode_skip(info->auth_info, hash_base,
			hdr_offset + data_dir_offset + 4 + 8 * PECOFF_DATA_DIRECTORY_CERTTBL_INDEX, 8);

	authenticode_exclude_range(info->auth_info,
			info->data_dirs[PECOFF_DATA_DIRECTORY_CERTTBL_INDEX].addr,
			info->data_dirs[PECOFF_DATA_DIRECTORY_CERTTBL_INDEX].size);

	/* digest everything until the end of the PE headers, incl the section headers */
	authenticode_add_range(info->auth_info, hash_base, info->pe_optional_header.size_of_headers - hash_base);
	info->auth_info->hashed_bytes = info->pe_optional_header.size_of_headers;

	return true;
}

static bool
__pecoff_process_sections(buffer_t *in, pecoff_image_info_t *info)
{
	unsigned int tbl_offset = info->pe_hdr.section_table_offset;
	unsigned int num_sections = info->pe_hdr.num_sections;
	buffer_t hdr;
	unsigned int i;
	pecoff_section_t *sec;

	pe_debug("  Processing %u sections (table at offset %u)\n", num_sections, tbl_offset);

	/* Create a buffer that provides access to the PE header but not beyond */
	if (!buffer_seek_read(in, tbl_offset)
	 || !buffer_get_buffer(in, 40 * num_sections, &hdr))
		return false;

	info->num_sections = num_sections;
	info->section = calloc(num_sections, sizeof(info->section[0]));
	for (i = 0; i < num_sections; ++i) {
		pecoff_section_t *sec = info->section + i;

		if (!buffer_seek_read(&hdr, i * 40))
			return false;

		if (!buffer_get(&hdr, sec->name, 8)
		 || !buffer_get_u32le(&hdr, &sec->virtual.size)
		 || !buffer_get_u32le(&hdr, &sec->virtual.addr)
		 || !buffer_get_u32le(&hdr, &sec->raw.size)
		 || !buffer_get_u32le(&hdr, &sec->raw.addr))
			return false;

		pe_debug("  Section %-8s raw %7u at 0x%08x-0x%08x\n",
				sec->name, sec->raw.size, sec->raw.addr, sec->raw.addr + sec->raw.size);
	}

	/* We are supposed to sort the sections in ascending order, but we're not doing it here, we
	 * let authenticode_finalize() do it for us. */
	for (i = 0, sec = info->section; i < num_sections; ++i, ++sec) {
		if (sec->raw.size != 0) {
			authenticode_add_range(info->auth_info, sec->raw.addr, sec->raw.size);
			/* Note: even if we later omit (part of) this section because it overlaps
			 * a hole, we still account for these as "hashed_bytes" */
			info->auth_info->hashed_bytes += sec->raw.size;
		}
	}

	return true;
}

static inline void
__pecoff_show_header(pecoff_image_info_t *img)
{
	pe_debug("  PE header at 0x%x\n", img->pe_hdr.offset);
	pe_debug("  Architecture: %s\n", __pecoff_get_machine(img));
	pe_debug("  Number of sections: %d\n", img->pe_hdr.num_sections);
	pe_debug("  Symbol table position: 0x%08x\n", img->pe_hdr.symtab_offset);
	pe_debug("  Optional header size: %d\n", img->pe_hdr.optional_hdr_size);
}

static inline void
__pecoff_show_optional_header(pecoff_image_info_t *img)
{
	unsigned int i;

	switch (img->format) {
	case PECOFF_FORMAT_PE32:
		pe_debug("  PECOFF image format: PE32\n");
		break;

	case PECOFF_FORMAT_PE32_PLUS:
		pe_debug("  PECOFF image format: PE32+\n");
		break;

	default:
		pe_debug("  PECOFF image format: unknown\n");
		break;
	}

	pe_debug("  Size of headers: %d\n", img->pe_optional_header.size_of_headers);
	pe_debug("  Data dir entries: %d\n", img->pe_optional_header.data_dir_count);

	for (i = 0; i < img->num_data_dirs; ++i) {
		pecoff_image_datadir_t *de = img->data_dirs + i;

		if (de->size)
			pe_debug("  Data dir %d: %u bytes at %08x\n", i, de->size, de->addr);
	}
}

/*
 * Process the certificate table.
 * This code isn't used yet, and may go away again at some point.
 * The cert table contains one or more authenticode signatures, which is a PKCS7
 * signed blob of data. That blob is the asn1 encoded finger print of the binary.
 */
win_cert_t *
win_cert_alloc(int type, buffer_t *blob)
{
	win_cert_t *cert;

	cert = calloc(1, sizeof(*cert));
	cert->type = type;
	cert->blob = blob;

	return cert;
}

static buffer_t *
win_cert_get_signer(win_cert_t *cert)
{
	if (cert->type != WIN_CERT_TYPE_AUTH) {
		debug("Can't extract signer's certificate from a type %d cert\n", cert->type);
		return NULL;
	}

	debug("Trying to extract signer's certificate from Authenticode cert\n");
	return pkcs7_extract_signer(cert->blob);
}

void
win_cert_free(win_cert_t *cert)
{
	buffer_free(cert->blob);
	if (cert->signer_cert)
		buffer_free(cert->signer_cert);
}

cert_table_t *
cert_table_alloc(void)
{
	cert_table_t *result;

	result = calloc(1, sizeof(*result));
	return result;
}

void
cert_table_free(cert_table_t *cert_tbl)
{
	unsigned int i;

	for (i = 0; i < cert_tbl->count; ++i)
		win_cert_free(cert_tbl->cert[i]);

	cert_tbl->count = 0;
	free(cert_tbl);
}

static bool
__pecoff_process_certificate_table(buffer_t *in, pecoff_image_info_t *img, cert_table_t *cert_tbl)
{
	buffer_t cert_tbl_data;

	/* Set up the buffer to provide access to the certificate table but not beyond */
	if (!buffer_seek_read(in, img->data_dirs[PECOFF_DATA_DIRECTORY_CERTTBL_INDEX].addr)
	 || !buffer_get_buffer(in, img->data_dirs[PECOFF_DATA_DIRECTORY_CERTTBL_INDEX].size, &cert_tbl_data))
		return false;

	/* sections are padded out to multiples of 8, so9 the buffer may contain padding at the end */
	while (buffer_available(&cert_tbl_data) > 8) {
		uint32_t entry_size, blob_size;
		uint16_t cert_revision, cert_type;
		buffer_t *blob;
		unsigned int index;

		if (!buffer_get_u32le(&cert_tbl_data, &entry_size)
		 || !buffer_get_u16le(&cert_tbl_data, &cert_revision)
		 || !buffer_get_u16le(&cert_tbl_data, &cert_type)) {
			error("Cannot process certificate table; short buffer\n");
			return false;
		}

		if (cert_revision != 0x200) {
			error("Cannot process certificate table; unsupported certificate format rev %u.%u\n",
					cert_revision >> 8,
					cert_revision & 0xff);
			return false;
		}

		pe_debug("Certificate %u is a type %u certificate\n", cert_tbl->count, cert_type);
		if (cert_type != WIN_CERT_TYPE_X509 &&
		    cert_type != WIN_CERT_TYPE_AUTH) {
			error("Cannot process certificate table; unsupported certificate type %u\n", cert_type);
			return false;
		}

		if (cert_tbl->count >= MAX_CERTIFICATES) {
			error("Cannot process certificate table; too many cert blobs\n");
			return false;
		}
		index = cert_tbl->count++;

		/* The entry size covers the 8 bytes of decoration we parsed above */
		blob_size = entry_size - 8;

		blob = buffer_alloc_write(blob_size);
		if (!buffer_copy(&cert_tbl_data, blob_size, blob)) {
			error("Cannot process certificate table; no enough data for blob\n");
			buffer_free(blob);
			return false;
		}

		cert_tbl->cert[index] = win_cert_alloc(cert_type, blob);
	}

	debug("%s: returning %u cert blobs\n", __func__, cert_tbl->count);
	return true;
}

static bool
__pecoff_get_authenticode_ranges(buffer_t *in, authenticode_image_info_t *auth_info)
{
	pecoff_image_info_t img_info;

	memset(&img_info, 0, sizeof(img_info));
	img_info.auth_info = auth_info;

	pe_debug("Processing PE COFF image\n");
	if (!__pecoff_process_header(in, &img_info)) {
		error("PECOFF: error processing image header\n");
		return false;
	}

	__pecoff_show_header(&img_info);

	if (!__pecoff_process_optional_header(in, &img_info)) {
		error("PECOFF: error processing optional header of image file\n");
		return false;
	}

	__pecoff_show_optional_header(&img_info);

	if (!__pecoff_process_sections(in, &img_info)) {
		error("PECOFF: error processing section table of image file\n");
		return false;
	}

	if (auth_info->hashed_bytes < in->wpos) {
		unsigned int trailing = in->wpos - auth_info->hashed_bytes;

		authenticode_add_range(auth_info, auth_info->hashed_bytes, trailing);
		auth_info->hashed_bytes += trailing;
	}

	authenticode_set_range(auth_info, 0, auth_info->hashed_bytes);
	return true;
}

tpm_evdigest_t *
authenticode_get_digest(buffer_t *raw_data, digest_ctx_t *digest)
{
	authenticode_image_info_t auth_info;
	tpm_evdigest_t *md = NULL;

	memset(&auth_info, 0, sizeof(auth_info));
	if (__pecoff_get_authenticode_ranges(raw_data, &auth_info))
		md = authenticode_compute(&auth_info, raw_data, digest);
	return md;
}

cert_table_t *
authenticode_get_certificate_table(buffer_t *in)
{
	pecoff_image_info_t img_info;
	authenticode_image_info_t auth_info;
	cert_table_t *result = NULL;

	memset(&auth_info, 0, sizeof(auth_info));
	memset(&img_info, 0, sizeof(img_info));
	img_info.auth_info = &auth_info;

	if (!__pecoff_process_header(in, &img_info)
	 || !__pecoff_process_optional_header(in, &img_info)) {
		error("PECOFF: error processing image header\n");
		return NULL;
	}

	result = cert_table_alloc();
	if (!__pecoff_process_certificate_table(in, &img_info, result)) {
		cert_table_free(result);
		return NULL;
	}

	return result;
}

buffer_t *
authenticode_get_signer_from_buffer(buffer_t *in)
{
	cert_table_t *cert_tbl;
	unsigned int i;
	buffer_t *signer;

	cert_tbl = authenticode_get_certificate_table(in);
	if (cert_tbl == NULL) {
		error("failed to read certificate table\n");
		return NULL;
	}

	for (i = 0; i < cert_tbl->count; ++i) {
		win_cert_t *cert = cert_tbl->cert[i];

		signer = win_cert_get_signer(cert);
		if (signer != NULL)
			return signer;
	}

	error("unable to find a valid signer cert in certificate table\n");
	return NULL;
}

buffer_t *
authenticode_get_signer(const char *filename)
{
	buffer_t *buffer, *cert = NULL;

	debug("Extracting Authenticode signer using built-in PECOFF parser\n");
	if ((buffer = runtime_read_file(filename, 0)) != NULL) {
		cert = authenticode_get_signer_from_buffer(buffer);
		buffer_free(buffer);
	}

	return cert;
}

