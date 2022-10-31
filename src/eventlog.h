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
 */

#ifndef EVENTLOG_H
#define EVENTLOG_H

#include <stdbool.h>
#include "digest.h"
#include "util.h"

typedef struct tpm_event {
	struct tpm_event *	next;

	long			file_offset;
	struct tpm_parsed_event *__parsed;

	uint32_t		pcr_index;
	uint32_t		event_type;

	unsigned int		pcr_count;
	tpm_evdigest_t *	pcr_values;

	unsigned int		event_size;
	void *			event_data;
} tpm_event_t;

typedef void			tpm_event_bit_printer(const char *, ...);

enum {
	TPM2_EVENT_PREBOOT_CERT              = 0x00000000,
	TPM2_EVENT_POST_CODE                 = 0x00000001,
	TPM2_EVENT_UNUSED                    = 0x00000002,
	TPM2_EVENT_NO_ACTION                 = 0x00000003,
	TPM2_EVENT_SEPARATOR                 = 0x00000004,
	TPM2_EVENT_ACTION                    = 0x00000005,
	TPM2_EVENT_EVENT_TAG                 = 0x00000006,
	TPM2_EVENT_S_CRTM_CONTENTS           = 0x00000007,
	TPM2_EVENT_S_CRTM_VERSION            = 0x00000008,
	TPM2_EVENT_CPU_MICROCODE             = 0x00000009,
	TPM2_EVENT_PLATFORM_CONFIG_FLAGS     = 0x0000000A,
	TPM2_EVENT_TABLE_OF_DEVICES          = 0x0000000B,
	TPM2_EVENT_COMPACT_HASH              = 0x0000000C,
	TPM2_EVENT_IPL                       = 0x0000000D,
	TPM2_EVENT_IPL_PARTITION_DATA        = 0x0000000E,
	TPM2_EVENT_NONHOST_CODE              = 0x0000000F,
	TPM2_EVENT_NONHOST_CONFIG            = 0x00000010,
	TPM2_EVENT_NONHOST_INFO              = 0x00000011,
	TPM2_EVENT_OMIT_BOOT_DEVICE_EVENTS   = 0x00000012,

	TPM2_EFI_EVENT_BASE                  = 0x80000000,
	TPM2_EFI_VARIABLE_DRIVER_CONFIG      = 0x80000001,
	TPM2_EFI_VARIABLE_BOOT               = 0x80000002,
	TPM2_EFI_BOOT_SERVICES_APPLICATION   = 0x80000003,
	TPM2_EFI_BOOT_SERVICES_DRIVER        = 0x80000004,
	TPM2_EFI_RUNTIME_SERVICES_DRIVER     = 0x80000005,
	TPM2_EFI_GPT_EVENT                   = 0x80000006,
	TPM2_EFI_ACTION                      = 0x80000007,
	TPM2_EFI_PLATFORM_FIRMWARE_BLOB      = 0x80000008,
	TPM2_EFI_HANDOFF_TABLES              = 0x80000009,
	TPM2_EFI_PLATFORM_FIRMWARE_BLOB2     = 0x8000000A,
	TPM2_EFI_HANDOFF_TABLES2             = 0x8000000B,
	TPM2_EFI_VARIABLE_BOOT2              = 0x8000000C,
	TPM2_EFI_HCRTM_EVENT                 = 0x80000010,
	TPM2_EFI_VARIABLE_AUTHORITY          = 0x800000E0,
	TPM2_EFI_SPDM_FIRMWARE_BLOB          = 0x800000E1,
	TPM2_EFI_SPDM_FIRMWARE_CONFIG        = 0x800000E2,
};

enum {
	/* IPL subtypes for grub */
	GRUB_EVENT_COMMAND		     = 0x0001,
	GRUB_EVENT_FILE			     = 0x0002,
	GRUB_EVENT_KERNEL_CMDLINE	     = 0x0003,
	SHIM_EVENT_VARIABLE		     = 0x0004,
};

#define EFI_DEVICE_PATH_MAX		16

typedef struct efi_device_path {
	unsigned int		count;
	struct efi_device_path_item {
		unsigned char	type, subtype;
		uint16_t	len;
		void *		data;
	} entries[EFI_DEVICE_PATH_MAX];
} efi_device_path_t;

enum {
	TPM2_EFI_DEVPATH_TYPE_HARDWARE_DEVICE	= 0x01,
	TPM2_EFI_DEVPATH_TYPE_ACPI_DEVICE	= 0x02,
	TPM2_EFI_DEVPATH_TYPE_MESSAGING_DEVICE	= 0x03,
	TPM2_EFI_DEVPATH_TYPE_MEDIA_DEVICE	= 0x04,
	TPM2_EFI_DEVPATH_TYPE_BIOS_BOOT_DEVICE	= 0x05,
	TPM2_EFI_DEVPATH_TYPE_END		= 0x7f,
};

enum {
	TPM2_EFI_DEVPATH_HARDWARE_SUBTYPE_PCI		= 0x01,
	TPM2_EFI_DEVPATH_HARDWARE_SUBTYPE_PCCARD	= 0x02,
	TPM2_EFI_DEVPATH_HARDWARE_SUBTYPE_MEMORY_MAPPED	= 0x03,
	TPM2_EFI_DEVPATH_HARDWARE_SUBTYPE_VENDOR	= 0x04,
	TPM2_EFI_DEVPATH_HARDWARE_SUBTYPE_CONTROLLER	= 0x05,
	TPM2_EFI_DEVPATH_HARDWARE_SUBTYPE_BMC		= 0x06,
};

enum {
	TPM2_EFI_DEVPATH_ACPI_SUBTYPE_ACPI		= 0x01,
	TPM2_EFI_DEVPATH_ACPI_SUBTYPE_ACPI_EXT		= 0x02,
	TPM2_EFI_DEVPATH_ACPI_SUBTYPE_ACPI_ADR		= 0x03,
};

enum {
	TPM2_EFI_DEVPATH_MEDIA_SUBTYPE_HARDDRIVE	= 0x01,
	TPM2_EFI_DEVPATH_MEDIA_SUBTYPE_CDROM		= 0x02,
	TPM2_EFI_DEVPATH_MEDIA_SUBTYPE_VENDOR		= 0x03,
	TPM2_EFI_DEVPATH_MEDIA_SUBTYPE_FILE_PATH	= 0x04,
	TPM2_EFI_DEVPATH_MEDIA_SUBTYPE_MEDIA_PROTOCOL	= 0x05,
	TPM2_EFI_DEVPATH_MEDIA_SUBTYPE_PIWG_FIRMWARE	= 0x06,
	TPM2_EFI_DEVPATH_MEDIA_SUBTYPE_PIWG_FIRMWARE_VOLUME = 0x07,
	TPM2_EFI_DEVPATH_MEDIA_SUBTYPE_RELATIVE_OFFSET_RANGE = 0x08,
	TPM2_EFI_DEVPATH_MEDIA_SUBTYPE_RAMDISK		= 0x09,
};

enum {
	TPM2_EFI_DEVPATH_MESSAGING_SUBTYPE_ATAPI	= 0x01,
	TPM2_EFI_DEVPATH_MESSAGING_SUBTYPE_SCSI		= 0x02,
	TPM2_EFI_DEVPATH_MESSAGING_SUBTYPE_FIBRECHANNEL	= 0x03,
	TPM2_EFI_DEVPATH_MESSAGING_SUBTYPE_FIREWIRE	= 0x04,
	TPM2_EFI_DEVPATH_MESSAGING_SUBTYPE_USB		= 0x05,
	TPM2_EFI_DEVPATH_MESSAGING_SUBTYPE_I20		= 0x06,
	TPM2_EFI_DEVPATH_MESSAGING_SUBTYPE_INFINIBAND	= 0x09,
	TPM2_EFI_DEVPATH_MESSAGING_SUBTYPE_VENDOR	= 0x0A,
	TPM2_EFI_DEVPATH_MESSAGING_SUBTYPE_MACADDR	= 0x0B,
	TPM2_EFI_DEVPATH_MESSAGING_SUBTYPE_IPV4		= 0x0C,
	TPM2_EFI_DEVPATH_MESSAGING_SUBTYPE_IPV6		= 0x0D,
	TPM2_EFI_DEVPATH_MESSAGING_SUBTYPE_UART		= 0x0E,
	TPM2_EFI_DEVPATH_MESSAGING_SUBTYPE_USBCLASS	= 0x0F,
	TPM2_EFI_DEVPATH_MESSAGING_SUBTYPE_USBWWID	= 0x10,
	TPM2_EFI_DEVPATH_MESSAGING_SUBTYPE_DEVICE_LUN	= 0x11,
	TPM2_EFI_DEVPATH_MESSAGING_SUBTYPE_SATA		= 0x12,
	TPM2_EFI_DEVPATH_MESSAGING_SUBTYPE_ISCSI	= 0x13,
	TPM2_EFI_DEVPATH_MESSAGING_SUBTYPE_VLAN		= 0x14,
	TPM2_EFI_DEVPATH_MESSAGING_SUBTYPE_FIRECHANNEL_EX = 0x15,
	TPM2_EFI_DEVPATH_MESSAGING_SUBTYPE_SAS_EX	= 0x16,
	TPM2_EFI_DEVPATH_MESSAGING_SUBTYPE_NVME		= 0x17,
	TPM2_EFI_DEVPATH_MESSAGING_SUBTYPE_URI		= 0x18,
	TPM2_EFI_DEVPATH_MESSAGING_SUBTYPE_BT		= 0x1B,
	TPM2_EFI_DEVPATH_MESSAGING_SUBTYPE_WIFI		= 0x1C,
	TPM2_EFI_DEVPATH_MESSAGING_SUBTYPE_EMMC		= 0x1D,
};

/*
 * This structure is used when re-hashing all events in the event log.
 *
 * Apart from the desired hash algo, it records the boot partition we
 * identify while parsing BSA events
 */
typedef struct tpm_event_log_rehash_ctx {
	const tpm_algo_info_t *	algo;
	bool			use_pesign;		/* compute authenticode FP using external pesign application */
	char *			efi_partition;
} tpm_event_log_rehash_ctx_t;

#define GRUB_COMMAND_ARGV_MAX	32

/*
 * Parsed event types
 */
typedef struct tpm_parsed_event {
	unsigned int		event_type;
	unsigned int		event_subtype;		/* for grub command, grub file, which are encoded as IPL events */
	const char *		(*describe)(const struct tpm_parsed_event *);
	void			(*destroy)(struct tpm_parsed_event *);
	void			(*print)(struct tpm_parsed_event *, tpm_event_bit_printer *);
	struct buffer *		(*rebuild)(const struct tpm_parsed_event *, const void *raw_data, unsigned int raw_data_len);
	const tpm_evdigest_t *	(*rehash)(const tpm_event_t *, const struct tpm_parsed_event *, tpm_event_log_rehash_ctx_t *);

	union {
		struct efi_variable_event {
			unsigned char	variable_guid[16];
			char *		variable_name;
			unsigned int	len;
			void *		data;
		} efi_variable_event;

		struct efi_bsa_event {
			uint64_t	image_location;
			size_t		image_length;
			size_t		image_lt_address;

			efi_device_path_t device_path;

			/* extracted from device_path: */
			char *		efi_partition;
			char *		efi_application;
		} efi_bsa_event;

		/* for GRUB_COMMAND, GRUB_KERNEL_CMDLINE */
		struct grub_command_event {
			char *		string;
			char *		argv[GRUB_COMMAND_ARGV_MAX];
		} grub_command;

		struct grub_file_event {
			char *		device;
			char *		path;
		} grub_file;

		struct shim_event {
			char *		string;
			const char *	efi_variable;
		} shim_event;

		struct efi_gpt_event {
			char *		disk_device;
		} efi_gpt_event;
	};
} tpm_parsed_event_t;

typedef struct tpm_event_log_reader tpm_event_log_reader_t;

extern tpm_event_log_reader_t *	event_log_open(void);
extern void			event_log_close(tpm_event_log_reader_t *log);
extern tpm_event_t *		event_log_read_next(tpm_event_log_reader_t *log);
extern void			tpm_event_print(tpm_event_t *ev);
extern void			__tpm_event_print(tpm_event_t *ev, tpm_event_bit_printer *print_fn);
extern void			tpm_event_log_rehash_ctx_init(tpm_event_log_rehash_ctx_t *,
					const tpm_algo_info_t *);
extern void			tpm_event_log_rehash_ctx_destroy(tpm_event_log_rehash_ctx_t *);
extern tpm_parsed_event_t *	tpm_event_parse(tpm_event_t *ev);
extern const char *		tpm_event_type_to_string(unsigned int event_type);
extern const tpm_evdigest_t *	tpm_event_get_digest(const tpm_event_t *ev, const char *algo_name);
extern void			tpm_parsed_event_print(tpm_parsed_event_t *parsed,
					tpm_event_bit_printer *);
extern const char *		tpm_parsed_event_describe(tpm_parsed_event_t *parsed);
extern struct buffer *		tpm_parsed_event_rebuild(tpm_parsed_event_t *, const void *, unsigned int);
extern const tpm_evdigest_t *	tpm_parsed_event_rehash(const tpm_event_t *, const tpm_parsed_event_t *,
					tpm_event_log_rehash_ctx_t *);

struct buffer; /* fwd decl */

/* helper functions for parsing events */
extern bool			__tpm_event_parse_efi_variable(tpm_event_t *, tpm_parsed_event_t *, struct buffer *);
extern bool			__tpm_event_parse_efi_bsa(tpm_event_t *, tpm_parsed_event_t *, struct buffer *);
extern bool			__tpm_event_parse_efi_gpt(tpm_event_t *, tpm_parsed_event_t *, struct buffer *);
extern bool			__tpm_event_parse_efi_device_path(efi_device_path_t *, struct buffer *);
extern void			__tpm_event_efi_device_path_print(const efi_device_path_t *path,
					tpm_event_bit_printer *print_fn);
extern void			__tpm_event_efi_device_path_destroy(efi_device_path_t *path);
extern const char *		__tpm_event_efi_device_path_item_harddisk_uuid(const struct efi_device_path_item *);
extern const char *		__tpm_event_efi_device_path_item_file_path(const struct efi_device_path_item *);

extern const char *		tpm_efi_variable_event_extract_full_varname(const tpm_parsed_event_t *parsed);
extern const char *		tpm_event_decode_uuid(const unsigned char *data);

extern bool			shim_variable_name_valid(const char *name);
extern const char *		shim_variable_get_rtname(const char *name);
extern const char *		shim_variable_get_full_rtname(const char *name);

#endif /* EVENTLOG_H */
