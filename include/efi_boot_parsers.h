#ifndef TRUSTPROBE_EFI_BOOT_PARSERS_H
#define TRUSTPROBE_EFI_BOOT_PARSERS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TRUSTPROBE_EFI_BOOT_MAX_ENTRIES 32

typedef enum {
    TRUSTPROBE_EFI_BOOT_TYPE_UNKNOWN = 0,
    TRUSTPROBE_EFI_BOOT_TYPE_DISK,
    TRUSTPROBE_EFI_BOOT_TYPE_CD,
    TRUSTPROBE_EFI_BOOT_TYPE_USB,
    TRUSTPROBE_EFI_BOOT_TYPE_NETWORK,
} trustprobe_efi_boot_type_t;

typedef struct {
    uint16_t number;
    bool active;
    trustprobe_efi_boot_type_t type;
    char description[128];
} trustprobe_efi_boot_entry_t;

typedef struct {
    uint16_t order[TRUSTPROBE_EFI_BOOT_MAX_ENTRIES];
    size_t order_count;
} trustprobe_efi_boot_order_t;

bool trustprobe_parse_efi_boot_order(const unsigned char *data, size_t len,
                                     trustprobe_efi_boot_order_t *order);

bool trustprobe_parse_efi_boot_entry(const unsigned char *data, size_t len,
                                     uint16_t number,
                                     trustprobe_efi_boot_entry_t *entry);

bool trustprobe_parse_efi_boot_next(const unsigned char *data, size_t len,
                                    uint16_t *number);

/* Secure Boot signature database (db/dbx) payload classification */
typedef enum {
    TRUSTPROBE_EFI_SIGDB_NONEMPTY = 0,
    TRUSTPROBE_EFI_SIGDB_EMPTY,
    TRUSTPROBE_EFI_SIGDB_INVALID,
} trustprobe_efi_sigdb_status_t;

trustprobe_efi_sigdb_status_t trustprobe_classify_efi_sigdb(
    const unsigned char *data, size_t len);

size_t trustprobe_count_efi_sigdb_lists(const unsigned char *data, size_t len);

#endif
