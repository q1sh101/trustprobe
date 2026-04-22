#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "efi_boot_parsers.h"

#define EFI_VAR_ATTR_SIZE 4
#define EFI_DP_END_TYPE 0x7F
#define EFI_DP_END_SUBTYPE 0xFF
#define EFI_DP_MSG_TYPE 0x03
#define EFI_DP_MEDIA_TYPE 0x04
#define EFI_DP_BBS_TYPE 0x05

#define EFI_DP_MSG_USB 0x05
#define EFI_DP_MSG_USB_CLASS 0x0F
#define EFI_DP_MSG_USB_WWID 0x10
#define EFI_DP_MSG_IPV4 0x0C
#define EFI_DP_MSG_IPV6 0x0D
#define EFI_DP_MSG_INFINIBAND 0x09
#define EFI_DP_MSG_MAC 0x0B
#define EFI_DP_MSG_URI 0x18

#define EFI_DP_MEDIA_HD 0x01
#define EFI_DP_MEDIA_CDROM 0x02
#define EFI_DP_MEDIA_FILEPATH 0x04

#define EFI_DP_BBS_BBS 0x01

#define BBS_TYPE_HD 0x02
#define BBS_TYPE_CD 0x03
#define BBS_TYPE_USB 0x05
#define BBS_TYPE_NETWORK 0x06
#define BBS_TYPE_BEV 0x80

static uint16_t read_le16(const unsigned char *p) {
    return (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t read_le32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void utf16le_to_ascii(const unsigned char *src, size_t src_bytes,
                             char *dst, size_t dst_size) {
    size_t di = 0;
    for (size_t si = 0; si + 1 < src_bytes && di + 1 < dst_size; si += 2) {
        uint16_t code = read_le16(src + si);
        if (code == 0) {
            break;
        }
        dst[di++] = (code < 128) ? (char)code : '?';
    }
    dst[di] = '\0';
}

static void to_lower_ascii(const char *src, char *dst, size_t dst_size) {
    size_t i = 0;
    for (; src[i] != '\0' && i + 1 < dst_size; i++) {
        dst[i] = (char)tolower((unsigned char)src[i]);
    }
    dst[i] = '\0';
}

static trustprobe_efi_boot_type_t classify_device_path(const unsigned char *dp,
                                                        size_t dp_len) {
    size_t offset = 0;

    while (offset + 4 <= dp_len) {
        unsigned char type = dp[offset];
        unsigned char subtype = dp[offset + 1];
        uint16_t node_len = read_le16(dp + offset + 2);

        if (node_len < 4) {
            break;
        }

        if (type == EFI_DP_END_TYPE && subtype == EFI_DP_END_SUBTYPE) {
            break;
        }

        if (type == EFI_DP_BBS_TYPE && subtype == EFI_DP_BBS_BBS) {
            if (offset + 6 <= dp_len) {
                uint16_t bbs_type = read_le16(dp + offset + 4);
                switch (bbs_type) {
                    case BBS_TYPE_HD:
                        return TRUSTPROBE_EFI_BOOT_TYPE_DISK;
                    case BBS_TYPE_CD:
                        return TRUSTPROBE_EFI_BOOT_TYPE_CD;
                    case BBS_TYPE_USB:
                    case BBS_TYPE_BEV:
                        return TRUSTPROBE_EFI_BOOT_TYPE_USB;
                    case BBS_TYPE_NETWORK:
                        return TRUSTPROBE_EFI_BOOT_TYPE_NETWORK;
                    default:
                        break;
                }
            }
        }

        if (type == EFI_DP_MSG_TYPE) {
            switch (subtype) {
                case EFI_DP_MSG_USB:
                case EFI_DP_MSG_USB_CLASS:
                case EFI_DP_MSG_USB_WWID:
                    return TRUSTPROBE_EFI_BOOT_TYPE_USB;
                case EFI_DP_MSG_IPV4:
                case EFI_DP_MSG_IPV6:
                case EFI_DP_MSG_INFINIBAND:
                case EFI_DP_MSG_MAC:
                case EFI_DP_MSG_URI:
                    return TRUSTPROBE_EFI_BOOT_TYPE_NETWORK;
                default:
                    break;
            }
        }

        if (type == EFI_DP_MEDIA_TYPE) {
            switch (subtype) {
                case EFI_DP_MEDIA_HD:
                case EFI_DP_MEDIA_FILEPATH:
                    return TRUSTPROBE_EFI_BOOT_TYPE_DISK;
                case EFI_DP_MEDIA_CDROM:
                    return TRUSTPROBE_EFI_BOOT_TYPE_CD;
                default:
                    break;
            }
        }

        offset += node_len;
    }

    return TRUSTPROBE_EFI_BOOT_TYPE_UNKNOWN;
}

static trustprobe_efi_boot_type_t classify_description(const char *desc) {
    char lower[128];
    to_lower_ascii(desc, lower, sizeof(lower));

    if (strstr(lower, "usb") != NULL || strstr(lower, "removable") != NULL) {
        return TRUSTPROBE_EFI_BOOT_TYPE_USB;
    }
    if (strstr(lower, "network") != NULL || strstr(lower, "pxe") != NULL ||
        strstr(lower, "ipv4") != NULL || strstr(lower, "ipv6") != NULL ||
        strstr(lower, "lan") != NULL) {
        return TRUSTPROBE_EFI_BOOT_TYPE_NETWORK;
    }
    if (strstr(lower, "cd") != NULL || strstr(lower, "dvd") != NULL) {
        return TRUSTPROBE_EFI_BOOT_TYPE_CD;
    }

    return TRUSTPROBE_EFI_BOOT_TYPE_UNKNOWN;
}

bool trustprobe_parse_efi_boot_order(const unsigned char *data, size_t len,
                                     trustprobe_efi_boot_order_t *order) {
    if (order == NULL) {
        return false;
    }

    *order = (trustprobe_efi_boot_order_t){0};

    if (data == NULL || len < 6) {
        return false;
    }

    const unsigned char *payload = data + EFI_VAR_ATTR_SIZE;
    size_t payload_len = len - EFI_VAR_ATTR_SIZE;
    size_t count = payload_len / 2;

    if (count > TRUSTPROBE_EFI_BOOT_MAX_ENTRIES) {
        count = TRUSTPROBE_EFI_BOOT_MAX_ENTRIES;
    }

    for (size_t i = 0; i < count; i++) {
        order->order[i] = read_le16(payload + i * 2);
    }

    order->order_count = count;
    return true;
}

bool trustprobe_parse_efi_boot_entry(const unsigned char *data, size_t len,
                                     uint16_t number,
                                     trustprobe_efi_boot_entry_t *entry) {
    if (entry == NULL) {
        return false;
    }

    *entry = (trustprobe_efi_boot_entry_t){0};
    entry->number = number;

    /* Boot#### must contain attributes, FilePathListLength, and a UTF-16 terminator. */
    if (data == NULL || len < 12) {
        return false;
    }

    const unsigned char *p = data + EFI_VAR_ATTR_SIZE;
    size_t remaining = len - EFI_VAR_ATTR_SIZE;

    uint32_t load_attrs = read_le32(p);
    entry->active = (load_attrs & 0x01) != 0;

    uint16_t fp_list_len = read_le16(p + 4);

    /* Load option text is UTF-16LE before the device path list. */
    const unsigned char *desc_start = p + 6;
    size_t desc_bytes = remaining - 6;

    size_t desc_end = 0;
    for (size_t i = 0; i + 1 < desc_bytes; i += 2) {
        if (desc_start[i] == 0 && desc_start[i + 1] == 0) {
            desc_end = i;
            break;
        }
        desc_end = i + 2;
    }

    utf16le_to_ascii(desc_start, desc_end, entry->description,
                     sizeof(entry->description));

    size_t dp_offset = 6 + desc_end + 2;
    if (dp_offset < remaining && fp_list_len > 0) {
        size_t dp_avail = remaining - dp_offset;
        if (dp_avail > fp_list_len) {
            dp_avail = fp_list_len;
        }
        entry->type = classify_device_path(p + dp_offset, dp_avail);
    }

    if (entry->type == TRUSTPROBE_EFI_BOOT_TYPE_UNKNOWN) {
        entry->type = classify_description(entry->description);
    }

    return true;
}

bool trustprobe_parse_efi_boot_next(const unsigned char *data, size_t len,
                                    uint16_t *number) {
    /* BootNext is EFI attributes plus one little-endian boot entry number. */
    if (data == NULL || number == NULL || len < EFI_VAR_ATTR_SIZE + 2) {
        return false;
    }

    *number = read_le16(data + EFI_VAR_ATTR_SIZE);
    return true;
}

trustprobe_efi_sigdb_status_t trustprobe_classify_efi_sigdb(
    const unsigned char *data, size_t len) {
    /* db/dbx are EFI attributes followed by the signature-list payload. */
    if (data == NULL || len < EFI_VAR_ATTR_SIZE) {
        return TRUSTPROBE_EFI_SIGDB_INVALID;
    }

    if (len == EFI_VAR_ATTR_SIZE) {
        return TRUSTPROBE_EFI_SIGDB_EMPTY;
    }

    return TRUSTPROBE_EFI_SIGDB_NONEMPTY;
}
