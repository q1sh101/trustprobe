#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "firmware_parsers.h"

static const char *const SECURE_BOOT_ENABLED_TEXT = "enabled";
static const char *const SECURE_BOOT_DISABLED_TEXT = "disabled";
static const char *const SECURE_BOOT_SETUP_MODE_TEXT = "Setup Mode";
static const char *const FWUPD_NO_UPDATES_TEXT = "No updates available";
static const char *const SBCTL_INSTALLED_LABEL = "Installed:";
static const char *const SBCTL_SETUP_MODE_LABEL = "Setup Mode:";
static const char *const SBCTL_SECURE_BOOT_LABEL = "Secure Boot:";
static const char *const SBCTL_OWNER_GUID_LABEL = "Owner GUID:";
static const char *const SBCTL_VENDOR_KEYS_LABEL = "Vendor Keys:";
static const char *const SBCTL_NOT_INSTALLED_TEXT = "not installed";
static const char *const SBCTL_INSTALLED_TEXT = "installed";
static const char *const SBCTL_ENABLED_TEXT = "Enabled";
static const char *const SBCTL_DISABLED_TEXT = "Disabled";

static char *skip_label_value(char *text) {
    char *sep = strchr(text, ':');
    if (sep == NULL) {
        return NULL;
    }

    sep++;
    while (*sep != '\0' && isspace((unsigned char)*sep)) {
        sep++;
    }

    return *sep == '\0' ? NULL : sep;
}

static void trim_trailing(char *text) {
    size_t len = strlen(text);
    while (len > 0 && isspace((unsigned char)text[len - 1])) {
        text[len - 1] = '\0';
        len--;
    }
}

size_t trustprobe_count_nonempty_lines(const char *text) {
    if (text == NULL) {
        return 0;
    }

    size_t count = 0;
    bool in_line = false;

    for (const char *p = text; *p != '\0'; p++) {
        if (*p == '\n' || *p == '\r') {
            if (in_line) {
                count++;
                in_line = false;
            }
            continue;
        }

        if (*p != ' ' && *p != '\t') {
            in_line = true;
        }
    }

    if (in_line) {
        count++;
    }

    return count;
}

bool trustprobe_extract_short_list_name(const char *text, char *buffer, size_t size) {
    if (text == NULL || buffer == NULL || size == 0) {
        return false;
    }

    buffer[0] = '\0';

    const char *line_end = strpbrk(text, "\r\n");
    size_t line_len = line_end == NULL ? strlen(text) : (size_t)(line_end - text);

    if (line_len == 0) {
        return false;
    }

    char line[512];
    if (line_len >= sizeof(line)) {
        line_len = sizeof(line) - 1;
    }

    memcpy(line, text, line_len);
    line[line_len] = '\0';

    char *name = strchr(line, ' ');
    if (name == NULL) {
        return false;
    }

    while (*name == ' ') {
        name++;
    }
    if (*name == '\0') {
        return false;
    }

    snprintf(buffer, size, "%s", name);
    return true;
}

trustprobe_secure_boot_status_t trustprobe_parse_secure_boot_state(const char *text) {
    if (text == NULL) {
        return TRUSTPROBE_SECURE_BOOT_UNKNOWN;
    }

    if (strstr(text, SECURE_BOOT_ENABLED_TEXT) != NULL) {
        return TRUSTPROBE_SECURE_BOOT_ENABLED;
    }
    if (strstr(text, SECURE_BOOT_DISABLED_TEXT) != NULL) {
        return TRUSTPROBE_SECURE_BOOT_DISABLED;
    }
    return TRUSTPROBE_SECURE_BOOT_UNKNOWN;
}

bool trustprobe_secure_boot_setup_mode(const char *text) {
    if (text == NULL) {
        return false;
    }

    return strstr(text, SECURE_BOOT_SETUP_MODE_TEXT) != NULL;
}

trustprobe_fwupd_updates_status_t trustprobe_parse_fwupd_updates(const char *text, int exit_status) {
    if (text == NULL) {
        return TRUSTPROBE_FWUPD_UPDATES_UNKNOWN;
    }

    if (strstr(text, FWUPD_NO_UPDATES_TEXT) != NULL) {
        return TRUSTPROBE_FWUPD_UPDATES_NONE;
    }
    if (exit_status == 0) {
        return TRUSTPROBE_FWUPD_UPDATES_AVAILABLE;
    }
    return TRUSTPROBE_FWUPD_UPDATES_UNKNOWN;
}

bool trustprobe_parse_sbctl_status(const char *text, trustprobe_sbctl_status_t *status) {
    if (text == NULL || status == NULL) {
        return false;
    }

    memset(status, 0, sizeof(*status));

    char line[256];
    const char *cursor = text;
    while (*cursor != '\0') {
        size_t line_len = strcspn(cursor, "\r\n");
        if (line_len >= sizeof(line)) {
            line_len = sizeof(line) - 1;
        }

        memcpy(line, cursor, line_len);
        line[line_len] = '\0';
        trim_trailing(line);

        char *value = skip_label_value(line);
        if (value != NULL) {
            if (strncmp(line, SBCTL_INSTALLED_LABEL, strlen(SBCTL_INSTALLED_LABEL)) == 0) {
                status->installed_known = true;
                if (strstr(value, SBCTL_NOT_INSTALLED_TEXT) != NULL) {
                    status->installed = false;
                } else if (strstr(value, SBCTL_INSTALLED_TEXT) != NULL) {
                    status->installed = true;
                } else {
                    status->installed_known = false;
                }
            } else if (strncmp(line, SBCTL_SETUP_MODE_LABEL, strlen(SBCTL_SETUP_MODE_LABEL)) == 0) {
                status->setup_mode_known = true;
                if (strstr(value, SBCTL_ENABLED_TEXT) != NULL) {
                    status->setup_mode_enabled = true;
                } else if (strstr(value, SBCTL_DISABLED_TEXT) != NULL) {
                    status->setup_mode_enabled = false;
                } else {
                    status->setup_mode_known = false;
                }
            } else if (strncmp(line, SBCTL_SECURE_BOOT_LABEL, strlen(SBCTL_SECURE_BOOT_LABEL)) == 0) {
                status->secure_boot_known = true;
                if (strstr(value, SBCTL_ENABLED_TEXT) != NULL) {
                    status->secure_boot_enabled = true;
                } else if (strstr(value, SBCTL_DISABLED_TEXT) != NULL) {
                    status->secure_boot_enabled = false;
                } else {
                    status->secure_boot_known = false;
                }
            } else if (strncmp(line, SBCTL_OWNER_GUID_LABEL, strlen(SBCTL_OWNER_GUID_LABEL)) == 0) {
                snprintf(status->owner_guid, sizeof(status->owner_guid), "%s", value);
                trim_trailing(status->owner_guid);
                status->owner_guid_present = status->owner_guid[0] != '\0';
            } else if (strncmp(line, SBCTL_VENDOR_KEYS_LABEL, strlen(SBCTL_VENDOR_KEYS_LABEL)) == 0) {
                snprintf(status->vendor_keys, sizeof(status->vendor_keys), "%s", value);
                trim_trailing(status->vendor_keys);
                status->vendor_keys_present = status->vendor_keys[0] != '\0';
            }
        }

        cursor += strcspn(cursor, "\r\n");
        while (*cursor == '\r' || *cursor == '\n') {
            cursor++;
        }
    }

    return status->installed_known || status->setup_mode_known || status->secure_boot_known || status->owner_guid_present;
}
