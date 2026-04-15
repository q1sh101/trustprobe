#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "usbguard_rules.h"

static char *left_trim(char *text) {
    while (*text != '\0' && isspace((unsigned char)*text)) {
        text++;
    }
    return text;
}

static void strip_newline(char *text) {
    size_t len = strlen(text);
    while (len > 0 && (text[len - 1] == '\n' || text[len - 1] == '\r')) {
        text[len - 1] = '\0';
        len--;
    }
}

static bool starts_with(const char *text, const char *prefix) {
    return strncmp(text, prefix, strlen(prefix)) == 0;
}

bool trustprobe_usbguard_rules_analyze(const char *path, trustprobe_usbguard_rules_report_t *report) {
    if (path == NULL || report == NULL) {
        return false;
    }

    *report = (trustprobe_usbguard_rules_report_t){0};

    FILE *file = fopen(path, "r");
    if (file == NULL) {
        return false;
    }

    char line[4096];
    while (fgets(line, sizeof(line), file) != NULL) {
        strip_newline(line);
        char *text = left_trim(line);
        if (*text == '\0' || *text == '#') {
            continue;
        }

        report->rule_count++;

        if (!starts_with(text, "allow ")) {
            continue;
        }

        report->allow_count++;

        if (strstr(text, "id *:*") != NULL) {
            report->wildcard_allow_count++;
        }
        if (strstr(text, " hash ") == NULL) {
            report->allow_without_hash_count++;
        }
        if (strstr(text, " with-connect-type ") == NULL) {
            report->allow_without_connect_type_count++;
        }
        if (strstr(text, " via-port ") != NULL) {
            report->via_port_count++;
        }

        if (strstr(text, "with-connect-type \"hardwired\"") == NULL) {
            report->external_allow_count++;
            if (strstr(text, " via-port ") == NULL) {
                report->external_without_via_port_count++;
            }
        }
    }

    fclose(file);
    return true;
}
