#ifndef TRUSTPROBE_USBGUARD_RULES_H
#define TRUSTPROBE_USBGUARD_RULES_H

#include <stdbool.h>
#include <stddef.h>

typedef struct {
    size_t rule_count;
    size_t allow_count;
    size_t wildcard_allow_count;
    size_t allow_without_hash_count;
    size_t allow_without_connect_type_count;
    size_t external_allow_count;
    size_t external_without_via_port_count;
    size_t via_port_count;
} trustprobe_usbguard_rules_report_t;

bool trustprobe_usbguard_rules_analyze(const char *path, trustprobe_usbguard_rules_report_t *report);

#endif
