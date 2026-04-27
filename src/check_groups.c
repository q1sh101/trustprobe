#include <stddef.h>

#include "checks.h"
#include "checks_internal.h"
#include "output.h"

#define SUBGROUP_REMAINING(sg) \
    (BYTHOS_MAX_SUBGROUP_RESULTS - (sg)->result_count)
#define SUBGROUP_TAIL(sg) \
    ((sg)->results + (sg)->result_count)

typedef size_t (*subgroup_check_fn)(check_result_t *, size_t);

typedef struct {
    const char *name;
    subgroup_check_fn fns[4];
} subgroup_def_t;

static void subgroup_init(check_subgroup_t *sg, const char *name) {
    sg->name = name;
    sg->result_count = 0;
    sg->summary = (posture_summary_t){0};
}

static void subgroup_finalize(check_subgroup_t *sg) {
    for (size_t i = 0; i < sg->result_count; i++) {
        bythos_summary_add(&sg->summary, &sg->results[i]);
    }
}

static size_t run_subgroups(const subgroup_def_t *defs,
                            check_subgroup_t *subgroups,
                            size_t max_subgroups) {
    if (subgroups == NULL || max_subgroups == 0) return 0;
    size_t used = 0;
    for (size_t i = 0; defs[i].name != NULL && used < max_subgroups; i++) {
        check_subgroup_t *sg = &subgroups[used++];
        subgroup_init(sg, defs[i].name);
        for (size_t j = 0; defs[i].fns[j] != NULL; j++) {
            sg->result_count += defs[i].fns[j](
                SUBGROUP_TAIL(sg), SUBGROUP_REMAINING(sg));
        }
        subgroup_finalize(sg);
    }
    return used;
}

static const subgroup_def_t physical_subgroups[] = {
    {"usbguard",       {bythos_check_usbguard, bythos_check_usbguard_policy, NULL}},
    {"desktop usb",    {bythos_check_desktop_usb, NULL}},
    {"iommu",          {bythos_check_iommu, NULL}},
    {"thunderbolt",    {bythos_check_bolt, NULL}},
    {"bluetooth",      {bythos_check_bluetooth, NULL}},
    {"platform debug", {bythos_check_dci, NULL}},
    {"serial console", {bythos_check_serial_console, NULL}},
    {NULL, {NULL}},
};

static const subgroup_def_t firmware_subgroups[] = {
    {"efi",               {bythos_check_efi, NULL}},
    {"secure boot",       {bythos_check_sbctl, bythos_check_secureboot, NULL}},
    {"boot chain",        {bythos_check_bios_boot, bythos_check_boot_chain, NULL}},
    {"esp",               {bythos_check_esp_posture, NULL}},
    {"tpm",               {bythos_check_tpm, NULL}},
    {"luks",              {bythos_check_luks, NULL}},
    {"platform firmware", {bythos_check_bios_cntl, bythos_check_me_version, NULL}},
    {"microcode",         {bythos_check_microcode, NULL}},
    {"fwupd",             {bythos_check_fwupd, NULL}},
    {NULL, {NULL}},
};

size_t bythos_check_physical(check_subgroup_t *subgroups, size_t max_subgroups) {
    return run_subgroups(physical_subgroups, subgroups, max_subgroups);
}

size_t bythos_check_firmware(check_subgroup_t *subgroups, size_t max_subgroups) {
    return run_subgroups(firmware_subgroups, subgroups, max_subgroups);
}
