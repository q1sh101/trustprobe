#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "assert_helpers.h"
#include "test_harness.h"
#include "firmware_ownership.h"

static void with_mock_mokutil(
    const char *script,
    void (*check)(trustprobe_mok_ownership_t *ownership)
) {
    char template[] = "./tmp-trustprobe-mokutil-XXXXXX";
    char script_path[PATH_MAX];
    char *dir = mkdtemp(template);
    if (dir == NULL) {
        fprintf(stderr, "firmware ownership failure: could not create temp dir\n");
        exit(1);
    }

    snprintf(script_path, sizeof(script_path), "%s/mokutil", dir);
    write_executable(script_path, script);

    const char *path = getenv("PATH");
    char *saved_path = path == NULL ? NULL : strdup(path);
    if (path != NULL && saved_path == NULL) {
        fprintf(stderr, "firmware ownership failure: could not save PATH\n");
        exit(1);
    }

    if (setenv("PATH", dir, 1) != 0) {
        fprintf(stderr, "firmware ownership failure: could not override PATH\n");
        free(saved_path);
        exit(1);
    }

    trustprobe_mok_ownership_t ownership = {0};
    assert_true("probe_mok_ownership", trustprobe_probe_mok_ownership(&ownership));
    check(&ownership);

    restore_path(saved_path);
    unlink(script_path);
    rmdir(dir);
}

static void assert_unavailable(trustprobe_mok_ownership_t *ownership) {
    assert_false("ownership_available_false", ownership->available);
    assert_false("ownership_owner_readable_false", ownership->owner_readable);
    assert_false("ownership_owner_parsed_false", ownership->owner_parsed);
    assert_false("ownership_enrollments_readable_false", ownership->enrollments_readable);
    assert_eq_sz("ownership_enrollment_count_zero", ownership->enrollment_count, 0);
}

static void assert_success(trustprobe_mok_ownership_t *ownership) {
    assert_true("ownership_available_true", ownership->available);
    assert_true("ownership_owner_readable_true", ownership->owner_readable);
    assert_true("ownership_owner_parsed_true", ownership->owner_parsed);
    assert_true("ownership_enrollments_readable_true", ownership->enrollments_readable);
    assert_true("ownership_owner_value", strcmp(ownership->owner, "Example Platform Certificate") == 0);
    assert_eq_sz("ownership_enrollment_count_two", ownership->enrollment_count, 2);
}

static void assert_partial(trustprobe_mok_ownership_t *ownership) {
    assert_true("ownership_partial_available_true", ownership->available);
    assert_true("ownership_partial_owner_readable_true", ownership->owner_readable);
    assert_false("ownership_partial_owner_parsed_false", ownership->owner_parsed);
    assert_false("ownership_partial_enrollments_readable_false", ownership->enrollments_readable);
    assert_eq_sz("ownership_partial_enrollment_count_zero", ownership->enrollment_count, 0);
}

int main(void) {
    trustprobe_mok_ownership_t ownership = {0};

    {
        char template[] = "./tmp-trustprobe-mokutil-empty-XXXXXX";
        char *dir = mkdtemp(template);
        if (dir == NULL) {
            fprintf(stderr, "firmware ownership failure: could not create empty PATH temp dir\n");
            return 1;
        }

        const char *path = getenv("PATH");
        char *saved_path = path == NULL ? NULL : strdup(path);
        if (path != NULL && saved_path == NULL) {
            fprintf(stderr, "firmware ownership failure: could not save PATH for empty PATH case\n");
            return 1;
        }

        if (setenv("PATH", dir, 1) != 0) {
            fprintf(stderr, "firmware ownership failure: could not set empty PATH dir\n");
            free(saved_path);
            return 1;
        }

        assert_true("probe_mok_ownership_unavailable", trustprobe_probe_mok_ownership(&ownership));
        assert_unavailable(&ownership);

        restore_path(saved_path);
        rmdir(dir);
    }

    with_mock_mokutil(
        "#!/bin/sh\n"
        "if [ \"$1\" = \"--pk\" ]; then\n"
        "  printf 'abcd123456 Example Platform Certificate\\n'\n"
        "  exit 0\n"
        "fi\n"
        "if [ \"$1\" = \"--list-enrolled\" ]; then\n"
        "  printf 'Key One\\n\\nKey Two\\n'\n"
        "  exit 0\n"
        "fi\n"
        "exit 1\n",
        assert_success
    );

    with_mock_mokutil(
        "#!/bin/sh\n"
        "if [ \"$1\" = \"--pk\" ]; then\n"
        "  printf 'UnparseableOwner\\n'\n"
        "  exit 0\n"
        "fi\n"
        "if [ \"$1\" = \"--list-enrolled\" ]; then\n"
        "  exit 1\n"
        "fi\n"
        "exit 1\n",
        assert_partial
    );

    printf("firmware ownership ok\n");
    return 0;
}
