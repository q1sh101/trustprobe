#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "assert_helpers.h"
#include "test_harness.h"
#include "runtime.h"

static void assert_state(const char *name, trustprobe_service_state_t want, trustprobe_service_state_t got) {
    if (want != got) {
        fprintf(stderr, "runtime capture failure: %s expected state %d, got %d\n", name, (int)want, (int)got);
        exit(1);
    }
}

static void assert_service_probe_with_script(
    const char *name,
    const char *script,
    trustprobe_service_state_t expected
) {
    char template[] = "./tmp-trustprobe-runtime-XXXXXX";
    char script_path[PATH_MAX];
    char *dir = mkdtemp(template);
    if (dir == NULL) {
        fprintf(stderr, "runtime capture failure: could not create temp dir for %s\n", name);
        exit(1);
    }

    snprintf(script_path, sizeof(script_path), "%s/systemctl", dir);
    write_executable(script_path, script);

    const char *path = getenv("PATH");
    char *saved_path = path == NULL ? NULL : strdup(path);
    if (path != NULL && saved_path == NULL) {
        fprintf(stderr, "runtime capture failure: could not save PATH\n");
        exit(1);
    }

    if (setenv("PATH", dir, 1) != 0) {
        fprintf(stderr, "runtime capture failure: could not override PATH\n");
        free(saved_path);
        exit(1);
    }

    trustprobe_service_state_t got = trustprobe_probe_systemd_service("mock.service");
    restore_path(saved_path);

    unlink(script_path);
    rmdir(dir);

    assert_state(name, expected, got);
}

int main(void) {
    static char payload[131072];
    char buffer[64] = {0};
    char value[64] = {0};
    int exit_status = -1;

    memset(payload, 'A', sizeof(payload) - 1);
    payload[sizeof(payload) - 1] = '\0';

    const char *const argv[] = {"/usr/bin/printf", "%s", payload, NULL};

    assert_true(
        "capture_large_output",
        trustprobe_capture_argv_status(argv, buffer, sizeof(buffer), &exit_status)
    );
    assert_eq_int("capture_large_output_exit_status", exit_status, 0);
    assert_eq_int("capture_large_output_truncated_length", (int)strlen(buffer), (int)sizeof(buffer) - 1);

    for (size_t i = 0; i < sizeof(buffer) - 1; i++) {
        if (buffer[i] != 'A') {
            fprintf(stderr, "runtime capture failure: unexpected byte at %zu\n", i);
            return 1;
        }
    }

    assert_true(
        "read_key_value_quoted_false",
        trustprobe_read_key_value("tests/fixtures/runtime/key_values.conf", "usb-protection", value, sizeof(value))
    );
    assert_true("read_key_value_quoted_false_value", strcmp(value, "false") == 0);

    assert_true(
        "read_key_value_single_quoted_true",
        trustprobe_read_key_value("tests/fixtures/runtime/key_values.conf", "autorun-never", value, sizeof(value))
    );
    assert_true("read_key_value_single_quoted_true_value", strcmp(value, "true") == 0);

    assert_true(
        "read_key_value_plain_true",
        trustprobe_read_key_value("tests/fixtures/runtime/key_values.conf", "Enabled", value, sizeof(value))
    );
    assert_true("read_key_value_plain_true_value", strcmp(value, "true") == 0);

    /* reject a NULL path before fopen() gets a chance to crash */
    assert_false("read_file_text_null",
        trustprobe_read_file_text(NULL, buffer, sizeof(buffer)));
    assert_true("trim_null", trustprobe_trim(NULL) == NULL);

    {
        char template[] = "./tmp-trustprobe-runtime-empty-XXXXXX";
        char *dir = mkdtemp(template);
        if (dir == NULL) {
            fprintf(stderr, "runtime capture failure: could not create temp dir for empty PATH\n");
            return 1;
        }

        const char *path = getenv("PATH");
        char *saved_path = path == NULL ? NULL : strdup(path);
        if (path != NULL && saved_path == NULL) {
            fprintf(stderr, "runtime capture failure: could not save PATH for empty PATH test\n");
            return 1;
        }

        if (setenv("PATH", dir, 1) != 0) {
            fprintf(stderr, "runtime capture failure: could not set empty PATH dir\n");
            free(saved_path);
            return 1;
        }

        assert_state(
            "service_probe_systemctl_unavailable",
            TRUSTPROBE_SERVICE_STATE_SYSTEMCTL_UNAVAILABLE,
            trustprobe_probe_systemd_service("mock.service")
        );

        restore_path(saved_path);
        rmdir(dir);
    }

    assert_service_probe_with_script(
        "service_probe_active",
        "#!/bin/sh\n"
        "if [ \"$1\" = \"is-active\" ]; then exit 0; fi\n"
        "if [ \"$1\" = \"show\" ]; then printf 'loaded\\n'; exit 0; fi\n"
        "exit 2\n",
        TRUSTPROBE_SERVICE_STATE_ACTIVE
    );
    assert_service_probe_with_script(
        "service_probe_inactive",
        "#!/bin/sh\n"
        "if [ \"$1\" = \"is-active\" ]; then exit 3; fi\n"
        "if [ \"$1\" = \"show\" ]; then printf 'loaded\\n'; exit 0; fi\n"
        "exit 2\n",
        TRUSTPROBE_SERVICE_STATE_INACTIVE
    );
    assert_service_probe_with_script(
        "service_probe_missing",
        "#!/bin/sh\n"
        "if [ \"$1\" = \"is-active\" ]; then exit 3; fi\n"
        "if [ \"$1\" = \"show\" ]; then printf 'not-found\\n'; exit 0; fi\n"
        "exit 2\n",
        TRUSTPROBE_SERVICE_STATE_MISSING
    );
    assert_service_probe_with_script(
        "service_probe_unknown",
        "#!/bin/sh\n"
        "kill -9 $$\n",
        TRUSTPROBE_SERVICE_STATE_UNKNOWN
    );

    printf("runtime capture ok\n");
    return 0;
}
