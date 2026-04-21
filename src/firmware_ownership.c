#include <stdbool.h>
#include <stddef.h>

#include "firmware_ownership.h"
#include "firmware_parsers.h"
#include "runtime.h"

bool trustprobe_probe_mok_ownership(trustprobe_mok_ownership_t *ownership) {
    static const char *const mokutil_pk_argv[] = {"mokutil", "--pk", "--short", NULL};
    static const char *const mokutil_enrolled_argv[] = {"mokutil", "--list-enrolled", "--short", NULL};

    if (ownership == NULL) {
        return false;
    }

    *ownership = (trustprobe_mok_ownership_t){0};

    if (!trustprobe_command_exists("mokutil")) {
        return true;
    }

    ownership->available = true;

    char pk_buffer[1024] = {0};
    int pk_exit = -1;
    if (trustprobe_capture_argv_status(mokutil_pk_argv, pk_buffer, sizeof(pk_buffer), &pk_exit) && pk_exit == 0) {
        ownership->owner_readable = true;
        ownership->owner_parsed = trustprobe_extract_short_list_name(
            pk_buffer,
            ownership->owner,
            sizeof(ownership->owner)
        );
    }

    char mok_buffer[2048] = {0};
    int mok_exit = -1;
    if (trustprobe_capture_argv_status(mokutil_enrolled_argv, mok_buffer, sizeof(mok_buffer), &mok_exit) && mok_exit == 0) {
        ownership->enrollments_readable = true;
        ownership->enrollment_count = trustprobe_count_nonempty_lines(mok_buffer);
    }

    return true;
}
