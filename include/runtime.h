#ifndef TRUSTPROBE_RUNTIME_H
#define TRUSTPROBE_RUNTIME_H

#include <stdbool.h>
#include <stddef.h>

typedef enum {
    TRUSTPROBE_SERVICE_STATE_UNKNOWN = 0,
    TRUSTPROBE_SERVICE_STATE_SYSTEMCTL_UNAVAILABLE,
    TRUSTPROBE_SERVICE_STATE_ACTIVE,
    TRUSTPROBE_SERVICE_STATE_INACTIVE,
    TRUSTPROBE_SERVICE_STATE_MISSING,
} trustprobe_service_state_t;

char *trustprobe_trim(char *text);
bool trustprobe_command_exists(const char *name);
bool trustprobe_file_exists(const char *path);
bool trustprobe_read_file_text(const char *path, char *buffer, size_t size);
bool trustprobe_read_file_binary(const char *path, unsigned char *buffer, size_t size, size_t *bytes_read);
bool trustprobe_count_child_dirs(const char *path, size_t *count);
bool trustprobe_read_key_value(const char *path, const char *key, char *buffer, size_t size);
bool trustprobe_capture_argv_status(const char *const argv[], char *buffer, size_t size, int *exit_status);
int trustprobe_run_argv_quiet(const char *const argv[]);
trustprobe_service_state_t trustprobe_probe_systemd_service(const char *unit);

#endif
