#ifndef BYTHOS_RUNTIME_H
#define BYTHOS_RUNTIME_H

#include <stdbool.h>
#include <stddef.h>

typedef enum {
    BYTHOS_SERVICE_STATE_UNKNOWN = 0,
    BYTHOS_SERVICE_STATE_SYSTEMCTL_UNAVAILABLE,
    BYTHOS_SERVICE_STATE_ACTIVE,
    BYTHOS_SERVICE_STATE_INACTIVE,
    BYTHOS_SERVICE_STATE_MISSING,
} bythos_service_state_t;

char *bythos_trim(char *text);
bool bythos_command_exists(const char *name);
bool bythos_file_exists(const char *path);
bool bythos_read_file_text(const char *path, char *buffer, size_t size);
bool bythos_read_file_binary(const char *path, unsigned char *buffer, size_t size, size_t *bytes_read);
bool bythos_count_child_dirs(const char *path, size_t *count);
bool bythos_read_key_value(const char *path, const char *key, char *buffer, size_t size);
bool bythos_capture_argv_status(const char *const argv[], char *buffer, size_t size, int *exit_status);
int bythos_run_argv_quiet(const char *const argv[]);
bythos_service_state_t bythos_probe_systemd_service(const char *unit);

#endif
