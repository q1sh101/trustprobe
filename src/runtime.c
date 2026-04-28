#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "runtime.h"

#define BYTHOS_CMD_TIMEOUT_SEC 10

static volatile sig_atomic_t bythos_alarm_fired = 0;

static void bythos_on_alarm(int sig) {
    (void)sig;
    bythos_alarm_fired = 1;
}

void bythos_to_lower_ascii(const char *src, char *dst, size_t dst_size) {
    if (src == NULL || dst == NULL || dst_size == 0) {
        return;
    }
    size_t i = 0;
    for (; src[i] != '\0' && i + 1 < dst_size; i++) {
        dst[i] = (char)tolower((unsigned char)src[i]);
    }
    dst[i] = '\0';
}

char *bythos_trim(char *text) {
    if (text == NULL) {
        return NULL;
    }

    while (*text != '\0' && isspace((unsigned char)*text)) {
        text++;
    }

    if (*text == '\0') {
        return text;
    }

    char *end = text + strlen(text) - 1;
    while (end > text && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }

    return text;
}

static void strip_inline_comment(char *text) {
    bool in_quotes = false;
    char quote = '\0';

    for (char *p = text; *p != '\0'; p++) {
        if (*p == '\\' && p[1] != '\0') {
            p++;
            continue;
        }

        if (*p == '"' || *p == '\'') {
            if (!in_quotes) {
                in_quotes = true;
                quote = *p;
            } else if (*p == quote) {
                in_quotes = false;
                quote = '\0';
            }
            continue;
        }

        if (!in_quotes && *p == '#') {
            *p = '\0';
            return;
        }
    }
}

static char *strip_matching_quotes(char *text) {
    size_t len = strlen(text);

    if (len >= 2 && ((text[0] == '"' && text[len - 1] == '"') || (text[0] == '\'' && text[len - 1] == '\''))) {
        text[len - 1] = '\0';
        return text + 1;
    }

    return text;
}

bool bythos_command_exists(const char *name) {
    if (name == NULL || *name == '\0') {
        return false;
    }

    const char *path = getenv("PATH");
    if (path == NULL || *path == '\0') {
        return false;
    }

    char *path_copy = strdup(path);
    if (path_copy == NULL) {
        return false;
    }

    bool found = false;
    char *saveptr = NULL;
    for (char *dir = strtok_r(path_copy, ":", &saveptr); dir != NULL; dir = strtok_r(NULL, ":", &saveptr)) {
        char candidate[PATH_MAX];
        if (snprintf(candidate, sizeof(candidate), "%s/%s", dir, name) >= (int)sizeof(candidate)) {
            continue;
        }
        if (access(candidate, X_OK) == 0) {
            found = true;
            break;
        }
    }

    free(path_copy);
    return found;
}

bool bythos_file_exists(const char *path) {
    if (path == NULL) {
        return false;
    }

    struct stat st;
    return stat(path, &st) == 0;
}

bool bythos_read_file_text(const char *path, char *buffer, size_t size) {
    if (path == NULL || buffer == NULL || size == 0) {
        return false;
    }

    FILE *file = fopen(path, "r");
    if (file == NULL) {
        return false;
    }

    size_t used = fread(buffer, 1, size - 1, file);
    if (ferror(file)) {
        fclose(file);
        return false;
    }

    buffer[used] = '\0';
    fclose(file);
    return true;
}

bool bythos_read_file_binary(const char *path, unsigned char *buffer, size_t size, size_t *bytes_read) {
    if (path == NULL || buffer == NULL || size == 0) {
        return false;
    }

    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        return false;
    }

    size_t n = fread(buffer, 1, size, file);
    if (ferror(file)) {
        fclose(file);
        return false;
    }

    fclose(file);
    if (bytes_read != NULL) {
        *bytes_read = n;
    }
    return true;
}

bool bythos_count_child_dirs(const char *path, size_t *count) {
    if (path == NULL) {
        return false;
    }

    DIR *dir = opendir(path);
    if (dir == NULL) {
        return false;
    }

    size_t used = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char candidate[PATH_MAX];
        struct stat st;

        if (snprintf(candidate, sizeof(candidate), "%s/%s", path, entry->d_name) >= (int)sizeof(candidate)) {
            continue;
        }

        if (stat(candidate, &st) == 0 && S_ISDIR(st.st_mode)) {
            used++;
        }
    }

    closedir(dir);

    if (count != NULL) {
        *count = used;
    }
    return true;
}

bool bythos_read_key_value(const char *path, const char *key, char *buffer, size_t size) {
    if (path == NULL || key == NULL || buffer == NULL || size == 0) {
        return false;
    }

    FILE *file = fopen(path, "r");
    if (file == NULL) {
        return false;
    }

    char line[1024];
    bool found = false;
    while (fgets(line, sizeof(line), file) != NULL) {
        char *text = bythos_trim(line);
        if (*text == '\0' || *text == '#') {
            continue;
        }

        char *sep = strchr(text, '=');
        if (sep == NULL) {
            continue;
        }

        *sep = '\0';
        char *lhs = bythos_trim(text);
        char *rhs = bythos_trim(sep + 1);
        strip_inline_comment(rhs);
        rhs = bythos_trim(rhs);
        rhs = strip_matching_quotes(rhs);
        if (strcmp(lhs, key) != 0) {
            continue;
        }

        snprintf(buffer, size, "%s", rhs);
        found = true;
        break;
    }

    fclose(file);
    return found;
}

bool bythos_capture_argv_status(const char *const argv[], char *buffer, size_t size, int *exit_status) {
    if (argv == NULL || argv[0] == NULL || buffer == NULL || size == 0) {
        return false;
    }

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        return false;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return false;
    }

    if (pid == 0) {
        close(pipefd[0]);

        if (dup2(pipefd[1], STDOUT_FILENO) < 0) {
            close(pipefd[1]);
            _exit(127);
        }
        if (dup2(pipefd[1], STDERR_FILENO) < 0) {
            close(pipefd[1]);
            _exit(127);
        }
        close(pipefd[1]);

        setenv("LC_ALL", "C", 1);
        execvp(argv[0], (char *const *)argv);
        _exit(errno == ENOENT ? 127 : 126);
    }

    close(pipefd[1]);

    struct sigaction sa = {0};
    struct sigaction old_sa;
    sa.sa_handler = bythos_on_alarm;
    sigaction(SIGALRM, &sa, &old_sa);
    bythos_alarm_fired = 0;
    alarm(BYTHOS_CMD_TIMEOUT_SEC);

    buffer[0] = '\0';
    size_t used = 0;
    char chunk[512];
    ssize_t count;
    while ((count = read(pipefd[0], chunk, sizeof(chunk))) > 0) {
        if (used + 1 < size) {
            size_t to_copy = (size_t)count;
            size_t remaining = size - used - 1;
            if (to_copy > remaining) {
                to_copy = remaining;
            }
            memcpy(buffer + used, chunk, to_copy);
            used += to_copy;
            buffer[used] = '\0';
        }
    }

    bool timed_out = bythos_alarm_fired;
    alarm(0);
    sigaction(SIGALRM, &old_sa, NULL);

    close(pipefd[0]);

    if (timed_out) {
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        return false;
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        return false;
    }
    if (!WIFEXITED(status)) {
        return false;
    }

    if (exit_status != NULL) {
        *exit_status = WEXITSTATUS(status);
    }

    return true;
}

int bythos_run_argv_quiet(const char *const argv[]) {
    if (argv == NULL || argv[0] == NULL) {
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        return -1;
    }

    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull < 0) {
            _exit(127);
        }

        if (dup2(devnull, STDOUT_FILENO) < 0) {
            close(devnull);
            _exit(127);
        }
        if (dup2(devnull, STDERR_FILENO) < 0) {
            close(devnull);
            _exit(127);
        }

        close(devnull);
        setenv("LC_ALL", "C", 1);
        execvp(argv[0], (char *const *)argv);
        _exit(errno == ENOENT ? 127 : 126);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        return -1;
    }
    if (!WIFEXITED(status)) {
        return -1;
    }

    return WEXITSTATUS(status);
}

bythos_service_state_t bythos_probe_systemd_service(const char *unit) {
    if (unit == NULL || *unit == '\0') {
        return BYTHOS_SERVICE_STATE_UNKNOWN;
    }

    if (!bythos_command_exists("systemctl")) {
        return BYTHOS_SERVICE_STATE_SYSTEMCTL_UNAVAILABLE;
    }

    const char *active_argv[] = {"systemctl", "is-active", "--quiet", unit, NULL};

    int active = bythos_run_argv_quiet(active_argv);
    if (active == 0) {
        return BYTHOS_SERVICE_STATE_ACTIVE;
    }
    if (active < 0) {
        return BYTHOS_SERVICE_STATE_UNKNOWN;
    }

    /* systemctl show exposes LoadState; pattern exit codes do not distinguish missing units. */
    const char *show_argv[] = {"systemctl", "show", "-p", "LoadState", "--value", "--no-pager", unit, NULL};
    char load_buf[64] = {0};
    int show_exit = -1;

    if (!bythos_capture_argv_status(show_argv, load_buf, sizeof(load_buf), &show_exit) || show_exit != 0) {
        return BYTHOS_SERVICE_STATE_UNKNOWN;
    }

    char *load_state = bythos_trim(load_buf);
    if (strcmp(load_state, "not-found") == 0) {
        return BYTHOS_SERVICE_STATE_MISSING;
    }

    return BYTHOS_SERVICE_STATE_INACTIVE;
}

const char *bythos_esp_efi_base(void) {
    static const char *cached = NULL;
    if (cached != NULL) {
        return cached;
    }
    static const char *const candidates[] = {"/boot/efi/EFI", "/efi/EFI"};
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        if (bythos_file_exists(candidates[i])) {
            cached = candidates[i];
            return cached;
        }
    }
    cached = candidates[0];
    return cached;
}
