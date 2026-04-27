#ifndef BYTHOS_ESP_PARSERS_H
#define BYTHOS_ESP_PARSERS_H

#include <stdbool.h>
#include <stddef.h>

bool bythos_esp_is_known_vendor(const char *name);
/* extracts 64-char hex hash from "sha256sum <file>" output line */
bool bythos_parse_sha256sum_line(const char *line, char *hash_out, size_t size);

#endif
