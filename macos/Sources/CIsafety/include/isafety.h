#ifndef ISAFETY_H
#define ISAFETY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ABI v1. Blocking: run on a worker thread. Independent calls are thread-safe.
 * path: valid NUL-terminated UTF-8 backup directory.
 * password: borrowed bytes, never logged. NULL/0 means not supplied;
 * non-NULL/0 means an empty password. Maximum length: 1024 bytes.
 * Returns owned NUL-terminated JSON: a report or {schema_version,error:{code,message}}.
 * Call isafety_string_free exactly once. Never free() this pointer yourself.
 * Caller owns and is responsible for clearing its password buffer.
 */
char *isafety_scan_backup(const char *path, const uint8_t *password, size_t password_len);
void isafety_string_free(char *value);
/* Wipe a caller-owned writable byte buffer; does not free it. NULL is a no-op. */
void isafety_clear_bytes(uint8_t *value, size_t length);

#ifdef __cplusplus
}
#endif
#endif
