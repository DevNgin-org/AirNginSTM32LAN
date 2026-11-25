#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

void airngin_secure_zero(void *data, size_t length);
int lan_b64_decode(uint8_t *out, size_t capacity, size_t *written, const uint8_t *text, size_t length);
bool lan_gcm(bool encrypt, const uint8_t key[32], const uint8_t nonce[12],
             const uint8_t *input, size_t size, uint8_t *output, uint8_t tag[16]);
