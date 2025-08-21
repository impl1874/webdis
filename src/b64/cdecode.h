#ifndef CDECODE_H
#define CDECODE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int step;
    char plainchar;
} base64_decodestate;

void base64_init_decodestate(base64_decodestate* state_in);
int  base64_decode_block(const char* code_in, const int length_in,
                         char* plaintext_out, base64_decodestate* state_in);

char *b64_decode(const char *data, size_t len, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* CDECODE_H */