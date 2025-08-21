#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "cdecode.h"

/* 反查表：
 *  0..63 : 合法 Base64 值
 *   -2   : '=' 填充，表示结束
 *   -1   : 其他非法字符（包括非 Base64 以及 0x80..0xFF）
 * 空白（isspace）在解码时被跳过
 * '+' -> 62, '/' -> 63
 */
static const signed char b64_reverse_table[256] = {
        /* 0x00-0x0F */ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        /* 0x10-0x1F */ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        /* 0x20-0x2F */ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, 62,-1,-1,-1, 63,
        /* 0x30-0x3F */ 52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,
        /* 0x40-0x4F */ -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        /* 0x50-0x5F */ 15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        /* 0x60-0x6F */ -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        /* 0x70-0x7F */ 41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        /* 0x80-0x8F */ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        /* 0x90-0x9F */ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        /* 0xA0-0xAF */ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        /* 0xB0-0xBF */ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        /* 0xC0-0xCF */ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        /* 0xD0-0xDF */ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        /* 0xE0-0xEF */ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        /* 0xF0-0xFF */ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
};

void base64_init_decodestate(base64_decodestate* state_in) {
    if (!state_in) return;
    state_in->step = 0;
    state_in->plainchar = 0;
}

/* 流式解码实现：忽略空白，遇到 '='（-2）终止。返回写入的明文字节数。 */
int base64_decode_block(const char* code_in, const int length_in, char* plaintext_out, base64_decodestate* state_in) {
    int out_len = 0;
    int val = 0;
    int valb = -8;
    (void)state_in; /* 保留 API 一致性，当前未使用 */

    for (int i = 0; i < length_in; ++i) {
        unsigned char c = (unsigned char)code_in[i];
        if (isspace(c)) continue;
        signed char d = b64_reverse_table[c];
        if (d == -1) continue;          /* 跳过非 base64 字符 */
        if (d == -2) break;             /* '=' 填充：停止 */
        val = (val << 6) | d;
        valb += 6;
        if (valb >= 0) {
            plaintext_out[out_len++] = (char)((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    return out_len;
}

/* 一次性解码：调用上面的块解码，返回 malloc 的缓冲，*out_len 为实际字节数（不含 '\0'）。 */
char *b64_decode(const char *data, size_t len, size_t *out_len) {
    if (out_len) *out_len = 0;
    if (!data) return NULL;

    /* 输出最大长度保守估计 */
    size_t cap = (len * 3) / 4 + 3;
    char *out = (char *)malloc(cap + 1);
    if (!out) return NULL;

    base64_decodestate st;
    base64_init_decodestate(&st);
    int produced = base64_decode_block(data, (int)len, out, &st);
    if (produced < 0) {
        free(out);
        return NULL;
    }
    out[produced] = '\0'; /* 便于日志打印（不计入 out_len） */
    if (out_len) *out_len = (size_t)produced;
    return out;
}