#ifndef RC4_H
#define RC4_H

typedef struct {
	unsigned char state[256];
	unsigned char x, y;
} rc4_ctx;

void xchg(unsigned char *a, unsigned char *b);
void rc4_init (unsigned char *key, int len, rc4_ctx *ctx);
void rc4 (unsigned char *data, int len, rc4_ctx *ctx);

#endif
