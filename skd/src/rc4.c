/*
 * $Id: rc4.c, the RC4 stream-cipher
 */

#include <string.h>
#include "rc4.h"

void xchg(unsigned char *a, unsigned char *b) {
	unsigned char	c = *a;
	*a = *b;
	*b = c;
}

void rc4_init (unsigned char *key, int len, rc4_ctx *ctx) {
	unsigned char	index1, index2;
	unsigned char	*state = ctx->state;
	unsigned char	i;
	
	i = 0;
	do {
		state[i] = i;
		i++;
	} while (i);

	ctx->x = ctx->y = 0;
	index1 = index2 = 0;
	do {
		index2 = key[index1] + state[i] + index2;
		xchg(&state[i], &state[index2]);
		index1++;
		if (index1 >= len)
			index1 = 0;
		i++;
	} while (i);
}

inline void	rc4 (unsigned char *data, int len, rc4_ctx *ctx) {
	unsigned char	*state = ctx->state;
	unsigned char	x = ctx->x;
	unsigned char	y = ctx->y;
	int	i;
	
	for (i = 0; i < len; i++) {
		unsigned char xor;

		x++;
		y = state[x] + y;
		xchg(&state[x], &state[y]);

		xor = state[x] + state[y];
		data[i] ^= state[xor];
	}

	ctx->x = x;
	ctx->y = y;
}

