// http://www.practicalcryptography.com/hashes/md5-hash/
// https://cse.unl.edu/~ssamal/crypto/genhash.php
// https://www.rapidtables.com/convert/number/index.html
// https://www.scribd.com/doc/35954574/MD5-With-Example

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

typedef unsigned char UCHAR;
typedef unsigned long int UINT4;

#define pow2_32 (UINT4)pow(2,32)

#define UINT4_WORD(word) ({ \
    UINT4 *pword; \
    pword = (UINT4)word; \
    *pword; \
})

#define F(x, y, z) ((x & y) | (~x & z))
#define G(x, y, z) ((x & z) | (y & ~z))
#define H(x, y, z) (x ^ y ^ z)
#define I(x, y, z) (y ^ (x | ~z))

#define ROTATE_LEFT(x, n) ((x << n) | (x >> (32-n)))

#define REVERSE_BITS(n) ( ((n>>24) & 0xff) | ((n<<8) & 0xff0000) | ((n>>8) & 0xff00) | ((n<<24) & 0xff000000) )

#define ROTATE_ABCD(abcd) ({\
    int temp = abcd[3]; \
    abcd[3] = abcd[2]; \
    abcd[2] = abcd[1]; \
    abcd[1] = abcd[0]; \
    abcd[0] = temp; \
})

#define MD5_OPERATION(f, abcd, w, t, s) ({ \
    UINT4 X; \
    if (f == 0) X = F(abcd[1], abcd[2], abcd[3]); \
    if (f == 1) X = G(abcd[1], abcd[2], abcd[3]); \
    if (f == 2) X = H(abcd[1], abcd[2], abcd[3]); \
    if (f == 3) X = I(abcd[1], abcd[2], abcd[3]); \
    abcd[0] = (abcd[0] + X + w + t) % pow2_32; \
    abcd[0] = ROTATE_LEFT(abcd[0], s); \
    abcd[0] = (abcd[0] + abcd[1]) % pow2_32; \
})


char *md5(UCHAR *str) {
	//***** Decleartions *****//
	short i, j, k, l, n, t, s, q, r, w;
	static short x[] = {1, 5, 3, 7};
	static short y[] = {0, 1, 5, 0};
	static short shift[] = {7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21};
	UINT4 abcd[] = {1732584193, 4023233417, 2562383102, 271733878};
	UINT4 ABCD[] = {0, 0, 0, 0};
	UINT4 T[64], *pword;
	UCHAR *len, *md5[4];
	UCHAR *padded_str = (UCHAR *)malloc(1000);
	UCHAR *word = (UCHAR *)malloc(10);
	UCHAR *MD5 = (UCHAR *)malloc(40);

	//***** Padding *****//
	i = -1;
	while(str[++i] != 0) padded_str[i] = str[i]; //append string to new string
	padded_str[i++] = 128; // append 128 ie, binary [10000000] to new str


	//***** Create T array *****//
	i = -1;
	while(++i < 64) T[i] = (UINT4)pow2_32 * fabs(sin(i+1));


	//***** Create 16byte UINT4 word blocks *****//
	l = strlen(str) * 8;
	n = l / 512 + 1;
	if (l % 512 > 448) n++;
	UINT4 *words = (UINT4 *)malloc(n * 16 * 10);
	// printf("# 16 word blocks = %d\n", n);
	for(i=0; i<n*16; i++) words[i] = 0;
	words[n*16 - 2] = l;
	j = 0;
	while(*padded_str != 0){
		i = -1;
		while(++i < 4) word[i] = *padded_str++; // assign 4 chars to word
		words[j++] = UINT4_WORD(word);
	}
	//for(i=0; i<n*16; i++) printf("Word %d = %u\n", i, words[i]);


	//***** MD5 Processing *****//
	//Process each 16 byte word block
	i = -1;
	j =  0;
	while(++i < n){
		memcpy(ABCD, abcd, 32);
		k = s = q = 0;
		for (t=0; t<64; t++){
			w = (x[k] * q + y[k]) %  16;
			MD5_OPERATION(k, abcd, words[w+j], T[t], shift[s]);
			ROTATE_ABCD(abcd);
			q++;
			s++;
			if (t == 15 || t == 31 || t == 47) {
				q = 0;
				k++;
			}
			if (q == 4 || q == 8 || q == 12) s = k * 4;;
		}
		j += 16;
		for(k=0; k<4; k++) abcd[k] = (abcd[k] + ABCD[k]) % pow2_32;
		//printf("Block %d: A=%u, B=%u, C=%u, D=%u\n", i+1, abcd[0], abcd[1], abcd[2], abcd[3]);
	}
	//printf("Final Hex value: A=%x, B=%x, C=%x, D=%x\n", abcd[0], abcd[1], abcd[2], abcd[3]);
	//printf("MD5(\"%s\") = %x%x%x%x", str, REVERSE_BITS(abcd[0]), REVERSE_BITS(abcd[1]), REVERSE_BITS(abcd[2]), REVERSE_BITS(abcd[3]));


	//***** Concatenate A, B, C, D to for md5 string *****//
	i = -1;
	while(++i < 4){
		md5[i] = (UCHAR *)malloc(10);
		sprintf(md5[i], "%x", REVERSE_BITS(abcd[i]));
		strcat(MD5, md5[i]);
	}
	//printf("\nMD5 = %s", MD5);
	return(MD5);
}


int main(int argc, char const *argv[]) {
	UCHAR *str = "Hello World!";
	printf("MD5(\"%s\") = %s\n", str, md5(str));
	return 0;
}
