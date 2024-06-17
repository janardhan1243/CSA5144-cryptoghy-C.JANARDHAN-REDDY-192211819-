#include <stdio.h>
#include <string.h>
#include <stdint.h>

// SHA-1 context structure
typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    uint8_t buffer[64];
} SHA1_CTX;

// Function prototypes
void SHA1Transform(uint32_t state[5], const uint8_t buffer[64]);
void SHA1Init(SHA1_CTX *context);
void SHA1Update(SHA1_CTX *context, const uint8_t *data, uint32_t len);
void SHA1Final(uint8_t digest[20], SHA1_CTX *context);
void bytesToHex(const uint8_t *bytes, int len, char *hexString);

// Constants for SHA-1 transform routine
#define SHA1_BLOCK_SIZE 64

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

#define F1(x, y, z) (((x) & (y)) | ((~(x)) & (z)))
#define F2(x, y, z) ((x) ^ (y) ^ (z))
#define F3(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define F4(x, y, z) ((x) ^ (y) ^ (z))

#define K1 0x5A827999
#define K2 0x6ED9EBA1
#define K3 0x8F1BBCDC
#define K4 0xCA62C1D6

void SHA1Transform(uint32_t state[5], const uint8_t buffer[64]) {
    uint32_t a, b, c, d, e;
    uint32_t w[80];
    int t;

    for (t = 0; t < 16; t++) {
        w[t] = ((uint32_t)buffer[t * 4]) << 24;
        w[t] |= ((uint32_t)buffer[t * 4 + 1]) << 16;
        w[t] |= ((uint32_t)buffer[t * 4 + 2]) << 8;
        w[t] |= ((uint32_t)buffer[t * 4 + 3]);
    }

    for (t = 16; t < 80; t++) {
        w[t] = ROTATE_LEFT(w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16], 1);
    }

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

    for (t = 0; t < 20; t++) {
        uint32_t temp = ROTATE_LEFT(a, 5) + F1(b, c, d) + e + w[t] + K1;
        e = d;
        d = c;
        c = ROTATE_LEFT(b, 30);
        b = a;
        a = temp;
    }

    for (t = 20; t < 40; t++) {
        uint32_t temp = ROTATE_LEFT(a, 5) + F2(b, c, d) + e + w[t] + K2;
        e = d;
        d = c;
        c = ROTATE_LEFT(b, 30);
        b = a;
        a = temp;
    }

    for (t = 40; t < 60; t++) {
        uint32_t temp = ROTATE_LEFT(a, 5) + F3(b, c, d) + e + w[t] + K3;
        e = d;
        d = c;
        c = ROTATE_LEFT(b, 30);
        b = a;
        a = temp;
    }

    for (t = 60; t < 80; t++) {
        uint32_t temp = ROTATE_LEFT(a, 5) + F4(b, c, d) + e + w[t] + K4;
        e = d;
        d = c;
        c = ROTATE_LEFT(b, 30);
        b = a;
        a = temp;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

void SHA1Init(SHA1_CTX *context) {
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}

void SHA1Update(SHA1_CTX *context, const uint8_t *data, uint32_t len) {
    uint32_t i, j;

    j = (context->count[0] >> 3) & 63;
    if ((context->count[0] += len << 3) < (len << 3)) context->count[1]++;
    context->count[1] += (len >> 29);
    if ((j + len) > 63) {
        memcpy(&context->buffer[j], data, (i = 64-j));
        SHA1Transform(context->state, context->buffer);
        for (; i + 63 < len; i += 64) {
            SHA1Transform(context->state, &data[i]);
        }
        j = 0;
    }
    else i = 0;
    memcpy(&context->buffer[j], &data[i], len - i);
}

void SHA1Final(uint8_t digest[20], SHA1_CTX *context) {
    uint8_t finalcount[8];
    uint8_t c;

    for (unsigned int i = 0; i < 8; i++) {
        finalcount[i] = (uint8_t)((context->count[(i >= 4 ? 0 : 1)]
                     >> ((3-(i & 3)) * 8) ) & 255);
    }

    c = 0200;
    SHA1Update(context, &c, 1);
    while ((context->count[0] & 504) != 448) {
        c = 0000;
        SHA1Update(context, &c, 1);
    }
    SHA1Update(context, finalcount, 8);  // Should cause a SHA1Transform()
    for (unsigned int i = 0; i < 20; i++) {
        digest[i] = (uint8_t)
                 ((context->state[i>>2] >> ((3-(i & 3)) * 8) ) & 255);
    }
}

// Function to convert bytes to hex string
void bytesToHex(const uint8_t *bytes, int len, char *hexString) {
    const char hexDigits[] = "0123456789ABCDEF";
    for (int i = 0; i < len; i++) {
        hexString[i * 2] = hexDigits[(bytes[i] >> 4) & 0xF];
        hexString[i * 2 + 1] = hexDigits[bytes[i] & 0xF];
    }
    hexString[len * 2] = '\0';
}

int main() {
    SHA1_CTX context;
    uint8_t digest[20];
    char hexOutput[41];

    const char *inputs[] = {"", "abc", "abcdefghijklmnopqrstuvwxyz"};
    int numInputs = sizeof(inputs) / sizeof(inputs[0]);

    printf("SHA1 hash calculation:\n");

    for (int i = 0; i < numInputs; i++) {
        SHA1Init(&context);
        SHA1Update(&context, (uint8_t *)inputs[i], strlen(inputs[i]));
        SHA1Final(digest, &context);
        bytesToHex(digest, 20, hexOutput);
        printf("SHA1(\"%s\") = %s\n", inputs[i], hexOutput);
    }

    return 0;
}

