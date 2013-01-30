#ifndef SHA1_INCLUDED
#define SHA1_INCLUDED

#include <stdint.h>

#define SHA1_BLOCK_LENGTH               64
#define SHA1_DIGEST_LENGTH              20

typedef struct {
    uint32_t       state[5];
    uint64_t       count;
    unsigned char   buffer[SHA1_BLOCK_LENGTH];
} SHA1_CTX;


void SHA1Init(SHA1_CTX *context);
void SHA1Update(SHA1_CTX *context, const unsigned char *data, unsigned int);
void SHA1Final(unsigned char digest[SHA1_DIGEST_LENGTH], SHA1_CTX *context);



#endif
