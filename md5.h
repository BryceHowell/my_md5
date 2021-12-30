#include <stdint.h>

const double FLOAT_2EXP32=4294967296.0;

// These values are big-endian
const uint32_t MD5_A0=0x67452301;
const uint32_t MD5_B0=0xefcdab89;
const uint32_t MD5_C0=0x98badcfe;
const uint32_t MD5_D0=0x10325476;

typedef int shift_t;

const shift_t MD5_shift[64]={ 7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22, 5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20, 4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23, 6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21 };

uint32_t MD5_K[64];

void MD5_precompute_K(); 

uint64_t convert_endian_uint64( uint64_t val );

uint32_t convert_endian_uint32( uint32_t val );

struct message_buffer {
	uint8_t * buffer;
	int byte_length;
};


struct message_buffer * read_whole_file_to_message(const char * filename);

#define UINT64_BITS 8*sizeof(uint64_t)
#define UINT32_BITS 8*sizeof(uint32_t)

uint64_t leftRotate64(uint64_t n, shift_t d);
uint64_t rightRotate64(uint64_t n, shift_t d);

uint32_t leftRotate32(uint32_t n, shift_t d);
uint32_t rightRotate32(uint32_t n, shift_t d);

struct message_buffer * MD5_message_pad(struct message_buffer * M);
struct message_buffer * MD5_digest(struct message_buffer * M);

char * sprintf_hexstring(struct message_buffer * M); 

