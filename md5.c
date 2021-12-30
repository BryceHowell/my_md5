#include "md5.h"
#include <math.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

uint64_t leftRotate64(uint64_t n, shift_t d)
{
	           return (n << d)|(n >> (UINT64_BITS - d));
}

uint64_t rightRotate64(uint64_t n, shift_t d)
{
	           return (n >> d)|(n << (UINT64_BITS - d));
}

uint32_t leftRotate32(uint32_t n, shift_t d)
{
	           return (n << d)|(n >> (UINT32_BITS - d));
}

uint32_t rightRotate32(uint32_t n, shift_t d)
{
	           return (n >> d)|(n << (UINT32_BITS - d));
}


uint64_t convert_endian_uint64( uint64_t val )
{
	    val = ((val << 8) & 0xFF00FF00FF00FF00ULL ) | ((val >> 8) & 0x00FF00FF00FF00FFULL );
	        val = ((val << 16) & 0xFFFF0000FFFF0000ULL ) | ((val >> 16) & 0x0000FFFF0000FFFFULL );
		    return (val << 32) | (val >> 32);
}

uint32_t convert_endian_uint32( uint32_t val )
{
	    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0x00FF00FF );
	    return (val << 16) | (val >> 16);
}

void MD5_precompute_K() {
	for (int i=1; i<=64; i++) MD5_K[i-1]=(uint32_t)floor(FLOAT_2EXP32*fabs(sin(i)));
}


struct message_buffer * MD5_message_pad(struct message_buffer * message) {
	int mod64 = message->byte_length%64;	
	int div64 = message->byte_length/64;
	int desired_bytes = div64*64;
	if (mod64<= 64-8-1) desired_bytes=div64+64; else desired_bytes=div64+128;
	struct message_buffer * retval=(struct message_buffer *)malloc(sizeof(struct message_buffer));
	uint8_t * buffer = (uint8_t *) malloc(desired_bytes*sizeof(uint8_t));
	memcpy(buffer,message->buffer,message->byte_length);
	// This byte handles the intial 1 bit and 7 following zeroes
	buffer[message->byte_length]=0x80;
	// This is the zero buffering before the encoding of the message length
	for (int i=message->byte_length+1; i<desired_bytes-16; i++) buffer[i]=0;
	// The next loop zeroes out the entire message length 64-bit word. 
	for (int i=desired_bytes-8; i<desired_bytes; i++) buffer[i]=0;
	// Now we will write the 64-bit word for the message length
	// This step converts the endian-ness to BIG ENDIAN as I am assuming I am on an Intel architecture
	// This needs to be fixed to auto-correct for the current platform
	//uint64_t msg_length=convert_endian_uint64((uint64_t)(8*message->byte_length));
	uint64_t msg_length=(uint64_t)(8*message->byte_length);
	uint64_t * original_length_code_ptr=(uint64_t *)(buffer+desired_bytes-8);
	*original_length_code_ptr=msg_length;
	retval->buffer=buffer;
	retval->byte_length=desired_bytes;
	return retval;
}

struct message_buffer * read_whole_file_to_message(const char * filename) {
	int fd;
	if (filename==NULL) { printf("NULL filename string.\n"); exit(1); }
	if (-1==(fd=open(filename,O_RDONLY))) { 
		printf("Unable to open file: %s\n",filename);
		exit(1);
	}
	int length=lseek(fd,0,SEEK_END);	
	//printf("file %s has length %d.\n",filename,length);
	struct message_buffer * message_file=(struct message_buffer *)malloc(sizeof(struct message_buffer));
	message_file->byte_length=length;
	message_file->buffer=(uint8_t *)malloc(length*sizeof(uint8_t));
	lseek(fd,0,SEEK_SET);	
	int i=0;
	int numread=0;
	char readbuf[65536];
	while ((numread=read(fd,&readbuf,65536))>0) {
		memcpy(i+message_file->buffer,&readbuf,numread);	
		i+=numread;
	} 
	close(fd);

	return message_file;
}

// MD5 function

struct message_buffer * MD5_digest(struct message_buffer * total_message) { 
	uint32_t * current_chunk=(uint32_t *)total_message->buffer;	

	// SET UP INITIAL HASH VALUES
	uint32_t H[4];
	H[0]=MD5_A0;
	H[1]=MD5_B0;
	H[2]=MD5_C0;
	H[3]=MD5_D0;
	//memcpy(&H, &SHA512_initial_hash, 8*sizeof(uint64_t));
	//for (int i=0; i<8; i++) H[i]=convert_endian_uint64(SHA512_initial_hash[i]);

	uint32_t M[16];
	while ( (void *)(current_chunk) < (void *)(total_message->byte_length+(total_message->buffer)) ) {
		// SET THE MESSAGE SCHEDULE FOR THIS CHUNK
		// - copy the chunk into the xx64 bit words of W
		memcpy(&M,current_chunk,16*sizeof(uint32_t));
		// - fix the endianness of the words since this is intel
		//for (int i=0; i<16; i++) M[i]=convert_endian_uint32(M[i]);
		// Initialize hash value for this chunk
		uint32_t A,B,C,D;
		int g;
		A=H[0];
		B=H[1];
		C=H[2];
		D=H[3];
		// Compression function main loop:
		for (int i=0; i<64; i++) {
			uint32_t F;
			int g;
			if (0<=i && i<=15) {
				F=(B & C) | (~B & D);
				g=i;
			} else if (16<=i && i<=31) {
				F=(D & B) | (~D & C);
				g=(5*i + 1) % 16;
			} else if (32<=i && i<=47) {
				F=B ^ C ^ D;
				g=(3*i + 5) % 16;
			} else { // Naturally, (48<=i && i<=63i) at this point
				F=C ^ (B | ~D);
				g=7*i % 16;
			}
			F+=A+MD5_K[i]+M[g];
			A=D; D=C; C=B; B+=leftRotate32(F,MD5_shift[i]);
		}

		H[0]+=A;
		H[1]+=B;
		H[2]+=C;
		H[3]+=D;

		// MOVE ON TO THE NEXT CHUNK
		current_chunk+=16;
	}
	
	uint8_t * val=(uint8_t *)malloc(4*sizeof(uint32_t));
	// The following should be executed on BIG-ENDIAN PLATFORMS only
	// IT SHOULD BE FIXED AT SOME POINT
	//for (int i=0; i<4; i++) H[i]=convert_endian_uint64(H[i]);
	memcpy(val,&H,4*sizeof(uint32_t));
	struct message_buffer * retval=(struct message_buffer *)malloc(sizeof(struct message_buffer));
	retval->byte_length=4*sizeof(uint32_t);
	retval->buffer=(uint8_t *)val;
	return retval;
}


char * sprintf_hexstring(struct message_buffer * M){
	char * output=(char *)malloc(1+2*M->byte_length);
	//printf("length=%d\n",M->byte_length);
	//if (output!=NULL) printf("stupid output alloc check passed.\n");
	//if (M->buffer!=NULL) printf("stupid M->buffer alloc check passed.\n");
	for (int i=0; i<M->byte_length; i++) {
		//printf("%02x",*(M->buffer+i));
		sprintf(output+2*i,"%02x",*(M->buffer+i));
	}
	output[2*M->byte_length]=0;
	return output;
}

void free_message_buffer(struct message_buffer * release) {
	free(release->buffer);
	free(release);
}

void maintest(char * filename) {
 MD5_precompute_K();
 struct message_buffer * filedata=read_whole_file_to_message(filename);
 struct message_buffer * data=MD5_message_pad(filedata);
 char * check_padding=sprintf_hexstring(data);
 //printf("PADDED INPUT:\n%s\n",check_padding);
 free_message_buffer(filedata);
 struct message_buffer * digest=MD5_digest(data);
 char * final_hash = sprintf_hexstring(digest);
 //printf("FINAL HASH VALUE:\n");
 printf("%s\n",final_hash);
 
}

int main(int argc, char *argv[]) {
    if (argc==2) maintest(argv[1]); else printf("No file specified.\n");
}

