#include <stdio.h>
#include <stdlib.h>

#include "bytelocker.h"

int main(int argc, char **argv) {
	// argv[1] = filename
	// argv[2] = password
	if (argc != 3) {
		fprintf(stderr, "Usage: %s <file to encrypt / decrypt> <password>\n", argv[0]);
		return EXIT_FAILURE;
	}
	if (!test_perms(argv[1])) {
		fprintf(stderr, "Do not have appropriate permissions on %s\n", argv[1]);
		return EXIT_FAILURE;
	}
	
	// checking first byte of file to see if it is ascii
	FILE *f = fopen(argv[1], "r");
	char check[1];
	fread(check, 1, sizeof(check), f);
	ungetc(check[0], f);
	fclose(f);
	
	// encrypts if ascii, otherwise decrypts
	if ( check[0] > 31 && check[0] < 127 ) {
		encrypt_f(argv[1], argv[2]);
	}
	else {
		decrypt_f(argv[1], argv[2]);
	}
}
