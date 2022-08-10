#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

#include "bytelocker.h"

const char *const MSG_ERROR_FILE_STAT  = "Could not stat file\n";
const char *const MSG_ERROR_DIRECTORY  =
    "bytelocker does not support encrypting directories.\n";
const char *const MSG_ERROR_READ       =
    "user does not have permission to read this file.\n";
const char *const MSG_ERROR_WRITE      =
    "user does not have permission to write here.\n";

void encrypt_f(char *f, char *pass) {
	char line[16];
	int r;
	FILE *f_r = fopen(f, "rb");
	FILE *tmp_w = fopen("tmp.txt", "wb");
	
	// writing a null character at start of file to indicate encrypted
	fwrite("\x00", 1, 1, tmp_w);

	// writing encrypted characters to tmp
	while ((r = fread(line, 1, sizeof line, f_r)) != 0) {
		if (r != 16) {
			for (int i = r; i < 16; i++) {
				line[i] = '\x00';
			}
		}
		fwrite(shift_encrypt(line, pass), 1, 16, tmp_w);
	}
	fclose(tmp_w);
	fclose(f_r);
	
	// writing encrypted characters to original file
	FILE *f_w = fopen(f, "wb");
	FILE *tmp_r = fopen("tmp.txt", "rb");
	int c;
	while ((c = fgetc(tmp_r)) != EOF) fputc(c, f_w);
	fclose(f_w);
	fclose(tmp_r);
	remove("tmp.txt");
}

void decrypt_f(char *f, char *pass) {
	char line[16];
	int r;
	FILE *f_r = fopen(f, "rb");
	FILE *tmp_w = fopen("tmp.txt", "wb");
	
	// gobbling first null character
	fseek(f_r, 1, SEEK_SET);

	// writing decrypted characters to tmp
	while ((r = fread(line, 1, sizeof line, f_r)) != 0) {
		if (r != 16) {
			for (int i = r; i < 16; i++) {
				line[i] = '\x00';
			}
		}
		fwrite(shift_decrypt(line, pass), 1, 16, tmp_w);
	}
	fclose(tmp_w);
	fclose(f_r);
	
	// writing decrypted characters to original file
	FILE *f_w = fopen(f, "wb");
	FILE *tmp_r = fopen("tmp.txt", "rb");
	int c;
	while ((c = fgetc(tmp_r)) != EOF && c != '\x00') fputc(c, f_w);
	fclose(f_w);
	fclose(tmp_r);
}


bool test_perms(char filename[MAX_PATH_LEN]) {
	// 4 cases:
	// - checks if file exists
	// - must be a regular file
	// - user must be able to read file
	// - user must have premissions to write
	
	struct stat s;
	// checking if a file exists
	if (stat(filename, &s) != 0) {
		printf(MSG_ERROR_FILE_STAT);
		return false;
	}
	// checking if file is a folder
	else if (s.st_mode & S_IFDIR) {
		printf(MSG_ERROR_DIRECTORY);
		return false;
	}
	// checking if user can read file
	else if (!(s.st_mode & S_IRUSR)) {
		printf(MSG_ERROR_READ);
		return false;
	}
	else if (!(s.st_mode & S_IWUSR)) {
		printf(MSG_ERROR_WRITE);
		return false;
	}
	else return true;
}


char *shift_encrypt(char *plaintext, char *password) {
	for (int i = 0; i < 16; i++) {
		uint8_t k = plaintext[i];
		for (int j = password[i]; j > 0; j--) {
			k = k << 1 | k >> (8 - 1);
		}
		plaintext[i] = k;
	}
	return plaintext;
}

char *shift_decrypt(char *ciphertext, char *password) {
	for (int i = 0; i < 16; i++) {
		uint8_t k = ciphertext[i];
		for (int j = password[i]; j > 0; j--) {
			k = k >> 1 | k << (8 - 1);
		}
		ciphertext[i] = k;
	}
	return ciphertext;
}

// and must be freed by the caller.
// generates random string of length 16
// same seed returns same string
// string composed of upper, lower and 0 - 9
char *rand_str(int seed) {
    if (seed != 0) {
        srand(seed);
    }

    char *alpha_num_str =
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789";

    char *random_str = malloc(RAND_STR_LEN);

    for (int i = 0; i < RAND_STR_LEN; i++) {
        random_str[i] = alpha_num_str[rand() % (strlen(alpha_num_str) - 1)];
    }

    return random_str;
}
