#ifndef _BYTELOCKER_H
#define _BYTELOCKER_H

#include <stdbool.h>

#define MAX_PATH_LEN 4096
#define MAX_LINE_LEN 2048
#define RAND_STR_LEN 16
#define CIPHER_BLOCK_SIZE 16


bool test_perms(char filename[MAX_PATH_LEN]);
void encrypt_f(char *f, char *pass);
void decrypt_f(char *f, char *pass);
char *shift_encrypt(char *plaintext, char *password);
char *shift_decrypt(char *ciphertext, char *password);
char *rand_str(int seed);

#endif // _BYTELOCKER_H
