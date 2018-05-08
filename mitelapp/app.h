

#define BUFSIZE 1024

#define AES_256_KEY_SIZE 32 /* key size could be 16, 24 or 32 bytes */

struct KMS_secret {
  char *memory;
  size_t size;
};


struct KMS_secret *app_startup_get_value(char *key);
