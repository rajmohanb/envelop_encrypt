#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <curl/curl.h>
#include <jansson.h>

#include "app.h"


/* forward refs */
void print_json(json_t *root);
void print_json_aux(json_t *element, int indent);
void print_json_indent(int indent);
const char *json_plural(int count);
void print_json_object(json_t *element, int indent);
void print_json_array(json_t *element, int indent);
void print_json_string(json_t *element, int indent);
void print_json_integer(json_t *element, int indent);
void print_json_real(json_t *element, int indent);
void print_json_true(json_t *element, int indent);
void print_json_false(json_t *element, int indent);
void print_json_null(json_t *element, int indent);

void print_json_indent(int indent) {
    int i;
    for (i = 0; i < indent; i++) { putchar(' '); }
}

const char *json_plural(int count) {
    return count == 1 ? "" : "s";
}


void print_json_object(json_t *element, int indent) {
    size_t size;
    const char *key;
    json_t *value;

    print_json_indent(indent);
    size = json_object_size(element);

    printf("JSON Object of %ld pair%s:\n", size, json_plural(size));
    json_object_foreach(element, key, value) {
        print_json_indent(indent + 2);
        printf("JSON Key: \"%s\"\n", key);
        print_json_aux(value, indent + 2);
    }

}

void print_json_array(json_t *element, int indent) {
    size_t i;
    size_t size = json_array_size(element);
    print_json_indent(indent);

    printf("JSON Array of %ld element%s:\n", size, json_plural(size));
    for (i = 0; i < size; i++) {
        print_json_aux(json_array_get(element, i), indent + 2);
    }
}

void print_json_string(json_t *element, int indent) {
    print_json_indent(indent);
    printf("JSON String: \"%s\"\n", json_string_value(element));
}

void print_json_integer(json_t *element, int indent) {
    print_json_indent(indent);
    printf("JSON Integer: \"%" JSON_INTEGER_FORMAT "\"\n", json_integer_value(element));
}

void print_json_real(json_t *element, int indent) {
    print_json_indent(indent);
    printf("JSON Real: %f\n", json_real_value(element));
}

void print_json_true(json_t *element, int indent) {
    (void)element;
    print_json_indent(indent);
    printf("JSON True\n");
}

void print_json_false(json_t *element, int indent) {
    (void)element;
    print_json_indent(indent);
    printf("JSON False\n");
}

void print_json_null(json_t *element, int indent) {
    (void)element;
    print_json_indent(indent);
    printf("JSON Null\n");
}


void print_json(json_t *root) {
    print_json_aux(root, 0);
}


void print_json_aux(json_t *element, int indent) {
    switch (json_typeof(element)) {
    case JSON_OBJECT:
        print_json_object(element, indent);
        break;
    case JSON_ARRAY:
        print_json_array(element, indent);
        break;
    case JSON_STRING:
        print_json_string(element, indent);
        break;
    case JSON_INTEGER:
        print_json_integer(element, indent);
        break;
    case JSON_REAL:
        print_json_real(element, indent);
        break;
    case JSON_TRUE:
        print_json_true(element, indent);
        break;
    case JSON_FALSE:
        print_json_false(element, indent);
        break;
    case JSON_NULL:
        print_json_null(element, indent);
        break;
    default:
        fprintf(stderr, "unrecognized JSON type %d\n", json_typeof(element));
    }
}


/*
 * Parse text into a JSON object. If text is valid JSON, returns a
 * json_t structure, otherwise prints and error and returns null.
 */
char *load_json(const char *text, char *key) {
    json_t *root, *data, *kek;
    json_error_t error;
    char *kek_str;

    root = json_loads(text, 0, &error);

#ifdef DEBUG
    if (root) {
        print_json(root);
    }
#endif

    if (!root) {
        fprintf(stderr, "json error on line %d: %s\n", error.line, error.text);
        return NULL;
    }

    data = json_object_get(root, "data");
    if (!data) {
        fprintf(stderr, "Error when extracting data object from received json, aborting ...");
        return NULL;
    }

    kek = json_object_get(data, key);
    if (!data) {
        fprintf(stderr, "Error when extracting KEK object from received json, aborting ...");
        return NULL;
    }

    kek_str = (char *)json_string_value(kek);

    return kek_str;
}




static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct KMS_secret *mem = (struct KMS_secret *)userp;
 
  mem->memory = realloc(mem->memory, mem->size + realsize + 1);
  if(mem->memory == NULL) {
    /* out of memory! */ 
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }
 
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;
 
  return realsize;
}


struct KMS_secret *app_startup_get_value(char *key) {
        
    /*
    hard coding the token here for now. This typically needs to be requested from
    KMS by authencating with KMS. KMS will upon successful authentication, provide
    access token and lease time
    */
    //char token[] = "3b5f80c3-db06-d393-0b26-c1e11aa1c405";
    char token[] = "d9e0d222-3600-b88b-35f5-951567d64b27";
    char vault_hdr[124] = {0};
    struct KMS_secret *kms_secret;

    char *ggg;

    kms_secret = (struct KMS_secret *)malloc(sizeof(struct KMS_secret));
    if (!kms_secret) {
        printf("memory allocation failed\n");
        return NULL;
    } 
 
      kms_secret->memory = malloc(1);
      kms_secret->size = 0;

    CURL *curl;
    CURLcode res;
    struct curl_slist *chunk = NULL;

    /*
    now that we have a token, we need to retreve the secret from KMS. Secret in our
    case as of now, is just KEK key
    */
    curl = curl_easy_init();
    if (!curl) {
        printf("Error initializing CURL library");
        exit(1);
    }
    
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);    
    curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:8200/v1/secret/miconnect/tenant/slick/certs");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)kms_secret);    

    /* add vault header */
    sprintf(vault_hdr, "X-Vault-Token: %s", token);
    chunk = curl_slist_append(chunk, vault_hdr);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        printf("Error: curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        exit(1);
    } else {
        printf("%lu bytes retrieved\n", (long)kms_secret->size);
    }

    /* parse the resulting output */
    ggg = load_json(kms_secret->memory, key);

    fprintf(stderr, "KEK string: %s\n", ggg);

    free(kms_secret->memory);

    curl_slist_free_all(chunk);
    curl_easy_cleanup(curl);

    kms_secret->memory = strdup(ggg);
    kms_secret->size = strlen(ggg);

    return kms_secret;
}


#if 1

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
	fflush(stderr);
    //abort();
}

#endif
