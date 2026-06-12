#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void vulnerable_payload(const char *input){
    char buffer[32];
    strcpy(buffer, input);
    printf("Payload: %s\n", buffer);
}

void vulnerable_format(const char *input){
    printf(input);
    printf("\n");
}

void vulnerable_integer(const char *input){
    int size = atoi(input);
    char *ptr = malloc(size + 100);
    if (ptr){
        memset(ptr, 'A', size);
        free(ptr);
    }
}

void vulnerable_array(const char *input){
    int values[4] = {1, 2, 3, 4};
    int index = atoi(input);
    printf("%d\n", values[index]);
}

void process_config(const char *input){
    if (strncmp(input, "CONFIG:", 7) == 0){
        vulnerable_integer(input + 7);
    }
}

void process_packet(const char *input){
    if (strncmp(input, "PACKET:", 7) != 0)
        return;
    if (strstr(input, "AUTH") == NULL)
        return;
    vulnerable_payload(input);
}

void process_admin(const char *input){
    if (strncmp(input, "PACKET:", 7) != 0)
        return;
    if (strstr(input, "AUTH") == NULL)
        return;
    if (strstr(input, "ADMIN") == NULL)
        return;
    vulnerable_format(input);
}

void process_magic(const char *input){
    if (memcmp(input, "MAGIC123", 8) != 0)
        return;
    vulnerable_array(input + 8);
}

void process_secret(const char *input){
    if (strcmp(input, "SUPER_SECRET_VALUE") != 0)
        return;
    char *ptr = NULL;
    strcpy(ptr, "CRASH");
}

void process_input(const char *input){
    process_config(input);
    process_packet(input);
    process_admin(input);
    process_magic(input);
    process_secret(input);
}

int main(int argc, char **argv){
    if (argc < 2){
        printf("Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f){
        perror("fopen");
        return 1;
    }
    char data[4096];
    size_t size = fread(data, 1, sizeof(data) - 1, f);
    fclose(f);
    data[size] = '\0';
    process_input(data);
    return 0;
}