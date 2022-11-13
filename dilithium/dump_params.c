#include "params.h"
#include <stdio.h>

int main() {
    printf("{\n");
    printf("\"SEEDBYTES\": %d,\n", SEEDBYTES);
    printf("\"CRHBYTES\": %d,\n", CRHBYTES);
    printf("\"N\": %d,\n", N);
    printf("\"Q\": %d,\n", Q);
    printf("\"D\": %d,\n", D);
    printf("\"ROOT_OF_UNITY\": %d,\n", ROOT_OF_UNITY);
    printf("\"K\": %d,\n", K);
    printf("\"L\": %d,\n", L);
    printf("\"ETA\": %d,\n", ETA);
    printf("\"TAU\": %d,\n", TAU);
    printf("\"BETA\": %d,\n", BETA);
    printf("\"GAMMA1\": %d,\n", GAMMA1);
    printf("\"GAMMA2\": %d,\n", GAMMA2);
    printf("\"OMEGA\": %d,\n", OMEGA);
    printf("\"POLYT1_PACKEDBYTES\": %d,\n", POLYT1_PACKEDBYTES);
    printf("\"POLYT0_PACKEDBYTES\": %d,\n", POLYT0_PACKEDBYTES);
    printf("\"POLYVECH_PACKEDBYTES\": %d,\n", POLYVECH_PACKEDBYTES);
    printf("\"POLYZ_PACKEDBYTES\": %d,\n", POLYZ_PACKEDBYTES);
    printf("\"POLYW1_PACKEDBYTES\": %d,\n", POLYW1_PACKEDBYTES);
    printf("\"POLYETA_PACKEDBYTES\": %d,\n", POLYETA_PACKEDBYTES);
    printf("\"CRYPTO_PUBLICKEYBYTES\": %d,\n", CRYPTO_PUBLICKEYBYTES);
    printf("\"CRYPTO_SECRETKEYBYTES\": %d,\n", CRYPTO_SECRETKEYBYTES);
    printf("\"CRYPTO_BYTES\": %d\n", CRYPTO_BYTES);
    printf("}");
}