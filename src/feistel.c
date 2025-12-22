// feistel_file_encrypt_portable.c

//  قابل بیلد/ران روی Linux و Windows (MSVC/MinGW)
//
// Build (Linux):
//   gcc -O2 -Wall -Wextra -std=c11 feistel.c -o feistel_enc
//   (روی بعضی لینوکس‌های قدیمی ممکنه نیاز بشه: ... -lrt)
//
// Build (Windows - MSVC, Developer Command Prompt):
//   cl /O2 /W4 feistel.c
//
// Build (Windows - MinGW-w64):
//   gcc -O2 -Wall -Wextra -std=c11 feistel_file_encrypt_portable.c -o feistel_enc.exe
//
// Run:
//   ./feistel_enc input.bin output.enc
//   (ویندوز: feistel.exe input.bin output.enc)




#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>


#ifdef _WIN32
#include <windows.h>   // QueryPerformanceCounter
#else
#include <time.h>      // clock_gettime / timespec_get
#endif

// ============================
//   CONFIG
// ============================

#define BLOCK_SIZE 64             // 64-bit block
#define HALF_SIZE  (BLOCK_SIZE/2)  // 32 bytes
#define HALF_HALF_SIZE  (HALF_SIZE/2)  // 16 bytes
#define ROUNDS     35
#define KEYLEN     64              // exactly 64 characters

// ============================
//   TIME (Portable)
// ============================

static double now_seconds(void) {
#ifdef _WIN32
    static LARGE_INTEGER freq;
    LARGE_INTEGER counter;

    if (freq.QuadPart == 0) {
        QueryPerformanceFrequency(&freq);
    }
    QueryPerformanceCounter(&counter);

    return (double)counter.QuadPart / (double)freq.QuadPart;
#else
#if defined(CLOCK_MONOTONIC)
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
    }
#endif

#if defined(TIME_UTC)
    struct timespec ts2;
    if (timespec_get(&ts2, TIME_UTC) != 0) {
        return (double)ts2.tv_sec + (double)ts2.tv_nsec / 1e9;
    }
#endif

    return 0.0;
#endif
}

// ============================
//   /2 - *2
// ============================
static int split_generic(const uint8_t *in, size_t n,
                         uint8_t *L, uint8_t *R)
{
    if (!in || !L || !R) return 1;
    if ((n % 2) != 0) return 1;

    size_t half = n / 2;

    memcpy(L, in, half);
    memcpy(R, in + half, half);
    return 0;
}

static int join_generic(uint8_t *out, size_t n,
                        const uint8_t *L, const uint8_t *R)
{
    if (!out || !L || !R) return 1;
    if ((n % 2) != 0) return 1;

    size_t half = n / 2;

    memcpy(out, L, half);
    memcpy(out + half, R, half);

    return 0;
}



// ============================
//   XOR
// ============================


static void xor_generic(const uint8_t *a, const uint8_t *b, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        out[i] = (uint8_t)(a[i] ^ b[i]);
    }
}

// ============================
//   F
// ============================

static inline uint8_t keymerg_onebit(uint8_t r, uint8_t k) {
    return (uint8_t)(r ^ k);
}

static void feistel_round(const uint8_t R[HALF_SIZE],
                          const uint8_t master_key[KEYLEN],
                          int round,
                          uint8_t f_out[HALF_SIZE])
{
    uint8_t newL[HALF_HALF_SIZE], newR[HALF_HALF_SIZE],keyL[HALF_HALF_SIZE];

    if (split_generic(R, HALF_SIZE, newL, newR) != 0) {
        memset(f_out, 0, HALF_SIZE);
        return;
    }


    for (int i = 0; i < HALF_HALF_SIZE; i++) {
        uint8_t kL = (uint8_t)(
            master_key[(round * HALF_SIZE + i) % KEYLEN] ^
            (uint8_t)(round * 17 + i * 31)
            );
        keyL[i] = keymerg_onebit(newL[i], kL);
    }

xor_generic(keyL, newR , newR, HALF_HALF_SIZE);

    for (int i = 0; i < HALF_HALF_SIZE; i++) {
        uint8_t oldR = newR[i];
        newR[i] =newL[i];
        newL[i] = oldR;

    }

    (void)join_generic(f_out, HALF_SIZE, newL, newR);
}



static void feistel_round_inv(const uint8_t f_out[HALF_SIZE],
                              const uint8_t master_key[KEYLEN],
                              int round,
                              uint8_t R[HALF_SIZE])
{
    uint8_t newL[HALF_HALF_SIZE], newR[HALF_HALF_SIZE];
    uint8_t oldL[HALF_HALF_SIZE], oldR[HALF_HALF_SIZE];

    // f_out = join(newL, newR)
    if (split_generic(f_out, HALF_SIZE, newL, newR) != 0) {
        memset(R, 0, HALF_SIZE);
        return;
    }

    // در encrypt داخل feistel_round آخرش swap شد:
    // newR == oldL
    // پس:
    memcpy(oldL, newR, HALF_HALF_SIZE);

    // newL = oldR ^ (oldL ^ k)  => oldR = newL ^ oldL ^ k
    for (int i = 0; i < HALF_HALF_SIZE; i++) {
        uint8_t kL = (uint8_t)(
            master_key[(round * HALF_SIZE + i) % KEYLEN] ^
            (uint8_t)(round * 17 + i * 31)
            );
        oldR[i] = (uint8_t)(newL[i] ^ oldL[i] ^ kL);
    }

    (void)join_generic(R, HALF_SIZE, oldL, oldR);
}

// ============================
//  encrypt_block
// ============================



static void encrypt_block(uint8_t block[BLOCK_SIZE], const uint8_t master_key[KEYLEN]) {
    uint8_t L[HALF_SIZE], R[HALF_SIZE];
    if (split_generic(block, BLOCK_SIZE, L, R) != 0) {
        return;
    }


    for (int round = 0; round < ROUNDS; round++) {

        uint8_t feistelout_R[HALF_SIZE];
        uint8_t feistelout_L[HALF_SIZE];
         uint8_t feistelout_M[HALF_SIZE];
        uint8_t xorout_one[HALF_SIZE];
        uint8_t xorout_two[HALF_SIZE];


        feistel_round(R, master_key, round, feistelout_R);
        feistel_round(L, master_key, round, feistelout_L);


       xor_generic(feistelout_L,feistelout_R, xorout_one, HALF_SIZE);

      feistel_round(xorout_one, master_key, round, feistelout_M);

       xor_generic(feistelout_L,feistelout_M, xorout_two, HALF_SIZE);

        for (int i = 0; i < HALF_SIZE; i++) {
            uint8_t oldR = xorout_one[i];
              R[i] = xorout_two[i];
            L[i] = oldR;

        }
    }

   (void)join_generic(block, BLOCK_SIZE, L, R);
}





// ============================
//  encrypt _ decrypt
// ============================





//  file with padding and encrypt


static int file_handling_enc(const char *in_path, const char *out_path, const uint8_t master_key[KEYLEN]) {
    FILE *in = fopen(in_path, "rb");
    if (!in) {
        perror("fopen input");
        return 1;
    }

    FILE *out = fopen(out_path, "wb");
    if (!out) {
        perror("fopen output");
        fclose(in);
        return 1;
    }

    uint8_t block[BLOCK_SIZE];
    size_t n;

  //encrypt for evry block
    while ((n = fread(block, 1, BLOCK_SIZE, in)) == BLOCK_SIZE) {
        encrypt_block(block, master_key);
        if (fwrite(block, 1, BLOCK_SIZE, out) != BLOCK_SIZE) {
            perror("fwrite");
            fclose(in);
            fclose(out);
            return 1;
        }
    }

    if (ferror(in)) {
        perror("fread");
        fclose(in);
        fclose(out);
        return 1;
    }

  //padding
    uint8_t pad = (uint8_t)(BLOCK_SIZE - n);
    memset(block + n, pad, pad);

    encrypt_block(block, master_key);
    if (fwrite(block, 1, BLOCK_SIZE, out) != BLOCK_SIZE) {
        perror("fwrite last");
        fclose(in);
        fclose(out);
        return 1;
    }

    fclose(in);
    fclose(out);
    return 0;
}







static void decrypt_block(uint8_t block[BLOCK_SIZE], const uint8_t master_key[KEYLEN])
{
    uint8_t L[HALF_SIZE], R[HALF_SIZE];

    if (split_generic(block, BLOCK_SIZE, L, R) != 0) {
        return;
    }

    for (int round = ROUNDS - 1; round >= 0; round--) {

        // در encrypt:
        // feistelout_R = F(R_prev)
        // feistelout_L = F(L_prev)
        // xorout_one   = feistelout_L ^ feistelout_R   (X)
        // feistelout_M = F(xorout_one)
        // xorout_two   = feistelout_L ^ feistelout_M   (Y)
        // و بعد:
        // L = xorout_one
        // R = xorout_two
        //
        // پس در decrypt الان:
        // L == xorout_one (X)
        // R == xorout_two (Y)

        uint8_t feistelout_M[HALF_SIZE];
        uint8_t feistelout_L[HALF_SIZE];
        uint8_t feistelout_R[HALF_SIZE];

        uint8_t xorout_one[HALF_SIZE];
        uint8_t xorout_two[HALF_SIZE];

        // feistelout_M = F(xorout_one)
        memcpy(xorout_one, L, HALF_SIZE);
        feistel_round(xorout_one, master_key, round, feistelout_M);

        // feistelout_L = xorout_two ^ feistelout_M
        memcpy(xorout_two, R, HALF_SIZE);
        xor_generic(xorout_two, feistelout_M, feistelout_L, HALF_SIZE);

        // feistelout_R = xorout_one ^ feistelout_L
        xor_generic(xorout_one, feistelout_L, feistelout_R, HALF_SIZE);

        // حالا باید L_prev و R_prev رو از feistelout_L و feistelout_R دربیاریم:
        feistel_round_inv(feistelout_L, master_key, round, L);
        feistel_round_inv(feistelout_R, master_key, round, R);
    }

    (void)join_generic(block, BLOCK_SIZE, L, R);
}






// ============================
//  file_handling
// ============================



static int file_handling_dec(const char *in_path, const char *out_path, const uint8_t master_key[KEYLEN])
{
    FILE *in = fopen(in_path, "rb");
    if (!in) {
        perror("fopen input");
        return 1;
    }

    FILE *out = fopen(out_path, "wb");
    if (!out) {
        perror("fopen output");
        fclose(in);
        return 1;
    }

    uint8_t block[BLOCK_SIZE];
    uint8_t next_block[BLOCK_SIZE];

    size_t n = fread(block, 1, BLOCK_SIZE, in);
    if (n == 0) {
        fprintf(stderr, "Error: empty ciphertext.\n");
        fclose(in);
        fclose(out);
        return 1;
    }
    if (n != BLOCK_SIZE) {
        fprintf(stderr, "Error: ciphertext size is not multiple of BLOCK_SIZE.\n");
        fclose(in);
        fclose(out);
        return 1;
    }

    // همه بلوک‌ها به جز آخری
    while ((n = fread(next_block, 1, BLOCK_SIZE, in)) == BLOCK_SIZE) {
        decrypt_block(block, master_key);

        if (fwrite(block, 1, BLOCK_SIZE, out) != BLOCK_SIZE) {
            perror("fwrite");
            fclose(in);
            fclose(out);
            return 1;
        }

        memcpy(block, next_block, BLOCK_SIZE);
    }

    if (ferror(in)) {
        perror("fread");
        fclose(in);
        fclose(out);
        return 1;
    }

    if (n != 0) {
        fprintf(stderr, "Error: ciphertext size is not multiple of BLOCK_SIZE.\n");
        fclose(in);
        fclose(out);
        return 1;
    }

    // آخرین بلوک: decrypt و unpad
    decrypt_block(block, master_key);

    uint8_t pad = block[BLOCK_SIZE - 1];
    if (pad == 0 || pad > BLOCK_SIZE) {
        fprintf(stderr, "Error: invalid padding value.\n");
        fclose(in);
        fclose(out);
        return 1;
    }

    for (size_t i = 0; i < pad; i++) {
        if (block[BLOCK_SIZE - 1 - i] != pad) {
            fprintf(stderr, "Error: invalid padding bytes.\n");
            fclose(in);
            fclose(out);
            return 1;
        }
    }

    size_t plain_len = (size_t)(BLOCK_SIZE - pad);
    if (plain_len > 0) {
        if (fwrite(block, 1, plain_len, out) != plain_len) {
            perror("fwrite last");
            fclose(in);
            fclose(out);
            return 1;
        }
    }

    fclose(in);
    fclose(out);
    return 0;
}








// ============================
//   MAIN (menu: 1=enc, 2=dec)
// ============================

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr,
                "Usage: %s <input_file_path> <output_file_path>\n",
                argv[0]);
        return 1;
    }

    const char *in_path  = argv[1];
    const char *out_path = argv[2];

    // انتخاب کاربر
    int choice = 0;
    printf("Select mode:\n");
    printf("  1) Encrypt\n");
    printf("  2) Decrypt\n");
    printf("Enter choice (1/2): ");
    if (scanf("%d", &choice) != 1) {
        fprintf(stderr, "Failed to read choice.\n");
        return 1;
    }

    // پاک کردن \n باقیمانده از scanf تا fgets درست کار کند
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}

    if (choice != 1 && choice != 2) {
        fprintf(stderr, "Invalid choice. Must be 1 or 2.\n");
        return 1;
    }

    // read key-64
    char key_in[KEYLEN + 4];
    uint8_t master_key[KEYLEN];

    printf("Enter a 64-character key (exactly 64 chars):\n");
    if (!fgets(key_in, sizeof(key_in), stdin)) {
        fprintf(stderr, "Failed to read key.\n");
        return 1;
    }

    // length of key and delete enter
    size_t klen = strcspn(key_in, "\r\n");
    key_in[klen] = '\0';

    if (klen != KEYLEN) {
        fprintf(stderr, "Error: key length is %zu, but must be exactly %d characters.\n", klen, KEYLEN);
        return 1;
    }

    // key = master key
    memcpy(master_key, key_in, KEYLEN);

    // encrypt/decrypt and timing
    double t0 = now_seconds();
    int rc;

    if (choice == 1) {
        rc = file_handling_enc(in_path, out_path, master_key);
    } else {
        rc = file_handling_dec(in_path, out_path, master_key);
    }

    double t1 = now_seconds();

    if (rc != 0) {
        fprintf(stderr, "%s failed.\n", (choice == 1) ? "Encryption" : "Decryption");
        return 1;
    }

    printf("Output file: %s\n", out_path);
    printf("Elapsed time: %.6f seconds\n", (t1 - t0));

    return 0;
}

