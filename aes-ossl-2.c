#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <string.h>   


// int encrypt_aes_gcm(unsigned char *plaintext, unsigned long long plaintext_len, unsigned char *aad,
//             unsigned long long aad_len, unsigned char *key, unsigned char *iv,
//             unsigned char *ciphertext, unsigned char *tag);

// int decrypt_aes_gcm(unsigned char *ciphertext, unsigned long long ciphertext_len, unsigned char *aad,
//             unsigned long long aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv,
//             unsigned char *plaintext);

// int main(int arc, char *argv[])
// {
//     OpenSSL_add_all_algorithms();
//     ERR_load_crypto_strings();     

//     /* Set up the key and iv. Do I need to say to not hard code these in a real application? :-) */

//     /* A 256 bit key */
//     static const unsigned char key[] = "01234567890123456789012345678901";

//     /* A 128 bit IV */
//     static const unsigned char iv[] = "0123456789012345";

//     /* Message to be encrypted */
//     unsigned char plaintext[] = "The quick brown fox jumps over the lazy dog";

//     /* Some additional data to be authenticated */
//     static const unsigned char aad[] = "Some AAD data";

//     /* Buffer for ciphertext. Ensure the buffer is long enough for the
//      * ciphertext which may be longer than the plaintext, dependant on the
//      * algorithm and mode
//      */
//     unsigned char ciphertext[128];

//     /* Buffer for the decrypted text */
//     unsigned char decryptedtext[128];
//     /* Buffer for the tag */
//     unsigned char tag[16];

//     int decryptedtext_len = 0, ciphertext_len = 0;

//     /* Encrypt the plaintext */
//     ciphertext_len = encrypt_aes_gcm(plaintext, strlen(plaintext), aad, strlen(aad), key, iv, ciphertext, tag);

//     /* Do something useful with the ciphertext here */
//     printf("Ciphertext is:\n");
//     BIO_dump_fp(stdout, ciphertext, ciphertext_len);
//     printf("Tag is:\n");
//     BIO_dump_fp(stdout, tag, 14);

//     /* Mess with stuff */
//     /* ciphertext[0] ^= 1; */
//     /* tag[0] ^= 1; */

//     /* Decrypt the ciphertext */
//     decryptedtext_len = decrypt_aes_gcm(ciphertext, ciphertext_len, aad, strlen(aad), tag, key, iv, decryptedtext);

//     if(decryptedtext_len < 0)
//     {
//         /* Verify error */
//         printf("Decrypted text failed to verify\n");
//     }
//     else
//     {
//         /* Add a NULL terminator. We are expecting printable text */
//         decryptedtext[decryptedtext_len] = '\0';

//         /* Show the decrypted text */
//         printf("Decrypted text is:\n");
//         printf("%s\n", decryptedtext);
//     }

//     /* Remove error strings */
//     ERR_free_strings();

//     return 0;
// }

void handleErrors(void)
{
    unsigned long errCode;

    printf("An error occurred\n");
    while(errCode = ERR_get_error())
    {
        char *err = ERR_error_string(errCode, NULL);
        printf("%s\n", err);
    }
    abort();
}

int encrypt_aes_ccm(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv,
                unsigned char *ciphertext,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;


    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL))
        handleErrors();

    /*
     * Setting IV len to 7. Not strictly necessary as this is the default
     * but shown here for the purposes of this example.
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 7, NULL))
        handleErrors();

    /* Set tag length */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 14, NULL);

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

    /* Provide the total plaintext length */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, NULL, plaintext_len))
        handleErrors();

    /* Provide any AAD data. This can be called zero or one times as required */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can only be called once for this.
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in CCM mode.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, 14, tag))
        handleErrors();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt_aes_ccm(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the decryption operation. */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL))
        handleErrors();

    /* Setting IV len to 7. Not strictly necessary as this is the default
     * but shown here for the purposes of this example */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 7, NULL))
        handleErrors();

    /* Set expected tag value. */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 14, tag))
        handleErrors();

    /* Initialise key and IV */
    if(1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();


    /* Provide the total ciphertext length */
    if(1 != EVP_DecryptUpdate(ctx, NULL, &len, NULL, ciphertext_len))
        handleErrors();

    /* Provide any AAD data. This can be called zero or more times as required */
    if(1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    ret = EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);

    plaintext_len = len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        /* Success */
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    }
}