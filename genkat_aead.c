//
// NIST-developed software is provided by NIST as a public service.
// You may use, copy and distribute copies of the software in any medium,
// provided that you keep intact this entire notice. You may improve, 
// modify and create derivative works of the software or any portion of
// the software, and you may copy and distribute such modifications or
// works. Modified works should carry a notice stating that you changed
// the software and should note the date and nature of any such change.
// Please explicitly acknowledge the National Institute of Standards and 
// Technology as the source of the software.
//
// NIST-developed software is expressly provided "AS IS." NIST MAKES NO 
// WARRANTY OF ANY KIND, EXPRESS, IMPLIED, IN FACT OR ARISING BY OPERATION
// OF LAW, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT AND DATA ACCURACY. NIST
// NEITHER REPRESENTS NOR WARRANTS THAT THE OPERATION OF THE SOFTWARE WILL BE 
// UNINTERRUPTED OR ERROR-FREE, OR THAT ANY DEFECTS WILL BE CORRECTED. NIST 
// DOES NOT WARRANT OR MAKE ANY REPRESENTATIONS REGARDING THE USE OF THE SOFTWARE
// OR THE RESULTS THEREOF, INCLUDING BUT NOT LIMITED TO THE CORRECTNESS, ACCURACY,
// RELIABILITY, OR USEFULNESS OF THE SOFTWARE.
//
// You are solely responsible for determining the appropriateness of using and 
// distributing the software and you assume all risks associated with its use, 
// including but not limited to the risks and costs of program errors, compliance 
// with applicable laws, damage to or loss of data, programs or equipment, and 
// the unavailability or interruption of operation. This software is not intended
// to be used in any situation where a failure could cause risk of injury or 
// damage to property. The software developed by NIST employees is not subject to
// copyright protection within the United States.
//

// disable deprecation for sprintf and fopen
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>

#include "crypto_aead.h"
#include "api.h"

#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

#define MAX_FILE_NAME				256
#define MAX_MESSAGE_LENGTH			32
#define MAX_ASSOCIATED_DATA_LENGTH	32

void init_buffer(unsigned char *buffer, unsigned long long numbytes);

void fprint_bstr(FILE *fp, const char *label, const unsigned char *data, unsigned long long length);
void print_bstr(const char *label, const unsigned char *data, unsigned long long length);

int generate_test_vectors();

int main()
{


	int ret = generate_test_vectors();

	
}

int generate_test_vectors()
{
	OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings(); 

	FILE                *fp;
	char                fileName[MAX_FILE_NAME];
	unsigned char       key[CRYPTO_KEYBYTES];
	unsigned char		nonce[CRYPTO_NPUBBYTES];
	unsigned char       msg[MAX_MESSAGE_LENGTH];
	unsigned char       msg2[MAX_MESSAGE_LENGTH];
	unsigned char		ad[MAX_ASSOCIATED_DATA_LENGTH];
	unsigned char		ct[MAX_MESSAGE_LENGTH + CRYPTO_ABYTES];
	unsigned long long  clen, mlen2;
	int                 count = 1;
	int                 func_ret, ret_val = KAT_SUCCESS;
	//unsigned char tag[16];


	init_buffer(key, sizeof(key));
	init_buffer(nonce, sizeof(nonce));
	init_buffer(msg, sizeof(msg));
	init_buffer(ad, sizeof(ad));

	sprintf(fileName, "LWC_AEAD_KAT_%d_%d.txt", (CRYPTO_KEYBYTES * 8), (CRYPTO_NPUBBYTES * 8));

	if ((fp = fopen(fileName, "w")) == NULL) {
		fprintf(stderr, "Couldn't open <%s> for write\n", fileName);
		return KAT_FILE_OPEN_ERROR;
	}
	unsigned char tag[16];
	for (unsigned long long mlen = 0; (mlen <= MAX_MESSAGE_LENGTH) && (ret_val == KAT_SUCCESS); mlen++) {

	 	for (unsigned long long adlen = 0; adlen <= MAX_ASSOCIATED_DATA_LENGTH; adlen++) {
			

			fprintf(fp, "Count = %d\n", count++);

			fprint_bstr(fp, "Key = ", key, CRYPTO_KEYBYTES);

			fprint_bstr(fp, "Nonce = ", nonce, CRYPTO_NPUBBYTES);

			fprint_bstr(fp, "PT = ", msg, mlen);

			fprint_bstr(fp, "AD = ", ad, adlen);

			
			

			int decryptedtext_len = 0, ciphertext_len = 0;

			/* Encrypt the plaintext */
			ciphertext_len = encrypt_aes_ccm(msg, mlen, ad, adlen, key, nonce, ct, tag);

			
			/* Decrypt the ciphertext */
			decryptedtext_len = decrypt_aes_ccm(ct, ciphertext_len, ad, adlen, tag, key, nonce, msg2);
			
			
			fprint_bstr(fp, "CT = ",ct , ciphertext_len);
			if(decryptedtext_len < 0)
			{
				/* Verify error */
				printf("Decrypted text failed to verify\n");
			}
			else
			{
				/* Add a NULL terminator. We are expecting printable text */
				msg2[decryptedtext_len] = '\0';

				/* Show the decrypted text */
				//printf("Decrypted text is:\n");
				//printf("%s\n", decryptedtext);
			}
			fprint_bstr(fp, "PT2= ", msg2, decryptedtext_len);
			fprintf(fp, "\n");
			
	 	}
	}

	fclose(fp);

	return ret_val;
}


void fprint_bstr(FILE *fp, const char *label, const unsigned char *data, unsigned long long length)
{    
    fprintf(fp, "%s", label);
        
	for (unsigned long long i = 0; i < length; i++)
		fprintf(fp, "%02X", data[i]);
	    
    fprintf(fp, "\n");
}

void print_bstr(const char *label, const unsigned char *data, unsigned long long length)
{    
    printf("%s", label);
        
	for (unsigned long long i = 0; i < length; i++)
		printf("%02X", data[i]);
	    
    printf("\n");
}


void init_buffer(unsigned char *buffer, unsigned long long numbytes)
{
	for (unsigned long long i = 0; i < numbytes; i++)
		buffer[i] = (unsigned char)i;
}
