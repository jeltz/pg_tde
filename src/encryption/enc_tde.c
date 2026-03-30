#include "postgres.h"

#include <openssl/err.h>
#include <openssl/rand.h>

#include "encryption/enc_tde.h"
#include "encryption/enc_aes.h"

#ifdef FRONTEND
#include "pg_tde_fe.h"
#endif

#define AES_BLOCK_SIZE 		        16
#define NUM_AES_BLOCKS_IN_BATCH     (1024 / 16)
#define DATA_BYTES_PER_AES_BATCH    (NUM_AES_BLOCKS_IN_BATCH * AES_BLOCK_SIZE)

#ifdef ENCRYPTION_DEBUG
static void
iv_prefix_debug(const char *iv_prefix, char *out_hex)
{
	for (int i = 0; i < 16; ++i)
	{
		sprintf(out_hex + i * 2, "%02x", (int) *(iv_prefix + i));
	}
	out_hex[32] = 0;
}
#endif

uint32
pg_tde_cipher_key_length(CipherType cipher)
{
	switch (cipher)
	{
		case CIPHER_AES_128:
			return KEY_DATA_SIZE_128;
		case CIPHER_AES_256:
			return KEY_DATA_SIZE_256;

		default:
			elog(ERROR, "failed to get key size from the unknown cipher %d",
				 cipher);
	}
}

void
pg_tde_generate_internal_key(InternalKey *int_key, int key_len)
{
	Assert(key_len == 16 || key_len == 32);

	/*
	 * key_len might be less then a size of the memory allocated for the key,
	 * so zero it just in case.
	 */
	memset(&int_key->key, 0, sizeof(int_key->key));

	if (!RAND_bytes(int_key->key, key_len))
		ereport(ERROR,
				errcode(ERRCODE_INTERNAL_ERROR),
				errmsg("could not generate internal key: %s",
					   ERR_error_string(ERR_get_error(), NULL)));
	if (!RAND_bytes(int_key->base_iv, INTERNAL_KEY_IV_LEN))
		ereport(ERROR,
				errcode(ERRCODE_INTERNAL_ERROR),
				errmsg("could not generate IV: %s",
					   ERR_error_string(ERR_get_error(), NULL)));

	int_key->key_len = key_len;
}

/*
 * Encrypts/decrypts `data` with a given `key`. The result is written to `out`.
 *
 * start_offset: is the absolute location of start of data in the file.
 */
void
pg_tde_stream_crypt(const char *iv_prefix,
					uint32 start_offset,
					const char *data,
					uint32 data_len,
					char *out,
					const uint8 *key,
					int key_len,
					void **ctxPtr)
{
	const uint64 aes_start_block = start_offset / AES_BLOCK_SIZE;
	const uint64 aes_end_block = (start_offset + data_len) / AES_BLOCK_SIZE;
	uint32		batch_no = 0;
	uint32		data_index = 0;

	Assert(start_offset % DATA_BYTES_PER_AES_BATCH == 0);
	Assert(data_len % DATA_BYTES_PER_AES_BATCH == 0);

	/* do max NUM_AES_BLOCKS_IN_BATCH blocks at a time */
	for (uint64 batch_start_block = aes_start_block; batch_start_block < aes_end_block; batch_start_block += NUM_AES_BLOCKS_IN_BATCH)
	{
		unsigned char enc_key[DATA_BYTES_PER_AES_BATCH];
		uint64		batch_end_block = batch_start_block + NUM_AES_BLOCKS_IN_BATCH;

		AesCtrEncryptedZeroBlocks(ctxPtr, key, key_len, iv_prefix, batch_start_block, batch_end_block, enc_key);

#ifdef ENCRYPTION_DEBUG
		{
			char		ivp_debug[33];

			iv_prefix_debug(iv_prefix, ivp_debug);
			ereport(LOG,
					errmsg("pg_tde_stream_crypt batch_no: %d start_offset: %lu data_len: %u, batch_start_block: %lu, batch_end_block: %lu, iv_prefix: %s",
						   batch_no, start_offset, data_len, batch_start_block, batch_end_block, ivp_debug));
		}
#endif

		for (uint32 i = 0; i < DATA_BYTES_PER_AES_BATCH; i++)
		{
			out[data_index] = data[data_index] ^ enc_key[i];

			data_index++;
		}
		batch_no++;
	}
}
