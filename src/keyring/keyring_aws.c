#include "postgres.h"

#include <curl/curl.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "common/base64.h"
#include "common/jsonapi.h"
#include "mb/pg_wchar.h"

#include "keyring/keyring_api.h"
#include "keyring/keyring_aws.h"

#ifdef FRONTEND
#include "pg_tde_fe.h"
#else
#include "utils/builtins.h"
#endif

typedef struct
{
	char	   *key;
	char	   *val;
} Header;

static CURL	   *curl = NULL;

/*
 * Taken from src/bin/pg_combinebackup/write_manifest.c
 */
static void
escape_json(StringInfo buf, const char *str)
{
	const char *p;

	appendStringInfoCharMacro(buf, '"');
	for (p = str; *p; p++)
	{
		switch (*p)
		{
			case '\b':
				appendStringInfoString(buf, "\\b");
				break;
			case '\f':
				appendStringInfoString(buf, "\\f");
				break;
			case '\n':
				appendStringInfoString(buf, "\\n");
				break;
			case '\r':
				appendStringInfoString(buf, "\\r");
				break;
			case '\t':
				appendStringInfoString(buf, "\\t");
				break;
			case '"':
				appendStringInfoString(buf, "\\\"");
				break;
			case '\\':
				appendStringInfoString(buf, "\\\\");
				break;
			default:
				if ((unsigned char) *p < ' ')
					appendStringInfo(buf, "\\u%04x", (int) *p);
				else
					appendStringInfoCharMacro(buf, *p);
				break;
		}
	}
	appendStringInfoCharMacro(buf, '"');
}

#ifdef FRONTEND
/*
 * Taken from src/backend/utils/adt/encode.c
 */
static const char hextbl[512] =
"000102030405060708090a0b0c0d0e0f"
"101112131415161718191a1b1c1d1e1f"
"202122232425262728292a2b2c2d2e2f"
"303132333435363738393a3b3c3d3e3f"
"404142434445464748494a4b4c4d4e4f"
"505152535455565758595a5b5c5d5e5f"
"606162636465666768696a6b6c6d6e6f"
"707172737475767778797a7b7c7d7e7f"
"808182838485868788898a8b8c8d8e8f"
"909192939495969798999a9b9c9d9e9f"
"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
"b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
"d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
"e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

static uint64
hex_encode(const char *src, size_t len, char *dst)
{
	const char *end = src + len;

	while (src < end)
	{
		unsigned char usrc = *((const unsigned char *) src);

		memcpy(dst, &hextbl[2 * usrc], 2);
		src++;
		dst += 2;
	}
	return (uint64) len * 2;
}
#endif

static size_t
curl_write_func(void *ptr, size_t size, size_t nmemb, StringInfo buf)
{
	appendBinaryStringInfo(buf, ptr, size * nmemb);

	return size * nmemb;
}

static void
hmac_sha256(const char *data, const char *key, size_t keylen, char *out)
{
	unsigned int len;

	HMAC_CTX *ctx = HMAC_CTX_new();
	HMAC_Init_ex(ctx, key, keylen, EVP_sha256(), NULL);

	HMAC_Update(ctx, (const unsigned char *) data, strlen(data));

	HMAC_Final(ctx, (unsigned char *) out, &len);
	Assert(len == 32);

	HMAC_CTX_free(ctx);
}

static char *
aws_signature(const char *time, const char *date, const char *region, const char *method, const char *path, const Header *headers, size_t nheaders, const char *body, const char *secretkey)
{
	char		bodychecksum[32];
	char		hexbodychecksum[64];
	StringInfoData buf;
	char		checksum[32];
	char		hexchecksum[64];
	char	   *key;
	char		hmac[32];
	char	   *signstr;
	char	   *out;

	SHA256((unsigned char *) body, strlen(body), (unsigned char *) bodychecksum);
	hex_encode(bodychecksum, 32, hexbodychecksum);

	initStringInfo(&buf);

	appendStringInfo(&buf, "%s\n%s\n", method, path);

	for (int i = 0; i < nheaders; i++)
	{
		appendStringInfo(&buf, "%s:%s\n", headers[i].key, headers[i].val);
	}

	appendStringInfoChar(&buf, '\n');

	for (int i = 0; i < nheaders; i++)
	{
		appendStringInfo(&buf, "%s;", headers[i].key);
	}

	appendStringInfoChar(&buf, '\n');
	appendBinaryStringInfo(&buf, hexbodychecksum, 64);

	SHA256((unsigned char *) buf.data, buf.len, (unsigned char *) checksum);
	hex_encode(checksum, 32, hexchecksum);

	key = psprintf("AWS4%s", secretkey);

	hmac_sha256(date, key, strlen(key), hmac);
	hmac_sha256(region, hmac, 32, hmac);
	hmac_sha256("kms", hmac, 32, hmac);
	hmac_sha256("aws4_request", hmac, 32, hmac);

	signstr = psprintf("AWS4-HMAC-SHA256\n%s\n%s/%s/kms/aws4_request\n%.64s", time, date, region, hexchecksum);

	hmac_sha256(signstr, hmac, 32, hmac);

	out = palloc(32 * 2 + 1);
	hex_encode(hmac, 32, out);
	out[32 * 2] = '\0';

	return out;
}

#define CHECK_SETOPT(curl, opt, val) \
	do { \
		CURLcode	_result = curl_easy_setopt(curl, opt, val); \
		if (_result) \
			elog(ERROR, "failed to set %s on curl: %s", #opt, curl_easy_strerror(_result)); \
	} while (0)

static char *
call_api(const AwsKmsKeyring *keyring, const char *service, const char *body)
{
	char	   *url = psprintf("%s/", keyring->aws_server);
	Header		headers[4];
	time_t		now;
	struct tm  *gmnow;
	char		nowstr[] = "YYYYMMDDTHHMMSSZ";
	char		today[] = "YYYYMMDD";
	char	   *signed_headers = "host;content-type;x-amz-date;x-amz-target";
	char	   *signature;
	struct curl_slist *curl_headers = NULL;
	StringInfoData buf;
	CURLcode	result;
	long		http_code = 0;

	now = time(NULL);
	gmnow = gmtime(&now);
	strftime(nowstr, sizeof(nowstr), "%Y%m%dT%H%M%SZ", gmnow);
	memcpy(today, nowstr, strlen(today));

	headers[0].key = "host";
	headers[0].val = keyring->aws_server;
	headers[1].key = "content-type";
	headers[1].val = "application/x-amz-json-1.1";
	headers[2].key = "x-amz-date";
	headers[2].val = nowstr;
	headers[3].key = "x-amz-target";
	headers[3].val = psprintf("TrentService.%s", service);

	signature = aws_signature(nowstr, today, keyring->aws_region, "POST", "/", headers, 4, body, keyring->aws_secretkey);

	for (int i = 0; i < 4; i++)
		curl_headers = curl_slist_append(curl_headers, psprintf("%s: %s", headers[i].key, headers[i].val));

	curl_headers = curl_slist_append(curl_headers, psprintf("Authorization: AWS4-HMAC-SHA256 Credential=%s/%s/%s/kms/aws4_request, SignedHeaders=%s, Signature=%s",
															keyring->aws_keyid, today, keyring->aws_region, signed_headers, signature));

	if (curl == NULL)
	{
		curl = curl_easy_init();
		if (curl == NULL)
			elog(ERROR, "initializing curl context failed");
	}
	else
		curl_easy_reset(curl);

	CHECK_SETOPT(curl, CURLOPT_VERBOSE, 1);
	CHECK_SETOPT(curl, CURLOPT_URL, url);
	CHECK_SETOPT(curl, CURLOPT_HTTPHEADER, curl_headers);
	CHECK_SETOPT(curl, CURLOPT_POSTFIELDS, body);
	CHECK_SETOPT(curl, CURLOPT_WRITEDATA, &buf);
	CHECK_SETOPT(curl, CURLOPT_WRITEFUNCTION, curl_write_func);

	initStringInfo(&buf);

	result = curl_easy_perform(curl);
	if (result != CURLE_OK)
		ereport(ERROR, errmsg("TrentService.%s request to %s failed: %s", service, url, curl_easy_strerror(result)));

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

	if (!(http_code == 200 || http_code == 404))
		elog(ERROR, "%ld %s", http_code, buf.data);

	curl_slist_free_all(curl_headers);

	return buf.data;
}

typedef struct
{
	const char *field;
	int			level;

	char	   *plaintext; // Plaintext
	// KeyId
	// KeyMaterialId
	// CiphertextForRecipient
	// EncryptionAlgorithm
} ParseDecryptState;

static JsonParseErrorType
parse_decrypt_object_start(void *state)
{
	ParseDecryptState *ctx = state;

	ctx->level++;

	return JSON_SUCCESS;
}

static JsonParseErrorType
parse_decrypt_object_end(void *state)
{
	ParseDecryptState *ctx = state;

	ctx->level--;

	return JSON_SUCCESS;
}

static JsonParseErrorType
parse_decrypt_object_field_start(void *state, char *name, bool isnull)
{
	ParseDecryptState *ctx = state;

	ctx->field = name;

	return JSON_SUCCESS;
}

static JsonParseErrorType
parse_decrypt_scalar(void *state, char *token, JsonTokenType type)
{
	ParseDecryptState *ctx = state;

	if (ctx->level == 1)
	{
		if (strcmp(ctx->field, "Plaintext") && type == JSON_TOKEN_STRING)
			ctx->plaintext = token;
	}

	return JSON_SUCCESS;
}

static JsonParseErrorType
parse_decrypt(ParseDecryptState *state, JsonLexContext *lex)
{
	JsonSemAction sem = {
		.semstate = state,
		.object_start = parse_decrypt_object_start,
		.object_end = parse_decrypt_object_end,
		.object_field_start = parse_decrypt_object_field_start,
		.array_start = parse_decrypt_object_start,
		.array_end = parse_decrypt_object_end,
		.scalar = parse_decrypt_scalar,
	};

	state->field = NULL;
	state->level = 0;
	state->plaintext = NULL;

	return pg_parse_json(lex, &sem);
}

static KeyData *
get_key_by_name(GenericKeyring *keyring, const char *key_name, KeyringReturnCode *return_code)
{
	AwsKmsKeyring *aws_keyring = (AwsKmsKeyring *) keyring;
	unsigned char *enc_key_data = {0};
	size_t		enc_key_len = 0;
	char		b64_enc_key_data[64];
	size_t		b64_enc_key_len;
	StringInfoData buf;
	char	   *response;
	JsonLexContext *jlex;
	JsonParseErrorType json_error;
	ParseDecryptState parse;

	// TODO: Handle error and length
#if PG_VERSION_NUM >= 180000
	b64_enc_key_len = pg_b64_encode(enc_key_data, enc_key_len, b64_enc_key_data, 64);
#else
	b64_enc_key_len = pg_b64_encode((char *) enc_key_data, enc_key_len, b64_enc_key_data, 64);
#endif
	b64_enc_key_data[b64_enc_key_len] = 0;

	initStringInfo(&buf);
	appendStringInfoChar(&buf, '{');
	escape_json(&buf, "KeyId");
	appendStringInfoChar(&buf, ':');
	escape_json(&buf, aws_keyring->aws_keyid);
	escape_json(&buf, "CiphertextBlob");
	appendStringInfoChar(&buf, ':');
	escape_json(&buf, b64_enc_key_data);
	appendStringInfoChar(&buf, '}');

	response = call_api(aws_keyring, "Decrypt", buf.data);

#if PG_VERSION_NUM >= 170000
	jlex = makeJsonLexContextCstringLen(NULL, response, strlen(response), PG_UTF8, true);
#else
	jlex = makeJsonLexContextCstringLen(response, strlen(response), PG_UTF8, true);
#endif

	json_error = parse_decrypt(&parse, jlex);

#if PG_VERSION_NUM >= 170000
	freeJsonLexContext(jlex);
#endif

	elog(ERROR, "got %s", response);
}

typedef struct
{
	const char *field;
	int			level;

	char	   *plaintext; // Plaintext
	char	   *ciphertext; // CiphertextBlob
	// KeyId
	// KeyMaterialId
	// CiphertextForRecipient
} ParseGenerateDataKeyState;

static JsonParseErrorType
parse_generate_data_key_object_start(void *state)
{
	ParseGenerateDataKeyState *ctx = state;

	ctx->level++;

	return JSON_SUCCESS;
}

static JsonParseErrorType
parse_generate_data_key_object_end(void *state)
{
	ParseGenerateDataKeyState *ctx = state;

	ctx->level--;

	return JSON_SUCCESS;
}

static JsonParseErrorType
parse_generate_data_key_object_field_start(void *state, char *name, bool isnull)
{
	ParseGenerateDataKeyState *ctx = state;

	ctx->field = name;

	return JSON_SUCCESS;
}

static JsonParseErrorType
parse_generate_data_key_scalar(void *state, char *token, JsonTokenType type)
{
	ParseGenerateDataKeyState *ctx = state;

	if (ctx->level == 1)
	{
		if (strcmp(ctx->field, "Plaintext") && type == JSON_TOKEN_STRING)
			ctx->plaintext = token;
		else if (strcmp(ctx->field, "CiphertextBlob") && type == JSON_TOKEN_STRING)
			ctx->ciphertext = token;
	}

	return JSON_SUCCESS;
}

static JsonParseErrorType
parse_generate_data_key(ParseGenerateDataKeyState *state, JsonLexContext *lex)
{
	JsonSemAction sem = {
		.semstate = state,
		.object_start = parse_generate_data_key_object_start,
		.object_end = parse_generate_data_key_object_end,
		.object_field_start = parse_generate_data_key_object_field_start,
		.array_start = parse_generate_data_key_object_start,
		.array_end = parse_generate_data_key_object_end,
		.scalar = parse_generate_data_key_scalar,
	};

	state->field = NULL;
	state->level = 0;
	state->plaintext = NULL;
	state->ciphertext = NULL;

	return pg_parse_json(lex, &sem);
}

static void
set_key_by_name(GenericKeyring *keyring, const char *key_name, const KeyData *key)
{
	AwsKmsKeyring *aws_keyring = (AwsKmsKeyring *) keyring;
	StringInfoData buf;
	char	   *response;
	JsonLexContext *jlex;
	JsonParseErrorType json_error;
	ParseGenerateDataKeyState parse;

	initStringInfo(&buf);
	appendStringInfoChar(&buf, '{');
	escape_json(&buf, "KeyId");
	appendStringInfoChar(&buf, ':');
	escape_json(&buf, aws_keyring->aws_keyid);
	appendStringInfoChar(&buf, '}');

	response = call_api(aws_keyring, "GenerateDataKey", buf.data);

#if PG_VERSION_NUM >= 170000
	jlex = makeJsonLexContextCstringLen(NULL, response, strlen(response), PG_UTF8, true);
#else
	jlex = makeJsonLexContextCstringLen(response, strlen(response), PG_UTF8, true);
#endif

	json_error = parse_generate_data_key(&parse, jlex);

#if PG_VERSION_NUM >= 170000
	freeJsonLexContext(jlex);
#endif

	elog(ERROR, "got %s", response);
}

static void
validate(GenericKeyring *keyring)
{
}

static const TDEKeyringRoutine keyringRoutine = {
	.keyring_get_key = get_key_by_name,
	.keyring_store_key = set_key_by_name,
	.keyring_validate = validate,
};

void
InstallAwsKmsKeyring(void)
{
	RegisterKeyProviderType(&keyringRoutine, AWS_KMS_KEY_PROVIDER);
}
