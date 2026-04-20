#include "postgres.h"

#include <openssl/err.h>
#include <openssl/rand.h>

#include "access/xlog.h"
#include "access/xlog_internal.h"
#include "access/xloginsert.h"
#include "common/file_perm.h"
#include "miscadmin.h"
#include "storage/fd.h"
#include "utils/builtins.h"
#include "utils/memutils.h"
#include "utils/wait_event.h"

#include "access/pg_tde_tdemap.h"
#include "access/pg_tde_xlog.h"
#include "catalog/tde_global_space.h"
#include "catalog/tde_principal_key.h"
#include "common/pg_tde_utils.h"
#include "encryption/enc_aes.h"
#include "encryption/enc_tde.h"
#include "keyring/keyring_api.h"
#include "pg_tde.h"

#ifdef FRONTEND
#include "pg_tde_fe.h"
#endif

/* A useful macro when debugging key encryption/decryption */
#ifdef DEBUG
#define ELOG_KEY(_msg, _key)												\
{																			\
	int i;																	\
	char buf[1024];															\
	for (i = 0; i < sizeof(_key.key); i++)					\
		sprintf(buf+i, "%02X", _key.key[i]);				\
	buf[i] = '\0';															\
	elog(INFO, "[%s] INTERNAL KEY => %s", _msg, buf);						\
}
#endif

#define PG_TDE_MAP_DIRNAME			"%d_keys"
#define PG_TDE_MAP_FILENAME			"principal"

typedef enum
{
	MAP_ENTRY_TYPE_EMPTY = 0,
	MAP_ENTRY_TYPE_KEY = 1,
}			TDEMapEntryType;

typedef struct TDEFileHeader
{
	int32		file_version;
	TDESignedPrincipalKeyInfo signed_key_info;
} TDEFileHeader;

typedef struct TDEMapEntry
{
	uint32		cipher;			/* Part of AAD. Cipher type. We support only
								 * AES_128 and AES_256 for now. */
	Oid			spcOid;			/* Part of AAD */
	RelFileNumber relNumber;	/* Part of AAD */
	uint32		type;			/* Part of AAD */

	/*
	 * IV and tag used when encrypting the key itself
	 *
	 * TODO: should we extend MAP_ENTRY_IV_SIZE to 192(?) bit and add an
	 * iv_size filed?
	 */
	unsigned char entry_iv[MAP_ENTRY_IV_SIZE];
	unsigned char aead_tag[MAP_ENTRY_AEAD_TAG_SIZE];

	uint8		key_base_iv[INTERNAL_KEY_IV_LEN];
	uint8		encrypted_key_data[INTERNAL_KEY_MAX_LEN];
} TDEMapEntry;

static void pg_tde_set_key_dir_path(Oid dbOid, char *path);
static void pg_tde_set_key_file_path(const RelFileLocator *rel, char *path);
static void pg_tde_set_db_file_path(Oid dbOid, char *path);
static InternalKey *tde_decrypt_rel_key(const TDEPrincipalKey *principal_key, TDEMapEntry *map_entry);
static int	pg_tde_open_file_basic(const char *tde_filename, int fileFlags, bool ignore_missing);
static void pg_tde_file_header_read(const char *tde_filename, int fd, TDEFileHeader *fheader, off_t *bytes_read);
static void pg_tde_read_key_file(int fd, TDEMapEntry *map_entry);

#ifndef FRONTEND
static void pg_tde_write_one_map_entry(int fd, const TDEMapEntry *map_entry, off_t *offset, const char *db_map_path);
static int	pg_tde_file_header_write(const char *tde_filename, int fd, const TDESignedPrincipalKeyInfo *signed_key_info, off_t *bytes_written);
static void pg_tde_initialize_map_entry(TDEMapEntry *map_entry, const TDEPrincipalKey *principal_key, const RelFileLocator *rlocator, const InternalKey *rel_key_data);
static int	pg_tde_open_file_write(const char *tde_filename, const TDESignedPrincipalKeyInfo *signed_key_info, bool truncate, off_t *curr_pos);

/*
 * Saves an internal key for the given relation. If replace_existing is false,
 * the function will not overwrite an existing key for the relation, but will
 * instead do nothing.
 */
void
pg_tde_save_smgr_key(RelFileLocator rel,
					 const InternalKey *rel_key_data,
					 bool replace_existing)
{
	char		file_path[MAXPGPATH];
	TDEPrincipalKey *principal_key;
	int			fd;
	TDEMapEntry write_entry;
	off_t		write_offset = 0;
	LWLock	   *lock_pk = tde_lwlock_enc_keys();

	pg_tde_set_key_file_path(&rel, file_path);

	LWLockAcquire(lock_pk, LW_EXCLUSIVE);
	principal_key = GetPrincipalKey(rel.dbOid, LW_EXCLUSIVE);
	if (principal_key == NULL)
	{
		ereport(ERROR,
				errmsg("principal key not configured"),
				errhint("Use pg_tde_set_key_using_database_key_provider() or pg_tde_set_key_using_global_key_provider() to configure one."));
	}

	if (replace_existing)
		fd = OpenTransientFile(file_path, O_CREAT | O_WRONLY | PG_BINARY);
	else
	{
		fd = OpenTransientFile(file_path, O_CREAT | O_WRONLY | PG_BINARY | O_EXCL);
		if (fd < 0 && errno == EEXIST)
		{
			LWLockRelease(lock_pk);
			return;
		}
	}

	if (fd < 0)
		elog(ERROR, "failed to open key files \"%s\": %m", file_path);

	pg_tde_initialize_map_entry(&write_entry, principal_key, &rel, rel_key_data);
	pg_tde_write_one_map_entry(fd, &write_entry, &write_offset, file_path);

	CloseTransientFile(fd);

	LWLockRelease(lock_pk);
}

const char *
tde_sprint_key(InternalKey *k)
{
	static char buf[256];
	int			i;

	for (i = 0; i < sizeof(k->key); i++)
		sprintf(buf + i, "%02X", k->key[i]);

	return buf;
}

/*
 * Deletes the key file for a given database.
 */
void
pg_tde_delete_tde_files(Oid dbOid)
{
	char		db_map_path[MAXPGPATH];

	pg_tde_set_db_file_path(dbOid, db_map_path);

	/* Remove file without emitting any error */
	PathNameDeleteTemporaryFile(db_map_path, false);
}

void
pg_tde_save_principal_key_redo(const TDESignedPrincipalKeyInfo *signed_key_info)
{
	int			map_fd;
	off_t		curr_pos = 0;
	char		dir_path[MAXPGPATH];
	char		db_map_path[MAXPGPATH];

	pg_tde_set_key_dir_path(signed_key_info->data.databaseId, dir_path);
	pg_tde_set_db_file_path(signed_key_info->data.databaseId, db_map_path);

	LWLockAcquire(tde_lwlock_enc_keys(), LW_EXCLUSIVE);

	if (MakePGDirectory(dir_path) < 0 && errno != EEXIST)
		ereport(ERROR,
			errcode_for_file_access(),
			errmsg("could not create tde key directory \"%s\": %m", dir_path));

	map_fd = pg_tde_open_file_write(db_map_path, signed_key_info, false, &curr_pos);
	CloseTransientFile(map_fd);

	LWLockRelease(tde_lwlock_enc_keys());
}

/*
 * Creates the key file and saves the principal key information.
 *
 * If the file pre-exist, it truncates the file before adding principal key
 * information.
 *
 * The caller must have an EXCLUSIVE LOCK on the files before calling this function.
 *
 * write_xlog: if true, the function will write an XLOG record about the
 * principal key addition. We may want to skip this during server recovery/startup
 * or in some other cases when WAL writes are not allowed.
 */
void
pg_tde_save_principal_key(const TDEPrincipalKey *principal_key, bool write_xlog)
{
	int			map_fd;
	off_t		curr_pos = 0;
	char		dir_path[MAXPGPATH];
	char		db_map_path[MAXPGPATH];
	TDESignedPrincipalKeyInfo signed_key_info;

	pg_tde_set_key_dir_path(principal_key->keyInfo.databaseId, dir_path);
	pg_tde_set_db_file_path(principal_key->keyInfo.databaseId, db_map_path);

	pg_tde_sign_principal_key_info(&signed_key_info, principal_key);

	if (write_xlog)
	{
		XLogBeginInsert();
		XLogRegisterData((char *) &signed_key_info, sizeof(TDESignedPrincipalKeyInfo));
		XLogInsert(RM_TDERMGR_ID, XLOG_TDE_ADD_PRINCIPAL_KEY);
	}

	if (MakePGDirectory(dir_path) < 0 && errno != EEXIST)
		ereport(ERROR,
			errcode_for_file_access(),
			errmsg("could not create tde key directory \"%s\": %m", dir_path));

	map_fd = pg_tde_open_file_write(db_map_path, &signed_key_info, true, &curr_pos);
	CloseTransientFile(map_fd);
}

/*
 * Mark relation map entry as free and overwrite the key
 *
 * This fucntion is called by the pg_tde SMGR when storage is unlinked on
 * transaction commit/abort.
 */
void
pg_tde_free_key_map_entry(const RelFileLocator rlocator)
{
	char		file_path[MAXPGPATH];

	pg_tde_set_key_file_path(&rlocator, file_path);

	LWLockAcquire(tde_lwlock_enc_keys(), LW_EXCLUSIVE);

	if (unlink(file_path) == -1 && errno != ENOENT)
		elog(ERROR, "removing key file \"%s\" failed: %m", file_path);

	LWLockRelease(tde_lwlock_enc_keys());
}

/*
 * Rotate keys and generates the WAL record for it.
 */
void
pg_tde_perform_rotate_key(const TDEPrincipalKey *principal_key, const TDEPrincipalKey *new_principal_key, bool write_xlog)
{
	TDESignedPrincipalKeyInfo new_signed_key_info;
	char		old_path[MAXPGPATH];
	char		new_path[MAXPGPATH];
	char		new_pk_path[MAXPGPATH];
	DIR		   *old_dir;
	off_t		curr_pos = 0;
	int			new_pk_fd;
	struct dirent *dirent;

	/* This function cannot be used to rotate the server key. */
	Assert(principal_key);
	Assert(principal_key->keyInfo.databaseId != GLOBAL_DATA_TDE_OID);

	pg_tde_sign_principal_key_info(&new_signed_key_info, new_principal_key);

	pg_tde_set_key_dir_path(principal_key->keyInfo.databaseId, old_path);
	snprintf(new_path, MAXPGPATH, "%s.r", old_path); // TODO: better name?
	snprintf(new_pk_path, MAXPGPATH, "%s/%s", new_path, PG_TDE_MAP_FILENAME);

	// TODO: Handle errors
	old_dir = opendir(old_path);

	// TODO: Remove posisble old temporary dirctory

	// TODO: Handle errors
	MakePGDirectory(new_path);

	new_pk_fd = pg_tde_open_file_write(new_pk_path, &new_signed_key_info, true, &curr_pos);
	CloseTransientFile(new_pk_fd);

	// TODO: Handle errors
	while ((dirent = readdir(old_dir)) != NULL)
	{
		char		read_path[MAXPGPATH];
		char		write_path[MAXPGPATH];
		int			read_fd;
		int			write_fd;
		InternalKey *rel_key_data;
		TDEMapEntry read_map_entry,
					write_map_entry;
		RelFileLocator rloc;
		off_t		new_curr_pos = 0;

		if (strcmp(dirent->d_name, ".") == 0 ||
			strcmp(dirent->d_name, "..") == 0 ||
			strcmp(dirent->d_name, PG_TDE_MAP_FILENAME) == 0)
			continue;

		sprintf(read_path, "%s/%s", old_path, dirent->d_name);

		// TODO: Handle errors
		read_fd = OpenTransientFile(read_path, O_RDONLY | PG_BINARY);

		pg_tde_read_key_file(read_fd, &read_map_entry);

		CloseTransientFile(read_fd);

		rloc.spcOid = read_map_entry.spcOid;
		rloc.dbOid = principal_key->keyInfo.databaseId;
		rloc.relNumber = read_map_entry.relNumber;

		/* Decrypt and re-encrypt key */
		rel_key_data = tde_decrypt_rel_key(principal_key, &read_map_entry);
		pg_tde_initialize_map_entry(&write_map_entry, new_principal_key, &rloc, rel_key_data);

		sprintf(write_path, "%s/%s", new_path, dirent->d_name);

		// TODO: Handle errors
		write_fd = OpenTransientFile(write_path, O_CREAT | O_WRONLY | PG_BINARY);

		pg_tde_write_one_map_entry(write_fd, &write_map_entry, &new_curr_pos, write_path);

		CloseTransientFile(write_fd);

		pfree(rel_key_data);
	}

	closedir(old_dir);

	// TODO: Wrong as fuck
	rmtree(old_path, true);
	rename(new_path, old_path);

	/*
	 * We do WAL writes past the event ("the write behind logging") rather
	 * than before ("the write ahead") because we need logging here only for
	 * replication purposes. The rotation results in data written and fsynced
	 * to disk. Which in most cases would happen way before it's written to
	 * the WAL disk file. As WAL will be flushed at the end of the
	 * transaction, on its commit, hence after this function returns (there is
	 * also a bg writer, but the commit is what is guaranteed). And it makes
	 * sense to replicate the event only after its effect has been
	 * successfully applied to the source.
	 */
	if (write_xlog)
	{
		XLogPrincipalKeyRotate xlrec;

		xlrec.databaseId = new_principal_key->keyInfo.databaseId;
		xlrec.keyringId = new_principal_key->keyInfo.keyringId;
		memcpy(xlrec.keyName, new_principal_key->keyInfo.name, sizeof(new_principal_key->keyInfo.name));

		XLogBeginInsert();
		XLogRegisterData((char *) &xlrec, sizeof(XLogPrincipalKeyRotate));
		XLogInsert(RM_TDERMGR_ID, XLOG_TDE_ROTATE_PRINCIPAL_KEY);
	}
}

void
pg_tde_delete_principal_key_redo(Oid dbOid)
{
	char		path[MAXPGPATH];

	pg_tde_set_key_dir_path(dbOid, path);

	LWLockAcquire(tde_lwlock_enc_keys(), LW_EXCLUSIVE);
	// TODO: Wrong as fuck
	if (access(path, F_OK) != -1)
		rmtree(path, false);
	LWLockRelease(tde_lwlock_enc_keys());
}

/*
 * Deletes the principal key for the database. This fucntion checks if key map
 * file has any entries, and if not, it removes the file. Otherwise raises an error.
 */
void
pg_tde_delete_principal_key(Oid dbOid)
{
	char		path[MAXPGPATH];

	Assert(LWLockHeldByMeInMode(tde_lwlock_enc_keys(), LW_EXCLUSIVE));
	Assert(pg_tde_count_encryption_keys(dbOid, InvalidOid) == 0);

	pg_tde_set_key_dir_path(dbOid, path);

	XLogBeginInsert();
	XLogRegisterData((char *) &dbOid, sizeof(Oid));
	XLogInsert(RM_TDERMGR_ID, XLOG_TDE_DELETE_PRINCIPAL_KEY);

	// TODO: Wrong as fuck
	if (access(path, F_OK) != -1)
		rmtree(path, false);
}

#endif							/* !FRONTEND */

static void
pg_tde_set_key_dir_path(Oid dbOid, char *path)
{
	snprintf(path, MAXPGPATH, "%s/" PG_TDE_MAP_DIRNAME, pg_tde_get_data_dir(), dbOid);
}

static void
pg_tde_set_key_file_path(const RelFileLocator *rel, char *path)
{
	snprintf(path, MAXPGPATH, "%s/%d_keys/%d_%d", pg_tde_get_data_dir(), rel->dbOid, rel->spcOid, rel->relNumber);
}

static void
pg_tde_set_db_file_path(Oid dbOid, char *path)
{
	snprintf(path, MAXPGPATH, "%s/" PG_TDE_MAP_DIRNAME "/" PG_TDE_MAP_FILENAME, pg_tde_get_data_dir(), dbOid);
}

void
pg_tde_sign_principal_key_info(TDESignedPrincipalKeyInfo *signed_key_info, const TDEPrincipalKey *principal_key)
{
	signed_key_info->data = principal_key->keyInfo;

	if (!RAND_bytes(signed_key_info->sign_iv, MAP_ENTRY_IV_SIZE))
		ereport(ERROR,
				errcode(ERRCODE_INTERNAL_ERROR),
				errmsg("could not generate iv for key map: %s", ERR_error_string(ERR_get_error(), NULL)));

	AesGcmEncrypt(principal_key->keyData, principal_key->keyLength,
				  signed_key_info->sign_iv, MAP_ENTRY_IV_SIZE,
				  (unsigned char *) &signed_key_info->data, sizeof(signed_key_info->data),
				  (unsigned char *) "", 0,
				  (unsigned char *) "",
				  signed_key_info->aead_tag, MAP_ENTRY_AEAD_TAG_SIZE);
}

#ifndef FRONTEND
static void
pg_tde_initialize_map_entry(TDEMapEntry *map_entry, const TDEPrincipalKey *principal_key, const RelFileLocator *rlocator, const InternalKey *rel_key_data)
{
	map_entry->spcOid = rlocator->spcOid;
	map_entry->relNumber = rlocator->relNumber;
	map_entry->type = MAP_ENTRY_TYPE_KEY;
	memcpy(map_entry->key_base_iv, rel_key_data->base_iv, INTERNAL_KEY_IV_LEN);

	Assert(rel_key_data->key_len == 16 || rel_key_data->key_len == 32);
	map_entry->cipher = rel_key_data->key_len == 32 ? CIPHER_AES_256 : CIPHER_AES_128;	/* We support only those
																						 * for now */

	if (!RAND_bytes(map_entry->entry_iv, MAP_ENTRY_IV_SIZE))
		ereport(ERROR,
				errcode(ERRCODE_INTERNAL_ERROR),
				errmsg("could not generate iv for key map: %s", ERR_error_string(ERR_get_error(), NULL)));

	AesGcmEncrypt(principal_key->keyData, principal_key->keyLength,
				  map_entry->entry_iv, MAP_ENTRY_IV_SIZE,
				  (unsigned char *) map_entry, offsetof(TDEMapEntry, entry_iv),
				  rel_key_data->key, rel_key_data->key_len,
				  map_entry->encrypted_key_data,
				  map_entry->aead_tag, MAP_ENTRY_AEAD_TAG_SIZE);
}
#endif

#ifndef FRONTEND
static void
pg_tde_write_one_map_entry(int fd, const TDEMapEntry *map_entry, off_t *offset, const char *db_map_path)
{
	int			bytes_written = 0;

	bytes_written = pg_pwrite(fd, map_entry, sizeof(TDEMapEntry), *offset);

	if (bytes_written != sizeof(TDEMapEntry))
	{
		ereport(ERROR,
				errcode_for_file_access(),
				errmsg("could not write tde map file \"%s\": %m", db_map_path));
	}
	if (pg_fsync(fd) != 0)
	{
		ereport(data_sync_elevel(ERROR),
				errcode_for_file_access(),
				errmsg("could not fsync file \"%s\": %m", db_map_path));
	}

	*offset += bytes_written;
}
#endif

/*
 * Counts number of encryption keys in a key file.
 *
 * Does not check if objects actually exist but just that they have keys in
 * the key file.
 *
 * Works even if the database has no key directory.
 */
int
pg_tde_count_encryption_keys(Oid dbOid, Oid spcOid)
{
	char		dir_path[MAXPGPATH];
	DIR		   *dir;
	int			count = 0;
	char		spcoid_string[MAXPGPATH]; // TODO: Sane size
	struct dirent *dirent;

	Assert(LWLockHeldByMeInMode(tde_lwlock_enc_keys(), LW_SHARED) || LWLockHeldByMeInMode(tde_lwlock_enc_keys(), LW_EXCLUSIVE));

	pg_tde_set_key_dir_path(dbOid, dir_path);

	dir = opendir(dir_path);
	if (dir == NULL) // TODO: Handle errors
		return count;

	if (spcOid != InvalidOid)
		sprintf(spcoid_string, "%u", spcOid);

	// TODO: Error handling
	while ((dirent = readdir(dir)) != NULL)
	{
		if (spcOid != InvalidOid && strncmp(dirent->d_name, spcoid_string, strlen(spcoid_string)) != 0)
			continue;

		// TODO: More exact check?
		if (strcmp(dirent->d_name, ".") == 0 ||
			strcmp(dirent->d_name, "..") == 0 ||
			strcmp(dirent->d_name, PG_TDE_MAP_FILENAME) == 0)
			continue;

		count++;
	}

	closedir(dir);

	return count;
}

bool
pg_tde_verify_principal_key_info(TDESignedPrincipalKeyInfo *signed_key_info, const KeyData *principal_key_data)
{
	return AesGcmDecrypt(principal_key_data->data, principal_key_data->len,
						 signed_key_info->sign_iv, MAP_ENTRY_IV_SIZE,
						 (unsigned char *) &signed_key_info->data, sizeof(signed_key_info->data),
						 (unsigned char *) "", 0,
						 (unsigned char *) "",
						 signed_key_info->aead_tag, MAP_ENTRY_AEAD_TAG_SIZE);
}

static InternalKey *
tde_decrypt_rel_key(const TDEPrincipalKey *principal_key, TDEMapEntry *map_entry)
{
	InternalKey *key = palloc_object(InternalKey);
	uint32		key_len = pg_tde_cipher_key_length(map_entry->cipher);

	Assert(principal_key);

	if (!AesGcmDecrypt(principal_key->keyData, principal_key->keyLength,
					   map_entry->entry_iv, MAP_ENTRY_IV_SIZE,
					   (unsigned char *) map_entry, offsetof(TDEMapEntry, entry_iv),
					   map_entry->encrypted_key_data, key_len,
					   key->key,
					   map_entry->aead_tag, MAP_ENTRY_AEAD_TAG_SIZE))
		ereport(ERROR,
				errmsg("Failed to decrypt key, incorrect principal key or corrupted key file"));

	memcpy(key->base_iv, map_entry->key_base_iv, INTERNAL_KEY_IV_LEN);
	key->key_len = key_len;

	return key;
}

/*
 * Open a TDE file:
 *
 * Returns the file descriptor in case of a success. Otherwise, error
 * is raised except when ignore_missing is true and the file does not exit.
 */
static int
pg_tde_open_file_basic(const char *tde_filename, int fileFlags, bool ignore_missing)
{
	int			fd;

	fd = OpenTransientFile(tde_filename, fileFlags);
	if (fd < 0 && !(errno == ENOENT && ignore_missing == true))
	{
		ereport(ERROR,
				errcode_for_file_access(),
				errmsg("could not open tde file \"%s\": %m", tde_filename));
	}

	return fd;
}

#ifndef FRONTEND
/*
 * Open for write and Validate File Header:
 * 		header: {Format Version, Principal Key Name}
 *
 * Returns the file descriptor in case of a success. Otherwise, error
 * is raised.
 */
static int
pg_tde_open_file_write(const char *tde_filename, const TDESignedPrincipalKeyInfo *signed_key_info, bool truncate, off_t *curr_pos)
{
	int			fd;
	TDEFileHeader fheader;
	off_t		bytes_read = 0;
	off_t		bytes_written = 0;
	int			file_flags = O_RDWR | O_CREAT | PG_BINARY | (truncate ? O_TRUNC : 0);

	Assert(LWLockHeldByMeInMode(tde_lwlock_enc_keys(), LW_EXCLUSIVE));

	fd = pg_tde_open_file_basic(tde_filename, file_flags, false);

	pg_tde_file_header_read(tde_filename, fd, &fheader, &bytes_read);
	if (bytes_read > 0 && fheader.file_version != PG_TDE_SMGR_FILE_MAGIC)
		ereport(FATAL,
				errcode_for_file_access(),
				errmsg("key file \"%s\" has wrong version: %m", tde_filename));

	/* In case it's a new file, let's add the header now. */
	if (bytes_read == 0 && signed_key_info)
		pg_tde_file_header_write(tde_filename, fd, signed_key_info, &bytes_written);

	*curr_pos = bytes_read + bytes_written;
	return fd;
}
#endif

/*
 * Read TDE file header from a TDE file and fill in the fheader data structure.
 */
static void
pg_tde_file_header_read(const char *tde_filename, int fd, TDEFileHeader *fheader, off_t *bytes_read)
{
	Assert(fheader);

	*bytes_read = pg_pread(fd, fheader, sizeof(TDEFileHeader), 0);

	/* File is empty */
	if (*bytes_read == 0)
		return;

	if (*bytes_read != sizeof(TDEFileHeader))
	{
		ereport(FATAL,
				errcode_for_file_access(),
				errmsg("TDE map file \"%s\" is corrupted: %m", tde_filename));
	}
}

#ifndef FRONTEND
/*
 * Write TDE file header to a TDE file.
 */
static int
pg_tde_file_header_write(const char *tde_filename, int fd, const TDESignedPrincipalKeyInfo *signed_key_info, off_t *bytes_written)
{
	TDEFileHeader fheader;

	Assert(signed_key_info);

	fheader.file_version = PG_TDE_SMGR_FILE_MAGIC;
	fheader.signed_key_info = *signed_key_info;
	*bytes_written = pg_pwrite(fd, &fheader, sizeof(TDEFileHeader), 0);

	if (*bytes_written != sizeof(TDEFileHeader))
	{
		ereport(ERROR,
				errcode_for_file_access(),
				errmsg("could not write tde file \"%s\": %m", tde_filename));
	}

	if (pg_fsync(fd) != 0)
	{
		ereport(data_sync_elevel(ERROR),
				errcode_for_file_access(),
				errmsg("could not fsync file \"%s\": %m", tde_filename));
	}

	ereport(DEBUG2, errmsg("Wrote the header to %s", tde_filename));

	return fd;
}
#endif

static void
pg_tde_read_key_file(int map_file, TDEMapEntry *map_entry)
{
	off_t		bytes_read;

	Assert(map_entry);

	bytes_read = pg_pread(map_file, map_entry, sizeof(TDEMapEntry), 0);

	if (bytes_read != sizeof(TDEMapEntry))
		elog(ERROR, "too short read: got %ld expected %lu", bytes_read, sizeof(TDEMapEntry));
}

/*
 * Get the principal key from the key file. The caller must hold
 * a LW_SHARED or higher lock on files before calling this function.
 */
TDESignedPrincipalKeyInfo *
pg_tde_get_principal_key_info(Oid dbOid)
{
	char		db_map_path[MAXPGPATH];
	int			fd;
	TDEFileHeader fheader;
	TDESignedPrincipalKeyInfo *signed_key_info = NULL;
	off_t		bytes_read = 0;

	pg_tde_set_db_file_path(dbOid, db_map_path);

	/*
	 * Ensuring that we always open the file in binary mode. The caller must
	 * specify other flags for reading, writing or creating the file.
	 */
	fd = pg_tde_open_file_basic(db_map_path, O_RDONLY, true);

	/* The file does not exist. */
	if (fd < 0)
		return NULL;

	pg_tde_file_header_read(db_map_path, fd, &fheader, &bytes_read);

	if (bytes_read > 0 &&
		FILEMAGIC_TYPE(fheader.file_version) != FILEMAGIC_TYPE(PG_TDE_SMGR_FILE_MAGIC))
	{
		ereport(FATAL,
				errcode_for_file_access(),
				errmsg("key file \"%s\" is corrupted or has wrong version: %m", db_map_path),
				errdetail("Getting principal key from the file."));
	}

	CloseTransientFile(fd);

	/*
	 * It's not a new file. So we can copy the principal key info from the
	 * header
	 */
	if (bytes_read > 0)
	{
		signed_key_info = palloc_object(TDESignedPrincipalKeyInfo);
		*signed_key_info = fheader.signed_key_info;
	}

	return signed_key_info;
}

/*
 * Figures out whether a relation is encrypted or not, but without trying to
 * decrypt the key if it is.
 */
bool
pg_tde_has_smgr_key(RelFileLocator rel)
{
	char		file_path[MAXPGPATH];
	bool		result;
	LWLock	   *lock_pk = tde_lwlock_enc_keys();

	Assert(rel.relNumber != InvalidRelFileNumber);

	pg_tde_set_key_file_path(&rel, file_path);

	LWLockAcquire(lock_pk, LW_SHARED);

	// TODO: Handle errors
	if (access(file_path, F_OK) == -1)
		result = false;
	else
		result = true;

	LWLockRelease(lock_pk);

	return result;
}

/*
 * Reads the map entry of the relation and decrypts the key.
 */
InternalKey *
pg_tde_get_smgr_key(RelFileLocator rel)
{
	char		file_path[MAXPGPATH];
	int			fd;
	TDEMapEntry map_entry;
	TDEPrincipalKey *principal_key;
	InternalKey *rel_key;
	LWLock	   *lock_pk = tde_lwlock_enc_keys();

	Assert(rel.relNumber != InvalidRelFileNumber);

	pg_tde_set_key_file_path(&rel, file_path);

	LWLockAcquire(lock_pk, LW_SHARED);

	fd = OpenTransientFile(file_path, O_RDONLY | PG_BINARY);

	// TODO: Handle errors
	if (fd == -1)
	{
		LWLockRelease(lock_pk);
		return NULL;
	}

	pg_tde_read_key_file(fd, &map_entry);

	CloseTransientFile(fd);

	/*
	 * Get/generate a principal key, create the key for relation and get the
	 * encrypted key with bytes to write
	 *
	 * We should hold the lock until the internal key is loaded to be sure the
	 * retrieved key was encrypted with the obtained principal key. Otherwise,
	 * the next may happen: - GetPrincipalKey returns key "PKey_1". - Some
	 * other process rotates the Principal key and re-encrypt an Internal key
	 * with "PKey_2". - We read the Internal key and decrypt it with "PKey_1"
	 * (that's what we've got). As the result we return an invalid Internal
	 * key.
	 */
	principal_key = GetPrincipalKey(rel.dbOid, LW_SHARED);
	if (principal_key == NULL)
		ereport(ERROR,
				errmsg("principal key not configured"),
				errhint("Use pg_tde_set_key_using_database_key_provider() or pg_tde_set_key_using_global_key_provider() to configure one."));
	rel_key = tde_decrypt_rel_key(principal_key, &map_entry);

	LWLockRelease(lock_pk);

	if (principal_key->keyLength != rel_key->key_len)
	{
		ereport(LOG,
				errmsg("length \"%u\" of principal key \"%s\" does not match the length \"%d\" of the internal key", principal_key->keyLength, principal_key->keyInfo.name, rel_key->key_len),
				errhint("Create a new principal key and set it instead of the current one."));
	}

	return rel_key;
}


#ifndef FRONTEND

/*****************************************
 * Functions for migrating old smgr keys into a new format file.
 *****************************************/

/*
 * A version-specific migration routine. It reads an entry of the specific
 * version from the given fd and offset, and transforms it into
 * TDEMapEntry (current version)
 */
typedef bool (*MapFromDiskEntry) (int fd, off_t *entry_offset, const TDEPrincipalKey *principal_key, TDEMapEntry *out);

typedef struct TDEMapEntryV3
{
	Oid			spcOid;			/* Part of AAD */
	RelFileNumber relNumber;	/* Part of AAD */
	uint32		type;			/* Part of AAD */
	uint32		_unused1;		/* Part of AAD */

	uint8		encrypted_key_data[16];
	uint8		key_base_iv[16];

	uint32		_unused2;		/* Will be 1 in existing files entries. */
	uint32		_unused3;
	uint64		_unused4;		/* Will be 0 in existing files entries. */

	/* IV and tag used when encrypting the key itself */
	unsigned char entry_iv[16];
	unsigned char aead_tag[16];
} TDEMapEntryV3;

static bool
read_one_map_entry_v3(int fd, TDEMapEntryV3 *entry, off_t *offset)
{
	off_t		bytes_read = 0;

	Assert(entry);
	Assert(offset);

	bytes_read = pg_pread(fd, entry, sizeof(TDEMapEntryV3), *offset);

	/* We've reached the end of the file. */
	if (bytes_read != sizeof(TDEMapEntryV3))
		return false;

	*offset += bytes_read;

	return true;
}

static void
ikey_from_map_entry_v3(TDEMapEntryV3 *entry, const TDEPrincipalKey *principal_key, InternalKey *out)
{
	out->key_len = sizeof(entry->encrypted_key_data);

	memcpy(out->base_iv, entry->key_base_iv, sizeof(entry->key_base_iv));
	if (!AesGcmDecrypt(principal_key->keyData, principal_key->keyLength,
					   entry->entry_iv, sizeof(entry->entry_iv),
					   (unsigned char *) entry, offsetof(TDEMapEntryV3, encrypted_key_data),
					   entry->encrypted_key_data, out->key_len,
					   out->key,
					   entry->aead_tag, sizeof(entry->aead_tag)))
		ereport(ERROR,
				errmsg("failed to decrypt key, incorrect principal key or corrupted key file"));
}

static bool
map_from_disk_entry_v3(int fd, off_t *entry_offset, const TDEPrincipalKey *principal_key, TDEMapEntry *out)
{
	TDEMapEntryV3 disk_entry;
	InternalKey key;
	RelFileLocator rloc;

	if (!read_one_map_entry_v3(fd, &disk_entry, entry_offset))
		return false;

	ikey_from_map_entry_v3(&disk_entry, principal_key, &key);

	rloc.spcOid = disk_entry.spcOid;
	rloc.dbOid = principal_key->keyInfo.databaseId;
	rloc.relNumber = disk_entry.relNumber;

	pg_tde_initialize_map_entry(out, principal_key, &rloc, &key);

	return true;
}

void
pg_tde_migrate_smgr_keys_file(void)
{
	DIR		   *dir;
	LWLock	   *lock_pk = tde_lwlock_enc_keys();
	struct dirent *file;
	TDEPrincipalKey *principal_key = NULL;
	TDESignedPrincipalKeyInfo signed_key_info;

	/*
	 * No real need in lock here as the func should be called only on the
	 * server start, but GetPrincipalKey() expects lock.
	 */
	LWLockAcquire(lock_pk, LW_EXCLUSIVE);

	dir = opendir(pg_tde_get_data_dir());
	if (dir == NULL && errno != ENOENT)
		elog(ERROR, "could not open directory \"%s\": %m",
			 pg_tde_get_data_dir());

	while (errno = 0, (file = readdir(dir)) != NULL)
	{
		char		db_map_path[MAXPGPATH] = {0};
		char		tmp_db_map_path[MAXPGPATH] = {0};
		off_t		read_pos,
					write_pos;
		int			old_fd,
					new_fd;
		Oid			dbOid;
		char	   *suffix;
		TDEFileHeader fheader;
		MapFromDiskEntry read_map_entry;
		TDEMapEntry new_entry;


		dbOid = strtoul(file->d_name, &suffix, 10);

		if (strcmp(suffix, "_keys") != 0)
			continue;

		pg_tde_set_db_file_path(dbOid, db_map_path);

		snprintf(tmp_db_map_path, MAXPGPATH, "%s.r", db_map_path);

		old_fd = pg_tde_open_file_basic(db_map_path, O_RDONLY | PG_BINARY, false);
		pg_tde_file_header_read(db_map_path, old_fd, &fheader, &read_pos);

		/* check if we have anything to do */
		if (fheader.file_version == PG_TDE_SMGR_FILE_MAGIC)
		{
			CloseTransientFile(old_fd);
			continue;
		}

		/* The type check later, when extracting the principal key */
		if (FILEMAGIC_VERSION(fheader.file_version) == 3)
			read_map_entry = map_from_disk_entry_v3;
		else
			elog(ERROR, "keys migration: unsupported or corrupted version %d of file \"%s\"", FILEMAGIC_VERSION(fheader.file_version), db_map_path);

		/*
		 * The old file exists and it's not empty, hence a principal key
		 * should exist as well.
		 */
		if (principal_key == NULL)
		{
			principal_key = GetPrincipalKey(dbOid, LW_EXCLUSIVE);
			if (principal_key == NULL)
			{
				ereport(ERROR,
						errmsg("could not get server principal key"),
						errdetail("Failed to migrate the keys file of %u database.", dbOid));
			}
			pg_tde_sign_principal_key_info(&signed_key_info, principal_key);
		}

		new_fd = pg_tde_open_file_write(tmp_db_map_path, &signed_key_info, true, &write_pos);

		while (read_map_entry(old_fd, &read_pos, principal_key, &new_entry))
		{
			pg_tde_write_one_map_entry(new_fd, &new_entry, &write_pos, db_map_path);
		}

		CloseTransientFile(old_fd);
		CloseTransientFile(new_fd);
		durable_rename(tmp_db_map_path, db_map_path, ERROR);
	}

	closedir(dir);
	LWLockRelease(lock_pk);
}

#endif
