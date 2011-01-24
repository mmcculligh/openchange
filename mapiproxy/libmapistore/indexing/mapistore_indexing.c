/*
   OpenChange Storage Abstraction Layer library

   OpenChange Project

   Copyright (C) Julien Kerihuel 2010-2011

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <string.h>

#include "mapiproxy/libmapistore/mapistore_errors.h"
#include "mapiproxy/libmapistore/mapistore.h"
#include "mapiproxy/libmapistore/mapistore_common.h"
#include "mapiproxy/libmapistore/mapistore_private.h"
#include "gen_ndr/ndr_mapistore_indexing_db.h"

#include <dlinklist.h>
#include <tdb.h>

/**
   \file mapistore_indexing.c

   \brief Interface API to the mapistore indexing database
   
   This database is used to map FID/MID to mapistore URI, plus additional parameters
 */

/**
   \details Increase the reference counter associated to a given
   mapistore indexing context

   \param mictx pointer to the mapistore indexing context

   \return MAPISTORE_SUCCESS on success, otherwise MAPISTORE error
 */
static enum MAPISTORE_ERROR mapistore_indexing_context_add_ref_count(struct mapistore_indexing_context_list *mictx)
{
	/* Sanity checks */
	MAPISTORE_RETVAL_IF(!mictx, MAPISTORE_ERROR, NULL);

	DEBUG(2, ("* [%s:%d][%s]: ref count was %i, about to increment\n", __FILE__, __LINE__, __FUNCTION__, mictx->ref_count));

	return MAPISTORE_SUCCESS;
}

/**
   \details Decrease the reference counter associated to a given
   mapistore indexing context

   \param mictx pointer to the mapistore indexing context

   \return MAPISTORE_SUCCESS on success, otherwise MAPISTORE error
 */
static enum MAPISTORE_ERROR mapistore_indexing_context_del_ref_count(struct mapistore_indexing_context_list *mictx)
{
	/* Sanity checks */
	MAPISTORE_RETVAL_IF(!mictx, MAPISTORE_ERROR, NULL);
	MAPISTORE_RETVAL_IF(!mictx->ref_count, MAPISTORE_SUCCESS, NULL);
	
	DEBUG(2, ("* [%s:%d][%s]: ref count was %i, about to decrement\n", __FILE__, __LINE__, __FUNCTION__, mictx->ref_count));
	mictx->ref_count -= 1;

	return MAPISTORE_SUCCESS;
}

/**
   \details (Accessor) Retrieve the reference counter associated to a
   given mapistore indexing context

   \param mictx pointer to the mapistore indexing context

   \return the reference counter value associated to the mapistore
   indexing context
 */
static uint32_t mapistore_indexing_context_get_ref_count(struct mapistore_indexing_context_list *mictx)
{
	return mictx->ref_count;
}

/**
   \details Search the mapistore indexing context list for an existing
   record matching the specified username

   \param mstore_ctx pointer to the mapistore context
   \param username the username to lookup

   \return pointer to the existing mapistore indexing context list on success, otherwise NULL
 */
static struct mapistore_indexing_context_list *mapistore_indexing_context_search(struct mapistore_context *mstore_ctx,
										 const char *username)
{
	struct mapistore_indexing_context_list	*el;

	/* Sanity checks */
	if (!mstore_ctx || !username) return NULL;

	for (el = mstore_ctx->mapistore_indexing_list; el; el = el->next) {
		if (el && el->username && !strcmp(el->username, username)) {
			return el;
		}
	}

	return NULL;
}

/**
   \details Open a connection context to the indexing database for
   given user

   \param mstore_ctx pointer to the mapistore context
   \param username username of the indexing database owner
   \param indexing_ctx pointer on pointer to the inde3xing context to return
 */
enum MAPISTORE_ERROR mapistore_indexing_context_add(struct mapistore_context *mstore_ctx,
						    const char *username,
						    struct mapistore_indexing_context_list **indexing_ctx)
{
	TALLOC_CTX				*mem_ctx;
	struct mapistore_indexing_context_list	*mictx;
	char					*dbpath;

	/* Sanity checks */
	MAPISTORE_RETVAL_IF(!mstore_ctx, MAPISTORE_ERR_NOT_INITIALIZED, NULL);
	MAPISTORE_RETVAL_IF(!username, MAPISTORE_ERR_INVALID_PARAMETER, NULL);
	MAPISTORE_RETVAL_IF(!indexing_ctx, MAPISTORE_ERR_INVALID_PARAMETER, NULL);

	/* Step 1. Return existing context if available */
	mictx = mapistore_indexing_context_search(mstore_ctx, username);
	if (mictx) {
		DEBUG(2, ("* [%s:%d][%s]: Reusing existing context\n", __FILE__, __LINE__, __FUNCTION__));
		mapistore_indexing_context_add_ref_count(mictx);
		*indexing_ctx = mictx;
		return MAPISTORE_SUCCESS;
	}
	
	/* Step 2. Otherwise create a new context */
	mem_ctx = talloc_named(NULL, 0, "mapistore_indexing_context_add");
	mictx = talloc_zero(mstore_ctx->mapistore_indexing_list, struct mapistore_indexing_context_list);

	dbpath = talloc_asprintf(mem_ctx, MAPISTORE_INDEXING_DBPATH_TMPL,
				 mapistore_get_mapping_path(), username);
	mictx->tdb_ctx = tdb_wrap_open(mictx, dbpath, 0, 0, O_RDWR|O_CREAT, 0600);
	talloc_free(dbpath);

	if (!mictx->tdb_ctx) {
		DEBUG(3, ("! [%s:%d][%s]: %s\n", __FILE__, __LINE__, __FUNCTION__, strerror(errno)));
		talloc_free(mictx);
		talloc_free(mem_ctx);

		return MAPISTORE_ERR_DATABASE_INIT;
	}

	mictx->username = (const char *) talloc_strdup(mictx, username);
	mictx->ref_count = 1;
	DEBUG(2, ("* [%s:%d][%s] indexing context value is now %i\n", __FILE__, __LINE__, __FUNCTION__, mictx->ref_count));
	DLIST_ADD_END(mstore_ctx->mapistore_indexing_list, mictx, struct mapistore_indexing_context_list *);

	*indexing_ctx = mictx;

	talloc_free(mem_ctx);

	return MAPISTORE_SUCCESS;
}


/**
   \details Delete indexing database context for given user

   \param mstore_ctx pointer to the mapistore context
   \param username username of the indexing database owner

   \return MAPISTORE_SUCCESS on success, otherwise MAPISTORE error

   \return MAPISTORE_SUCCESS on success, otherwise MAPISTORE error
 */
enum MAPISTORE_ERROR mapistore_indexing_context_del(struct mapistore_context *mstore_ctx,
						    const char *username)
{
	struct mapistore_indexing_context_list	*mictx;
	enum MAPISTORE_ERROR			retval;

	/* Sanity checks */
	MAPISTORE_RETVAL_IF(!mstore_ctx, MAPISTORE_ERR_NOT_INITIALIZED, NULL);
	MAPISTORE_RETVAL_IF(!username, MAPISTORE_ERROR, NULL);

	/* Step 1. Search for the context */
	mictx = mapistore_indexing_context_search(mstore_ctx, username);
	MAPISTORE_RETVAL_IF(!mictx, MAPISTORE_ERROR, NULL);

	/* Step 2. Decrement the reference count */
	retval = mapistore_indexing_context_del_ref_count(mictx);

	if (mapistore_indexing_context_get_ref_count(mictx)) {
		/* Step 3. If we still have ref counts, just return */
		return MAPISTORE_SUCCESS;
	} else {
		/* Step 4. If no more associated references, remove and release memory */
		DLIST_REMOVE(mstore_ctx->mapistore_indexing_list, mictx);
		talloc_free(mictx);
	}

	return MAPISTORE_SUCCESS;
}


/**
   \details Increment the reference counter of the existing context
   for given user

   \param mstore_ctx pointer to the mapistore context
   \param username the user string to lookup

   \return MAPISTORE_SUCCESS on success, otherwise MAPISTORE error
 */
enum MAPISTORE_ERROR mapistore_indexing_context_add_ref(struct mapistore_context *mstore_ctx,
							const char *username)
{
	struct mapistore_indexing_context_list	*mictx;
	enum MAPISTATUS				retval;

	/* Sanity checks */
	MAPISTORE_RETVAL_IF(!mstore_ctx, MAPISTORE_ERR_NOT_INITIALIZED, NULL);
	MAPISTORE_RETVAL_IF(!username, MAPISTORE_ERROR, NULL);

	/* Step 1. Search for the context */
	mictx = mapistore_indexing_context_search(mstore_ctx, username);
	MAPISTORE_RETVAL_IF(!mictx, MAPISTORE_ERROR, NULL);

	/* Step 2. Increment the reference counter */
	retval = mapistore_indexing_context_add_ref_count(mictx);

	return retval;
}


/**
   \details Search the TDB database and check if the fmid already exists

   \param mictx pointer to the mapistore indexing context list
   \param fmid the folder or message identifier to lookup

   \return MAPISTORE_ERR_NOT_FOUND if the fmid was not found,
   MAPISTORE_ERR_EXIST if it was found, otherwise different MAPISTORE error
 */
static enum MAPISTORE_ERROR mapistore_indexing_record_search_fmid(struct mapistore_indexing_context_list *mictx,
								  uint64_t fmid)
{
	int		ret;
	TDB_DATA	key;

	/* Sanity checks */
	MAPISTORE_RETVAL_IF(!mictx, MAPISTORE_ERR_NOT_INITIALIZED, NULL);
	MAPISTORE_RETVAL_IF(!fmid, MAPISTORE_ERR_INVALID_PARAMETER, NULL);

	/* Step 1. Set the TDB key for searching */
	key.dptr = (unsigned char *) talloc_asprintf(mictx, MAPISTORE_INDEXING_FMID, fmid);
	key.dsize = strlen((const char *)key.dptr);

	ret = tdb_exists(mictx->tdb_ctx->tdb, key);
	talloc_free(key.dptr);

	MAPISTORE_RETVAL_IF(ret, MAPISTORE_ERR_EXIST, NULL);

	return MAPISTORE_ERR_NOT_FOUND;
}


/**
   \details Search the TDB database and check if the URI already exists

   \param mictx pointer to the mapistore indexing context list
   \param uri the uri to lookup

   \return MAPISTORE_ERR_NOT_FOUND if the fmid was not found,
   MAPISTORE_ERR_EXIST if it was found, otherwise different MAPISTORE error
*/
static enum MAPISTORE_ERROR mapistore_indexing_record_search_uri(struct mapistore_indexing_context_list *mictx,
								 const char *uri)
{
	int		ret;
	TDB_DATA	key;

	/* Sanity checks */
	MAPISTORE_RETVAL_IF(!mictx, MAPISTORE_ERR_NOT_INITIALIZED, NULL);
	MAPISTORE_RETVAL_IF(!uri, MAPISTORE_ERR_INVALID_PARAMETER, NULL);

	/* Step 1. Set the TDB key for searching */
	key.dptr = (unsigned char *) talloc_asprintf(mictx, MAPISTORE_INDEXING_URI, uri);
	key.dsize = strlen((const char *)key.dptr);

	ret = tdb_exists(mictx->tdb_ctx->tdb, key);
	talloc_free(key.dptr);

	MAPISTORE_RETVAL_IF(ret, MAPISTORE_ERR_EXIST, NULL);
	
	return MAPISTORE_ERR_NOT_FOUND;
}

/**
   \details Add a folder or message record to the indexing database

   \param mictx pointer to the mapistore indexing context
   \param fmid the Folder or Message identifier to register
   \param mapistore_uri the mapistore URI to register
   \param parent_fid the parent folder identifier
   \param type the element type to add

   \return MAPISTORE_SUCCESS on success, otherwise MAPISTORE error
 */
enum MAPISTORE_ERROR mapistore_indexing_add_fmid_record(struct mapistore_indexing_context_list *mictx,
							uint64_t fmid,
							const char *mapistore_uri,
							uint64_t parent_fid,
							uint8_t type)
{
	enum MAPISTORE_ERROR			retval;
	TALLOC_CTX				*mem_ctx;
	int					ret;
	struct mapistore_indexing_entry		entry;
	DATA_BLOB				data;
	enum ndr_err_code			ndr_err;
	TDB_DATA				key;
	TDB_DATA				dbuf;

	/* Sanity checks */
	MAPISTORE_RETVAL_IF(!mictx, MAPISTORE_ERR_NOT_INITIALIZED, NULL);
	MAPISTORE_RETVAL_IF(!fmid, MAPISTORE_ERR_INVALID_PARAMETER, NULL);
	MAPISTORE_RETVAL_IF(!mapistore_uri, MAPISTORE_ERR_INVALID_PARAMETER, NULL);

	/* Step 1.a Check if the fid/mid already exists */
	retval = mapistore_indexing_record_search_fmid(mictx, fmid);
	if (retval == MAPISTORE_ERR_EXIST) {
		DEBUG(5, ("! [%s:%d][%s]: FMID 0x%.16"PRIx64" already exists!\n", __FILE__, __LINE__, __FUNCTION__, fmid));
		return retval;
	}

	/* Step 1.b Check if the URI already exists */
	retval = mapistore_indexing_record_search_uri(mictx, mapistore_uri);
	if (retval == MAPISTORE_ERR_EXIST) {
		DEBUG(5, ("! [%s:%d][%s]: URI %s already exists!\n", __FILE__, __LINE__, __FUNCTION__, mapistore_uri));
		return retval;
	}

	/* Step 2. Ensure parent_fid is a valid fid */
	if (parent_fid) {
		retval = mapistore_indexing_record_search_fmid(mictx, parent_fid);
		if (retval == MAPISTORE_ERR_NOT_FOUND) {
			DEBUG(5, ("! [%s:%d][%s]: Parent folder 0x%.16"PRIx64" doesn't exist!\n", __FILE__, __LINE__, __FUNCTION__, parent_fid));
			return retval;
		}
	} else {
		DEBUG(5, ("* [%s:%d][%s]: Registering root mailbox entry\n", __FILE__, __LINE__, __FUNCTION__));
	}

	/* Step 3. Create the key/dbuf record */
	mem_ctx = talloc_new(mictx);
	key.dptr = (unsigned char *) talloc_asprintf(mem_ctx, MAPISTORE_INDEXING_FMID, fmid);
	key.dsize = strlen((const char *)key.dptr);

	entry.version = 1;
	entry.info.mapistore_indexing_v1.mapistoreURI = mapistore_uri;
	entry.info.mapistore_indexing_v1.Type = type;
	entry.info.mapistore_indexing_v1.ParentFolderID = parent_fid;
	if (type == MAPISTORE_INDEXING_FOLDER) {
		entry.info.mapistore_indexing_v1.MessageRangeIDs.range.next_allocation_id = 0;
		entry.info.mapistore_indexing_v1.MessageRangeIDs.range.last_allocation_id = 0;

		entry.info.mapistore_indexing_v1.Acls.acls_folder.acl_number = 0;
	}

	ndr_err = ndr_push_struct_blob(&data, mem_ctx, &entry, (ndr_push_flags_fn_t)ndr_push_mapistore_indexing_entry);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(5, ("! [%s:%d][%s]: Failed to push mapistore_indexing_entry into NDR blob\n", __FILE__, __LINE__, __FUNCTION__));
		talloc_free(mem_ctx);
		return MAPISTORE_ERROR;
	}

	dbuf.dptr = data.data;
	dbuf.dsize = data.length;

	/* Step 4. Insert the FMID record */
	ret = tdb_store(mictx->tdb_ctx->tdb, key, dbuf, TDB_INSERT);

	if (ret == -1) {
		DEBUG(3, ("! [%s:%d][%s]: Unable to create " MAPISTORE_INDEXING_FMID " record: %s\n",
			  __FILE__, __LINE__, __FUNCTION__, fmid, mapistore_uri));
		talloc_free(mem_ctx);
		return MAPISTORE_ERR_DATABASE_OPS;
	}

	/* Step 5. Insert the reverse record URI/ indexing record */
	key.dptr = (unsigned char *) talloc_asprintf(mem_ctx, MAPISTORE_INDEXING_URI, mapistore_uri);
	key.dsize = strlen((const char *)key.dptr);

	dbuf.dptr = (unsigned char *)talloc_asprintf(mem_ctx, MAPISTORE_INDEXING_FMID, fmid);
	dbuf.dsize = strlen((const char *)dbuf.dptr);

	ret = tdb_store(mictx->tdb_ctx->tdb, key, dbuf, TDB_INSERT);
	talloc_free(mem_ctx);

	if (ret == -1) {
		DEBUG(3, ("[%s:%d][%s]: Unable to create " MAPISTORE_INDEXING_URI " record: " MAPISTORE_INDEXING_FMID "\n",
			  __FILE__, __LINE__, __FUNCTION__, mapistore_uri, fmid));
		return MAPISTORE_ERR_DATABASE_OPS;
	}

	return MAPISTORE_SUCCESS;
}
