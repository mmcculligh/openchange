/*
   Stand-alone MAPI testsuite

   OpenChange Project - LZXPRESS compression/decompression

   Copyright (C) Julien Kerihuel 2010

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

#include "utils/mapitest/mapitest.h"
#include "utils/mapitest/proto.h"
#include "gen_ndr/ndr_exchange.h"
#include "libmapi/libmapi_private.h"

/**
   \file module_lzxpress.c

   \brief LZXPRESS compression and decompression test suite
 */

/* temporary hack until linker problems with ndr_map_error2ntstatus() are worked out */
NTSTATUS static mt_ndr_map_error2ntstatus(enum ndr_err_code ndr_err)
{
        switch (ndr_err) {
        case NDR_ERR_SUCCESS:
                return NT_STATUS_OK;
        case NDR_ERR_BUFSIZE:
                return NT_STATUS_BUFFER_TOO_SMALL;
        case NDR_ERR_TOKEN:
                return NT_STATUS_INTERNAL_ERROR;
        case NDR_ERR_ALLOC:
                return NT_STATUS_NO_MEMORY;
        case NDR_ERR_ARRAY_SIZE:
                return NT_STATUS_ARRAY_BOUNDS_EXCEEDED;
        case NDR_ERR_INVALID_POINTER:
                return NT_STATUS_INVALID_PARAMETER_MIX;
        case NDR_ERR_UNREAD_BYTES:
                return NT_STATUS_PORT_MESSAGE_TOO_LONG;
        default:
                break;
        }

        /* we should map all error codes to different status codes */
        return NT_STATUS_INVALID_PARAMETER;
}

_PUBLIC_ bool mapitest_lzxpress_validate_test_001(struct mapitest *mt)
{
	bool			ret = false;
	char			*filename = NULL;
	DATA_BLOB		blob;
	uint8_t			*data;
	size_t			size;
	struct ndr_print	*ndr_print;
	struct ndr_pull		*ndr_pull;
	struct ndr_push		*ndr_push;
	struct ndr_push		*ndr_comp;
	struct ndr_push		*ndr_rgbIn;
	struct RPC_HEADER_EXT	RPC_HEADER_EXT;
	struct EcDoRpcExt2	r;
	struct mapi2k7_request	request;
	NTSTATUS		status;
	enum ndr_err_code	ndr_err;

	/* Step 1. Load Test File 001_Outlook_2007_in_ModifyRecipients_comp.dat */
	filename = talloc_asprintf(mt->mem_ctx, "%s/001_Outlook_2007_in_ModifyRecipients_comp.dat", LZXPRESS_DATADIR);
/* 	filename = talloc_asprintf(mt->mem_ctx, "%s/002_Outlook_2007_in_Tables_operations_comp.dat", LZXPRESS_DATADIR); */
	data = (uint8_t *)file_load(filename, &size, 0, mt->mem_ctx);
	if (!data) {
		perror(filename);
		mapitest_print_retval_fmt(mt, "lzxpress_validate", "Error while loading %s", filename);
		talloc_free(filename);
		return false;
	}
	blob.data = data;
	blob.length = size;
	mapitest_print_retval_step(mt, "1", "Loading 001_Outlook_2007_in_ModifyRecipients_comp.dat", MAPI_E_SUCCESS);

	ndr_print = talloc_zero(mt->mem_ctx, struct ndr_print);
	ndr_print->print = ndr_print_debug_helper;
	ndr_print->depth = 1;

	/* Step 2. Pull 001_Outlook_2007_in_ModifyRecipients_comp.dat data */
	ndr_pull = ndr_pull_init_blob(&blob, mt->mem_ctx);
	ndr_pull->flags |= LIBNDR_FLAG_REF_ALLOC;

	ndr_err = ndr_pull_EcDoRpcExt2(ndr_pull, NDR_IN, &r);
	talloc_free(ndr_pull);
	status = mt_ndr_map_error2ntstatus(ndr_err);
	if (NT_STATUS_IS_OK(status)) {
		mapitest_print_retval_step(mt, "2", "001_Outlook_2007_in_ModifyRecipients_comp.dat", 
					   MAPI_E_SUCCESS);
	} else {
		mapitest_print_retval_step(mt, "2", "Pulling 001_Outlook_2007_in_ModifyRecipients_comp.dat", 
					   MAPI_E_CALL_FAILED);
		return false;
	}

	/* Step 4. Decompress data */
	blob.data = talloc_memdup(mt->mem_ctx, r.in.rgbIn, r.in.cbIn);
	blob.length = r.in.cbIn;
	ndr_pull = ndr_pull_init_blob(&blob, mt->mem_ctx);
	ndr_set_flags(&ndr_pull->flags, LIBNDR_FLAG_NOALIGN|LIBNDR_FLAG_REF_ALLOC);
	ndr_err = ndr_pull_mapi2k7_request(ndr_pull, NDR_SCALARS|NDR_BUFFERS, &request);
	talloc_free(blob.data);
	talloc_free(ndr_pull);
	status = mt_ndr_map_error2ntstatus(ndr_err);
	if (NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Success\n"));
	}

	/* Step 5. Recompress data */
	ndr_push = ndr_push_init_ctx(mt->mem_ctx);
	ndr_set_flags(&ndr_push->flags, LIBNDR_FLAG_NOALIGN|LIBNDR_FLAG_REF_ALLOC);
	ndr_push_mapi_request(ndr_push, NDR_SCALARS|NDR_BUFFERS, request.mapi_request);
	ndr_comp = ndr_push_init_ctx(mt->mem_ctx);
	ndr_push_lzxpress_compress(ndr_comp, ndr_push);
	
	/* Recreate complete blob */
	ndr_rgbIn = ndr_push_init_ctx(mt->mem_ctx);
	ndr_set_flags(&ndr_rgbIn->flags, LIBNDR_FLAG_NOALIGN|LIBNDR_FLAG_REF_ALLOC);

	RPC_HEADER_EXT.Version = 0x0000;
	RPC_HEADER_EXT.Flags = RHEF_Compressed|RHEF_Last;
	RPC_HEADER_EXT.Size = ndr_comp->offset;
	RPC_HEADER_EXT.SizeActual = ndr_push->offset;
	ndr_push_RPC_HEADER_EXT(ndr_rgbIn, NDR_SCALARS|NDR_BUFFERS, &RPC_HEADER_EXT);

	ndr_push_bytes(ndr_rgbIn, ndr_comp->data, ndr_comp->offset);
	talloc_free(ndr_comp);

	/* Compare Outlook and openchange rgbIn compressed blob */
	DEBUG(0, ("Outlook    compressed blob size = 0x%x\n", r.in.cbIn));
	DEBUG(0, ("OpenChange compressed blob size = 0x%x\n", ndr_rgbIn->offset));
	ret = true;
	{
		int i;
		int min;

		min = (ndr_rgbIn->offset >= r.in.cbIn) ? r.in.cbIn : ndr_rgbIn->offset;
		DEBUG(0, ("Comparing Outlook and OpenChange blobs on 0x%x bytes\n", min));
		for (i = 0; i < min; i++) {
			if (r.in.rgbIn[i] != ndr_rgbIn->data[i]) {
				DEBUG(0, ("Bytes differs at offset 0x%x: Outlook (0x%.2x) OpenChange (0x%.2x)\n", 
					  i, r.in.rgbIn[i], ndr_rgbIn->data[i]));
				ret = false;
			}
		}
		
	}

	mapitest_print(mt, "Compressed rgbIn by Outlook\n");
	mapitest_print(mt, "==============================\n");
	dump_data(0, r.in.rgbIn, r.in.cbIn);
	mapitest_print(mt, "==============================\n");

	mapitest_print(mt, "Compressed rgbIn by OpenChange\n");
	mapitest_print(mt, "==============================\n");
	dump_data(0, ndr_rgbIn->data, ndr_rgbIn->offset);
	mapitest_print(mt, "==============================\n");

	talloc_free(ndr_rgbIn);

	return ret;
}
