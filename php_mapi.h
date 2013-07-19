#ifndef PHP_MAPI_H
#define PHP_MAPI_H 1

// from openchange
#include "utils/mapitest/mapitest.h"
#include "utils/openchange-tools.h"
#include "libmapi/mapidefs.h"
//#include "libmapi/libmapi_private.h"
//#include "libmapi/mapi_nameid.h"
#include "talloc.h"

#define PHP_MAPI_VERSION "1.0"
#define PHP_MAPI_EXTNAME "mapi"
#define MAPI_CLASS_NAME "MAPI"

PHP_MINIT_FUNCTION(mapi);
PHP_MSHUTDOWN_FUNCTION(mapi);

PHP_METHOD(MAPI, __construct);
PHP_METHOD(MAPI, __destruct);
PHP_METHOD(MAPI, profiles);
PHP_METHOD(MAPI, dump_profile);
PHP_METHOD(MAPI, folders);

struct mapi_context* mapi_context_init(char *profdb);
void mapi_context_dtor(void *mapi_ctx);
struct mapi_context* get_mapi_context(zval* object);
static struct mapi_profile* get_profile(TALLOC_CTX* mem_ctx,  struct mapi_context* mapi_ctx, char* opt_profname);
static zval* get_child_folders(TALLOC_CTX *mem_ctx, mapi_object_t *parent, mapi_id_t folder_id, int count);
static const char *get_container_class(TALLOC_CTX *mem_ctx, mapi_object_t *parent, mapi_id_t folder_id);

extern zend_module_entry mapi_module_entry;
#define phpext_mapi_ptr &mapi_module_entry

#define OBJ_CTMEM_CTZ(ZVAL) get_mapi_context(ZVAL)->mem_ctx

#define EXPECTED_MAPI_OBJECTS 32

#endif
