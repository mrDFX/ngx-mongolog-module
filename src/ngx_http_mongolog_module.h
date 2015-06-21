#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <bson.h>
#include <mongoc.h>

/* Log variables function return value types */
#define	MONGOLOG_RETVAR_NOVAL  0
#define MONGOLOG_RETVAR_INT    1
#define MONGOLOG_RETVAR_STR    2
#define MONGOLOG_RETVAR_TIME   3
#define MONGOLOG_RETVAR_BSON   4
#define MONGOLOG_RETVAR_OFFT   5

/* How times module will attempts reconnect to mongo */
#define MONGO_CONNECT_MAX_TRIES 3

/* Module defintion */
extern ngx_module_t ngx_http_mongolog_module;

/* Log variables function return value struct */
typedef struct {
	char *name;
	unsigned *name_len;
	unsigned ret;
	unsigned val_len;
	void *value;
} log_entry_val;

/* Log variables list type */
typedef struct {
	void (*process_func)(ngx_http_request_t*, log_entry_val*, unsigned);
	char type_name[256];
	unsigned name_len;
} ngx_mongolog_module_log_entry;

/* Collection to which log will be written */
typedef struct {
	ngx_int_t   request_body_conf_num;
	ngx_int_t   upstream_addr_variable_num;
	ngx_int_t   upstream_response_time_num;
	ngx_int_t   time_local_num;
	ngx_int_t   request_time_num;
	ngx_int_t   msec_num;
} ngx_mongolog_module_entry_helpers;

/* Config store structure */
typedef struct {
	char   		*address;
	char   		*database;
	char   		*collection;
	ngx_array_t **format;
	ngx_mongolog_module_entry_helpers *helpers;
	mongoc_client_t *client_i;
	mongoc_collection_t *collection_i;
	mongoc_cursor_t *cursor_i;
} ngx_http_mongolog_main_conf_t;

/* Create module config pool */
static void* ngx_http_mongolog_create_main_conf(ngx_conf_t *cf);
/* Log handler: fires after every request */
static ngx_int_t ngx_http_mongolog_handler(ngx_http_request_t *r);
/* Module init function */
static ngx_int_t ngx_http_mongolog_init(ngx_conf_t *cf);
/* Parse list of logged variables */
char * ngx_conf_set_log_elems_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
/* Get mongo connection data function
   like the ngx_conf_set_str_slot() but
   with return char* and final \0 added */
char * ngx_conf_set_mongo_connection_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

/* Get variables for log functions */
static void ngx_mongolog_module_timestamp(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum);
static void ngx_mongolog_module_time_local(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum);
static void ngx_mongolog_module_request_time(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum);
static void ngx_mongolog_module_msec(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum);
static void ngx_mongolog_module_server_name(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum);
static void ngx_mongolog_module_remote_addr(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum);
static void ngx_mongolog_module_request_uri(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum);
static void ngx_mongolog_module_request_args(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum);
static void ngx_mongolog_module_user_agent(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum);
static void ngx_mongolog_module_http_status(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum);
static void ngx_mongolog_module_http_referer(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum);
static void ngx_mongolog_module_is_internal(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum);
static void ngx_mongolog_module_method_name(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum);
static void ngx_mongolog_module_http_protocol(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum);
static void ngx_mongolog_module_request_length(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum);
static void ngx_mongolog_module_bytes_sent(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum);
static void ngx_mongolog_module_body_bytes_sent(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum);
static void ngx_mongolog_module_headers_in(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum);
static void ngx_mongolog_module_headers_out(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum);
static void ngx_mongolog_module_request_body(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum);
static void ngx_mongolog_module_upstream_addr(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum);
static void ngx_mongolog_module_upstream_response_time(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum);

/* Module config commads defintion */
static ngx_command_t ngx_http_mongolog_commands[] = {
	/* Mongo connection url */
	{
		ngx_string("mongolog_address"),
		NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_mongo_connection_slot,
		NGX_HTTP_MAIN_CONF_OFFSET,
		offsetof(ngx_http_mongolog_main_conf_t, address),
		NULL
	},
	/* Database to which log will be written */
	{
		ngx_string("mongolog_database"),
		NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_mongo_connection_slot,
		NGX_HTTP_MAIN_CONF_OFFSET,
		offsetof(ngx_http_mongolog_main_conf_t, database),
		NULL
	},
	/* Collection to which log will be written */
	{
		ngx_string("mongolog_collection"),
		NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_mongo_connection_slot,
		NGX_HTTP_MAIN_CONF_OFFSET,
		offsetof(ngx_http_mongolog_main_conf_t, collection),
		NULL
	},
	/* Logformat */
	{
		ngx_string("mongolog_format"),
		NGX_HTTP_MAIN_CONF|NGX_CONF_1MORE,
		ngx_conf_set_log_elems_slot,
		NGX_HTTP_MAIN_CONF_OFFSET,
		offsetof(ngx_http_mongolog_main_conf_t, format),
		NULL
	},
	/* null command needed by nginx */
	ngx_null_command
};

/* Module context defintion */
static ngx_http_module_t ngx_http_mongolog_ctx = {
	NULL,                                 /* preconfiguration */
	ngx_http_mongolog_init,               /* postconfiguration */
	ngx_http_mongolog_create_main_conf,   /* create main configuration */
	NULL,                                 /* init main configuration */
	NULL,                                 /* create server configuration */
	NULL,                                 /* merge server configuration */
	NULL,                                 /* create location configuration */
	NULL                                  /* merge location configuration */
};

/* Module defintion */
ngx_module_t ngx_http_mongolog_module = {
	NGX_MODULE_V1,
	&ngx_http_mongolog_ctx,          /* module context */
	ngx_http_mongolog_commands,      /* module directives */
	NGX_HTTP_MODULE,                 /* module type */
	NULL,                            /* init master */
	NULL,                            /* init module */
	NULL,                            /* init process */
	NULL,                            /* init thread */
	NULL,                            /* exit thread */
	NULL,                            /* exit process */
	NULL,                            /* exit master */
	NGX_MODULE_V1_PADDING
};

/* Log possible variables list: new should be added here
{
	&log_function_pointer,
	"conf_variable_name",
	strlen("conf_variable_name") - 1
}
*/
static ngx_mongolog_module_log_entry array_log_arg_types[] = {
	{
		NULL,
		"null",
		4
	},
    {
		&ngx_mongolog_module_timestamp,
		"timestamp",
		9
	},
    {
		&ngx_mongolog_module_time_local,
		"time_local",
		10
	},
    {
		&ngx_mongolog_module_request_time,
		"request_time",
		12
	},
    {
		&ngx_mongolog_module_msec,
		"msec",
		4
	},
    {
		&ngx_mongolog_module_server_name,
		"server_name",
		11
	},
    {
		&ngx_mongolog_module_remote_addr,
		"remote_addr",
		11
	},
    {
		&ngx_mongolog_module_request_uri,
		"request_uri",
		11
	},
    {
		&ngx_mongolog_module_request_args,
		"request_args",
		12
	},
    {
		&ngx_mongolog_module_http_status,
		"http_status",
		11
	},
    {
		&ngx_mongolog_module_user_agent,
		"user_agent",
		10
	},
    {
		&ngx_mongolog_module_http_referer,
		"http_referer",
		12
	},
	{
		&ngx_mongolog_module_is_internal,
		"is_internal",
		11
	},
	{
		&ngx_mongolog_module_method_name,
		"method_name",
		11
	},
	{
		&ngx_mongolog_module_http_protocol,
		"http_protocol",
		13
	},
	{
		&ngx_mongolog_module_request_length,
		"request_length",
		14
	},
	{
		&ngx_mongolog_module_bytes_sent,
		"bytes_sent",
		10
	},
	{
		&ngx_mongolog_module_body_bytes_sent,
		"body_bytes_sent",
		15
	},
    {
        &ngx_mongolog_module_headers_in,
        "headers_in",
        10
    },
    {
        &ngx_mongolog_module_headers_out,
        "headers_out",
        11
    },
    {
        &ngx_mongolog_module_request_body,
        "request_body",
        12
    },
    {
        &ngx_mongolog_module_upstream_addr,
        "upstream_addr",
        13
    },
    {
        &ngx_mongolog_module_upstream_response_time,
        "upstream_response_time",
        22
    }
};

