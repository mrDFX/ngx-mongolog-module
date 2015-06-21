#include "ngx_http_mongolog_module.h"

/* Create module config pool */
static void* ngx_http_mongolog_create_main_conf(ngx_conf_t *cf) {
	ngx_http_mongolog_main_conf_t *conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_mongolog_main_conf_t));
	if (conf == NULL) {
		return NULL;
	}

	return conf;
}

/* Module init function */
static ngx_int_t ngx_http_mongolog_init(ngx_conf_t *cf) {
	ngx_http_handler_pt *h;
	ngx_http_core_main_conf_t *cmcf;
	ngx_http_mongolog_main_conf_t *conf;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
	conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_mongolog_module);
	
	conf->helpers = ngx_pcalloc(cf->pool, sizeof(ngx_mongolog_module_entry_helpers));

	/* Getting variable index numbers */
		/* $request_body */
			ngx_str_t request_body_var_name = ngx_string("request_body");
			ngx_int_t request_body_var_index = ngx_http_get_variable_index(cf, &request_body_var_name);
			if( request_body_var_index == NGX_ERROR) {
				return NGX_ERROR;
			}
			conf->helpers->request_body_conf_num = request_body_var_index;
		/* $upstream_addr */
			ngx_str_t upstream_addr_var_name = ngx_string("upstream_addr");
			ngx_int_t upstream_addr_var_index = ngx_http_get_variable_index(cf, &upstream_addr_var_name);
			if( upstream_addr_var_index == NGX_ERROR) {
				return NGX_ERROR;
			}
			conf->helpers->upstream_addr_variable_num = upstream_addr_var_index;
		/* upstream_response_time */
			ngx_str_t upstream_response_time_var_name = ngx_string("upstream_response_time");
			ngx_int_t upstream_response_time_var_index = ngx_http_get_variable_index(cf, &upstream_response_time_var_name);
			if( upstream_response_time_var_index == NGX_ERROR) {
				return NGX_ERROR;
			}
			conf->helpers->upstream_response_time_num = upstream_response_time_var_index;
		/* time_local */
			ngx_str_t time_local_var_name = ngx_string("time_local");
			ngx_int_t time_local_var_index = ngx_http_get_variable_index(cf, &time_local_var_name);
			if( time_local_var_index == NGX_ERROR) {
				return NGX_ERROR;
			}
			conf->helpers->time_local_num = time_local_var_index;

		/* request_time */
			ngx_str_t request_time_var_name = ngx_string("request_time");
			ngx_int_t request_time_var_index = ngx_http_get_variable_index(cf, &request_time_var_name);
			if( request_time_var_index == NGX_ERROR) {
				return NGX_ERROR;
			}
			conf->helpers->request_time_num = request_time_var_index;

		/* msec */
			ngx_str_t msec_var_name = ngx_string("msec");
			ngx_int_t msec_var_index = ngx_http_get_variable_index(cf, &msec_var_name);
			if( msec_var_index == NGX_ERROR) {
				return NGX_ERROR;
			}
			conf->helpers->msec_num = msec_var_index;

	/* End getting variable index numbers */


	if (conf->address && conf->database && conf->collection && conf->format) {

		mongoc_init ();
		conf->client_i = mongoc_client_new (conf->address);
		conf->collection_i = mongoc_client_get_collection (conf->client_i, conf->database, conf->collection);

		h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
		if (h == NULL) {
			return NGX_ERROR;
		}

		*h = ngx_http_mongolog_handler;
	}

	return NGX_OK;
}

/* Parse list of logged variables */
char * ngx_conf_set_log_elems_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    char  *p = conf;

    ngx_str_t        *value;
    unsigned         i, j, jct, *s, pbuf;
    ngx_array_t      **a;

    a = (ngx_array_t **) (p + cmd->offset);

    if (*a == NULL || *a == NGX_CONF_UNSET_PTR) {
        *a = ngx_array_create(cf->pool, 4, sizeof(unsigned));
        if (*a == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;
    pbuf = 0;
    jct = sizeof(array_log_arg_types) / sizeof(ngx_mongolog_module_log_entry);
    for (i=1; i<cf->args->nelts; i++) {
	char *temp = ngx_pcalloc(cf->pool, (value[i].len + 1) * sizeof(char));
        for (j=1; j<jct; j++) {
		memcpy(temp, value[i].data, value[i].len);
		if(ngx_strcmp (array_log_arg_types[j].type_name, temp) == 0) {
			pbuf = j;
		}
	}
	ngx_pfree(cf->pool, temp);
        if (pbuf == 0) {
	    	char *rettextadd = "got unknown parameter ";
	    	char *rettext = ngx_pcalloc(cf->pool, (strlen(rettextadd) + strlen(temp) + 3) * sizeof(char));
	    	sprintf(rettext, "%s\"%s\"", rettextadd, temp);
            return rettext;
        }
        else {
    	    s = ngx_array_push(*a);
            if (s == NULL) {
                return NGX_CONF_ERROR;
            }
            *s = pbuf;
	    pbuf = 0;
       }
    }
    return NGX_CONF_OK;
}

/* Get mongo connection data function
   like the ngx_conf_set_str_slot() but
   with return char* and final \0 added */
char * ngx_conf_set_mongo_connection_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    char  *p = conf;

    char        **field;
    ngx_str_t   *value;
 
    field = (char **) (p + cmd->offset);

    if (*field) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *field = ngx_pcalloc(cf->pool, (value[1].len + 1) * sizeof(char));
    memcpy(*field, value[1].data, value[1].len);

    return NGX_CONF_OK;
}

/* Log handler: fires after every request */
static ngx_int_t ngx_http_mongolog_handler(ngx_http_request_t *r) {
	bson_error_t error;
	bson_oid_t oid;
	bson_t *doc;
	ngx_http_mongolog_main_conf_t *conf;

	conf = ngx_http_get_module_main_conf(r, ngx_http_mongolog_module);

	doc = bson_new ();
	bson_oid_init (&oid, NULL);
	BSON_APPEND_OID (doc, "_id", &oid);

	unsigned lctr;

	ngx_array_t *arrformat = (ngx_array_t*) conf->format;
	unsigned lcount =  arrformat->nelts;
	unsigned *lpointer = arrformat->elts;

	/* For every configured log variable */
	for (lctr = 0; lctr < lcount; lctr++) {
		log_entry_val *buf = ngx_pcalloc(r->pool, sizeof(log_entry_val));
		void (*elt)(ngx_http_request_t *, log_entry_val *, unsigned) = (void *) array_log_arg_types[lpointer[lctr]].process_func;
		(*elt)(r, buf, lpointer[lctr]);
		switch (buf->ret) {
			case MONGOLOG_RETVAR_TIME:
				bson_append_timestamp (doc, buf->name, *buf->name_len, *((unsigned*) buf->value), 0 );
			break;
			case MONGOLOG_RETVAR_STR:
				bson_append_utf8 (doc, buf->name, *buf->name_len, buf->value, buf->val_len);
			break;
			case MONGOLOG_RETVAR_INT:
				bson_append_int32(doc, buf->name, *buf->name_len, *((unsigned*) buf->value));
			break;
			case MONGOLOG_RETVAR_BSON:
				bson_append_document(doc, buf->name, *buf->name_len, buf->value);
				bson_destroy (buf->value);
			break;
			case MONGOLOG_RETVAR_OFFT:
				bson_append_int64(doc, buf->name, *buf->name_len, *((off_t*) buf->value));
			break;
			default:
				bson_append_null(doc, buf->name, *buf->name_len);
		}

		ngx_pfree(r->pool, buf);
	}

	int i;
	/* On error try reconnect MONGO_CONNECT_MAX_TRIES times */
	for (i=0; i<MONGO_CONNECT_MAX_TRIES; i++) {
		if (mongoc_collection_insert (conf->collection_i, MONGOC_INSERT_NONE, doc, NULL, &error)) {
			/* If all is ok - exit cycle */
			break;
		}
		else {
			/* Destroy old connection and try connect again */
			bson_destroy (doc);
			mongoc_collection_destroy (conf->collection_i);
			mongoc_client_destroy (conf->client_i);

			mongoc_init ();
			conf->client_i = mongoc_client_new (conf->address);
			conf->collection_i = mongoc_client_get_collection (conf->client_i, conf->database, conf->collection);
		}
	}

	bson_destroy (doc);

	return NGX_OK;
}

/* Get variables for log functions bellow*/
static void ngx_mongolog_module_timestamp(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum) {
	/* first three lines are default for the log functions */
	/* default ret type */
	buf->ret = MONGOLOG_RETVAR_NOVAL;
	/* key name in mongo */
	buf->name = array_log_arg_types[fnum].type_name;
	/* key name len */
	buf->name_len = &array_log_arg_types[fnum].name_len;

	/* ret val */
	unsigned value = 0;
	buf->value = &value;
	/* ret length */
	buf->val_len = 1;
	/* if no error set ret type at the end of function */
	buf->ret = MONGOLOG_RETVAR_TIME;
	return;
}

static void ngx_mongolog_module_time_local(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum) {
    	buf->ret = MONGOLOG_RETVAR_NOVAL;
    	buf->name = array_log_arg_types[fnum].type_name;
 		buf->name_len = &array_log_arg_types[fnum].name_len;

        ngx_http_mongolog_main_conf_t *conf = ngx_http_get_module_main_conf(r, ngx_http_mongolog_module);
        ngx_http_variable_value_t  *value;

        value = ngx_http_get_indexed_variable(r, conf->helpers->time_local_num);
        
        if (value == NULL || value->not_found) {
                return;
        }
        else {
                buf->value = value->data;
                buf->val_len = value->len;
                buf->ret = MONGOLOG_RETVAR_STR;
        }
                
        return;
}

static void ngx_mongolog_module_request_time(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum) {
    	buf->ret = MONGOLOG_RETVAR_NOVAL;
    	buf->name = array_log_arg_types[fnum].type_name;
 		buf->name_len = &array_log_arg_types[fnum].name_len;

        ngx_http_mongolog_main_conf_t *conf = ngx_http_get_module_main_conf(r, ngx_http_mongolog_module);
        ngx_http_variable_value_t  *value;

        value = ngx_http_get_indexed_variable(r, conf->helpers->request_time_num);
        
        if (value == NULL || value->not_found) {
                return;
        }
        else {
                buf->value = value->data;
                buf->val_len = value->len;
                buf->ret = MONGOLOG_RETVAR_STR;
        }
                
        return;
}

static void ngx_mongolog_module_msec(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum) {
    	buf->ret = MONGOLOG_RETVAR_NOVAL;
    	buf->name = array_log_arg_types[fnum].type_name;
 		buf->name_len = &array_log_arg_types[fnum].name_len;

        ngx_http_mongolog_main_conf_t *conf = ngx_http_get_module_main_conf(r, ngx_http_mongolog_module);
        ngx_http_variable_value_t  *value;

        value = ngx_http_get_indexed_variable(r, conf->helpers->msec_num);
        
        if (value == NULL || value->not_found) {
                return;
        }
        else {
                buf->value = value->data;
                buf->val_len = value->len;
                buf->ret = MONGOLOG_RETVAR_STR;
        }
                
        return;
}

static void ngx_mongolog_module_server_name(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum) {
	buf->ret = MONGOLOG_RETVAR_NOVAL;
	buf->name = array_log_arg_types[fnum].type_name;
	buf->name_len = &array_log_arg_types[fnum].name_len;

	if (r->headers_in.server.len) {
		buf->value = r->headers_in.server.data;
		buf->val_len = r->headers_in.server.len;
		buf->ret = MONGOLOG_RETVAR_STR;
	}
	return;
}

static void ngx_mongolog_module_remote_addr(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum) {
        buf->ret = MONGOLOG_RETVAR_NOVAL;
        buf->name = array_log_arg_types[fnum].type_name;
        buf->name_len = &array_log_arg_types[fnum].name_len;

	if (r->connection->addr_text.len) {
                buf->value = r->connection->addr_text.data;
                buf->val_len = r->connection->addr_text.len;
                buf->ret = MONGOLOG_RETVAR_STR;
        }
	return;
}

static void ngx_mongolog_module_request_uri(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum) {
        buf->ret = MONGOLOG_RETVAR_NOVAL;
        buf->name = array_log_arg_types[fnum].type_name;
        buf->name_len = &array_log_arg_types[fnum].name_len;

	if (r->uri.len) {
                buf->value = r->uri.data;
                buf->val_len = r->uri.len;
                buf->ret = MONGOLOG_RETVAR_STR;
	}
	return;
}

static void ngx_mongolog_module_request_args(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum) {
        buf->ret = MONGOLOG_RETVAR_NOVAL;
        buf->name = array_log_arg_types[fnum].type_name;
        buf->name_len = &array_log_arg_types[fnum].name_len;

	if (r->args.len) {
                buf->value = r->args.data;
                buf->val_len = r->args.len;
                buf->ret = MONGOLOG_RETVAR_STR;
	}
	return;
}

static void ngx_mongolog_module_user_agent(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum) {
        buf->ret = MONGOLOG_RETVAR_NOVAL;
        buf->name = array_log_arg_types[fnum].type_name;
 	buf->name_len = &array_log_arg_types[fnum].name_len;

	if (r->headers_in.user_agent) {
                buf->value = r->headers_in.user_agent->value.data;
                buf->val_len = r->headers_in.user_agent->value.len;
                buf->ret = MONGOLOG_RETVAR_STR;
	}
	return;
}

static void ngx_mongolog_module_http_status(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum) {
        buf->ret = MONGOLOG_RETVAR_NOVAL;
        buf->name = array_log_arg_types[fnum].type_name;
        buf->name_len = &array_log_arg_types[fnum].name_len;

	if (r->headers_out.status) {
                buf->value = &r->headers_out.status;
		unsigned var_len = 1;
                buf->val_len = var_len;
		buf->ret = MONGOLOG_RETVAR_INT;
	}
	return;
}

static void ngx_mongolog_module_http_referer(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum) {
        buf->ret = MONGOLOG_RETVAR_NOVAL;
        buf->name = array_log_arg_types[fnum].type_name;
        buf->name_len = &array_log_arg_types[fnum].name_len;

	if (r->headers_in.referer) {
                buf->value = r->headers_in.referer->value.data;
                buf->val_len = r->headers_in.referer->value.len;
                buf->ret = MONGOLOG_RETVAR_STR;
	}
	return;
}

static void ngx_mongolog_module_is_internal(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum) {
        buf->ret = MONGOLOG_RETVAR_NOVAL;
        buf->name = array_log_arg_types[fnum].type_name;
        buf->name_len = &array_log_arg_types[fnum].name_len;

        if (r->headers_out.status) {
		unsigned value = 1;
                buf->value = &value;
                unsigned var_len = 1;
                buf->val_len = var_len;
                buf->ret = MONGOLOG_RETVAR_INT;
        }
	return;
}

static void ngx_mongolog_module_headers_in(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum) {
        buf->ret = MONGOLOG_RETVAR_NOVAL;
        buf->name = array_log_arg_types[fnum].type_name;
        buf->name_len = &array_log_arg_types[fnum].name_len;
	ngx_table_elt_t *h;
	ngx_list_part_t *part;

        bson_t *doc;
        doc = bson_new ();
	
	part = &r->headers_in.headers.part;

	while(part) {
		h = part->elts;
		unsigned i;
		for (i=0; i<part->nelts; i++){
			bson_append_utf8 (doc, (const char *) h[i].key.data, h[i].key.len, (const char *) h[i].value.data, h[i].value.len);
		}
		part = part->next;
	}

	buf->value = doc;	
	buf->val_len = 1;

	buf->ret = MONGOLOG_RETVAR_BSON;
	return;
}

static void ngx_mongolog_module_headers_out(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum) {
        buf->ret = MONGOLOG_RETVAR_NOVAL;
 	buf->name = array_log_arg_types[fnum].type_name;
        buf->name_len = &array_log_arg_types[fnum].name_len;
 	ngx_table_elt_t *h;
        ngx_list_part_t *part;
        
        bson_t *doc;
        doc = bson_new ();
         
        part = &r->headers_out.headers.part;
        
        while(part) {
                h = part->elts;
                unsigned i;
                for (i=0; i<part->nelts; i++){
                        bson_append_utf8 (doc, (const char *) h[i].key.data, h[i].key.len, (const char *) h[i].value.data, h[i].value.len);
                }
                part = part->next;
        }
        
        buf->value = doc;
        buf->val_len = 1;
                
        buf->ret = MONGOLOG_RETVAR_BSON;
 	return;
}

static void ngx_mongolog_module_request_body(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum) {
    	buf->ret = MONGOLOG_RETVAR_NOVAL;
    	buf->name = array_log_arg_types[fnum].type_name;
 		buf->name_len = &array_log_arg_types[fnum].name_len;

        ngx_http_mongolog_main_conf_t *conf = ngx_http_get_module_main_conf(r, ngx_http_mongolog_module);
        ngx_http_variable_value_t  *value;

        value = ngx_http_get_indexed_variable(r, conf->helpers->request_body_conf_num);
        
        if (value == NULL || value->not_found) {
                return;
        }
        else {
                buf->value = value->data;
                buf->val_len = value->len;
                buf->ret = MONGOLOG_RETVAR_STR;
        }
                
        return;
}

static void ngx_mongolog_module_method_name(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum) {
    	buf->ret = MONGOLOG_RETVAR_NOVAL;
    	buf->name = array_log_arg_types[fnum].type_name;
 		buf->name_len = &array_log_arg_types[fnum].name_len;
	
		if (r->method_name.len) {
	                buf->value = r->method_name.data;
	                buf->val_len = r->method_name.len;
	                buf->ret = MONGOLOG_RETVAR_STR;
		}
 		return;
 }

static void ngx_mongolog_module_http_protocol(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum) {
    	buf->ret = MONGOLOG_RETVAR_NOVAL;
    	buf->name = array_log_arg_types[fnum].type_name;
 		buf->name_len = &array_log_arg_types[fnum].name_len;

		if (r->http_protocol.len) {
	                buf->value = r->http_protocol.data;
	                buf->val_len = r->http_protocol.len;
	                buf->ret = MONGOLOG_RETVAR_STR;
		}
 		return;
 }
 
static void ngx_mongolog_module_request_length(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum) {
    	buf->ret = MONGOLOG_RETVAR_NOVAL;
    	buf->name = array_log_arg_types[fnum].type_name;
 		buf->name_len = &array_log_arg_types[fnum].name_len;

		if (r->request_length) {
	        buf->value = &r->request_length;
			buf->val_len = 1;
			buf->ret = MONGOLOG_RETVAR_OFFT;
		}

 		return;
 }

static void ngx_mongolog_module_bytes_sent(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum) {
    	buf->ret = MONGOLOG_RETVAR_NOVAL;
    	buf->name = array_log_arg_types[fnum].type_name;
 		buf->name_len = &array_log_arg_types[fnum].name_len;

		if (r->connection->sent) {
	        buf->value = &r->connection->sent;
			buf->val_len = 1;
			buf->ret = MONGOLOG_RETVAR_OFFT;
		}

 		return;
 }
 
static void ngx_mongolog_module_body_bytes_sent(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum) {
    	buf->ret = MONGOLOG_RETVAR_NOVAL;
    	buf->name = array_log_arg_types[fnum].type_name;
 		buf->name_len = &array_log_arg_types[fnum].name_len;

		off_t  length;
		if (r->connection->sent) {
			if (r->header_size) {
				length = r->connection->sent - r->header_size;
			}
			else {
				length = r->connection->sent;
			}
		}
		else {
			length = 0;
		}
 		if (length > 0 ) {
	        buf->value = &length;
			buf->val_len = 1;
			buf->ret = MONGOLOG_RETVAR_OFFT;
		}

 		return;
 }
 
static void ngx_mongolog_module_upstream_addr(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum) {
    	buf->ret = MONGOLOG_RETVAR_NOVAL;
    	buf->name = array_log_arg_types[fnum].type_name;
 		buf->name_len = &array_log_arg_types[fnum].name_len;

        ngx_http_mongolog_main_conf_t *conf = ngx_http_get_module_main_conf(r, ngx_http_mongolog_module);
        ngx_http_variable_value_t  *value;

        value = ngx_http_get_indexed_variable(r, conf->helpers->upstream_addr_variable_num);
        
        if (value == NULL || value->not_found) {
                return;
        }
        else {
                buf->value = value->data;
                buf->val_len = value->len;
                buf->ret = MONGOLOG_RETVAR_STR;
        }
                
        return;
}

static void ngx_mongolog_module_upstream_response_time(ngx_http_request_t *r, log_entry_val *buf, unsigned fnum) {
    	buf->ret = MONGOLOG_RETVAR_NOVAL;
    	buf->name = array_log_arg_types[fnum].type_name;
 		buf->name_len = &array_log_arg_types[fnum].name_len;

        ngx_http_mongolog_main_conf_t *conf = ngx_http_get_module_main_conf(r, ngx_http_mongolog_module);
        ngx_http_variable_value_t  *value;

        value = ngx_http_get_indexed_variable(r, conf->helpers->upstream_response_time_num);
        
        if (value == NULL || value->not_found) {
                return;
        }
        else {
                buf->value = value->data;
                buf->val_len = value->len;
                buf->ret = MONGOLOG_RETVAR_STR;
        }
                
        return;
}

