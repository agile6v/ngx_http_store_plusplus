
/*
 * Copyright (C) agile6v
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <nginx.h>
#include <ngx_http.h>
#include <ngx_md5.h>
#include <ngx_consistent_hash.h>

#define NGX_STORE_PLUSPLUS_TMP_PATH    "store_temp"
#define STORE_KEY_STR                  "cmd"
#define STORE_VALUE_STR                "value"
#define STORE_BRACKET_L                "("
#define STORE_BRACKET_R                ")"

ngx_module_t  ngx_http_store_plusplus_module;
ngx_conhash_ctx_t ngx_http_conhash_store_plusplus_ctx = {NULL, &ngx_http_store_plusplus_module};

typedef struct {
    ngx_str_t               name;           //  hnode name
    ngx_pool_t             *pool;
} ngx_http_store_plusplus_combination_t;

typedef struct {
    ngx_str_t               path_name;
    ngx_path_t             *origin_path;
    ngx_int_t              (*input_filter_init)(void *data);
    void                   (*finalize_request)(ngx_http_request_t *r, ngx_int_t rc);
    void                   *input_ctx;
    ngx_http_request_t     *request;
} ngx_http_store_plusplus_ctx_t;

typedef struct {
    ngx_array_t             *paths;         //  array of ngx_path_t *
} ngx_http_store_plusplus_path_t;

typedef struct {
    ngx_http_store_plusplus_path_t  *store_path;
    ngx_conhash_t                   *conhash;
} ngx_http_store_plusplus_main_conf_t;

static char *ngx_http_store_plusplus_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_store_plusplus_path_group_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_store_plusplus_path_conf(ngx_conf_t *cf, ngx_command_t *dummy, void *conf);
static ngx_int_t ngx_http_store_plusplus_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_store_plusplus_file_path_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static void *ngx_http_store_plusplus_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_store_plusplus_init_main_conf(ngx_conf_t *cf, void *conf);
static ngx_int_t ngx_http_store_plusplus_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_store_plusplus_module_init(ngx_cycle_t *cycle);
static void ngx_http_store_plusplus_get_data(ngx_conhash_vnode_t *vnode, void *data);
static void ngx_http_store_plusplus_make_hnode_len(ngx_conhash_vnode_t *vnode, void *data);
static void ngx_http_store_plusplus_make_hnode_info(ngx_conhash_vnode_t *vnode, void *data);
static ngx_int_t ngx_http_store_plusplus_filter_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_store_plusplus_node_traverse(ngx_http_request_t *r, ngx_conhash_t *conhash, 
    ngx_chain_t *out);
static ngx_int_t ngx_http_store_plusplus_add_path(ngx_http_request_t *r, ngx_conhash_t *conhash, 
    ngx_chain_t *out);
static ngx_int_t ngx_http_store_plusplus_del_path(ngx_http_request_t *r, ngx_conhash_t *conhash, 
    ngx_chain_t *out);
static ngx_int_t ngx_http_store_plusplus_input_filter_init(void *data);
static void ngx_http_store_plusplus_finalize_request(ngx_http_request_t *r, ngx_int_t rc);
static void ngx_http_store_plusplus_restore_status(ngx_http_request_t *r);

static ngx_str_t ngx_http_store_plusplus_file_path_var = ngx_string("store_plusplus_file_path");

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;

static ngx_command_t ngx_http_store_plusplus_module_commands[] = {
    
    { ngx_string("store_plusplus"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_store_plusplus_conf,
      0,
      0,
      NULL },
      
    { ngx_string("store_plusplus_conhash_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE12,
      ngx_conhash_shm_set_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_store_plusplus_main_conf_t, conhash),
      &ngx_http_conhash_store_plusplus_ctx},
    
    { ngx_string("store_plusplus_dir"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_http_store_plusplus_path_group_conf,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_store_plusplus_main_conf_t, store_path),
      NULL },
    
    ngx_null_command
};

static ngx_http_module_t  ngx_http_store_plusplus_module_ctx = {
    ngx_http_store_plusplus_add_variables,      /* preconfiguration */
    ngx_http_store_plusplus_filter_init,        /* postconfiguration */
    ngx_http_store_plusplus_create_main_conf,   /* create main configuration */
    ngx_http_store_plusplus_init_main_conf,     /* init main configuration */
    NULL,                                       /* create server configuration */
    NULL,                                       /* merge server configuration */
    NULL,                                       /* create location configuration */
    NULL                                        /* merge location configuration */
};

ngx_module_t  ngx_http_store_plusplus_module = {
    NGX_MODULE_V1,
    &ngx_http_store_plusplus_module_ctx,        /* module context */
    ngx_http_store_plusplus_module_commands,    /* module directives */
    NGX_HTTP_MODULE,                            /* module type */
    NULL,                                       /* init master */
    ngx_http_store_plusplus_module_init,        /* init module */
    NULL,                                       /* init process */
    NULL,                                       /* init thread */
    NULL,                                       /* exit thread */
    NULL,                                       /* exit process */
    NULL,                                       /* exit master */
    NGX_MODULE_V1_PADDING
};

static char *
ngx_http_store_plusplus_path_group_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char  *p = conf;
    
    ngx_http_store_plusplus_path_t  **a;
    ngx_http_store_plusplus_path_t   *store_path;
    char                             *rv;
    ngx_conf_t                        save;
    
    a = (ngx_http_store_plusplus_path_t **) (p + cmd->offset);
    if (*a != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }
    
    //  TODO:   parse parameter level
    
    store_path = ngx_pcalloc(cf->pool, sizeof(ngx_http_store_plusplus_path_t));
    if (store_path == NULL) {
        return NGX_CONF_ERROR;
    }
    
    save = *cf;
    cf->handler = ngx_http_store_plusplus_path_conf;
    cf->handler_conf = (void *) store_path;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;
    
    if (rv != NGX_CONF_OK) {
        return rv;
    }
    
    if (!store_path->paths->nelts) {
        //  TODO:   check whether block is empty
    }
    
    *a = store_path;
    
    return rv;
}

static char * 
ngx_http_store_plusplus_path_conf(ngx_conf_t *cf, ngx_command_t *dummy, void *conf)
{
    ngx_http_store_plusplus_path_t     *store_path = conf;
    
    u_char                             *p;
    ngx_str_t                          *value;
    ngx_path_t                         *path, *temp_path, **tmp;
    
    value = cf->args->elts;
    
    if (cf->args->nelts != 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid arguments in \"%V\"", &value[0]);
        return NGX_CONF_ERROR;
    }
    
    if (store_path->paths == NULL) {
        store_path->paths = ngx_array_create(cf->pool, 2, sizeof(ngx_path_t *));
        if (store_path->paths == NULL) {
            return NGX_CONF_ERROR;
        }
    }
    
    path = ngx_pcalloc(cf->pool, sizeof(ngx_path_t));
    if (path == NULL) {
        return NGX_CONF_ERROR;
    }
    
    path->name = value[0];
    if (path->name.data[path->name.len - 1] == '/') {
        path->name.len--;
    }
    
    if (ngx_conf_full_name(cf->cycle, &path->name, 0) != NGX_OK) {
        return NGX_CONF_ERROR;
    }
    
    path->len = 0;
    path->manager = NULL;
    path->loader = NULL;
    path->conf_file = cf->conf_file->file.name.data;
    path->line = cf->conf_file->line;
    
    tmp = ngx_array_push(store_path->paths);
    if (tmp == NULL) {
        return NGX_CONF_ERROR;
    }
    
    *tmp = path;
    
    if (ngx_add_path(cf, &path) == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }
    
    temp_path = ngx_pcalloc(cf->pool, sizeof(ngx_path_t));
    if (temp_path == NULL) {
        return NGX_CONF_ERROR;
    }
    
    temp_path->name.len = path->name.len + 1 + sizeof(NGX_STORE_PLUSPLUS_TMP_PATH) - 1;
    temp_path->name.data = ngx_pnalloc(cf->pool, temp_path->name.len + 1);
    if (temp_path->name.data == NULL) {
        return NGX_CONF_ERROR;
    }
    
    p = ngx_cpymem(temp_path->name.data, path->name.data, path->name.len);
    *p++ = '/';
    p = ngx_cpymem(p, NGX_STORE_PLUSPLUS_TMP_PATH, sizeof(NGX_STORE_PLUSPLUS_TMP_PATH) - 1);
    *p++ = '\0';
    
    temp_path->len = 0;
    temp_path->manager = NULL;
    temp_path->loader = NULL;
    temp_path->conf_file = cf->conf_file->file.name.data;
    temp_path->line = cf->conf_file->line;
    
    if (ngx_add_path(cf, &temp_path) == NGX_ERROR) {
        return NGX_CONF_ERROR;
    }
    
    return NGX_CONF_OK;
}

static ngx_int_t 
ngx_http_store_plusplus_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t             *var;

    var = ngx_http_add_variable(cf, &ngx_http_store_plusplus_file_path_var, NGX_HTTP_VAR_NOHASH);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_store_plusplus_file_path_variable;
   
    return NGX_OK;
}

static ngx_int_t
ngx_http_store_plusplus_file_path_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_int_t                               rc;
    ngx_http_store_plusplus_main_conf_t    *sppmcf;
    ngx_http_store_plusplus_ctx_t          *ctx;
    ngx_http_store_plusplus_combination_t   combination;
    
    sppmcf = ngx_http_get_module_main_conf(r, ngx_http_store_plusplus_module);
    
    if (sppmcf->store_path != NULL && sppmcf->store_path->paths != NULL) {
        
        ctx = ngx_http_get_module_ctx(r, ngx_http_store_plusplus_module);
        if (ctx == NULL) {
        
            ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_store_plusplus_ctx_t));
            if (ctx == NULL) {
                return NGX_ERROR;
            }
            
            combination.pool = r->pool;
            
            rc = ngx_conhash_lookup_node(sppmcf->conhash, r->uri.data, r->uri.len, 
                                         ngx_http_store_plusplus_get_data, &combination);
            if (rc != NGX_OK) {
                ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "the conhash space is not enough!");
                goto done;
            }
            
            ctx->path_name = combination.name;

            ngx_http_set_ctx(r, ctx, ngx_http_store_plusplus_module);
        } else {
            combination.name = ctx->path_name;
        }
        
        v->len = combination.name.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = combination.name.data;
        
        return NGX_OK;
    }

done:
    v->not_found = 1;
    return NGX_OK;
}

static void *
ngx_http_store_plusplus_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_store_plusplus_main_conf_t *sppmcf;
    
    sppmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_store_plusplus_main_conf_t));
    if (sppmcf == NULL) {
        return NULL;
    }
    
    sppmcf->store_path = NGX_CONF_UNSET_PTR;
    sppmcf->conhash = NGX_CONF_UNSET_PTR;

    return sppmcf;
}

static char *
ngx_http_store_plusplus_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_store_plusplus_main_conf_t *sppmcf = conf;
    
    if (sppmcf->store_path == NGX_CONF_UNSET_PTR) {
        sppmcf->store_path = NULL;
    }
    
    if (sppmcf->conhash == NGX_CONF_UNSET_PTR) {
        sppmcf->conhash = NULL;
    }
    
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_store_plusplus_header_filter(ngx_http_request_t *r)
{
    ngx_http_store_plusplus_main_conf_t  *sppmcf;
    ngx_http_store_plusplus_ctx_t        *ctx;
    u_char                               *p;
    ngx_path_t                           *path;

    sppmcf = ngx_http_get_module_main_conf(r, ngx_http_store_plusplus_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_store_plusplus_module);
    
    if (r->headers_out.status != NGX_HTTP_OK
        || !r->upstream
        || !r->upstream->store
        || !sppmcf->store_path
        || !ctx
        || !r->upstream->buffering
        || r->upstream->upgrade)
    {
        return ngx_http_next_header_filter(r);
    }
    
    ctx->input_filter_init = r->upstream->input_filter_init;
    ctx->finalize_request = r->upstream->finalize_request;
    ctx->input_ctx = r->upstream->pipe->input_ctx;
    ctx->request = r;
    ctx->origin_path = r->upstream->conf->temp_path;
    r->upstream->finalize_request = ngx_http_store_plusplus_finalize_request;
    r->upstream->input_filter_init = ngx_http_store_plusplus_input_filter_init;
    
    path = ngx_pcalloc(r->pool, sizeof(ngx_path_t));
    if (path == NULL) {
        return NGX_ERROR;
    }
    
    path->len = 0;
    path->level[0] = 0;
    path->level[1] = 0;
    path->level[2] = 0;
    
    path->name.len = ctx->path_name.len + sizeof(NGX_STORE_PLUSPLUS_TMP_PATH) - 1 + 1;
    path->name.data = ngx_pcalloc(r->pool, path->name.len + 1);
    if (path->name.data == NULL) {
        return NGX_ERROR;
    }
    
    p = ngx_sprintf(path->name.data, "%s" NGX_STORE_PLUSPLUS_TMP_PATH, ctx->path_name.data);
    *p++ = '/';
    *p++ = '\0';
    
    r->upstream->conf->temp_path = path;
    
    return ngx_http_next_header_filter(r);
}

static ngx_int_t 
ngx_http_store_plusplus_handler(ngx_http_request_t *r)
{
    ngx_int_t                            rc, cmd;
    ngx_chain_t                          out;
    ngx_str_t                            value;
    ngx_conhash_t                       *conhash;
    ngx_http_store_plusplus_main_conf_t *sppmcf;
    
    sppmcf = ngx_http_get_module_main_conf(r, ngx_http_store_plusplus_module);
    
    conhash = sppmcf->conhash;
    if (conhash == NULL) {
        return NGX_DECLINED;
    }

    out.buf = NULL;
    out.next = NULL;
    
    rc = ngx_http_arg(r, (u_char *) STORE_KEY_STR, sizeof(STORE_KEY_STR) - 1, &value);
    if (rc != NGX_OK) {
        return rc;
    }
    
    cmd = ngx_atoi(value.data, value.len);
    if (cmd < 1 && cmd > 4) {
        return NGX_DECLINED;
    }
    
    switch (cmd) {
        case 1:         //  add
            rc = ngx_http_store_plusplus_add_path(r, conhash, &out);
            break;
        case 2:         //  del
            rc = ngx_http_store_plusplus_del_path(r, conhash, &out);
            break;
        case 3:         //  traverse(for debug)
            rc = ngx_http_store_plusplus_node_traverse(r, conhash, &out);
            break;
    }
    
    if (rc != NGX_OK) {
        return rc;
    }
    
    r->headers_out.status = NGX_HTTP_OK;
    ngx_str_set(&r->headers_out.content_type, "text/plain");
    
    if (out.buf != NULL) {
        r->headers_out.content_length_n = ngx_buf_size(out.buf);
    } else {
        r->header_only = 1;
        r->headers_out.content_length_n = 0;
    }
    
    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }
    
    return ngx_http_output_filter(r, &out);
}

static char *
ngx_http_store_plusplus_conf(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;
    
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_store_plusplus_handler;
    
    return NGX_CONF_OK;
}

static ngx_int_t 
ngx_http_store_plusplus_module_init(ngx_cycle_t *cycle)
{
    ngx_uint_t                            i;
    ngx_int_t                             rc;
    ngx_path_t                           *path, **tmp_path;
    ngx_http_store_plusplus_main_conf_t  *sppmcf;

    sppmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_store_plusplus_module);
    
    if (sppmcf->store_path == NULL) {
        return NGX_OK;
    }
    
    tmp_path = (ngx_path_t **) sppmcf->store_path->paths->elts;
    
    for (i = 0; i < sppmcf->store_path->paths->nelts; i++) {
    
        path = tmp_path[i];
        
        rc = ngx_conhash_add_node(sppmcf->conhash, path->name.data, path->name.len, NULL);
        if (rc == NGX_DECLINED) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "the node already exists!");
            continue;
        }
        
        if (rc == NGX_ERROR) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "the conhash has not been initialized");
            return NGX_ERROR;
        }
        
        if (rc == NGX_AGAIN) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "the conhash space is not enough!");
            return NGX_ERROR;
        }
    }
    
    return NGX_OK;
}

static void 
ngx_http_store_plusplus_get_data(ngx_conhash_vnode_t *vnode, void *data)
{
    ngx_http_store_plusplus_combination_t *combination = data;
    
    u_char     *p;
    
    combination->name.len = vnode->hnode->name.len + 1;
    combination->name.data = ngx_pcalloc(combination->pool, combination->name.len + 1);
    if (combination->name.data == NULL) {
        return;
    }
    
    p = ngx_cpymem(combination->name.data, vnode->hnode->name.data, vnode->hnode->name.len);
    *p++ = '/';
    *p++ = '\0';
}

static ngx_int_t
ngx_http_store_plusplus_node_traverse(ngx_http_request_t *r, ngx_conhash_t *conhash, ngx_chain_t *out)
{
    size_t                len;
    ngx_buf_t            *b;
    ngx_int_t             rc;
    
    len = 0;
    
    rc = ngx_conhash_node_traverse(conhash, ngx_http_store_plusplus_make_hnode_len, &len);
    if (rc == NGX_DECLINED) {
    
        b = ngx_create_temp_buf(r->pool, 1024);
        if (b == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        
        b->last = ngx_sprintf(b->last, "The node tree is empty!" CRLF);
        
        goto done;
    }
    
    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    rc = ngx_conhash_node_traverse(conhash, ngx_http_store_plusplus_make_hnode_info, b);
    if (rc == NGX_DECLINED) {
    
        b = ngx_create_temp_buf(r->pool, 1024);
        if (b == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        
        b->last = ngx_sprintf(b->last, "The node tree is empty!" CRLF);
    }

done:

    b->last_buf = 1;
    out->buf = b;
    
    return NGX_OK;
}

static void
ngx_http_store_plusplus_make_hnode_len(ngx_conhash_vnode_t *vnode, void *data)
{
    size_t *len = data;
    
    *len += vnode->name.len + sizeof(STORE_BRACKET_L) - 1 + NGX_OFF_T_LEN + 
           sizeof(STORE_BRACKET_R) - 1 + sizeof(CRLF) - 1;
}

static void
ngx_http_store_plusplus_make_hnode_info(ngx_conhash_vnode_t *vnode, void *data)
{
    ngx_buf_t   *b = data;
    
    b->last = ngx_sprintf(b->last, "%V" STORE_BRACKET_L "%ui" STORE_BRACKET_R CRLF, 
                            &vnode->name, vnode->node.key);
}

static ngx_int_t
ngx_http_store_plusplus_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_store_plusplus_header_filter;
    
    return NGX_OK;
}

static ngx_int_t
ngx_http_store_plusplus_add_path(ngx_http_request_t *r, ngx_conhash_t *conhash, ngx_chain_t *out)
{
    ngx_str_t                            value;
    size_t                               len;
    ngx_int_t                            rc;
    ngx_buf_t                           *b;
    u_char                              *p, *path_name;
    ngx_file_info_t                      fi;
    ngx_err_t                            err;
    
    rc = ngx_http_arg(r, (u_char *) STORE_VALUE_STR, sizeof(STORE_VALUE_STR) - 1, &value);
    if (rc != NGX_OK) {
        return rc;
    }
    
    b = ngx_create_temp_buf(r->pool, 1024);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    if (value.data[0] != '/') {
        b->last = ngx_sprintf(b->last, "ERROR: must be an absolute path." CRLF);
        rc = NGX_OK;
        goto done;
    }
    
    if (value.data[value.len - 1] == '/') {
        value.len--;
    }
    
    //  check whether the store path is existent.
    len = value.len + 1 + sizeof(NGX_STORE_PLUSPLUS_TMP_PATH) - 1;
    path_name = ngx_pcalloc(r->pool, len + 1);
    if (path_name == NULL) {
        return NGX_ERROR;
    }
    
    p = ngx_cpymem(path_name, value.data, value.len);
    *p = '\0';
    
    rc = ngx_file_info(path_name, &fi);
    if (rc == NGX_FILE_ERROR) {
        err = ngx_errno;
        b->last = ngx_strerror(err, b->last, b->end - b->last);
        *b->last++ = CR;
        *b->last++ = LF;
        rc = NGX_OK;
        goto done;
    }
    
    //  create temp_path in this store path
    p = ngx_cpymem(path_name, value.data, value.len);
    *p++ = '/';
    p = ngx_cpymem(p, NGX_STORE_PLUSPLUS_TMP_PATH, sizeof(NGX_STORE_PLUSPLUS_TMP_PATH) - 1);
    *p++ = '\0';

    if (ngx_create_dir(path_name, ngx_dir_access(NGX_FILE_OWNER_ACCESS)) 
        == NGX_FILE_ERROR) 
    {
        err = ngx_errno;
        if (err != NGX_EEXIST) {
            b->last = ngx_strerror(err, b->last, b->end - b->last);
            *b->last++ = CR;
            *b->last++ = LF;
            rc = NGX_OK;
            goto done;
        }
    }
    
    rc = ngx_conhash_add_node(conhash, value.data, value.len, NULL);
    if (rc == NGX_OK) {
        b->last = ngx_sprintf(b->last, "Add node successfully!" CRLF);
    }
    
    if (rc == NGX_DECLINED) {
        b->last = ngx_sprintf(b->last, "The node already exists!" CRLF);
        rc = NGX_OK;
    }
    
    if (rc == NGX_AGAIN) {
        b->last = ngx_sprintf(b->last, "The conhash space is not enough!" CRLF);
        rc = NGX_OK;
    }

done:
    b->last_buf = 1;
    out->buf = b;
    
    return rc;
}

static ngx_int_t
ngx_http_store_plusplus_del_path(ngx_http_request_t *r, ngx_conhash_t *conhash, ngx_chain_t *out)
{
    ngx_str_t                            value;
    ngx_int_t                            rc;
    ngx_buf_t                           *b;
    
    rc = ngx_http_arg(r, (u_char *) STORE_VALUE_STR, sizeof(STORE_VALUE_STR) - 1, &value);
    if (rc != NGX_OK) {
        return rc;
    }
    
    b = ngx_create_temp_buf(r->pool, 1024);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    rc = ngx_conhash_del_node(conhash, value.data, value.len);
    if (rc == NGX_OK) {
        b->last = ngx_sprintf(b->last, "Delete node successfully!" CRLF);
    }
    
    if (rc == NGX_DECLINED) {
        b->last = ngx_sprintf(b->last, "The node does not exists!" CRLF);
        rc = NGX_OK;
    }
    
    b->last_buf = 1;
    out->buf = b;
    
    return rc;
}

static ngx_int_t
ngx_http_store_plusplus_input_filter_init(void *data)
{
    ngx_http_request_t  *request = data;
    
    ngx_http_store_plusplus_restore_status(request);
    
    return request->upstream->input_filter_init(data);
}

static void
ngx_http_store_plusplus_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_http_store_plusplus_restore_status(r);

    return r->upstream->finalize_request(r, rc);
}

static void 
ngx_http_store_plusplus_restore_status(ngx_http_request_t *r)
{
    ngx_http_store_plusplus_ctx_t   *ctx;
    
    ctx = ngx_http_get_module_ctx(r, ngx_http_store_plusplus_module);
    
    r->upstream->input_filter_init = ctx->input_filter_init;
    r->upstream->finalize_request = ctx->finalize_request;
    r->upstream->pipe->input_ctx = ctx->input_ctx;
    r->upstream->conf->temp_path = ctx->origin_path;
}
