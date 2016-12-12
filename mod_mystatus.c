#include "ap_mpm.h"
#include "apr_strings.h"
#include "scoreboard.h"
#include "httpd.h"
#include "http_log.h"
#include "http_core.h"
#include "http_request.h"
#include "http_protocol.h"

#include <regex.h>

#include "cJSON.h"

#define ENO_ERROR 0
#define EPARAMETER_IS_NULL 1
#define EREGCOMP_ERROR 2
#define EREGEXEC_ERROR 3
#define ESPLIT_REQUEST_ERROR 4
#define ENO_BODY_ERROR 5
#define EPARSE_JSON_ERROR 6
#define EJSON_KEY_NOT_EXISTS 7

static int server_limit, thread_limit;

// the following structs be used when traversing the socreboard to get conn_bytes
typedef struct url {
    char name[32];
    char request[64];
} url_t ;

typedef struct status {
    unsigned long conn_count;
    unsigned long flow;
} status_t ;

typedef struct url_status_map {
    url_t url;
    status_t status;
} url_status_map_t ;

typedef struct url_status_map_list {
  url_status_map_t url_status_map;
  struct url_status_map_list *next;
} url_status_map_list_t ;

APR_OPTIONAL_FN_TYPE(ap_logio_add_bytes_in) *mystatus_logio_add_bytes_in;
APR_OPTIONAL_FN_TYPE(ap_logio_add_bytes_out) *mystatus_logio_add_bytes_out;
APR_OPTIONAL_FN_TYPE(ap_logio_get_last_bytes) *mystatus_logio_get_last_bytes;

// modify http error page
static void set_error_message(request_rec *r, int err_code, const char *err_msg) {
    ap_set_content_type(r, "application/json");
    cJSON *root;

    root = cJSON_CreateObject();

    cJSON_AddNumberToObject(root, "error", err_code);
    cJSON_AddStringToObject(root, "message", err_msg);

    ap_custom_response(r, HTTP_INTERNAL_SERVER_ERROR, cJSON_PrintUnformatted(root));
}

static int status_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp,
                       server_rec *s)
{
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_THREADS, &thread_limit);
    ap_mpm_query(AP_MPMQ_HARD_LIMIT_DAEMONS, &server_limit);

    return OK;
}

// split url based on space character
static int get_url_request_part(request_rec *r, const char *request, char *result) {
    int retval = ENO_ERROR;
    char err_msg[128] = {0};

    const char *p = strchr(request, ' ');
    const char *q = strchr(p + 1, ' ');

    if (p && q) {
        strncpy(result, p + 1, q - p - 1);
    } else {
        retval = ESPLIT_REQUEST_ERROR;
        apr_snprintf(err_msg, sizeof (err_msg),
                     "split the request error, request is %s", request);
        set_error_message(r, retval, err_msg);
    }

    return retval;
}

// get url status map list based on scoreboard
static void get_url_status_map_list(request_rec *r, url_status_map_list_t **list) {
    int i, j;
    apr_off_t conn_bytes;
    worker_score *ws_record = apr_palloc(r->pool, sizeof *ws_record);

    url_status_map_list_t *head_node = NULL, *tail_node = NULL, *temp_node = NULL;
    url_status_map_t status_map;
    url_status_map_list_t *p = head_node;

    for (i = 0; i < server_limit; ++i) {
        for (j = 0; j < thread_limit; ++j) {
            ap_copy_scoreboard_worker(ws_record, i, j);

            if (ws_record->status == SERVER_READY ||
                     ws_record->status == SERVER_DEAD) {
                continue;
            }

            conn_bytes = ws_record->conn_bytes;

            memset(&status_map, 0, sizeof(url_status_map_t));
            // copy vhost
            strcpy(status_map.url.name, ws_record->vhost);

            // split 'GET /aaaa HTTP1.1' ==> /aaaa
            get_url_request_part(r, ws_record->request, status_map.url.request);

            status_map.status.conn_count = 1; // by vhost and request to calculate connection count
            status_map.status.flow = conn_bytes;

            p = head_node;
            for (; p != NULL; p = p->next) {
                if (!strcmp(p->url_status_map.url.name, status_map.url.name)
                    && !strcmp(p->url_status_map.url.request, status_map.url.request)) {
                    p->url_status_map.status.conn_count += 1;
                    p->url_status_map.status.flow += conn_bytes;

                    break;
                }
            }
            if (p == NULL) {
                temp_node = apr_palloc(r->pool, sizeof(url_status_map_list_t));

                memcpy(&temp_node->url_status_map, &status_map, sizeof(url_status_map_t));
                temp_node->next = NULL;

                if (head_node == NULL) {
                    head_node = temp_node;
                    tail_node = head_node;
                } else {
                    tail_node->next = temp_node;
                    tail_node = temp_node;
                }
            }
        }
    }

    *list = head_node;
}

// calculating connection count and bandwidth by specific vhost and pattern once again
static int find_url_status_map_by_pattern(
        request_rec *r,
        const url_status_map_list_t *list,
        const char *pattern,
        url_status_map_t *result) {
    int retval = ENO_ERROR;
    char err_msg[128] = {0};
    const url_status_map_list_t *p = list;

    if (p == NULL) {
        retval = EPARAMETER_IS_NULL;
        set_error_message(r, retval, "the parameter of source list is null");
        return retval;
    }

    regex_t regex;
    if (regcomp(&regex, pattern, 0) < 0) {
        retval = EREGCOMP_ERROR;
        apr_snprintf(err_msg, sizeof (err_msg),
                     "regcomp function error, pattern is %s", pattern);
        set_error_message(r, retval, err_msg);
        return retval;
    }

    apr_snprintf(result->url.name, sizeof (result->url.name), "%s:%d",
                 r->server->server_hostname, r->connection->local_addr->port);
    apr_cpystrn(result->url.request, pattern, sizeof(result->url.request));
    result->status.conn_count = 0L;
    result->status.flow = 0L;

    while (p != NULL) {
        if (!apr_strnatcmp(result->url.name, p->url_status_map.url.name)) {

            retval = regexec(&regex, p->url_status_map.url.request, 0, NULL, 0);

            if (!retval) {
                result->status.conn_count += p->url_status_map.status.conn_count;
                result->status.flow += p->url_status_map.status.flow;
            } else if (retval == REG_NOMATCH) {
                retval = ENO_ERROR;
            } else {
                retval = EREGEXEC_ERROR;
                apr_snprintf(err_msg, sizeof (err_msg),
                             "regexec function error, request is %s", p->url_status_map.url.request);
                set_error_message(r, retval, err_msg);

                regfree(&regex);
                return retval;
            }
        }

        p = p->next;
    }

    regfree(&regex);
    return retval;
}

// read http request body
static int util_read(request_rec *r, const char **rbuf, apr_off_t *size)
{
    int retval = ENO_ERROR;

    if((retval = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR))) {
        return retval;
    }

    if(ap_should_client_block(r)) {
        char argsbuffer[HUGE_STRING_LEN];
        apr_off_t rsize, len_read, rpos = 0;
        apr_off_t length = r->remaining;

        *rbuf = (const char *) apr_pcalloc(r->pool, (apr_size_t) (length + 1));
        *size = length;
        while((len_read = ap_get_client_block(r, argsbuffer, sizeof(argsbuffer))) > 0) {
            if((rpos + len_read) > length) {
                rsize = length - rpos;
            }
            else {
                rsize = len_read;
            }

            memcpy((char *) *rbuf + rpos, argsbuffer, (size_t) rsize);
            rpos += rsize;
        }
    }

    return retval;
}

#if 0
// parse "a=1&b=2"
static void parse_content_body(request_rec *r, const char *buffer, key_value_pair_list_t **list) {
    key_value_pair_list_t *head_node = NULL, *tail_node = NULL, *temp_node = NULL;
    const char *p = NULL;
    const char *q = buffer;

    while ((p = strchr(q, '=')) != NULL) {
        temp_node = apr_palloc(r->pool, sizeof(key_value_pair_list_t));
        temp_node->next = NULL;

        memset(temp_node, 0, sizeof(key_value_pair_list_t));
        memcpy(temp_node->key_value_pair.key, q, p - q);

        if (head_node == NULL) {
          head_node = temp_node;
          tail_node = head_node;
        } else {
          tail_node->next = temp_node;
          tail_node = temp_node;
        }

        q = ++p;
        if ((p = strchr(q, '&')) != NULL) {
            memcpy(temp_node->key_value_pair.value, q, p - q);
            q = ++p;
        } else {
            // terminate
            memcpy(temp_node->key_value_pair.value, q, buffer + strlen(buffer) - q);
            break;
        }
    }

    *list = head_node;
}

#endif

// parse http body json string to get pattern regex expression
static int get_pattern(request_rec *r, char *pattern) {
    int retval = ENO_ERROR;
    apr_off_t   size = 0;
    const char  *buffer = NULL;

    if ((retval = util_read(r, &buffer, &size))) {
        return retval;
    }

    if (size == 0) {
        retval = ENO_BODY_ERROR;
        set_error_message(r, retval, "the body be read is empty");
        return retval;
    }

    char *decode_buffer = apr_palloc(r->pool, size * sizeof(char) + 1);
    memcpy(decode_buffer, buffer, size + 1);

    // urldecode
//    ap_unescape_url(decode_buffer);

    // parse json
    cJSON *root = cJSON_Parse(decode_buffer);

    if (!root) {
        retval = EPARSE_JSON_ERROR;
        set_error_message(r, retval, "parse json error");
        return retval;
    }
    cJSON *item = cJSON_GetObjectItem(root, "pattern");

    if (!item) {
        retval = EJSON_KEY_NOT_EXISTS;
        set_error_message(r, retval, "json key is not exists, it should be pattern");
        return retval;
    }

    apr_cpystrn(pattern, item->valuestring, strlen(item->valuestring) + 1);

    return retval;
}

// for debug
static void print_list(request_rec *r, url_status_map_list_t *list) {
    url_status_map_list_t *p = list;

    while (p != NULL) {
        ap_rprintf(r, " name=%s,req=%s,count=%ld,flow=%ld\n",
                   p->url_status_map.url.name, p->url_status_map.url.request,
                   p->url_status_map.status.conn_count, p->url_status_map.status.flow);

        p = p->next;
    }
}

// format data to json format and output
static int output_bandwidth_connection_count(request_rec *r) {
    int retval = ENO_ERROR;
    url_status_map_list_t *list1, *list2;

    ap_set_content_type(r, "application/json");

    // first, get map list
    get_url_status_map_list(r, &list1);

    apr_sleep(1000 * 1000);

    // get map list once again
    get_url_status_map_list(r, &list2);

    cJSON *root = NULL;
    char *json_str = NULL;

    root = cJSON_CreateObject();

    char pattern[64] = {0};

    if ((retval = get_pattern(r, pattern))) {
        return retval;
    }

    url_status_map_t status_map1, status_map2;
    memset(&status_map1, 0, sizeof(url_status_map_t));
    memset(&status_map2, 0, sizeof(url_status_map_t));

    long flow_abs = 0;

    if (!(retval = find_url_status_map_by_pattern(r, list1, pattern, &status_map1))
            && !(retval = find_url_status_map_by_pattern(r, list2, pattern, &status_map2))) {
        flow_abs = status_map1.status.flow - status_map2.status.flow;
        flow_abs = (flow_abs < 0) ? -flow_abs : flow_abs;

        cJSON_AddNumberToObject(root, "connection_count", status_map2.status.conn_count);
        cJSON_AddNumberToObject(root, "bandwidth", flow_abs);

        json_str = cJSON_PrintUnformatted(root);

        ap_rputs(json_str, r);
    }

    cJSON_Delete(root);

    return retval;
}

static int mystatus_handler(request_rec *r)
{
    if (!r->handler || strcmp(r->handler, "mystatus-handler")) return DECLINED;

    if (!output_bandwidth_connection_count(r)) return OK;

    return HTTP_INTERNAL_SERVER_ERROR;
}

/*
 * Optional function for the core to add to bytes_out
 */

static void ap_logio_add_bytes_out(conn_rec *c, apr_off_t bytes)
{
//    ap_log_error(APLOG_MARK, APLOG_EMERG, 0, NULL, APLOGNO(02818)
//                 "mystatus ap_logio_add_bytes_out");

    worker_score *ws = ap_get_scoreboard_worker(c->sbh);

    if (ws) {
//        ws->status = SERVER_BUSY_LOG;

        ws->bytes_served += bytes;
        ws->access_count += bytes;
        ws->my_access_count += bytes;
        ws->conn_bytes += bytes;
    }

    if (mystatus_logio_add_bytes_out)
        mystatus_logio_add_bytes_out(c, bytes);
}

/*
 * Optional function for modules to adjust bytes_in
 */

static void ap_logio_add_bytes_in(conn_rec *c, apr_off_t bytes)
{
//    ap_log_error(APLOG_MARK, APLOG_EMERG, 0, NULL, APLOGNO(02818)
//                 "mystatus ap_logio_add_bytes_in");

    worker_score *ws = ap_get_scoreboard_worker(c->sbh);

    if (ws) {
//        ws->status = SERVER_BUSY_LOG;

        ws->bytes_served += bytes;
        ws->access_count += bytes;
        ws->my_access_count += bytes;
        ws->conn_bytes += bytes;
    }

    if (mystatus_logio_add_bytes_in)
        mystatus_logio_add_bytes_in(c, bytes);
}

static apr_off_t ap_logio_get_last_bytes(conn_rec *c)
{
//    ap_log_error(APLOG_MARK, APLOG_EMERG, 0, NULL, APLOGNO(02818)
//                 "mystatus ap_logio_get_last_bytes");

    if (mystatus_logio_get_last_bytes)
        (void)mystatus_logio_get_last_bytes(c);

    return 0;
}

static int status_pre_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp)
{
    /* When mod_status is loaded, default our ExtendedStatus to 'on'
     * other modules which prefer verbose scoreboards may play a similar game.
     * If left to their own requirements, mpm modules can make do with simple
     * scoreboard entries.
     */
    ap_extended_status = 1;
    return OK;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_handler(mystatus_handler, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_pre_config(status_pre_config, NULL, NULL, APR_HOOK_LAST);
    ap_hook_post_config(status_init, NULL, NULL, APR_HOOK_MIDDLE);

    mystatus_logio_add_bytes_in = APR_RETRIEVE_OPTIONAL_FN(ap_logio_add_bytes_in);
    mystatus_logio_add_bytes_out = APR_RETRIEVE_OPTIONAL_FN(ap_logio_add_bytes_out);
    mystatus_logio_get_last_bytes = APR_RETRIEVE_OPTIONAL_FN(ap_logio_get_last_bytes);

    APR_REGISTER_OPTIONAL_FN(ap_logio_add_bytes_out);
    APR_REGISTER_OPTIONAL_FN(ap_logio_add_bytes_in);
    APR_REGISTER_OPTIONAL_FN(ap_logio_get_last_bytes);
}

module AP_MODULE_DECLARE_DATA mystatus_module = 
{
    STANDARD20_MODULE_STUFF,
    NULL,                       /* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    NULL,                       /* command table */
    register_hooks              /* register_hooks */
};


