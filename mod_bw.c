/*

Apache2 - Mod_bw v0.7

Author       : Ivan Barrera A. (Bruce)

HomePage     : Http://Ivn.cl/apache

Release Date : 01-09-2005

Status       : Functional. Tested under medium and heavy load.

License      : Licensed under the Apache Software License v2.0
               It must be included as LICENSE in this package.

Platform     : Linux/x86         (Tested with Fedora Core 4, Suse, etc)
               FreeBSD/x86       (Tested on 5.2)
               MacOS X/Ppc x86   (Tested on both platforms)
               Solaris 8/sparc   (Some notes on compile)
               Microsoft Windows (Win XP, Win2003. Others should work)

Notes        : This is a stable version of mod_bw. It works fine with
               almost any MPM (tested with WinNT/prefork/Worker MPM).

Limitations  : This mod doesn't know how fast is the client really 
               downloading a file, so it just divides the bw assigned
               between the users.
               MaxConnections works only for the given scope. (i.e , all
               will limit maxconnections from all,not per ip or user)

*/

#define VERSION "0.7"

#include "apr_buckets.h"
#include "apr_strings.h"
#include "apr_atomic.h"
#include "apr_lib.h"
#include "apr_shm.h"
#include "ap_config.h"
#include "util_filter.h"
#include "ap_mpm.h"
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_log.h"
#include "http_main.h"
#include "util_script.h"
#include "http_core.h"
#include "scoreboard.h"

#define MIN_BW 256              /* Minimal bandwidth 256 bytes  */
#define PACKET 8192             /* Default packet at 8192 bytes */

#define BANDWIDTH_DISABLED             1<<0
#define BANDWIDTH_ENABLED              1<<1
#define SHARED_FILENAME "logs/bwmod_runtime_status"

/* Compatibility for ARP < 1 */
#ifdef APR_MAJOR_VERSION
#if (APR_MAJOR_VERSION < 1)
    #define apr_atomic_inc32 apr_atomic_inc
    #define apr_atomic_dec32 apr_atomic_dec
    #define apr_atomic_add32 apr_atomic_add
    #define apr_atomic_cas32 apr_atomic_cas
    #define apr_atomic_set32 apr_atomic_set
#endif
#endif

/* Enum types of "from address" */
enum from_type {
    T_ALL,
    T_IP,
    T_HOST,
};

/* 
 - Stats of each conf
 -
 - id          = Configuration ID
 - time        = Time of the last data update
 - bandwidth   = Estimated bandwidth measured
 - bytes_count = Bytes sent last second
 - connection_ = Number of simultaneos clientes downloading
 - lock        = Lock, to avoid simultaneous write access to shm
*/
typedef struct
{
    apr_uint32_t id;
    apr_uint32_t connection_count;
    apr_uint32_t bandwidth;
    apr_uint32_t bytes_count;
    volatile apr_uint32_t lock;
    apr_time_t time;
} bw_data;

/* A temporal context to save our splitted brigade */
typedef struct ctx_struct_t
{
    apr_bucket_brigade *bb;
    struct timeval wait;
} ctx_struct;

/* With sid we count the shared memory needed. 
   BwBase, is a holder to the shared memory base addres */
static int sid = 0;
bw_data *bwbase;
apr_shm_t *shm;


/* Limits for MaxConnections based on directory */
typedef struct
{
    apr_uint32_t sid;
    union {
        char *from;
        apr_ipsubnet_t *ip;
    } x;
    enum from_type type;
    apr_uint32_t max;
} bw_maxconn;

/* Limits for bandwidth and minimal bandwidth based on directory */
typedef struct
{
    apr_uint32_t sid;
    union {
        char *from;
        apr_ipsubnet_t *ip;
    } x;
    enum from_type type;
    apr_uint32_t rate;
} bw_entry;

/* Limits for bandwidth based on file size */
typedef struct
{
    apr_uint32_t sid;
    char *file;
    apr_uint32_t size;
    apr_uint32_t rate;
} bw_sizel;

/* Per directory configuration structure */
typedef struct
{
    apr_array_header_t *limits;
    apr_array_header_t *minlimits;
    apr_array_header_t *sizelimits;
    apr_array_header_t *maxconnection;
    int packet;
    int error;
    char *directory;
} bandwidth_config;

/* Per server configuration structure */
typedef struct
{
    int state;
    int force;
} bandwidth_server_config;

/* Module declaration */
module AP_MODULE_DECLARE_DATA bw_module;

/*---------------------------------------------------------------------*
 * Configurations Directives                                           *
 *---------------------------------------------------------------------*/
/* Set the mod enabled ... or disabled */
static const char *bandwidthmodule(cmd_parms * cmd, void *dconf, int flag)
{
    bandwidth_server_config *sconf;

    sconf =
        (bandwidth_server_config *) ap_get_module_config(cmd->server->
                                                         module_config,
                                                         &bw_module);
    sconf->state = (flag ? BANDWIDTH_ENABLED : BANDWIDTH_DISABLED);

    return NULL;
}

/* Set force mode enabled ... or disabled */
static const char *forcebandwidthmodule(cmd_parms * cmd, void *dconf,
                                        int flag)
{
    bandwidth_server_config *sconf;

    sconf =
        (bandwidth_server_config *) ap_get_module_config(cmd->server->
                                                         module_config,
                                                         &bw_module);
    sconf->force = (flag ? BANDWIDTH_ENABLED : BANDWIDTH_DISABLED);

    return NULL;
}

/* Set the packetsize used in the context */
static const char *setpacket(cmd_parms * cmd, void *s, const char *pack)
{
    bandwidth_config *conf = (bandwidth_config *) s;
    int temp;

    if (pack && *pack && apr_isdigit(*pack))
        temp = atol(pack);
    else
        return "Invalid argument";

    if ((temp < 1024) || (temp > 131072))
        return "Packet must be a number of bytes between 1024 and 131072";

    conf->packet = temp;

    return NULL;
}

/* Set the error to send when maxconnections is reached */
static const char *bandwidtherror(cmd_parms * cmd, void *s, const char *err)
{
    bandwidth_config *conf = (bandwidth_config *) s;
    int temp;

    if (err && *err && apr_isdigit(*err))
        temp = atol(err);
    else
        return "Invalid argument";

    if ((temp < 300) || (temp > 999))
        return "Error must be a number between 300 and 599";

    conf->error = temp;

    return NULL;
}

/* Set the maxconnections on a per host basis */
static const char *maxconnection(cmd_parms * cmd, void *s, const char *from,
                                 const char *maxc)
{
    bandwidth_config *conf = (bandwidth_config *) s;
    bw_maxconn *a;
    int temp;
    char *str;
    char *where = (char *) apr_pstrdup(cmd->pool, from);
    apr_status_t rv;
    char msgbuf[120];

    if (maxc && *maxc && apr_isdigit(*maxc))
        temp = atoi(maxc);
    else
        return "Invalid argument";

    if (temp < 0)
        return
            "Connections must be a number of simultaneous connections allowed/s";

    a = (bw_maxconn *) apr_array_push(conf->maxconnection);

    a->x.from = where;
    if (!strcasecmp(where, "all")) {
        a->type = T_ALL;
    }
    else if ((str = strchr(where, '/'))) {
        *str++ = '\0';
        rv = apr_ipsubnet_create(&a->x.ip, where, str, cmd->pool);
        if(APR_STATUS_IS_EINVAL(rv)) { 
            /* looked nothing like an IP address */
            return "An IP address was expected";
        }
        else if (rv != APR_SUCCESS) {
            apr_strerror(rv, msgbuf, sizeof msgbuf);
            return apr_pstrdup(cmd->pool, msgbuf);
        }
        a->type = T_IP;
    }       
    else if (!APR_STATUS_IS_EINVAL(rv = apr_ipsubnet_create(&a->x.ip, where, NULL, cmd->pool))) {
        if (rv != APR_SUCCESS) {
            apr_strerror(rv, msgbuf, sizeof msgbuf);
            return apr_pstrdup(cmd->pool, msgbuf);
        }
        a->type = T_IP;
    }       
    else { /* no slash, didn't look like an IP address => must be a host */
        a->type = T_HOST;
    }

    a->max = temp;

    return NULL;
}

/* Set the bandwidth on a per host basis */
static const char *bandwidth(cmd_parms * cmd, void *s, const char *from,
                             const char *bw)
{
    bandwidth_config *conf = (bandwidth_config *) s;
    bw_entry *a;
    long int temp;
    char *str;
    char *where = (char *) apr_pstrdup(cmd->pool, from);
    apr_status_t rv;
    char msgbuf[120];

    if (bw && *bw && apr_isdigit(*bw))
        temp = atol(bw);
    else
        return "Invalid argument";

    if (temp < 0)
        return "BandWidth must be a number of bytes/s";

    a = (bw_entry *) apr_array_push(conf->limits);
    a->x.from = where;
    if (!strcasecmp(where, "all")) {
        a->type = T_ALL;
    }
    else if ((str = strchr(where, '/'))) {
        *str++ = '\0';
        rv = apr_ipsubnet_create(&a->x.ip, where, str, cmd->pool);
        if(APR_STATUS_IS_EINVAL(rv)) {
            /* looked nothing like an IP address */
            return "An IP address was expected";
        }
        else if (rv != APR_SUCCESS) {
            apr_strerror(rv, msgbuf, sizeof msgbuf);
            return apr_pstrdup(cmd->pool, msgbuf);
        }
        a->type = T_IP;
    }
    else if (!APR_STATUS_IS_EINVAL(rv = apr_ipsubnet_create(&a->x.ip, where, NULL, cmd->pool))) {
        if (rv != APR_SUCCESS) {
            apr_strerror(rv, msgbuf, sizeof msgbuf);
            return apr_pstrdup(cmd->pool, msgbuf);
        }
        a->type = T_IP;
    }
    else { /* no slash, didn't look like an IP address => must be a host */
        a->type = T_HOST;
    }
    a->rate = temp;
    a->sid = sid++;

    return NULL;
}

/* Set the minimum bandwidth to send */
static const char *minbandwidth(cmd_parms * cmd, void *s, const char *from,
                                const char *bw)
{
    bandwidth_config *conf = (bandwidth_config *) s;
    bw_entry *a;
    long int temp;
    char *str;
    char *where = (char *) apr_pstrdup(cmd->pool, from);
    apr_status_t rv;
    char msgbuf[120];

    if (bw && *bw && (*bw == '-' || apr_isdigit(*bw)))
        temp = atol(bw);
    else
        return "Invalid argument";

    a = (bw_entry *) apr_array_push(conf->minlimits);
    a->x.from = where;
    if (!strcasecmp(where, "all")) {
        a->type = T_ALL;
    }
    else if ((str = strchr(where, '/'))) {
        *str++ = '\0';
        rv = apr_ipsubnet_create(&a->x.ip, where, str, cmd->pool);
        if(APR_STATUS_IS_EINVAL(rv)) {
            /* looked nothing like an IP address */
            return "An IP address was expected";
        }
        else if (rv != APR_SUCCESS) {
            apr_strerror(rv, msgbuf, sizeof msgbuf);
            return apr_pstrdup(cmd->pool, msgbuf);
        }
        a->type = T_IP;
    }
    else if (!APR_STATUS_IS_EINVAL(rv = apr_ipsubnet_create(&a->x.ip, where, NULL, cmd->pool))) {
        if (rv != APR_SUCCESS) {
            apr_strerror(rv, msgbuf, sizeof msgbuf);
            return apr_pstrdup(cmd->pool, msgbuf);
        }
        a->type = T_IP;
    }
    else { /* no slash, didn't look like an IP address => must be a host */
        a->type = T_HOST;
    }

    a->rate = temp;

    return NULL;
}

/* Set the large file bandwidth limit */
static const char *largefilelimit(cmd_parms * cmd, void *s, const char *file,
                                  const char *size, const char *bw)
{
    bandwidth_config *conf = (bandwidth_config *) s;
    bw_sizel *a;
    long int temp, tsize;

    if (strlen(file) < 1)
        return "You must enter a filetype (use * for all)";

    if (bw && *bw && (*bw == '-' || apr_isdigit(*bw)))
        temp = atol(bw);
    else
        return "Invalid argument";

    if (size && *size && apr_isdigit(*size))
        tsize = atol(size);
    else
        return "Invalid argument";

    if (temp < 0)
        return "BandWidth must be a number of bytes/s";

    if (tsize < 0)
        return "File size must be a number of Kbytes";

    a = (bw_sizel *) apr_array_push(conf->sizelimits);
    a->file = (char *) file;
    a->size = tsize;
    a->rate = temp;
    a->sid = sid++;

    return NULL;
}


/*----------------------------------------------------------------------------*
 * Helper Functions                                                           *
 *----------------------------------------------------------------------------*/

/* Match the input, as part of a domain */
static int in_domain(const char *domain, const char *what)
{
    int dl = strlen(domain);
    int wl = strlen(what);

    if ((wl - dl) >= 0) {
        if (strcasecmp(domain, &what[wl - dl]) != 0)
            return 0;

        /* Make sure we matched an *entire* subdomain --- if the user
         * said 'allow from good.com', we don't want people from nogood.com
         * to be able to get in.
         */
        if (wl == dl)
            return 1;           /* matched whole thing */
        else
            return (domain[0] == '.' || what[wl - dl - 1] == '.');
    }
    else
        return 0;
}

/* Validate the input as an ip */
static int is_ip(const char *host)
{
    while ((*host == '.') || (*host == '/') || apr_isdigit(*host))
        host++;
    return (*host == '\0');
}

/* Get the bandwidth limit based on from address */
static long get_bw_rate(request_rec * r, apr_array_header_t * a)
{
    bw_entry *e = (bw_entry *) a->elts;
    const char *remotehost = NULL;
    int i;
    int gothost = 0;

    for (i = 0; i < a->nelts; i++) {

        switch (e[i].type) {
        case T_ALL:
            return e[i].rate;

        case T_IP:
            if (apr_ipsubnet_test(e[i].x.ip, r->connection->client_addr)) {
                return e[i].rate;
            }
            break;
        case T_HOST:
            if (!gothost) {
                int remotehost_is_ip;

                remotehost = ap_get_remote_host(r->connection, r->per_dir_config,
                                                REMOTE_DOUBLE_REV, &remotehost_is_ip);

                if ((remotehost == NULL) || remotehost_is_ip)
                    gothost = 1;
                else
                    gothost = 2;
            }

            if ((gothost == 2) && in_domain(e[i].x.from, remotehost))
                return (e[i].rate);
            break;
        }
      
    }
    return 0;
}

/* 
  Match the pattern with the last digist from filename 
  An asterisk means any.    
*/
static int match_ext(const char *file, char *match)
{
    if (strlen(match) > strlen(file))
        return 0;
    if (strncmp(match, "*", 1) == 0)
        return 1;

    file += strlen(file) - strlen(match);

    if (strncmp(match, file, strlen(match)) == 0)
        return 1;
    return 0;
}

/* Get the bandwidth limit based on filesize */
static long get_bw_filesize(request_rec * r, apr_array_header_t * a,
                            off_t filesize, const char *filename)
{
    bw_sizel *e = (bw_sizel *) a->elts;
    int i;
    long int tmpsize = 0, tmprate = 0;

    if (!filesize)
        return (0);

    filesize /= 1024;

    for (i = 0; i < a->nelts; i++) {
        if ((e[i].size <= filesize) && match_ext(filename, e[i].file))
            if (tmpsize <= e[i].size) {
                tmpsize = e[i].size;
                tmprate = e[i].rate;
            }
    }

    return (tmprate);
}

/* Get the MaxConnections allowed */
static int get_maxconn(request_rec * r, apr_array_header_t * a)
{
    bw_maxconn *e = (bw_maxconn *) a->elts;
    const char *remotehost = NULL;
    int i;
    int gothost = 0;

    for (i = 0; i < a->nelts; i++) {

        switch (e[i].type) {
        case T_ALL:
            return e[i].max;

        case T_IP:
            if (apr_ipsubnet_test(e[i].x.ip, r->connection->client_addr)) {
                return e[i].max;
            }
            break;
        case T_HOST:
            if (!gothost) {
                int remotehost_is_ip;

                remotehost = ap_get_remote_host(r->connection, r->per_dir_config,
                                                REMOTE_DOUBLE_REV, &remotehost_is_ip);

                if ((remotehost == NULL) || remotehost_is_ip)
                    gothost = 1;
                else
                    gothost = 2;
            }

            if ((gothost == 2) && in_domain(e[i].x.from, remotehost))
                return (e[i].max);
            break;
        }

    }
    return 0;
}

/* Get an id based on bandwidth limit */
static int get_sid(request_rec * r, apr_array_header_t * a)
{
    bw_entry *e = (bw_entry *) a->elts;
    const char *remotehost = NULL;
    int i;
    int gothost = 0;

    remotehost =
        ap_get_remote_host(r->connection, r->per_dir_config, REMOTE_HOST,
                           NULL);

    for (i = 0; i < a->nelts; i++) {

        switch (e[i].type) {
        case T_ALL:
            return e[i].sid;

        case T_IP:
            if (apr_ipsubnet_test(e[i].x.ip, r->connection->client_addr)) {
                return e[i].sid;
            }
            break;
        case T_HOST:
            if (!gothost) {
                int remotehost_is_ip;

                remotehost = ap_get_remote_host(r->connection, r->per_dir_config,
                                                REMOTE_DOUBLE_REV, &remotehost_is_ip);

                if ((remotehost == NULL) || remotehost_is_ip)
                    gothost = 1;
                else
                    gothost = 2;
            }

            if ((gothost == 2) && in_domain(e[i].x.from, remotehost))
                return (e[i].sid);
            break;
        }

    }
    return -1;
}

/* Get an id based on filesize limit */
static int get_f_sid(request_rec * r, apr_array_header_t * a, off_t filesize,
                     const char *filename)
{
    bw_sizel *e = (bw_sizel *) a->elts;
    int i;
    long int tmpsize = 0, tmpsid = -1;

    if (!filesize)
        return (0);

    filesize /= 1024;

    for (i = 0; i < a->nelts; i++) {
        if ((e[i].size <= filesize) && match_ext(filename, e[i].file))
            if (tmpsize <= e[i].size) {
                tmpsize = e[i].size;
                tmpsid = e[i].sid;
            }
    }

    if (tmpsid < 0)
        return -1;
    return (tmpsid);
}

/* Update memory (shm) counters, which holds the bw data per context */
static void update_counters(bw_data * bwstat, ap_filter_t * f)
{
    apr_time_t nowtime;

    /* Refresh only if 1s has passed */
    nowtime = apr_time_now();
    if (bwstat->time < (nowtime - 1000000)) {
        /* And if we got lock */
        if (apr_atomic_cas32(&bwstat->lock, 1, 0) == 0) {

            /* Calculate bw used in the last timeinterval */
            bwstat->bandwidth =
                (bwstat->bytes_count / (double) (nowtime - bwstat->time)) *
                1000000;

            /* Reset counters */
            bwstat->bytes_count = 0;

            /* Set timestamp */
            bwstat->time = apr_time_now();

            /* Release lock */
            apr_atomic_set32(&bwstat->lock, 0);
        }
    }
}


/*----------------------------------------------------------------------------*
 * The Handler and the Output Filter. Core of the mod.                        *
 *----------------------------------------------------------------------------*/
/* With this handler, we can *force* the use of the mod. */
static int handle_bw(request_rec * r)
{
    bandwidth_server_config *sconf =
        (bandwidth_server_config *) ap_get_module_config(r->server->
                                                         module_config,
                                                         &bw_module);
    bandwidth_config *conf =
        (bandwidth_config *) ap_get_module_config(r->per_dir_config,
                                                  &bw_module);
    bw_data *bwstat;
    int confid;

    /* Only work on main request/no subrequests */
    if (r->main)
        return DECLINED;

    /* Return if module is not enabled */
    if (sconf->state == BANDWIDTH_DISABLED)
        return DECLINED;

    /* Get the ID of the memory space we are using */
    confid = get_sid(r, conf->limits);

    /* Only if we have a valid space */
    if (confid >= 0) {
        /* We "get" the data of the current configuration */
        bwstat = bwbase + confid;

        /* If we are too busy, deny connection */
        confid = get_maxconn(r, conf->maxconnection);
        if ((bwstat->connection_count >= confid) && (confid > 0))
            return conf->error;
    }

    /* Add the Filter, if in forced mode */
    if (sconf->force == BANDWIDTH_ENABLED)
        ap_add_output_filter("mod_bw", NULL, r, r->connection);

    /* Pass the control */
    return DECLINED;
}

static int bw_filter(ap_filter_t * f, apr_bucket_brigade * bb)
{
    request_rec *r = f->r;
    bandwidth_config *conf =
        (bandwidth_config *) ap_get_module_config(r->per_dir_config,
                                                  &bw_module);
    bandwidth_server_config *sconf =
        (bandwidth_server_config *) ap_get_module_config(r->server->
                                                         module_config,
                                                         &bw_module);
    apr_bucket_alloc_t *bucket_alloc = apr_bucket_alloc_create(f->r->pool);
    ctx_struct *ctx = f->ctx;
    apr_bucket *b = APR_BRIGADE_FIRST(bb);
    bw_data *bwstat, *bwmaxconn;
    int confid = -1, connid = -1;
    apr_size_t packet = conf->packet, bytes = 0;
    apr_off_t bblen = 0;
    long int bw_rate, bw_min, bw_f_rate, cur_rate = 0, sleep;
    const char *buf;

    /* Only work on main request/no subrequests */
    if (r->main) {
        ap_remove_output_filter(f);
        return ap_pass_brigade(f->next, bb);
    }

    /* Return as fast as possible if the module is not enabled */
    if (sconf->state == BANDWIDTH_DISABLED) {
        ap_pass_brigade(f->next, bb);
        return APR_SUCCESS;
    }

    /* Get the bw rates */
    bw_rate = get_bw_rate(r, conf->limits);
    bw_min = get_bw_rate(r, conf->minlimits);
    confid = connid = get_sid(r, conf->limits);

    /* Get the File Rate. r->finfo.size is not used anymore. */
    bblen = r->bytes_sent;
    bw_f_rate = get_bw_filesize(r, conf->sizelimits, bblen, r->finfo.fname);


    /* Check if we've got an ilimited client */
    if ((bw_rate == 0 && bw_f_rate == 0) || bw_f_rate < 0) {
        ap_pass_brigade(f->next, bb);
        return APR_SUCCESS;
    }

    /*
       - File size limit has precedence over location limit, if it's slower.
       - The minimal bw used, will never be less than the default minimal bw.
       - If file size is zero, all files apply
     */
    if (bw_f_rate && (bw_rate > bw_f_rate || !bw_rate)) {
        confid = get_f_sid(r, conf->sizelimits, bblen, r->finfo.fname);
        bw_rate = bw_f_rate;
    }

    if (bw_min < 0)
        bw_min = bw_rate;
    else if (!bw_min)
        bw_min = MIN_BW;

    /* Initialize our temporal space */
    if (ctx == NULL) {
        f->ctx = ctx = apr_pcalloc(f->r->pool, sizeof(*ctx));
        ctx->bb = apr_brigade_create(f->r->pool, bucket_alloc);
    }

    /* We "get" the data of the current configuration */
    bwstat = bwbase + confid;

    /* If we have a valid bandwidth limit per host, get the maxconn limit */
    if (connid >= 0)
        bwmaxconn = bwbase + connid;
    else
        bwmaxconn = bwstat;

    /* Add 1 active connection to the record */
    apr_atomic_inc32(&bwmaxconn->connection_count);

    /* Verbose Output */
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "ID: %ld Directory : %s Rate : %ld Minimum : %ld Size rate : %ld",
                 confid, conf->directory, bw_rate, bw_min, bw_f_rate);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                 "clients : %d/%d  rate/min : %ld,%ld", bwmaxconn->connection_count,
                 (connid >= 0) ? get_maxconn(r, conf->maxconnection) : 0,
                  bw_rate, bw_min);


    /*
       - We get buckets until a sentinel appears
       - Read the content of the bucket, and send it to the next filter, piece
       by piece
     */
    while (b != APR_BRIGADE_SENTINEL(bb)) {
        /* If the bucket is EOS end here */
        if (APR_BUCKET_IS_EOS(b) || APR_BUCKET_IS_FLUSH(b)) {
            APR_BUCKET_REMOVE(b);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
            ap_pass_brigade(f->next, ctx->bb);

            /* Delete 1 active connection */
            apr_atomic_dec32(&bwmaxconn->connection_count);
            return APR_SUCCESS;
        }

        if (apr_bucket_read(b, &buf, &bytes, APR_NONBLOCK_READ) ==
            APR_SUCCESS) {
            /* This changed, cause of the limit handling error.. see below */
            while (bytes > 0) {
                /*
                   - Ok, i'm doing lots of things here. The bw the client will have, is 
                   the bw available divided by the number of clients.
                   - The minimum bw, will always be MIN_BW. If all bw is used, and new 
                   connections arrives, they'll have MIN_BW bw available.
                 */
                cur_rate = (long int) bw_rate / bwmaxconn->connection_count;

                if (cur_rate > bw_rate)
                    cur_rate = bw_rate;
                if (cur_rate < bw_min)
                    cur_rate = bw_min;

                /*
                   - Some times we got a bw that is less than packetsize. That causes to have
                   a delay between packets > 1s. There are some clients that will timeout if
                   we took too long between packets, so , we adapt the packetsize, to always
                   be sending data, every 1s top.
                 */
                if (cur_rate <= conf->packet)
                    packet = cur_rate;
                else
                    packet = conf->packet;

                /* This was a really weird issue. If the bytes available are less than the
                   packet to send.. all bw was used. Limit that */
                if (bytes < packet)
                    packet = bytes;

                /* Here we get the time we need to sleep to get the specified bw */
                sleep =
                    (long int) (1000000 /
                                ((double) cur_rate / (double) packet));

                /* 
                   Here, we are going to split the bucket, and send it on piece at a time,
                  doing a "delay" between each piece. That way, we send the data at the 
                  specified rate.
                 */
                apr_bucket_split(b, packet);
                APR_BUCKET_REMOVE(b);
                APR_BRIGADE_INSERT_TAIL(ctx->bb, b);

                /* Decrease our counter */
                bytes -= packet;

                /* Flush and move to the next bucket */
                ap_pass_brigade(f->next, ctx->bb);
                b = APR_BRIGADE_FIRST(bb);

                /* Add the number of bytes transferred, so we can get an estimated bw usage */
                apr_atomic_add32(&bwstat->bytes_count, packet);

                /* If the connection goes to hell... go with it ! */
                if (r->connection->aborted) {
                    /* Verbose. Tells when the connection was ended */
                    ap_log_error(APLOG_MARK, APLOG_DEBUG,
                                 0, r->server, "Connection to hell");
                    apr_atomic_dec32(&bwmaxconn->connection_count);
                    return APR_SUCCESS;
                }

                /* Sleep ... zZZzZzZzzzz */
                apr_sleep(sleep);

                /* Refresh counters, so we can keep working :) */
                update_counters(bwstat, f);
            }
        }
        /* A leftover bucket. Pass it as the others */
        APR_BUCKET_REMOVE(b);
        APR_BRIGADE_INSERT_TAIL(ctx->bb, b);
        b = APR_BRIGADE_FIRST(bb);

        /* Add the number of bytes to the counter */
        apr_atomic_add32(&bwstat->bytes_count, bytes);

        /* Pass the final brigade */
        ap_pass_brigade(f->next, ctx->bb);
    }

    /* Delete 1 active connection to the record */
    apr_atomic_dec32(&bwmaxconn->connection_count);

    /* Give the control to the next filter's */
    return APR_SUCCESS;
}


/*----------------------------------------------------------------------------*
 * Module Init functions                                                      *
 *----------------------------------------------------------------------------*/
static int bw_init(apr_pool_t * p, apr_pool_t * plog, apr_pool_t * ptemp,
                   server_rec * s)
{
    apr_status_t status;
    apr_size_t retsize;
    apr_size_t shm_size;
    bw_data *bwstat;
    int t;

    /* These two help ensure that we only init once. */
    void *data;
    const char *userdata_key = "ivn_shm_bw_limit_module";

    apr_pool_userdata_get(&data, userdata_key, s->process->pool);
    if (!data) {
        apr_pool_userdata_set((const void *) 1, userdata_key,
                              apr_pool_cleanup_null, s->process->pool);
        return OK;
    }

    /* Init APR's atomic functions */
    status = apr_atomic_init(p);
    if (status != APR_SUCCESS)
        return HTTP_INTERNAL_SERVER_ERROR;

    shm_size = (apr_size_t) sizeof(bw_data) * sid;


    /* If there was a memory block already assigned.. destroy it */
    if (shm) {
        status = apr_shm_destroy(shm);
        if (status != APR_SUCCESS) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                         "mod_bw : Couldn't destroy old memory block\n");
            return status;
        } else {
            ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s,
                 "mod_bw : Old Shared memory block, destroyed.");
        }
    }

    /* Create shared memory block */
    status = apr_shm_create(&shm, shm_size, NULL, p);
    if (status != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "mod_bw : Error creating shm block\n");
        return status;
    }
    /* Check size of shared memory block */
    retsize = apr_shm_size_get(shm);
    if (retsize != shm_size) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "mod_bw : Error allocating shared memory block\n");
        return status;
    }
    /* Init shm block */
    bwbase = apr_shm_baseaddr_get(shm);
    if (bwbase == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "mod_bw : Error creating status block.\n");
        return status;
    }
    memset(bwbase, 0, retsize);

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                 "mod_bw : Memory Allocated %d bytes (each conf takes %d bytes)",
                 (int) retsize, (int) sizeof(bw_data));

    if (retsize < (sizeof(bw_data) * sid)) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                     "mod_bw : Not enough memory allocated!! Giving up");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    for (t = 0; t < sid; t++) {
        bwstat = bwbase + t;

        /* This inits the struct that will contain current bw use */
        bwstat->time = apr_time_now();
        bwstat->lock = 0;
        bwstat->connection_count = 0;
        bwstat->bandwidth = 0;
        bwstat->bytes_count = 0;
    }

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                 "mod_bw : Version %s - Initialized [%d Confs]", VERSION,
                 sid);

    return OK;
}


static void *create_bw_config(apr_pool_t * p, char *path)
{
    bandwidth_config *new =
        (bandwidth_config *) apr_palloc(p, sizeof(bandwidth_config));

    new->limits = apr_array_make(p, 20, sizeof(bw_entry));
    new->minlimits = apr_array_make(p, 20, sizeof(bw_entry));
    new->sizelimits = apr_array_make(p, 10, sizeof(bw_sizel));
    new->maxconnection = apr_array_make(p, 10, sizeof(bw_maxconn));
    new->directory = (char *) apr_pstrdup(p, path);
    new->packet = PACKET;
    new->error = HTTP_SERVICE_UNAVAILABLE;

    return (void *) new;
}

static void *create_bw_server_config(apr_pool_t * p, server_rec * s)
{
    bandwidth_server_config *new;

    new =
        (bandwidth_server_config *) apr_pcalloc(p,
                                                sizeof
                                                (bandwidth_server_config));
    new->state = BANDWIDTH_DISABLED;
    new->force = BANDWIDTH_DISABLED;

    return (void *) new;
}

/*----------------------------------------------------------------------------*
 * Apache register functions                                                  *
 *----------------------------------------------------------------------------*/

static void register_hooks(apr_pool_t * p)
{
    /*
       - Register a handler, which enforces mod_bw if needed
       - Register the Output Filter
       - And the init function of the mod.
     */
    ap_hook_handler(handle_bw, NULL, NULL, APR_HOOK_FIRST);
    ap_register_output_filter("mod_bw", bw_filter, NULL, AP_FTYPE_TRANSCODE);
    ap_hook_post_config(bw_init, NULL, NULL, APR_HOOK_MIDDLE);

}

/* Command Table */
static const command_rec bw_cmds[] = {
    AP_INIT_TAKE2("MaxConnection", maxconnection, NULL,
                  RSRC_CONF | ACCESS_CONF,
                  "a domain (or ip, or all) and the max connections allowed"),
    AP_INIT_FLAG("BandWidthModule", bandwidthmodule, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "On or Off to enable or disable (default) the whole bandwidth module"),
    AP_INIT_FLAG("ForceBandWidthModule", forcebandwidthmodule, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "On or Off to enable or disable (default) the mod catching every request"),
    AP_INIT_TAKE1("BandWidthPacket", setpacket, NULL, RSRC_CONF | ACCESS_CONF,
                  "Size of the maximun packet to use."),
    AP_INIT_TAKE2("BandWidth", bandwidth, NULL, RSRC_CONF | ACCESS_CONF,
                  "a domain (or ip, or all) and a bandwidth limit (in bytes/s)"),
    AP_INIT_TAKE2("MinBandWidth", minbandwidth, NULL, RSRC_CONF | ACCESS_CONF,
                  "a domain (or ip, or all) and a minimal bandwidth limit (in bytes/s)"),
    AP_INIT_TAKE1("BandWidthError", bandwidtherror, NULL,
                  RSRC_CONF | ACCESS_CONF,
                  "a http error number. Useful to deliver standar (or personal) error messages"),
    AP_INIT_TAKE3("LargeFileLimit", largefilelimit, NULL,
                  RSRC_CONF | ACCESS_CONF,
                  "a filesize (in Kbytes) and a bandwidth limit (in bytes/s)"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA bw_module = {
    STANDARD20_MODULE_STUFF,
    create_bw_config,           /* dir config creater */
    NULL,                       /* dir merger --- default is to override */
    create_bw_server_config,    /* server config */
    NULL,                       /* merge server config */
    bw_cmds,                    /* command table */
    register_hooks              /* register_hooks */
};
