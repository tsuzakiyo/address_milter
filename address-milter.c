#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include "libmilter/mfapi.h"
#include "libmilter/mfdef.h"
#include "pthread.h"
#include <glib.h>

/*
 * DEFINITION
 *
 * DET_HASH_NUMBER         : The number of the hash tables to use for detection
 *
 * REM_DET_HASH_INTERVAL   : The interval to remain hash entry for each hash table for detection
 * REF_DATA_INTERVAL       : The interval to refer hash entry for all hash table for detection
 *
 * REM_BLO_HASH_INTERVAL   : The interval to remain hash entry for each tash table for blocklist
 *
 * COMP_HASH_NUM           : The number of the entries admitting the passage by each hash table
 * BLO_INS_NUMBER          : The number of the entries registering to blocklist
 *
 * INS_LINE_LENGTH         : The number of characters of hash key
 */

#define DET_HASH_NUMBER 5

#define REM_DET_HASH_INTERVAL 300
#define REF_DATA_INTERVAL (DET_HASH_NUMBER * REM_DET_HASH_INTERVAL)

#define REM_BLO_HASH_INTERVAL 3600

#define COMP_HASH_NUM 1100
#define BLO_INS_NUMBER 11000

#define INS_LINE_LENGTH 1000

#define SMTPINFO ((smtpinfo_t *) smfi_getpriv(ctx))

typedef struct smtpinfo
{
    char *envelope_from;
    char *envelope_to;
    char *ident_from_to;
    int receive_time;
} smtpinfo_t;

#define SMTPINFO ((smtpinfo_t *) smfi_getpriv(ctx))

static pthread_mutex_t table_mutex = PTHREAD_MUTEX_INITIALIZER;

static void print_func(gpointer key, gpointer val, gpointer ud);
static void foreach(GHashTable* hashtable, int hash_num);
void destroy_key (gpointer key);
void destroy_val (gpointer val);

GHashTable* hashtable[DET_HASH_NUMBER];
GHashTable* blocklist;

int det_hash_num;
char dataline[INS_LINE_LENGTH];
int receive_time;
int specified_hash_num;
int current_blo_times = 0;
int chk_blo_times = 0;
int current_hash_num = 0;
int del_hash_num = 0;
int chk_hash_num = 0;
char *insert_data;
int *initial_val;
int *block_count;
int *sum_of_hash_count;
clock_t start, end;
struct timeval s, e;

// Function: print key and value in hash table
static void print_func(gpointer key, gpointer val, gpointer ud)
{
    //g_print("key = %s, value = %d\n", (gchar*)key, (gint)GPOINTER_TO_INT(val));
    g_print("%d\n", *(int *)val);
}

// Function: search element in hash table
//static void all_table_element(GHashTable* hashtable, int hash_num)
//static void all_table_element(GHashTable* hashtable)
static void all_table_element(GHashTable* hashtable, int hour, int min)
{
    g_hash_table_foreach(hashtable, print_func, NULL);
}

// Function: delete memory of hash key
void destroy_key (gpointer key)
{
    //g_print("key = %s free memory\n", key);
    g_free(key);
}

// Function: delete memory of hash value
void destroy_val (gpointer val)
{
    //g_print("value = %d free memory\n", *(int *)val);
    g_free(val);
}

static char hash_judgement (char* hash_key, int get_time)
{
    g_strchomp(dataline);
    insert_data = dataline;
    receive_time = get_time;
    chk_blo_times = receive_time / REM_BLO_HASH_INTERVAL;
    specified_hash_num = (receive_time % REF_DATA_INTERVAL) / REM_DET_HASH_INTERVAL;

    // Recreation of hash table for detection
    if (current_blo_times != chk_blo_times) {
        //all_table_element(blocklist, 0);
        g_hash_table_destroy(blocklist);
        blocklist = g_hash_table_new_full(g_str_hash, g_str_equal, destroy_key, destroy_val);
        //blocklist = g_hash_table_new(g_str_hash, g_str_equal);
        current_blo_times = chk_blo_times;
    }

    // Recreation of hash table for detection
    if (specified_hash_num != current_hash_num) {
        if (current_hash_num + 1 <= specified_hash_num) {
            for (del_hash_num = current_hash_num + 1; del_hash_num <= specified_hash_num; del_hash_num++) {
                gettimeofday(&s, NULL);
                //all_table_element(hashtable[del_hash_num], timeObject->tm_hour, timeObject->tm_min);
                g_hash_table_destroy(hashtable[del_hash_num]);
                hashtable[del_hash_num] = g_hash_table_new_full(g_str_hash, g_str_equal, destroy_key, destroy_val);
                //hashtable[del_hash_num] = g_hash_table_new(g_str_hash, g_str_equal);
                gettimeofday(&e, NULL);
            }
            current_hash_num = specified_hash_num;
        }
        else if (current_hash_num + 1 > specified_hash_num) {
            for (del_hash_num = current_hash_num + 1; del_hash_num < DET_HASH_NUMBER; del_hash_num++) {
                gettimeofday(&s, NULL);
                //all_table_element(hashtable[del_hash_num], timeObject->tm_hour, timeObject->tm_min);
                g_hash_table_destroy(hashtable[del_hash_num]);
                hashtable[del_hash_num] = g_hash_table_new_full(g_str_hash, g_str_equal, destroy_key, destroy_val);
                //hashtable[del_hash_num] = g_hash_table_new(g_str_hash, g_str_equal);
                gettimeofday(&e, NULL);
            }
            for (del_hash_num = 0; del_hash_num <= specified_hash_num; del_hash_num++) {
                gettimeofday(&s, NULL);
                //all_table_element(hashtable[del_hash_num], timeObject->tm_hour, timeObject->tm_min);
                g_hash_table_destroy(hashtable[specified_hash_num]);
                hashtable[specified_hash_num] = g_hash_table_new_full(g_str_hash, g_str_equal, destroy_key, destroy_val);
                //hashtable[specified_hash_num] = g_hash_table_new(g_str_hash, g_str_equal);
                gettimeofday(&e, NULL);
            }
            current_hash_num = specified_hash_num;
        }
    }

    // lookup hash table for blocklist and judgment of a huge amount of e-mails
    if (g_hash_table_lookup(blocklist, g_strdup(insert_data))) {
        return SMFIS_TEMPFAIL;
    }

    // lookup hash table and insert key and value
    if (!g_hash_table_lookup(hashtable[specified_hash_num], insert_data)) {
        initial_val = g_new0(unsigned int, 1);
        *initial_val = 1;
        g_hash_table_insert(hashtable[specified_hash_num], g_strdup(insert_data), initial_val);
    }
    else {
        sum_of_hash_count = g_new0(unsigned int, 1);
        *sum_of_hash_count = *(int *)(g_hash_table_lookup(hashtable[specified_hash_num], g_strdup(insert_data))) + 1;
        g_hash_table_insert(hashtable[specified_hash_num], g_strdup(insert_data), sum_of_hash_count);

        if (*sum_of_hash_count >= COMP_HASH_NUM) {
            if (specified_hash_num == 0){
                for (chk_hash_num = 1; chk_hash_num <= DET_HASH_NUMBER; chk_hash_num++) {
                    *sum_of_hash_count =+ *(int *) (g_hash_table_lookup(hashtable[specified_hash_num], g_strdup(insert_data)));
                }
            }
            else if (specified_hash_num == DET_HASH_NUMBER) {
                for (chk_hash_num = 0; chk_hash_num < DET_HASH_NUMBER; chk_hash_num++) {
                    *sum_of_hash_count =+ *(int *) (g_hash_table_lookup(hashtable[specified_hash_num], g_strdup(insert_data)));
                }
            }
            else {
                for (chk_hash_num = 0; chk_hash_num < specified_hash_num; chk_hash_num++) {
                    *sum_of_hash_count =+ *(int *) (g_hash_table_lookup(hashtable[specified_hash_num], g_strdup(insert_data)));
                }
                for (chk_hash_num = specified_hash_num + 1; chk_hash_num <= DET_HASH_NUMBER; chk_hash_num++) {
                    *sum_of_hash_count =+ *(int *) (g_hash_table_lookup(hashtable[specified_hash_num], g_strdup(insert_data)));
                }
            }
            if (*sum_of_hash_count >= BLO_INS_NUMBER) {
                block_count = g_new0(int, 1);
                *block_count = 1;
                g_hash_table_insert(blocklist, g_strdup(insert_data), block_count);
            }
        }
    }
    return SMFIS_CONTINUE;
}
    



extern sfsistat xxfi_cleanup(SMFICTX *, bool);

/* connection info filter */
sfsistat
xxfi_connect(ctx, hostname, hostaddr)
    SMFICTX *ctx;
    char *hostname;
    _SOCK_ADDR *hostaddr;
{
    smtpinfo_t *info;
    info = (smtpinfo_t *)malloc(sizeof(smtpinfo_t));
    if (info == NULL)
    {
        return SMFIS_TEMPFAIL;
    }
    memset(info, '\0', sizeof *info);
    smfi_setpriv(ctx, info);
    return SMFIS_CONTINUE;
}

/* SMTP HELO command filter */
sfsistat
xxfi_helo(ctx, helohost)
    SMFICTX *ctx;
    char *helohost;
{
    return SMFIS_CONTINUE;
}

/* envelope sender filter */
sfsistat
xxfi_envfrom(ctx, argv)
    SMFICTX *ctx;
    char **argv;
{
    smtpinfo_t *info = SMTPINFO;
    int len;
    char *mailaddr = smfi_getsymval(ctx, "{mail_addr}");
    char *mail_from;
    len = strlen(mailaddr) + 1; 
    if ((mail_from = (char *)malloc(len)) == NULL)
    {
        return SMFIS_TEMPFAIL;
    }
    snprintf(mail_from, len, "%s", mailaddr);
    if (info->envelope_from != NULL)
    {
        free(info->envelope_from);
    }
    info->envelope_from = mail_from;
    //printf ("envelope_from = %s\n", info->envelope_from);
    return SMFIS_CONTINUE;
}

/* envelope recipient filter */
sfsistat
xxfi_envrcpt(ctx, argv)
    SMFICTX *ctx;
    char **argv;
{
    smtpinfo_t *info = SMTPINFO;
    int len,retval;
    char *rcptaddr = smfi_getsymval(ctx, "{rcpt_addr}");
    char *rcpt_to;
    char *ident_from_to;
    time_t accept_time;
    //snprintf(rcpt_to, sizeof rcpt_to, "%s", rcptaddr);
    //printf ("rcptaddr = %s\n", rcptaddr);
    len = strlen(rcptaddr) + 1;    
    if ((rcpt_to = (char *)malloc(len)) == NULL)
    {  
        return SMFIS_TEMPFAIL;
    }
    snprintf(rcpt_to, len, "%s", rcptaddr);
    if (info->envelope_to != NULL)
        free(info->envelope_to);
    info->envelope_to = rcpt_to;
    //printf ("envelope_to = %s\n", info->envelope_to);
    len = strlen(info->envelope_from) + strlen(info->envelope_to) + 3;
    if ((ident_from_to = (char *)malloc(len)) == NULL)
    {  
        return SMFIS_TEMPFAIL;
    }
    if (info->ident_from_to != NULL)
        free(info->ident_from_to);
    sprintf(ident_from_to, "%s%s", info->envelope_from, info->envelope_to);
    info->ident_from_to = ident_from_to;
    //printf ("ident_from_to = %s\n", info->ident_from_to);
    time(&accept_time);
    info->receive_time = accept_time;
    retval = hash_judgement(info->ident_from_to, info->receive_time);
    return retval;
    //return SMFIS_CONTINUE;
}

/* header filter */
sfsistat
xxfi_header(ctx, headerf, headerv)
    SMFICTX *ctx;
    char *headerf;
    unsigned char *headerv;
{
    return SMFIS_CONTINUE;
}

/* end of header */
sfsistat
xxfi_eoh(ctx)
    SMFICTX *ctx;
{
    return SMFIS_CONTINUE;
}

/* body block filter */
sfsistat
xxfi_body(ctx, bodyp, bodylen)
    SMFICTX *ctx;
    unsigned char *bodyp;
    size_t bodylen;
{
    return SMFIS_CONTINUE;
}

/* end of message */
sfsistat
xxfi_eom(ctx)
    SMFICTX *ctx;
{
    return SMFIS_CONTINUE;
}

/* message aborted */
sfsistat
xxfi_abort(ctx)
    SMFICTX *ctx;
{
    return xxfi_cleanup(ctx, FALSE);
}

/* session cleanup */
sfsistat
xxfi_cleanup(ctx, ok)
    SMFICTX *ctx;
    bool ok;
{
    return SMFIS_CONTINUE;
}

/* connection cleanup */
sfsistat
xxfi_close(ctx)
    SMFICTX *ctx;
{
    smtpinfo_t *info = SMTPINFO;
    if (info == NULL)
        return SMFIS_CONTINUE;
    if (info->envelope_from != NULL)
    {
        free(info->envelope_from);
        info->envelope_from = NULL;
    }
    if (info->envelope_to != NULL)
    {
        free(info->envelope_to);
        info->envelope_to = NULL;
    }
    if (info->ident_from_to != NULL)
    {
        free(info->ident_from_to);
        info->ident_from_to = NULL;
    }
    if (info->receive_time != 0)
        info->receive_time = 0;
    free(info);
    smfi_setpriv(ctx, NULL);
    return SMFIS_CONTINUE;
}

/* Once, at the start of each SMTP connection */
sfsistat
xxfi_unknown(ctx, cmd)
    SMFICTX *ctx;
    char *cmd;
{
    smtpinfo_t *info;
    return SMFIS_CONTINUE;
}

/* DATA command */
sfsistat
xxfi_data(ctx)
    SMFICTX *ctx;
{
    smtpinfo_t *info;
    return SMFIS_CONTINUE;
}

/* Once, at the start of each SMTP connection */
sfsistat
xxfi_negotiate(ctx, f0, f1, f2, f3, pf0, pf1, pf2, pf3)
    SMFICTX *ctx;
    unsigned long f0;
    unsigned long f1;
    unsigned long f2;
    unsigned long f3;
    unsigned long *pf0;
    unsigned long *pf1;
    unsigned long *pf2;
    unsigned long *pf3;
{
    smtpinfo_t *info;
    return SMFIS_ALL_OPTS;
}

struct smfiDesc smfilter =
{
    "MyMilter",                     /* filter name */
    SMFI_VERSION,                   /* version code */
    SMFIF_ADDHDRS|SMFIF_ADDRCPT,    /* flags */
    xxfi_connect,                   /* connection info filter */
    xxfi_helo,                      /* SMTP HELO command filter */
    xxfi_envfrom,                   /* envelope sender filter */
    xxfi_envrcpt,                   /* envelope recipient filter */
    xxfi_header,                    /* header filter */
    xxfi_eoh,                       /* end of header */
    xxfi_body,                      /* body block filter */
    xxfi_eom,                       /* end of message */
    xxfi_abort,                     /* message aborted */
    xxfi_close,                     /* connection cleanup */
    xxfi_unknown,                   /* unknown SMTP commands */
    xxfi_data,                      /* DATA command */
    xxfi_negotiate                  /* Once, at the start of each SMTP connection */
};

static void
usage(prog)
    char *prog;
{
    fprintf(stderr, "Usage: %s -p socket-addr [-t timeout]\n", prog);
}

int
main(argc, argv)
    int argc;
    char **argv;
{
    bool setconn = FALSE;
    int c;
    const char *args = "p:t:h";
    extern char *optarg;
    /* Process command line options */
    while ((c = getopt(argc, argv, args)) != -1)
    {
        switch (c)
        {
            case 'p':
                if (optarg == NULL || *optarg == '\0')
                {
                    (void) fprintf(stderr, "Illegal conn: %s\n", optarg);
                    exit(EX_USAGE);
                }
                if (smfi_setconn(optarg) == MI_FAILURE)
                {
                    (void) fprintf(stderr, "smfi_setconn failed\n");
                    exit(EX_SOFTWARE);
                }
/*
 * **  If we're using a local socket, make sure it
 * **  doesn't already exist.  Don't ever run this
 * **  code as root!!
 */
                if (strncasecmp(optarg, "unix:", 5) == 0)
                    unlink(optarg + 5);
                else if (strncasecmp(optarg, "local:", 6) == 0)
                    unlink(optarg + 6);
                setconn = TRUE;
                    break;
            case 't':
                if (optarg == NULL || *optarg == '\0')
                {
                    (void) fprintf(stderr, "Illegal timeout: %s\n", optarg);
                        exit(EX_USAGE);
                    }
                    if (smfi_settimeout(atoi(optarg)) == MI_FAILURE)
                    {
                        (void) fprintf(stderr, "smfi_settimeout failed\n");
                        exit(EX_SOFTWARE);
                    }
                    break;
            case 'h':
                default:
                usage(argv[0]);
                exit(EX_USAGE);
        }
    }
    if (!setconn)
    {
        fprintf(stderr, "%s: Missing required -p argument\n", argv[0]);
        usage(argv[0]);
        exit(EX_USAGE);
    }
    if (smfi_register(smfilter) == MI_FAILURE)
    {
        fprintf(stderr, "smfi_register failed\n");
        exit(EX_UNAVAILABLE);
    }
    // Prepare for the specified number of the detection hash table
    for (det_hash_num = 0; det_hash_num < DET_HASH_NUMBER; det_hash_num++) {
        //hash_table_new(hashtable[det_hash_num]);
        hashtable[det_hash_num] = g_hash_table_new_full(g_str_hash, g_str_equal, destroy_key, destroy_val);
        //hashtable[det_hash_num] = g_hash_table_new(g_str_hash, g_str_equal);
    }
    // Prepare for the specified number of the blocklist hash table
    blocklist = g_hash_table_new_full(g_str_hash, g_str_equal, destroy_key, destroy_val);
    //blocklist = g_hash_table_new(g_str_hash, g_str_equal);
    
    return smfi_main();
}
/* eof */
