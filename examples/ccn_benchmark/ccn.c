/*
 * Copyright (C) 2016 Yang Wen
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * Reference: https://github.com/yangwenca/RIOT/blob/ndn/sys/shell/commands/sc_ccnl.c
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       CCN-lite benchmark
 *
 * @author      Yang Wen <yangwenca@gmail.com>
 * 
 *
 * @}
 */

#include "random.h"
#include "sched.h"
#include "net/gnrc/netif.h"
#include "ccn-lite-riot.h"
#include "ccnl-pkt-ndntlv.h"

#define BUF_SIZE (64)

#define CCNL_CACHE_SIZE (5)
/**
 * Maximum number of Interest retransmissions
 */
#define CCNL_INTEREST_RETRIES   (3)

#define MAX_ADDR_LEN            (8U)


static unsigned char int_buf[BUF_SIZE];
static unsigned char cont_buf[BUF_SIZE];

static const char *default_content = "Start the RIOT!";
static unsigned char out[CCNL_MAX_PACKET_SIZE];

/* check for one-time initialization */
static bool started = false;

/* usage for open command */
static void open_usage(void)
{
    puts("ccnl <interface>");
}

static void interest_usage(char *arg)
{
    printf("usage: %s <URI> [relay]\n"
            "%% %s /riot/peter/schmerzl                     (classic lookup)\n",
            arg, arg);
}

static struct ccnl_content_s* ccnl_content_add(struct ccnl_relay_s *ccnl, struct ccnl_content_s *c)
{
    if ((ccnl->max_cache_entries < 0) || (ccnl->contentcnt < ccnl->max_cache_entries)){
        DBL_LINKED_LIST_ADD(ccnl->contents, c);
        ccnl->contentcnt++;
    }else{
        return NULL;
    }
    return c;
}



static struct ccnl_face_s *intern_face_get(char *addr_str)
{
    // initialize address with 0xFF for broadcast
    size_t addr_len = MAX_ADDR_LEN;
    uint8_t relay_addr[MAX_ADDR_LEN];
    memset(relay_addr, UINT8_MAX, MAX_ADDR_LEN);

    addr_len = gnrc_netif_addr_from_str(relay_addr, sizeof(relay_addr), addr_str);
    if (addr_len == 0) {
        printf("Error: %s is not a valid link layer address\n", addr_str);
        return NULL;
    }

    sockunion sun;
    sun.sa.sa_family = AF_PACKET;
    memcpy(&(sun.linklayer.sll_addr), relay_addr, addr_len);
    sun.linklayer.sll_halen = addr_len;
    sun.linklayer.sll_protocol = htons(ETHERTYPE_NDN);

    // TODO: set correct interface instead of always 0
    struct ccnl_face_s *fibface = ccnl_get_face_or_create(&ccnl_relay, 0, &sun.sa, sizeof(sun.linklayer));

    return fibface;
}

static int intern_fib_add(char *pfx, char *addr_str)
{
    int suite = CCNL_SUITE_NDNTLV;
    struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(pfx, suite, NULL, 0);
    if (!prefix) {
        puts("Error: prefix could not be created!");
        return -1;
    }

    struct ccnl_face_s *fibface = intern_face_get(addr_str);
    if (fibface == NULL) {
        return -1;
    }
    fibface->flags |= CCNL_FACE_FLAGS_STATIC;

    if (ccnl_fib_add_entry(&ccnl_relay, prefix, fibface) != 0) {
        printf("Error adding (%s : %s) to the FIB\n", pfx, addr_str);
        return -1;
    }

    return 0;
}

static void content_usage(char *argv)
{
    printf("usage: %s <URI> [content]\n"
            "%% %s /riot/peter/schmerzl             (default content)\n"
            "%% %s /riot/peter/schmerzl RIOT\n",
            argv, argv, argv);
}


static void ccnl_fib_usage(char *argv)
{
    printf("usage: %s [<action> <options>]\n"
           "prints the FIB if called without parameters:\n"
           "%% %s\n"
           "<action> may be one of the following\n"
           "  * \"add\" - adds an entry to the FIB, requires a prefix and a next-hop address, e.g.\n"
           "            %s add /riot/peter/schmerzl ab:cd:ef:01:23:45:67:89\n"
           "  * \"del\" - deletes an entry to the FIB, requires a prefix or a next-hop address, e.g.\n"
           "            %s del /riot/peter/schmerzl\n"
           "            %s del ab:cd:ef:01:23:45:67:89\n",
            argv, argv, argv, argv, argv);
}

int ccn(int argc, char **argv)
{
    ccnl_core_init();
    int pid=3;
    if (argc < 2){
        printf("Not enough arguments\n");
        return -1;
    }
    /* check if already running */
    if (strcmp(argv[1], "ccnl_open") == 0) {
        if (started) {
            puts("Already opened an interface for CCN!");
            return -1;
        }

        /* check if parameter is given */
        if (argc != 3) {
            open_usage();
            return -1;
        }

        /* check if given number is a valid netif PID */
        pid = atoi(argv[2]);
        if (!gnrc_netif_exist(pid)) {
            printf("%i is not a valid interface!\n", pid);
            return -1;
        }

        ccnl_start();

        /* set the relay's PID, configure the interface to interface to use CCN
         * nettype */
        if (ccnl_open_netif(pid, GNRC_NETTYPE_CCN) < 0) {
            puts("Error registering at network interface!");
            return -1;
        }

        started = true;

        return 0;
    }
    
    if (strcmp(argv[1], "ccnl_int") == 0){
        
            if (argc < 3) {
            interest_usage(argv[1]);
            return -1;
        }
        
        

        if (argc > 3) {
            if (intern_fib_add(argv[2], argv[3]) < 0) {
                interest_usage(argv[1]);
                return -1;
            }
        }

        memset(int_buf, '\0', BUF_SIZE);
        memset(cont_buf, '\0', BUF_SIZE);
        for (int cnt = 0; cnt < CCNL_INTEREST_RETRIES; cnt++) {
            gnrc_netreg_entry_t ne;
            // register for content chunks
            ne.demux_ctx =  GNRC_NETREG_DEMUX_CTX_ALL;
            // ne.pid = sched_active_pid;
            ne.pid = pid;
            gnrc_netreg_register(GNRC_NETTYPE_CCN_CHUNK, &ne);
            ccnl_send_interest(CCNL_SUITE_NDNTLV, argv[2], NULL, int_buf, BUF_SIZE);
            int temp = ccnl_wait_for_chunk(cont_buf, BUF_SIZE, 0);
            if (temp >= 0) {
                gnrc_netreg_unregister(GNRC_NETTYPE_CCN_CHUNK, &ne);
                printf("Content received: %s\n", cont_buf);
                return 0;
            }
            gnrc_netreg_unregister(GNRC_NETTYPE_CCN_CHUNK, &ne);
            printf("Content received: %s\n", cont_buf);
        }
        printf("Timeout! No content received in response to the Interest for %s.\n", argv[2]);

        return -1;
    }
    
    if (strcmp(argv[1], "ccnl_cont") == 0){
        char *body = (char*) default_content;
        int arg_len = strlen(default_content) + 1;
        int offs = CCNL_MAX_PACKET_SIZE;
        if (argc < 3) {
            content_usage(argv[1]);
            return -1;
        }

        if (argc > 3) {
            char buf[BUF_SIZE];
            memset(buf, ' ', BUF_SIZE);
            char *buf_ptr = buf;
            for (int i = 3; (i < argc) && (buf_ptr < (buf + BUF_SIZE)); i++) {
                arg_len = strlen(argv[i]);
                if ((buf_ptr + arg_len) > (buf + BUF_SIZE)) {
                    arg_len = (buf + BUF_SIZE) - buf_ptr;
                }
                strncpy(buf_ptr, argv[i], arg_len);
                buf_ptr += arg_len + 1;
            }
            *buf_ptr = '\0';
            body = buf;
            arg_len = strlen(body);
        }


        int suite = CCNL_SUITE_NDNTLV;


        struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(argv[2], suite, NULL, NULL);


        arg_len = ccnl_ndntlv_prependContent(prefix, (unsigned char*) body, arg_len, NULL, NULL, &offs, out);


        unsigned char *olddata;
        unsigned char *data = olddata = out + offs;

        int len;
        unsigned typ;

        if (ccnl_ndntlv_dehead(&data, &arg_len, (int*) &typ, &len) ||
            typ != NDN_TLV_Data) {
            return -1;
        }

        struct ccnl_content_s *c = 0;
        struct ccnl_pkt_s *pk = ccnl_ndntlv_bytes2pkt(typ, olddata, &data, &arg_len);
        c = ccnl_content_new(&ccnl_relay, &pk);
        ccnl_relay.max_cache_entries = CCNL_CACHE_SIZE;
        struct ccnl_relay_s *test;
        test = &ccnl_relay;
        // ccnl_content_add2cache(&ccnl_relay, c);
        ccnl_content_add(&ccnl_relay, c);
        c->flags |= CCNL_CONTENT_FLAGS_STATIC;

        return 0;
    
    }
    
    
    if (strcmp(argv[1], "ccnl_fib") == 0){
        if (argc < 3) {
            ccnl_fib_show(&ccnl_relay);
        }
        else if ((argc == 4) && (strncmp(argv[2], "del", 3) == 0)) {
            int suite = CCNL_SUITE_NDNTLV;
            if (strchr(argv[3], '/')) {
                struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(argv[3], suite, NULL, 0);
                if (!prefix) {
                    puts("Error: prefix could not be created!");
                    return -1;
                }
                int res = ccnl_fib_rem_entry(&ccnl_relay, prefix, NULL);
                free_prefix(prefix);
                return res;
            }
            else {
                struct ccnl_face_s *face = intern_face_get(argv[3]);
                if (face == NULL) {
                    printf("There is no face for address %s\n", argv[2]);
                    return -1;
                }
                int res = ccnl_fib_rem_entry(&ccnl_relay, NULL, face);
                return res;
            }
        }
        else if ((argc == 5) && (strncmp(argv[2], "add", 3) == 0)) {
            if (intern_fib_add(argv[3], argv[4]) < 0) {
                ccnl_fib_usage(argv[1]);
                return -1;
            }
        }
        else {
            ccnl_fib_usage(argv[1]);
            return -1;
        }
        return 0;
    }
    
    
    printf("Invalid command\n");

    return -1;
}

