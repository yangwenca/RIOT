/*
 * Copyright (C) 2016 Yang Wen
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
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
 * @}
 */

#include "random.h"
#include "sched.h"
#include "net/gnrc/netif.h"
#include "ccn-lite-riot.h"
#include "ccnl-pkt-ndntlv.h"

#define BUF_SIZE (64)

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

int ccn(int argc, char **argv)
{
    /* check if already running */
    if (started) {
        puts("Already opened an interface for CCN!");
        return -1;
    }

    /* check if parameter is given */
    if (argc != 2) {
        open_usage();
        return -1;
    }

    printf("Enter the ccn function\n");
    /* check if given number is a valid netif PID */
    int pid = atoi(argv[1]);
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

/*
static void content_usage(char *argv)
{
    printf("usage: %s <URI> [content]\n"
            "%% %s /riot/peter/schmerzl             (default content)\n"
            "%% %s /riot/peter/schmerzl RIOT\n",
            argv, argv, argv);
}

int ccnl_content(int argc, char **argv)
{
    char *body = (char*) default_content;
    int arg_len = strlen(default_content) + 1;
    int offs = CCNL_MAX_PACKET_SIZE;
    if (argc < 2) {
        content_usage(argv[0]);
        return -1;
    }

    if (argc > 2) {
        char buf[BUF_SIZE];
        memset(buf, ' ', BUF_SIZE);
        char *buf_ptr = buf;
        for (int i = 2; (i < argc) && (buf_ptr < (buf + BUF_SIZE)); i++) {
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

    struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(argv[1], suite, NULL, NULL);

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
    ccnl_content_add2cache(&ccnl_relay, c);
    c->flags |= CCNL_CONTENT_FLAGS_STATIC;

    return 0;
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

static void interest_usage(char *arg)
{
    printf("usage: %s <URI> [relay]\n"
            "%% %s /riot/peter/schmerzl                     (classic lookup)\n",
            arg, arg);
}
/*
int ccnl_interest(int argc, char **argv)
{
    if (argc < 2) {
        interest_usage(argv[0]);
        return -1;
    }

    if (argc > 2) {
        if (intern_fib_add(argv[1], argv[2]) < 0) {
            interest_usage(argv[0]);
            return -1;
        }
    }

    memset(int_buf, '\0', BUF_SIZE);
    memset(cont_buf, '\0', BUF_SIZE);
    for (int cnt = 0; cnt < CCNL_INTEREST_RETRIES; cnt++) {
        gnrc_netreg_entry_t ne;
        // register for content chunks
        ne.demux_ctx =  GNRC_NETREG_DEMUX_CTX_ALL;
        ne.pid = sched_active_pid;
        gnrc_netreg_register(GNRC_NETTYPE_CCN_CHUNK, &ne);

        ccnl_send_interest(CCNL_SUITE_NDNTLV, argv[1], NULL, int_buf, BUF_SIZE);
        if (ccnl_wait_for_chunk(cont_buf, BUF_SIZE, 0) > 0) {
            gnrc_netreg_unregister(GNRC_NETTYPE_CCN_CHUNK, &ne);
            printf("Content received: %s\n", cont_buf);
            return 0;
        }
        gnrc_netreg_unregister(GNRC_NETTYPE_CCN_CHUNK, &ne);
    }
    printf("Timeout! No content received in response to the Interest for %s.\n", argv[1]);

    return -1;
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

int ccnl_fib(int argc, char **argv)
{
    if (argc < 2) {
        ccnl_fib_show(&ccnl_relay);
    }
    else if ((argc == 3) && (strncmp(argv[1], "del", 3) == 0)) {
        int suite = CCNL_SUITE_NDNTLV;
        if (strchr(argv[2], '/')) {
            struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(argv[2], suite, NULL, 0);
            if (!prefix) {
                puts("Error: prefix could not be created!");
                return -1;
            }
            int res = ccnl_fib_rem_entry(&ccnl_relay, prefix, NULL);
            free_prefix(prefix);
            return res;
        }
        else {
            struct ccnl_face_s *face = intern_face_get(argv[2]);
            if (face == NULL) {
                printf("There is no face for address %s\n", argv[1]);
                return -1;
            }
            int res = ccnl_fib_rem_entry(&ccnl_relay, NULL, face);
            return res;
        }
    }
    else if ((argc == 4) && (strncmp(argv[1], "add", 3) == 0)) {
        if (intern_fib_add(argv[2], argv[3]) < 0) {
            ccnl_fib_usage(argv[0]);
            return -1;
        }
    }
    else {
        ccnl_fib_usage(argv[0]);
        return -1;
    }
    return 0;
}

int ccn(int argc, char **argv)
{
    if (argc < 2) {
        printf("usage: %s [name|interest|data]\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "name") == 0) {
	test_name_from_uri();
	test_name_get_size();
	test_name_get_component();
	test_name_append();
    }
    else if (strcmp(argv[1], "interest") == 0) {
	test_interest_create();
	test_interest_get_name();
    }
    else if (strcmp(argv[1], "data") == 0) {
	test_data_create_digest();
	test_data_create_hmac();
	test_data_create_ecdsa();
	test_data_verify_ecdsa();
	test_data_get_name();
	test_data_get_content();
    }
    else if (strcmp(argv[1], "memory") == 0) {
	if (argc < 3) {
	    printf("usage: %s memory _size_\n", argv[0]);
	    return 1;
	}
	int s = atoi(argv[2]);
	test_malloc(s);
	test_memset(s);
	test_memcpy(s);
    }
    else {
        puts("error: invalid command");
    }
    return 0;
}
*/
