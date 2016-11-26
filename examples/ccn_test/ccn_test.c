/*
 * Copyright (C) 2016 Yang Wen
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
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
 * @}
 */

#include "random.h"
#include "sched.h"
#include "net/gnrc/netif.h"
#include "ccn-lite-riot.h"
#include "ccnl-pkt-ndntlv.h"

#include "xtimer.h"

//#include "ccnl-core.c"

//#include "ccnl-defs.h"
//#include "ccnl-core.h"


#define BUF_SIZE (64)


static unsigned char out[CCNL_MAX_PACKET_SIZE];
static const char *default_content = "Start the RIOT!";

static unsigned char int_buf[BUF_SIZE];

/**
 * currently configured suite
 */
static int ccnl_suite = CCNL_SUITE_NDNTLV;

/**
 * Frees all memory directly and indirectly allocated for prefix information
 */
#define free_prefix(p)  do{ if(p) \
                free_5ptr_list(p->bytes,p->comp,p->complen,p->chunknum,p); } while(0)

/**
 * Frees memory for a given content and the associated packet data
 */
#define free_content(c) do{ /* free_prefix(c->name); */ free_packet(c->pkt); \
                        ccnl_free(c); } while(0)



/**
 * @brief function prototypes required by ccnl-core.c
 * @{
 */
void free_packet(struct ccnl_pkt_s *pkt);





/**
 * @brief Some function pointers
 * @{
 */
typedef int (*ccnl_mkInterestFunc)(struct ccnl_prefix_s*, int*, unsigned char*, int);
typedef int (*ccnl_isContentFunc)(unsigned char*, int);

extern ccnl_mkInterestFunc ccnl_suite2mkInterestFunc(int suite);
extern ccnl_isContentFunc ccnl_suite2isContentFunc(int suite);


/**
 * @brief Local loopback face
 */
static struct ccnl_face_s *loopback_face;


static const uint32_t sleep_time = 30;

static void test_uri_to_prefix(char *uri){

    uint32_t begin, end;

    int repeat = 1000000;
    printf("ccnl_URItoPrefix start at (repeat=%d)\n", repeat);
    begin = xtimer_now();
    bool err = false;
    for (int i=0; i<repeat; i++){
        int suite = CCNL_SUITE_NDNTLV;
        //char* uri = "/hi";
        struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(uri, suite, NULL, NULL);
        if (prefix == NULL){
            err = true;
            break;
        }
        free_prefix(prefix);
    }
    end = xtimer_now();
    
    if(!err){
        printf("ccnl_URItoPrefix average time is %"PRIu32" us\n", (end-begin)/repeat);
    }else{
        printf("ccnl_URItoPrefix failed\n");
    }
}


static void test_ccnl_ndntlv_prependContent(char *uri){

    char *body = (char*) default_content;
    int arg_len = strlen(default_content) + 1;
    int offs = CCNL_MAX_PACKET_SIZE;
    int suite = CCNL_SUITE_NDNTLV;

    struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(uri, suite, NULL, NULL);



    uint32_t begin, end;

    int repeat = 4000000;
    printf("ccnl_ndntlv_prependContent start at (repeat=%d)\n", repeat);
    begin = xtimer_now();
    bool err = false;
    for (int i=0; i<repeat; i++){
        arg_len = strlen(default_content) + 1;
        arg_len = ccnl_ndntlv_prependContent(prefix, (unsigned char*) body, arg_len, NULL, NULL, &offs, out);
    }
    end = xtimer_now();
    
    if(!err){
        printf("ccnl_ndntlv_prependContent average time is %"PRIu32" us\n", (end-begin)/repeat);
    }else{
        printf("ccnl_ndntlv_prependContent failed\n");
    }
}




static void test_ccnl_ndntlv_bytes2pkt(char *uri){

    char *body = (char*) default_content;
    int arg_len = strlen(default_content) + 1;
    int offs = CCNL_MAX_PACKET_SIZE;
    int suite = CCNL_SUITE_NDNTLV;

    struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(uri, suite, NULL, NULL);

    arg_len = ccnl_ndntlv_prependContent(prefix, (unsigned char*) body, arg_len, NULL, NULL, &offs, out);

    unsigned char *olddata;
    unsigned char *data = olddata = out + offs;

    int len;
    unsigned typ;

    if (ccnl_ndntlv_dehead(&data, &arg_len, (int*) &typ, &len) ||
        typ != NDN_TLV_Data) {
        return ;
    }

    uint32_t begin, end;

    int repeat = 1000000;
    printf("Bytes2pkt start at (repeat=%d)\n", repeat);
    begin = xtimer_now();
    bool err = false;
    for (int i=0; i<repeat; i++){
        struct ccnl_pkt_s *pk = ccnl_ndntlv_bytes2pkt(typ, olddata, &data, &arg_len);
        if (pk == NULL){
            err = true;
            break;
        }
        free_packet(pk);
    }
    end = xtimer_now();
    
    if(!err){
        printf("Bytes2pkt average time is %"PRIu32" us\n", (end-begin)/repeat);
    }else{
        printf("Bytes2pkt failed\n");
    }
}



static void test_create_content(char *uri){

    char *body = (char*) default_content;
    int arg_len = strlen(default_content) + 1;
    int offs = CCNL_MAX_PACKET_SIZE;
    int suite = CCNL_SUITE_NDNTLV;

    struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(uri, suite, NULL, NULL);

    arg_len = ccnl_ndntlv_prependContent(prefix, (unsigned char*) body, arg_len, NULL, NULL, &offs, out);

    unsigned char *olddata;
    unsigned char *data = olddata = out + offs;

    int len;
    unsigned typ;

    if (ccnl_ndntlv_dehead(&data, &arg_len, (int*) &typ, &len) ||
        typ != NDN_TLV_Data) {
        return ;
    }

    struct ccnl_content_s *c = 0;
    struct ccnl_pkt_s *pk = ccnl_ndntlv_bytes2pkt(typ, olddata, &data, &arg_len);

    uint32_t begin, end;

    int repeat = 600000;
    printf("Create content start at (repeat=%d)\n", repeat);
    begin = xtimer_now();
    bool err = false;
    for (int i=0; i<repeat; i++){
        c = ccnl_content_new(&ccnl_relay, &pk);
        if (c == NULL){
            err = true;
            break;
        }
        free_content(c);
    }
    end = xtimer_now();
    
    if(!err){
        printf("Create content average time is %"PRIu32" us\n", (end-begin)/repeat);
    }else{
        printf("Create content failed\n");
    }
}


static void test_content_get_prefix(char *uri){

    char *body = (char*) default_content;
    int arg_len = strlen(default_content) + 1;
    int offs = CCNL_MAX_PACKET_SIZE;
    int suite = CCNL_SUITE_NDNTLV;

    struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(uri, suite, NULL, NULL);

    arg_len = ccnl_ndntlv_prependContent(prefix, (unsigned char*) body, arg_len, NULL, NULL, &offs, out);

    unsigned char *olddata;
    unsigned char *data = olddata = out + offs;

    int len;
    unsigned typ;

    if (ccnl_ndntlv_dehead(&data, &arg_len, (int*) &typ, &len) ||
        typ != NDN_TLV_Data) {
        return ;
    }


    struct ccnl_pkt_s *pk = ccnl_ndntlv_bytes2pkt(typ, olddata, &data, &arg_len);
    struct ccnl_content_s *c = ccnl_content_new(&ccnl_relay, &pk);
    
    struct ccnl_prefix_s *prefix_temp;
    
    
    uint32_t begin, end;

    int repeat = 4000000;
    printf("Content gets prefix at (repeat=%d)\n", repeat);
    begin = xtimer_now();
    bool err = false;
    for (int i=0; i<repeat; i++){
        prefix_temp = c->pkt->pfx;
        if (prefix_temp == NULL){
            err = true;
            break;
        }
        free_prefix(prefix_temp);
    }
    end = xtimer_now();
    
    if(!err){
        printf("Content gets prefix average time is %"PRIu32" us\n", (end-begin)/repeat);
    }else{
        printf("Content gets prefix failed\n");
    }
}


static void test_create_interest(char *uri){

    memset(int_buf, '\0', BUF_SIZE);
    
    int suite = CCNL_SUITE_NDNTLV;

    struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(uri, suite, NULL, NULL);
    // struct ccnl_interest_s *ccnl_send_interest(struct ccnl_prefix_s *prefix, unsigned char *buf, size_t buf_len)
    // ccnl_send_interest(argv[1], int_buf, BUF_SIZE);

    if (ccnl_suite != CCNL_SUITE_NDNTLV) {
        printf("Suite not supported by RIOT!");
        return;
    }

    ccnl_mkInterestFunc mkInterest;
    ccnl_isContentFunc isContent;

    mkInterest = ccnl_suite2mkInterestFunc(ccnl_suite);
    isContent = ccnl_suite2isContentFunc(ccnl_suite);

    if (!mkInterest || !isContent) {
        printf("No functions for this suite were found!");
        return;
    }

    //printf("interest for chunk number: %u\n", (prefix->chunknum == NULL) ? 0 : *prefix->chunknum);

    if (!prefix) {
        printf("prefix could not be created!\n");
        return;
    }

    int nonce = random_uint32();
    //printf("nonce: %i\n", nonce);

    int len = mkInterest(prefix, &nonce, int_buf, BUF_SIZE);

    unsigned char *start = int_buf;
    unsigned char *data = int_buf;
    struct ccnl_pkt_s *pkt;

    int typ;
    int int_len;

    /* TODO: support other suites */
    if (ccnl_ndntlv_dehead(&data, &len, (int*) &typ, &int_len) || (int) int_len > len) {
        printf("  invalid packet format\n");
        return;
    }
    pkt = ccnl_ndntlv_bytes2pkt(NDN_TLV_Interest, start, &data, &len);

    struct ccnl_interest_s *myinterest;
    loopback_face = ccnl_get_face_or_create(&ccnl_relay, -1, NULL, 0);
    loopback_face->flags |= CCNL_FACE_FLAGS_STATIC;


    uint32_t begin, end;

    int repeat = 500000;
    printf("Create interest start at (repeat=%d)\n", repeat);
    begin = xtimer_now();
    bool err = false;
    for (int i=0; i<repeat; i++){
        myinterest = ccnl_interest_new(&ccnl_relay, loopback_face, &pkt);
        if (myinterest == NULL){
            err = true;
            break;
        }
        free_packet(myinterest->pkt);
        ccnl_free(myinterest);
    }
    end = xtimer_now();
    
    if(!err){
        printf("Create interest average time is %"PRIu32" us\n", (end-begin)/repeat);
    }else{
        printf("Create interest failed\n");
    }
}



static void test_interest_get_prefix(char *uri){


    memset(int_buf, '\0', BUF_SIZE);
    
    int suite = CCNL_SUITE_NDNTLV;

    struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(uri, suite, NULL, NULL);
    // struct ccnl_interest_s *ccnl_send_interest(struct ccnl_prefix_s *prefix, unsigned char *buf, size_t buf_len)
    // ccnl_send_interest(argv[1], int_buf, BUF_SIZE);

    if (ccnl_suite != CCNL_SUITE_NDNTLV) {
        printf("Suite not supported by RIOT!");
        return;
    }

    ccnl_mkInterestFunc mkInterest;
    ccnl_isContentFunc isContent;

    mkInterest = ccnl_suite2mkInterestFunc(ccnl_suite);
    isContent = ccnl_suite2isContentFunc(ccnl_suite);

    if (!mkInterest || !isContent) {
        printf("No functions for this suite were found!");
        return;
    }

    //printf("interest for chunk number: %u\n", (prefix->chunknum == NULL) ? 0 : *prefix->chunknum);

    if (!prefix) {
        printf("prefix could not be created!\n");
        return;
    }

    int nonce = random_uint32();


    int len = mkInterest(prefix, &nonce, int_buf, BUF_SIZE);

    unsigned char *start = int_buf;
    unsigned char *data = int_buf;
    struct ccnl_pkt_s *pkt;

    int typ;
    int int_len;

    /* TODO: support other suites */
    if (ccnl_ndntlv_dehead(&data, &len, (int*) &typ, &int_len) || (int) int_len > len) {
        printf("  invalid packet format\n");
        return;
    }
    pkt = ccnl_ndntlv_bytes2pkt(NDN_TLV_Interest, start, &data, &len);

    loopback_face = ccnl_get_face_or_create(&ccnl_relay, -1, NULL, 0);
    loopback_face->flags |= CCNL_FACE_FLAGS_STATIC;
    struct ccnl_interest_s *myinterest = ccnl_interest_new(&ccnl_relay, loopback_face, &pkt);

    struct ccnl_prefix_s *prefix_temp;


    uint32_t begin, end;

    int repeat = 4000000;
    printf("Interest gets prefix at (repeat=%d)\n", repeat);
    begin = xtimer_now();
    bool err = false;
    for (int i=0; i<repeat; i++){
        prefix_temp = myinterest->pkt->pfx;
        if (prefix_temp == NULL){
            err = true;
            break;
        }
        free_prefix(prefix_temp);
    }
    end = xtimer_now();
    
    if(!err){
        printf("Interest gets prefix average time is %"PRIu32" us\n", (end-begin)/repeat);
    }else{
        printf("Interest gets prefix failed\n");
    }
}



/*
static void test_add2cache(char *uri){

    char *body = (char*) default_content;
    int arg_len = strlen(default_content) + 1;
    int offs = CCNL_MAX_PACKET_SIZE;
    int suite = CCNL_SUITE_NDNTLV;

    struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(uri, suite, NULL, NULL);

    arg_len = ccnl_ndntlv_prependContent(prefix, (unsigned char*) body, arg_len, NULL, NULL, &offs, out);

    unsigned char *olddata;
    unsigned char *data = olddata = out + offs;

    int len;
    unsigned typ;

    if (ccnl_ndntlv_dehead(&data, &arg_len, (int*) &typ, &len) ||
        typ != NDN_TLV_Data) {
        return ;
    }

    struct ccnl_content_s *c = 0;
    struct ccnl_pkt_s *pk = ccnl_ndntlv_bytes2pkt(typ, olddata, &data, &arg_len);
    c = ccnl_content_new(&ccnl_relay, &pk);
    
    uint32_t begin, end;

    int repeat = 5;
    printf("Create content start at (repeat=%d)\n", repeat);
    begin = xtimer_now();
    bool err = false;
    for (int i=0; i<repeat; i++){
        c = ccnl_content_new(&ccnl_relay, &pk);
        if (c == NULL){
            err = true;
            break;
        }
        ccnl_free(c);
    }
    end = xtimer_now();
    
    if(!err){
        printf("Create content average time is %"PRIu32" us\n", (end-begin)/repeat);
    }else{
        printf("Create content failed\n");
    }
}

*/
int ccn_test(int argc, char **argv)
{
    ccnl_core_init();

    if (argc < 2){
        printf("Not enough arguments\n");
        return -1;
    }
    /* check if already running */
    if (strcmp(argv[1], "content") == 0) {
        test_create_content(argv[2]);
        test_content_get_prefix(argv[2]);

    }
    if (strcmp(argv[1], "prefix") == 0) {
        test_uri_to_prefix(argv[2]);
        test_ccnl_ndntlv_prependContent(argv[2]);
        test_ccnl_ndntlv_bytes2pkt(argv[2]);
    }
    if (strcmp(argv[1], "interest") == 0) {
        test_create_interest(argv[2]);
        test_interest_get_prefix(argv[2]);
    }    
    
    if (strcmp(argv[1], "total") == 0) {
	 xtimer_sleep(sleep_time);
        test_create_content(argv[2]);
	 xtimer_sleep(sleep_time);
        test_content_get_prefix(argv[2]);
	 xtimer_sleep(sleep_time);
        test_create_interest(argv[2]);
	 xtimer_sleep(sleep_time);
        test_interest_get_prefix(argv[2]);
	 xtimer_sleep(sleep_time);
        test_uri_to_prefix(argv[2]);
	 xtimer_sleep(sleep_time);
        test_ccnl_ndntlv_prependContent(argv[2]);
	 xtimer_sleep(sleep_time);
        test_ccnl_ndntlv_bytes2pkt(argv[2]);
	 xtimer_sleep(sleep_time);
    }
    
    
    /*
    if (strcmp(argv[1], "cache") == 0){
        test_add2cache(argv[2]);
    }
    */
    
    
    
    return -1;
}

