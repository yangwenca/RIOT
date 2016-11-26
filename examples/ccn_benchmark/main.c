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

#include <stdio.h>

#include "shell.h"
#include "msg.h"
#include "ccn-lite-riot.h"

/* main thread's message queue */
#define MAIN_QUEUE_SIZE     (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];


extern int ccn(int argc, char **argv);

static const shell_command_t shell_commands[] = {
    { "ccn", "start ccn benchmark", ccn },
    { NULL, NULL, NULL }
};

int main(void)
{
    /* start shell */
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);

    puts("Basic CCN-Lite example");
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    /* should be never reached */
    return 0;
}
