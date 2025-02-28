/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2022
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#ifndef P11TOOL_H_
#define P11TOOL_H_

#include "pkcs11types.h"

#define UNUSED(var)             ((void)(var))

#define MAX_PRINT_LINE_LENGTH   80

enum p11tool_arg_type {
    ARG_TYPE_PLAIN = 0, /* no argument */
    ARG_TYPE_STRING = 1,
    ARG_TYPE_ENUM = 2,
    ARG_TYPE_NUMBER = 3,
};

struct p11tool_enum_value {
    const char *value;
    const struct p11tool_arg *args;
    union {
        const void *ptr;
        CK_ULONG num;
    } private;
    char **any_value; /* if this is not NULL then this enum value matches to
                         any string, and the string is set into any_value */
};

struct p11tool_arg {
    const char *name;
    enum p11tool_arg_type type;
    bool required;
    bool case_sensitive;
    const struct p11tool_enum_value *enum_values;
    union {
        bool *plain;
        char **string;
        struct p11tool_enum_value **enum_value;
        CK_ULONG *number;
    } value;
    bool (*is_set)(const struct p11tool_arg *arg);
    const char *description;
};

struct p11tool_opt {
    char short_opt; /* 0 if no short option is used */
    const char *long_opt; /* NULL if no long option */
    int long_opt_val; /* Used only if short_opt is 0 */
    bool required;
    struct p11tool_arg arg;
    const char *description;
};

struct p11tool_cmd {
    const char *cmd;
    const char *cmd_short1;
    const char *cmd_short2;
    CK_RV (*func)(void);
    const struct p11tool_opt *opts;
    const struct p11tool_arg *args;
    const char *description;
    void (*help)(void);
    CK_FLAGS session_flags;
};

const struct p11tool_cmd *p11tool_find_command(const struct p11tool_cmd *cmds,
                                               const char *cmd);
CK_RV p11tool_parse_cmd_arguments(const struct p11tool_cmd *cmd,
                                  int *argc, char **argv[]);
CK_RV p11tool_parse_cmd_options(const struct p11tool_cmd *cmd,
                                const struct p11tool_opt *generic_opts,
                                int argc, char *argv[]);
CK_RV p11tool_check_required_args(const struct p11tool_arg *args);
CK_RV p11tool_check_required_cmd_opts(const struct p11tool_opt *cmd_opts,
                                      const struct p11tool_opt *generic_opts);
void p11tool_print_indented(const char *str, int indent);
void p11tool_print_help(const struct p11tool_cmd *commands,
                        const struct p11tool_opt *generic_opts,
                        int indent_pos);
void p11tool_print_command_help(const struct p11tool_cmd *cmd,
                                const struct p11tool_opt *generic_opts,
                                int indent_pos);

#endif
