/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2025
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */


#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <unistd.h>
#include <limits.h>
#include <ctype.h>
#include "platform.h"

#if !defined(_AIX)
    #include <linux/limits.h>
#endif /* _AIX */

#include <openssl/obj_mac.h>
#include <openssl/err.h>

#include "p11tool.h"

const struct p11tool_cmd *p11tool_find_command(const struct p11tool_cmd *cmds,
                                               const char *cmd)
{
    unsigned int i;

    for (i = 0; cmds[i].cmd != NULL; i++) {
        if (strcasecmp(cmd, cmds[i].cmd) == 0)
            return &cmds[i];
        if (cmds[i].cmd_short1 != NULL &&
            strcasecmp(cmd, cmds[i].cmd_short1) == 0)
            return &cmds[i];
        if (cmds[i].cmd_short2 != NULL &&
            strcasecmp(cmd, cmds[i].cmd_short2) == 0)
            return &cmds[i];
    }

    return NULL;
}

static void p11tool_count_opts(const struct p11tool_opt *opts,
                               unsigned int *optstring_len,
                               unsigned int *longopts_count)
{
    const struct p11tool_opt *opt;

    for (opt = opts; opt->short_opt != 0 || opt->long_opt != NULL; opt++) {
        if (opt->short_opt != 0) {
            (*optstring_len)++;
            if (opt->arg.type != ARG_TYPE_PLAIN) {
                (*optstring_len)++;
                if (!opt->arg.required)
                    (*optstring_len)++;
            }
        }

        if (opt->long_opt != NULL)
            (*longopts_count)++;
    }
}

static CK_RV p11tool_build_opts(const struct p11tool_opt *opts,
                                char *optstring,
                                struct option *longopts)
{
    const struct p11tool_opt *opt;
    unsigned int opts_idx, long_idx;

    opts_idx = strlen(optstring);

    for (long_idx = 0; longopts[long_idx].name != NULL; long_idx++)
        ;

    for (opt = opts; opt->short_opt != 0 || opt->long_opt != NULL; opt++) {
        if (opt->short_opt != 0) {
            optstring[opts_idx++] = opt->short_opt;
            if (opt->arg.type != ARG_TYPE_PLAIN) {
                optstring[opts_idx++] = ':';
                if (!opt->arg.required)
                    optstring[opts_idx++] = ':';
            }
        }

        if (opt->long_opt != NULL) {
            longopts[long_idx].name = opt->long_opt;
            longopts[long_idx].has_arg = opt->arg.type != ARG_TYPE_PLAIN ?
                              (opt->arg.required ?
                                      required_argument : optional_argument ) :
                              no_argument;
            longopts[long_idx].flag = NULL;
            longopts[long_idx].val = opt->short_opt != 0 ?
                                        opt->short_opt : opt->long_opt_val;
            long_idx++;
        }
    }

    return CKR_OK;
}

static CK_RV p11tool_build_cmd_opts(const struct p11tool_opt *cmd_opts,
                                    const struct p11tool_opt *generic_opts,
                                    char **optstring, struct option **longopts)
{
    unsigned int optstring_len = 0, longopts_count = 0;
    CK_RV rc;

    p11tool_count_opts(generic_opts, &optstring_len, &longopts_count);
    if (cmd_opts != NULL)
        p11tool_count_opts(cmd_opts, &optstring_len, &longopts_count);

    *optstring = calloc(1 + optstring_len + 1, 1);
    *longopts = calloc(longopts_count + 1, sizeof(struct option));
    if (*optstring == NULL || *longopts == NULL) {
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    (*optstring)[0] = ':'; /* Let getopt return ':' on missing argument */

    rc = p11tool_build_opts(generic_opts, *optstring, *longopts);
    if (rc != CKR_OK)
        goto error;

    if (cmd_opts != NULL) {
        rc = p11tool_build_opts(cmd_opts, *optstring, *longopts);
        if (rc != CKR_OK)
            goto error;
    }

    return CKR_OK;

error:
    if (*optstring != NULL)
        free(*optstring);
    *optstring = NULL;

    if (*longopts != NULL)
        free(*longopts);
    *longopts = NULL;

    return rc;
}

static CK_RV p11tool_process_plain_argument(const struct p11tool_arg *arg)
{
    *arg->value.plain = true;

    return CKR_OK;
}

static CK_RV p11tool_process_string_argument(const struct p11tool_arg *arg,
                                             char *val)
{
    *arg->value.string = val;

    return CKR_OK;
}

static CK_RV p11tool_process_enum_argument(const struct p11tool_arg *arg,
                                           char *val)
{
    const struct p11tool_enum_value *enum_val, *any_val = NULL;

    for (enum_val = arg->enum_values; enum_val->value != NULL; enum_val++) {

        if (enum_val->any_value != NULL) {
            any_val = enum_val;
        } else if (arg->case_sensitive ?
                            strcmp(val, enum_val->value) == 0 :
                            strcasecmp(val, enum_val->value) == 0) {

            *arg->value.enum_value = (struct p11tool_enum_value *)enum_val;
            return CKR_OK;
        }
    }

    /* process ANY enumeration value after all others */
    if (any_val != NULL) {
        *any_val->any_value = val;
        *arg->value.enum_value = (struct p11tool_enum_value *)any_val;
        return CKR_OK;
    }

    return CKR_ARGUMENTS_BAD;
}

static CK_RV p11tool_process_number_argument(const struct p11tool_arg *arg,
                                             char *val)
{
    char *endptr;

    errno = 0;
    *arg->value.number = strtoul(val, &endptr, 0);

    if ((errno == ERANGE && *arg->value.number == ULONG_MAX) ||
        (errno != 0 && *arg->value.number == 0) ||
        endptr == val) {
        return CKR_ARGUMENTS_BAD;
    }

    return CKR_OK;
}

static CK_RV p11tool_processs_argument(const struct p11tool_arg *arg, char *val)
{
    switch (arg->type) {
    case ARG_TYPE_PLAIN:
        return p11tool_process_plain_argument(arg);
    case ARG_TYPE_STRING:
        return p11tool_process_string_argument(arg, val);
    case ARG_TYPE_ENUM:
        return p11tool_process_enum_argument(arg, val);
    case ARG_TYPE_NUMBER:
        return p11tool_process_number_argument(arg, val);
    default:
        return CKR_ARGUMENTS_BAD;
    }
}

static bool p11tool_argument_is_set(const struct p11tool_arg *arg)
{
    if (arg->is_set != NULL)
       return arg->is_set(arg);

    switch (arg->type) {
    case ARG_TYPE_PLAIN:
        return *arg->value.plain;
    case ARG_TYPE_STRING:
        return *arg->value.string != NULL;
    case ARG_TYPE_ENUM:
        return *arg->value.enum_value != NULL;
    case ARG_TYPE_NUMBER:
        return *arg->value.number != 0;
    default:
        return false;
    }
}

static void p11tool_option_arg_error(const struct p11tool_opt *opt,
                                     const char *arg)
{
    if (opt->short_opt != 0 && opt->long_opt != NULL)
        warnx("Invalid argument '%s' for option '-%c/--%s'", arg,
             opt->short_opt, opt->long_opt);
    else if (opt->long_opt != NULL)
        warnx("Invalid argument '%s' for option '--%s'", arg, opt->long_opt);
    else
        warnx("Invalid argument '%s' for option '-%c'", arg, opt->short_opt);
}

static void p11tool_option_missing_error(const struct p11tool_opt *opt)
{
    if (opt->short_opt != 0 && opt->long_opt != NULL)
        warnx("Option '-%c/--%s' is required but not specified", opt->short_opt,
             opt->long_opt);
    else if (opt->long_opt != NULL)
        warnx("Option '--%s is required but not specified'", opt->long_opt);
    else
        warnx("Option '-%c' is required but not specified", opt->short_opt);
}

static CK_RV p11tool_process_option(const struct p11tool_opt *opts,
                                    int ch, char *val)
{
    const struct p11tool_opt *opt;
    CK_RV rc;

    for (opt = opts; opt->short_opt != 0 || opt->long_opt != NULL; opt++) {
        if (ch == (opt->short_opt != 0 ? opt->short_opt : opt->long_opt_val)) {
            rc = p11tool_processs_argument(&opt->arg, val);
            if (rc != CKR_OK) {
                p11tool_option_arg_error(opt, val);
                return rc;
            }

            return CKR_OK;
        }
    }

    return CKR_ARGUMENTS_BAD;
}

static CK_RV p11tool_process_cmd_option(const struct p11tool_opt *cmd_opts,
                                        const struct p11tool_opt *generic_opts,
                                        int opt, char *arg)
{
    CK_RV rc;

    rc = p11tool_process_option(generic_opts, opt, arg);
    if (rc == CKR_OK)
        return CKR_OK;

    if (cmd_opts != NULL) {
        rc = p11tool_process_option(cmd_opts, opt, arg);
        if (rc == CKR_OK)
            return CKR_OK;
    }

    return rc;
}

static CK_RV p11tool_check_required_opts(const struct p11tool_opt *opts)
{
    const struct p11tool_opt *opt;
    CK_RV rc = CKR_OK;

    for (opt = opts; opt->short_opt != 0 || opt->long_opt != NULL; opt++) {
        if (opt->required && opt->arg.required &&
            p11tool_argument_is_set(&opt->arg) == false) {
            p11tool_option_missing_error(opt);
            rc = CKR_ARGUMENTS_BAD;
            /* No break, report all missing options */
        }
    }

    return rc;
}

CK_RV p11tool_check_required_cmd_opts(const struct p11tool_opt *cmd_opts,
                                      const struct p11tool_opt *generic_opts)
{
    CK_RV rc;

    rc = p11tool_check_required_opts(generic_opts);
    if (rc != CKR_OK)
        return rc;

    if (cmd_opts != NULL) {
        rc = p11tool_check_required_opts(cmd_opts);
        if (rc != CKR_OK)
            return rc;
    }

    return CKR_OK;
}

CK_RV p11tool_parse_cmd_options(const struct p11tool_cmd *cmd,
                                const struct p11tool_opt *generic_opts,
                                int argc, char *argv[])
{
    char *optstring = NULL;
    struct option *longopts = NULL;
    CK_RV rc;
    int c;

    rc = p11tool_build_cmd_opts(cmd != NULL ? cmd->opts : NULL, generic_opts,
                                &optstring, &longopts);
    if (rc != CKR_OK)
        goto done;

    opterr = 0;
    while (1) {
        c = getopt_long(argc, argv, optstring, longopts, NULL);
        if (c == -1)
            break;

        switch (c) {
        case ':':
            warnx("Option '%s' requires an argument", argv[optind - 1]);
            rc = CKR_ARGUMENTS_BAD;
            goto done;

        case '?': /* An invalid option has been specified */
            if (optopt)
                warnx("Invalid option '-%c'", optopt);
            else
                warnx("Invalid option '%s'", argv[optind - 1]);
            rc = CKR_ARGUMENTS_BAD;
            goto done;

        default:
            rc = p11tool_process_cmd_option(cmd != NULL ? cmd->opts : NULL,
                                            generic_opts, c, optarg);
            if (rc != CKR_OK)
                goto done;
            break;
        }
    }

    if (optind < argc) {
        warnx("Invalid argument '%s'", argv[optind]);
        rc = CKR_ARGUMENTS_BAD;
        goto done;
    }

done:
    if (optstring != NULL)
        free(optstring);
    if (longopts != NULL)
        free(longopts);

    return rc;
}

CK_RV p11tool_check_required_args(const struct p11tool_arg *args)
{
    const struct p11tool_arg *arg;
    CK_RV rc2, rc = CKR_OK;

    for (arg = args; arg != NULL && arg->name != NULL; arg++) {
        if (arg->required && p11tool_argument_is_set(arg) == false) {
            warnx("Argument '%s' is required but not specified", arg->name);
            rc = CKR_ARGUMENTS_BAD;
            /* No break, report all missing arguments */
        }

        /* Check enumeration value specific arguments (if any) */
        if (arg->type == ARG_TYPE_ENUM && *arg->value.enum_value != NULL &&
            (*arg->value.enum_value)->args != NULL) {
            rc2 = p11tool_check_required_args((*arg->value.enum_value)->args);
            if (rc2 != CKR_OK)
                rc = rc2;
            /* No break, report all missing arguments */
        }
    }

    return rc;
}

static CK_RV p11tool_parse_arguments(const struct p11tool_arg *args,
                                     int *argc, char **argv[])
{
    const struct p11tool_arg *arg;
    CK_RV rc = CKR_OK;

    for (arg = args; arg->name != NULL; arg++) {
        if (*argc < 2 || strncmp((*argv)[1], "-", 1) == 0)
            break;

        rc = p11tool_processs_argument(arg, (*argv)[1]);
        if (rc != CKR_OK) {
            if (rc == CKR_ARGUMENTS_BAD)
                warnx("Invalid argument '%s' for '%s'", (*argv)[1], arg->name);
            break;
        }

        (*argc)--;
        (*argv)++;

        /* Process enumeration value specific arguments (if any) */
        if (arg->type == ARG_TYPE_ENUM && *arg->value.enum_value != NULL &&
            (*arg->value.enum_value)->args != NULL) {
            rc = p11tool_parse_arguments((*arg->value.enum_value)->args,
                                         argc, argv);
            if (rc != CKR_OK)
                break;
        }
    }

    return rc;
}

CK_RV p11tool_parse_cmd_arguments(const struct p11tool_cmd *cmd,
                                  int *argc, char **argv[])
{
    if (cmd == NULL)
        return CKR_OK;

    return p11tool_parse_arguments(cmd->args, argc, argv);
}

void p11tool_print_indented(const char *str, int indent)
{
    char *word, *line, *desc, *desc_ptr;
    int word_len, pos = indent;

    desc = desc_ptr = strdup(str);
    if (desc == NULL)
        return;

    line = strsep(&desc, "\n");
    while (line != NULL) {
        word = strsep(&line, " ");
        pos = indent;
        while (word != NULL) {
            word_len = strlen(word);
            if (pos + word_len + 1 > MAX_PRINT_LINE_LENGTH) {
                printf("\n%*s", indent, "");
                pos = indent;
            }
            if (pos == indent)
                printf("%s", word);
            else
                printf(" %s", word);
            pos += word_len + 1;
            word = strsep(&line, " ");
        }
        if (desc)
            printf("\n%*s", indent, "");
        line =  strsep(&desc, "\n");
    }

    printf("\n");
    free(desc_ptr);
}

static void p11tool_print_options_help(const struct p11tool_opt *opts,
                                       int indent_pos)
{
    const struct p11tool_opt *opt;
    char tmp[200];
    int len;

    for (opt = opts; opt->short_opt != 0 || opt->long_opt != NULL; opt++) {
        if (opt->short_opt != 0 && opt->long_opt != NULL)
            len = snprintf(tmp, sizeof(tmp), "-%c, --%s", opt->short_opt,
                           opt->long_opt);
        else if (opt->short_opt == 0 && opt->long_opt != NULL)
            len = snprintf(tmp, sizeof(tmp),"    --%s", opt->long_opt);
        else
            len = snprintf(tmp, sizeof(tmp),"-%c", opt->short_opt);

        if (opt->arg.type != ARG_TYPE_PLAIN) {
            if (opt->arg.required)
                snprintf(&tmp[len], sizeof(tmp) - len, " %s", opt->arg.name);
            else if (opt->long_opt == NULL)
                snprintf(&tmp[len], sizeof(tmp) - len, "[%s]", opt->arg.name);
            else
                snprintf(&tmp[len], sizeof(tmp) - len, "[=%s]", opt->arg.name);
        }

        printf("    %-*.*s ", indent_pos - 5, indent_pos - 5, tmp);
        p11tool_print_indented(opt->description, indent_pos);
    }
}

static void p11tool_print_arguments_help(const struct p11tool_cmd *cmd,
                                         const struct p11tool_arg *args,
                                         int indent, int indent_pos)
{
    const struct p11tool_arg *arg;
    const struct p11tool_enum_value *val;
    int width;
    bool newline = false;

    if (indent > 0) {
        for (arg = args; arg->name != NULL; arg++) {
            if (arg->required)
                printf(" %s", arg->name);
            else
                printf(" [%s]", arg->name);
        }
        printf("\n\n");
    }

    for (arg = args; arg->name != NULL; arg++) {
        width = indent_pos - 5 - indent;
        if (width < (int)strlen(arg->name))
            width = (int)strlen(arg->name);

        printf("%*s    %-*.*s ", indent, "", width, width, arg->name);
        p11tool_print_indented(arg->description, indent_pos);

        newline = false;

        if (arg->type != ARG_TYPE_ENUM)
            continue;

        /* Enumeration: print possible values */
        for (val = arg->enum_values; val->value != NULL; val++) {
            if (arg == cmd->args && p11tool_argument_is_set(arg) &&
                *arg->value.enum_value != val)
                continue;

            newline = true;

            printf("%*s        %s", indent, "", val->value);

            if (val->args != NULL) {
                p11tool_print_arguments_help(cmd, val->args, indent + 8,
                                             indent_pos);
                newline = false;
            } else {
                printf("\n");
            }
        }
    }

    if (indent > 0 || newline)
        printf("\n");
}

void p11tool_print_help(const struct p11tool_cmd *commands,
                        const struct p11tool_opt *generic_opts,
                        int indent_pos)
{
    const struct p11tool_cmd *cmd;

    printf("\n");
    printf("Usage: p11sak COMMAND [ARGS] [OPTIONS]\n");
    printf("\n");
    printf("COMMANDS:\n");
    for (cmd = commands; cmd->cmd != NULL; cmd++) {
        printf("    %-*.*s ", indent_pos - 5, indent_pos - 5, cmd->cmd);
        p11tool_print_indented(cmd->description, indent_pos);
    }
    printf("\n");
    printf("COMMON OPTIONS\n");
    p11tool_print_options_help(generic_opts, indent_pos);
    printf("\n");
    printf("For more information use 'p11sak COMMAND --help'.\n");
    printf("\n");
}

void p11tool_print_command_help(const struct p11tool_cmd *cmd,
                                const struct p11tool_opt *generic_opts,
                                int indent_pos)
{
    printf("\n");
    printf("Usage: p11sak %s [ARGS] [OPTIONS]\n", cmd->cmd);
    printf("\n");
    printf("ARGS:\n");
    p11tool_print_arguments_help(cmd, cmd->args, 0, indent_pos);
    printf("OPTIONS:\n");
    p11tool_print_options_help(cmd->opts, indent_pos);
    p11tool_print_options_help(generic_opts, indent_pos);
    printf("\n");
    if (cmd->help != NULL)
        cmd->help();
}
