/* Code for loading Linux executables.  Mostly linux kernel code.  */

#include "qemu/osdep.h"

#include "qemu.h"

#define NGROUPS 32

/* ??? This should really be somewhere else.  */
abi_long memcpy_to_target(abi_ulong dest, const void *src,
                          unsigned long len)
{
    void *host_ptr;

    host_ptr = lock_user(VERIFY_WRITE, dest, len, 0);
    if (!host_ptr)
        return -TARGET_EFAULT;
    memcpy(host_ptr, src, len);
    unlock_user(host_ptr, dest, 1);
    return 0;
}

static int count(char ** vec)
{
    int		i;

    for(i = 0; *vec; i++) {
        vec++;
    }

    return(i);
}

static int prepare_binprm(struct linux_binprm *bprm)
{
    struct stat		st;
    int mode;
    int retval;

    if(fstat(bprm->fd, &st) < 0) {
        return(-errno);
    }

    mode = st.st_mode;
    if(!S_ISREG(mode)) {	/* Must be regular file */
        return(-EACCES);
    }
    if(!(mode & 0111)) {	/* Must have at least one execute bit set */
        return(-EACCES);
    }

    bprm->e_uid = geteuid();
    bprm->e_gid = getegid();

    /* Set-uid? */
    if(mode & S_ISUID) {
        bprm->e_uid = st.st_uid;
    }

    /* Set-gid? */
    /*
     * If setgid is set but no group execute bit then this
     * is a candidate for mandatory locking, not a setgid
     * executable.
     */
    if ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP)) {
        bprm->e_gid = st.st_gid;
    }

    retval = read(bprm->fd, bprm->buf, BPRM_BUF_SIZE);
    if (retval < 0) {
        perror("prepare_binprm");
        exit(-1);
    }
    if (retval < BPRM_BUF_SIZE) {
        /* Make sure the rest of the loader won't read garbage.  */
        memset(bprm->buf + retval, 0, BPRM_BUF_SIZE - retval);
    }
    return retval;
}

/* Construct the envp and argv tables on the target stack.  */
abi_ulong loader_build_argptr(int envc, int argc, abi_ulong sp,
                              abi_ulong stringp, int push_ptr)
{
    TaskState *ts = (TaskState *)thread_cpu->opaque;
    int n = sizeof(abi_ulong);
    abi_ulong envp;
    abi_ulong argv;

    sp -= (envc + 1) * n;
    envp = sp;
    sp -= (argc + 1) * n;
    argv = sp;
    if (push_ptr) {
        /* FIXME - handle put_user() failures */
        sp -= n;
        put_user_ual(envp, sp);
        sp -= n;
        put_user_ual(argv, sp);
    }
    sp -= n;
    /* FIXME - handle put_user() failures */
    put_user_ual(argc, sp);
    ts->info->arg_start = stringp;
    while (argc-- > 0) {
        /* FIXME - handle put_user() failures */
        put_user_ual(stringp, argv);
        argv += n;
        stringp += target_strlen(stringp) + 1;
    }
    ts->info->arg_end = stringp;
    /* FIXME - handle put_user() failures */
    put_user_ual(0, argv);
    while (envc-- > 0) {
        /* FIXME - handle put_user() failures */
        put_user_ual(stringp, envp);
        envp += n;
        stringp += target_strlen(stringp) + 1;
    }
    /* FIXME - handle put_user() failures */
    put_user_ual(0, envp);

    return sp;
}

int loader_exec(int fdexec, const char *filename, char **argv, char **envp,
             struct target_pt_regs * regs, struct image_info *infop,
             struct linux_binprm *bprm)
{
    int retval, depth;

    bprm->fd = fdexec;
    bprm->filename = (char *)filename;
    bprm->argc = count(argv);
    bprm->argv = argv;
    bprm->envc = count(envp);
    bprm->envp = envp;

    for (depth = 0; ; depth++) {
        if (depth > 5) {
            return -ELOOP;
        }
        retval = prepare_binprm(bprm);
        if(retval>=0) {
            if (bprm->buf[0] == 0x7f
                    && bprm->buf[1] == 'E'
                    && bprm->buf[2] == 'L'
                    && bprm->buf[3] == 'F') {
                retval = load_elf_binary(bprm, infop);
#if defined(TARGET_HAS_BFLT)
            } else if (bprm->buf[0] == 'b'
                    && bprm->buf[1] == 'F'
                    && bprm->buf[2] == 'L'
                    && bprm->buf[3] == 'T') {
                retval = load_flt_binary(bprm, infop);
#endif
            } else if (bprm->buf[0] == '#'
                    && bprm->buf[1] == '!') {
                retval = load_script(bprm);
                if (retval >= 0) continue;
            } else {
                return -ENOEXEC;
            }
        }
        break;
    }

    if(retval>=0) {
        /* success.  Initialize important registers */
        do_init_thread(regs, infop);
        return retval;
    }

    return(retval);
}

static inline bool spacetab(char c) { return c == ' ' || c == '\t'; }
static inline const char *next_non_spacetab(const char *first, const char *last)
{
    for (; first <= last; first++)
        if (!spacetab(*first))
            return first;
    return NULL;
}
static inline const char *next_terminator(const char *first, const char *last)
{
    for (; first <= last; first++)
        if (spacetab(*first) || !*first)
            return first;
    return NULL;
}

/*
 * Reads the interpreter (shebang #!) line and modifies bprm object accordingly
 * This is a modified version of Linux's load_script function.
*/
int load_script(struct linux_binprm *bprm)
{
    const char *i_name, *i_sep, *i_arg, *i_end, *buf_end;
    int execfd, i, argc_delta;

    buf_end = bprm->buf + sizeof(bprm->buf) - 1;
    i_end = (const char*)memchr(bprm->buf, '\n', sizeof(bprm->buf));
    if (!i_end) {
        i_end = next_non_spacetab(bprm->buf + 2, buf_end);
        if (!i_end) {
            perror("script_prepare_binprm: no interpreter name found");
            return -ENOEXEC; /* Entire buf is spaces/tabs */
        }
        /*
         * If there is no later space/tab/NUL we must assume the
         * interpreter path is truncated.
         */
        if (!next_terminator(i_end, buf_end)) {
            perror("script_prepare_binprm: truncated interpreter path");
            return -ENOEXEC;
        }
        i_end = buf_end;
    }
    /* Trim any trailing spaces/tabs from i_end */
    while (spacetab(i_end[-1]))
        i_end--;
    *((char *)i_end) = '\0';
    /* Skip over leading spaces/tabs */
    i_name = next_non_spacetab(bprm->buf+2, i_end);
    if (!i_name || (i_name == i_end)) {
        perror("script_prepare_binprm: no interpreter name found");
        return -ENOEXEC; /* No interpreter name found */
    }

    /* Is there an optional argument? */
    i_arg = NULL;
    i_sep = next_terminator(i_name, i_end);
    if (i_sep && (*i_sep != '\0')) {
        i_arg = next_non_spacetab(i_sep, i_end);
        *((char *)i_sep) = '\0';
    }

    /*
     * OK, we've parsed out the interpreter name and
     * (optional) argument.
     * Splice in (1) the interpreter's name for argv[0]
     *           (2) (optional) argument to interpreter
     *           (3) filename of shell script (replace argv[0])
     *           (4) user arguments (argv[1:])
     */

    bprm->argv[0] = bprm->filename;

    execfd = open(i_name, O_RDONLY);
    if (execfd < 0) {
        perror("script_prepare_binprm: could not open script");
        return -ENOEXEC; /* Could not open interpreter */
    }

    argc_delta = 1 /* extra filename */ + (i_arg ? 1 : 0);
    bprm->argc += argc_delta;
    bprm->argv = realloc(bprm->argv, sizeof(char*) * (bprm->argc + 1));

    /* shift argv by argc_delta */
    for (i = bprm->argc; i >= argc_delta; i--)
        bprm->argv[i] = bprm->argv[i-argc_delta];

    bprm->argv[0] = (char *)strdup(i_name);
    if (i_arg)
        bprm->argv[1] = (char *)strdup(i_arg);

    bprm->fd = execfd; /* not closing fd as it is needed for the duration of the program */
    bprm->filename = (char *)strdup(i_name); /* replace filename with script interpreter */
    /* envc and envp are kept unchanged */

    return 0;
}
