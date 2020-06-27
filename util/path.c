/* Code to mangle pathnames into those matching a given prefix.
   eg. open("/lib/foo.so") => open("/usr/gnemul/i386-linux/lib/foo.so");

   The assumption is that this area does not change.
*/
#include "qemu/osdep.h"
#include <sys/param.h>
#include <dirent.h>
#include "qemu/cutils.h"
#include "qemu/path.h"
#include "qemu/thread.h"

static const char *base;
static GHashTable *hash;
static QemuMutex lock;

void init_paths(const char *prefix)
{
    if (prefix[0] == '\0' || !strcmp(prefix, "/")) {
        return;
    }

    if (prefix[0] == '/') {
        base = g_strdup(prefix);
    } else {
        char *cwd = g_get_current_dir();
        base = g_build_filename(cwd, prefix, NULL);
        g_free(cwd);
    }

    hash = g_hash_table_new(g_str_hash, g_str_equal);
    qemu_mutex_init(&lock);
}

/* Look for path in emulation dir, otherwise return name. */
const char *path(const char *name)
{
    gpointer key, value;
    const char *ret;

    /* Only do absolute paths: quick and dirty, but should mostly be OK.  */
    if (!base || !name || name[0] != '/') {
        return name;
    }

    qemu_mutex_lock(&lock);

    /* Have we looked up this file before?  */
    if (g_hash_table_lookup_extended(hash, name, &key, &value)) {
        ret = value ? value : name;
    } else {
        char *save = g_strdup(name);
        char *full = g_build_filename(base, name, NULL);

        /* Look for the path; record the result, pass or fail.  */
        if (access(full, F_OK) == 0) {
            /* Exists.  */
            g_hash_table_insert(hash, save, full);
            ret = full;
        } else {
            /* Does not exist.  */
            g_free(full);
            g_hash_table_insert(hash, save, NULL);
            ret = name;
        }
    }

    qemu_mutex_unlock(&lock);
    return ret;
}

/* Prepends working directory if path is relative.
 * If path is absolute, it is returned as-is without any allocation.
 * Otherwise, caller is responsible to free returned path.
 * Returns NULL and sets errno upon error.
 * Note: realpath is not called to let the kernel do the rest of the resolution.
 */
const char *prepend_workdir_if_relative(const char *path)
{
    char buf[PATH_MAX];
    char *p;
    int i, j, k;

    if (!path || path[0] == '/') return path;

    if (!getcwd(buf, PATH_MAX)) return NULL;
    i = strlen(buf);
    j = strlen(path);
    k = i + 1 + j + 1; /* workdir + '/' + path + '\0' */
    if (i + j > PATH_MAX) {
        errno = ERANGE;
        return NULL;
    }
    if (!(p = malloc(k * sizeof(char*)))) return NULL;

    if (!strncat(p, buf, i)) return NULL;
    if (!strncat(p, "/", 1)) return NULL;
    if (!strncat(p, path, j)) return NULL;
    return p;
}
