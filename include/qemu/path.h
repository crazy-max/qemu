#ifndef QEMU_PATH_H
#define QEMU_PATH_H

void init_paths(const char *prefix);
const char *path(const char *pathname);
const char *prepend_workdir_if_relative(const char *path);

#endif
