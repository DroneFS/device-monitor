struct fsroot_path;

struct fsroot_path *fsroot_path_new(const char *path);
void fsroot_path_destroy(struct fsroot_path *);

char *fsroot_path_get_basename(const struct fsroot_path *path);
char *fsroot_path_get_dir(const struct fsroot_path *path);
char *fsroot_path_get_path(const struct fsroot_path *path);
