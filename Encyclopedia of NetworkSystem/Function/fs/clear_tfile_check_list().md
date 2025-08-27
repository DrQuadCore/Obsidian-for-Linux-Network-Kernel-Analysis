```c
static void clear_tfile_check_list(void)
{
	struct file *file;

	/* first clear the tfile_check_list */
	while (!list_empty(&tfile_check_list)) {
		file = list_first_entry(&tfile_check_list, struct file,
					f_tfile_llink);
		list_del_init(&file->f_tfile_llink);
	}
	INIT_LIST_HEAD(&tfile_check_list);
}
```