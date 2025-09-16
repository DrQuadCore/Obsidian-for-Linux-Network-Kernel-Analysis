---
Parameter:
- unsigned int
- char __user
- size_t
Return:
- ssize_t
Location:
- /fs/read_write.c
---
```c title=ksys_read()
ssize_t ksys_read(unsigned int fd, char __user *buf, size_t count)
{
	struct fd f = fdget_pos(fd);
	ssize_t ret = -EBADF;

	if (f.file) {
		loff_t pos, *ppos = file_ppos(f.file);
		if (ppos) {
			pos = *ppos;
			ppos = &pos;
		}
		ret = vfs_read(f.file, buf, count, ppos);
		if (ret >= 0 && ppos)
			f.file->f_pos = pos;
		fdput_pos(f);
	}
	return ret;
}

SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)
{
	return ksys_read(fd, buf, count);
}
```

- `fdget_pos()`함수로 파일 디스크립터 번호로 `struct fd` 구조체를 찾는다. 동시에 파일의 ㄹ 획득한다.
- `file_ppos()` 함수로 `f.file->f_pos`를 들고 온다
- `vfs_read()`로 다음 읽기 과정을 진행한다

[[vfs_read()]]