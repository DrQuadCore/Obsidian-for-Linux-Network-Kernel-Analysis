```c title=sock_alloc_file()
/*
 *	Obtains the first available file descriptor and sets it up for use.
 *
 *	These functions create file structures and maps them to fd space
 *	of the current process. On success it returns file descriptor
 *	and file struct implicitly stored in sock->file.
 *	Note that another thread may close file descriptor before we return
 *	from this function. We use the fact that now we do not refer
 *	to socket after mapping. If one day we will need it, this
 *	function will increment ref. count on file by 1.
 *
 *	In any case returned fd MAY BE not valid!
 *	This race condition is unavoidable
 *	with shared fd spaces, we cannot solve it inside kernel,
 *	but we take care of internal coherence yet.
 */

/**
 *	sock_alloc_file - Bind a &socket to a &file
 *	@sock: socket
 *	@flags: file status flags
 *	@dname: protocol name
 *
 *	Returns the &file bound with @sock, implicitly storing it
 *	in sock->file. If dname is %NULL, sets to "".
 *
 *	On failure @sock is released, and an ERR pointer is returned.
 *
 *	This function uses GFP_KERNEL internally.
 */

struct file *sock_alloc_file(struct socket *sock, int flags, const char *dname)
{
	struct file *file;

	if (!dname)
		dname = sock->sk ? sock->sk->sk_prot_creator->name : "";
	
	// 가상의 파일 만들기
	file = alloc_file_pseudo(SOCK_INODE(sock), sock_mnt, dname,
				O_RDWR | (flags & O_NONBLOCK),
				&socket_file_ops);
	if (IS_ERR(file)) { // 실패했을 경우 소켓 해제
		sock_release(sock);
		return file;
	}
	
	// 파일과 소켓 연결하기
	file->f_mode |= FMODE_NOWAIT;
	sock->file = file;
	file->private_data = sock;
	stream_open(SOCK_INODE(sock), file);
	return file;
}
EXPORT_SYMBOL(sock_alloc_file);
```

`alloc_file_pseudo()` 함수로 가상의 파일을 만든다. 이때 매개변수로 소켓의 inode와 `socket_file_ops`로 소켓 전용 파일 연산을 전달한다. 
파일과 소켓을 참조 관계로 연결한다.

---
## socket_file_ops
```c title=socket_file_ops

/*
 *	Socket files have a set of 'special' operations as well as the generic file ones. These don't appear
 *	in the operation structures but are done directly via the socketcall() multiplexor.
 */

static const struct file_operations socket_file_ops = {
	.owner =	THIS_MODULE,
	.llseek =	no_llseek,
	.read_iter =	sock_read_iter, // read() 시스템 콜에서 호출되는 함수
	.write_iter =	sock_write_iter,
	.poll =		sock_poll,
	.unlocked_ioctl = sock_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = compat_sock_ioctl,
#endif
	.uring_cmd =    io_uring_cmd_sock,
	.mmap =		sock_mmap,
	.release =	sock_close,
	.fasync =	sock_fasync,
	.splice_write = splice_to_socket,
	.splice_read =	sock_splice_read,
	.splice_eof =	sock_splice_eof,
	.show_fdinfo =	sock_show_fdinfo,
};
```


---
## alloc_file_pseudo()
```c title=alloc_file_pseudo()
// /fs/file_table.c
struct file *alloc_file_pseudo(struct inode *inode, struct vfsmount *mnt,
			       const char *name, int flags,
			       const struct file_operations *fops)
{
	int ret;
	struct path path;
	struct file *file;

	// 가상의 경로 만들기
	ret = alloc_path_pseudo(name, inode, mnt, &path);
	if (ret)
		return ERR_PTR(ret);

	// 파일 만들기
	file = alloc_file(&path, flags, fops);
	if (IS_ERR(file)) {
		ihold(inode);
		path_put(&path);
	}
	return file;
}
EXPORT_SYMBOL(alloc_file_pseudo);
```

`alloc_path_pseudo()` 함수로 가상의 경로를 만들고 그 경로를 바탕으로 `alloc_file()` 함수로 파일 구조체를 만든다. 이때 파일 연산 구조체(`file_operations`)도 파일에 연결한다.

---
## alloc_file()
```c title=alloc_file()
/**
 * alloc_file - allocate and initialize a 'struct file'
 *
 * @path: the (dentry, vfsmount) pair for the new file
 * @flags: O_... flags with which the new file will be opened
 * @fop: the 'struct file_operations' for the new file
 */
static struct file *alloc_file(const struct path *path, int flags,
		const struct file_operations *fop)
{
	struct file *file;
	
	file = alloc_empty_file(flags, current_cred());  // 핀 파일 구조체 만들기
	if (!IS_ERR(file))
		file_init_path(file, path, fop); // 파일과 경로, fop 연결하기
	return file;
}
```

---
## file_init_path()
```c title=file_init_path()
/**
 * file_init_path - initialize a 'struct file' based on path
 *
 * @file: the file to set up
 * @path: the (dentry, vfsmount) pair for the new file
 * @fop: the 'struct file_operations' for the new file
 */
static void file_init_path(struct file *file, const struct path *path,
			   const struct file_operations *fop)
{
	file->f_path = *path;
	file->f_inode = path->dentry->d_inode;
	file->f_mapping = path->dentry->d_inode->i_mapping;
	file->f_wb_err = filemap_sample_wb_err(file->f_mapping);
	file->f_sb_err = file_sample_sb_err(file);
	if (fop->llseek)
		file->f_mode |= FMODE_LSEEK;
	if ((file->f_mode & FMODE_READ) &&
	     likely(fop->read || fop->read_iter))
		file->f_mode |= FMODE_CAN_READ;
	if ((file->f_mode & FMODE_WRITE) &&
	     likely(fop->write || fop->write_iter))
		file->f_mode |= FMODE_CAN_WRITE;
	file->f_iocb_flags = iocb_flags(file);
	file->f_mode |= FMODE_OPENED;
	file->f_op = fop;
	if ((file->f_mode & (FMODE_READ | FMODE_WRITE)) == FMODE_READ)
		i_readcount_inc(path->dentry->d_inode);
}
```

경로, fop 연결
`file->f_mode`에 파일이 열려있음 설정
읽기 전용일 시 inode의 참조 카운트 증가