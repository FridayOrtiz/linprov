/*
 * CO-RE accessors for the kernel struct fields linprov-ebpf reads.
 *
 * rustc can't emit BTF relocations yet, so these live in C: with
 * `preserve_access_index`, clang records each field access as a CO-RE
 * relocation, bpf-linker links this bitcode into the Rust program (see
 * build.rs), and aya rewrites the offsets against the running kernel's BTF
 * at load. The structs declare only the fields we touch, under the kernel's
 * names. No typedefs or anonymous structs here: bpf-linker fails to link
 * them.
 *
 * Each accessor must inline into its Rust caller as a direct load. A load
 * through a trusted pointer keeps its BTF type (`bprm->file` stays
 * `trusted_ptr_file`), which bpf_inode_storage_get and the xattr kfunc
 * require. BPF_CORE_READ would go through bpf_probe_read_kernel and return a
 * plain scalar instead.
 */

struct inode;

struct path {
	void *mnt;
	void *dentry;
} __attribute__((preserve_access_index));

struct file {
	unsigned int f_mode;
	struct inode *f_inode;
	struct path f_path;
} __attribute__((preserve_access_index));

struct linux_binprm {
	struct file *file;
} __attribute__((preserve_access_index));

#define ACCESSOR __attribute__((always_inline))

ACCESSOR struct file *linprov_binprm_file(struct linux_binprm *bprm)
{
	return bprm->file;
}

ACCESSOR unsigned int linprov_file_mode(struct file *file)
{
	return file->f_mode;
}

ACCESSOR struct inode *linprov_file_inode(struct file *file)
{
	return file->f_inode;
}

ACCESSOR struct path *linprov_file_path(struct file *file)
{
	return &file->f_path;
}
