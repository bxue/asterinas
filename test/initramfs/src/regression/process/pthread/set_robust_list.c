// SPDX-License-Identifier: MPL-2.0

/*
 * A regression test for `set_robust_list` called with an unmapped userspace
 * address.
 *
 * Linux does not dereference the `head` argument when handling the syscall. It
 * only checks `len`, and then records the userspace pointer as-is:
 *
 *     SYSCALL_DEFINE2(set_robust_list, struct robust_list_head __user *, head,
 *                     size_t, len)
 *     {
 *             if (unlikely(len != sizeof(*head)))
 *                     return -EINVAL;
 *
 *             current->futex.robust_list = head;
 *             return 0;
 *     }
 *
 * So `head` is allowed to point to a userspace address that is not currently
 * mapped, and the syscall must return zero for it. If the kernel dereferences
 * the pointer instead, the faulting access happens in kernel mode rather than
 * being reported as an ordinary syscall error.
 *
 * This matters because OSTD deliberately permits a fallible userspace source or
 * destination to be an in-range address with no existing mapping, while a Rust
 * raw-pointer copy such as `core::ptr::copy` additionally requires its operands
 * to be valid for the whole access. When the LoongArch64 `__memcpy_fallible` was
 * implemented with `core::ptr::copy`, this syscall reached Rust undefined
 * behavior and then a kernel panic on an address that it is required to accept.
 *
 * Note that the syscall must accept *any* address, not merely an unmapped one in
 * range: Linux performs no range check either. The kernel only resolves the
 * pointer when the thread exits and walks the robust list.
 */

#define _GNU_SOURCE
#include <limits.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <linux/futex.h>

#include "../../common/test.h"

#define PAGE_SIZE 4096
#define ROBUST_LIST_HEAD_LEN (sizeof(struct robust_list_head))

static void *unmapped_addr;

FN_SETUP(unmapped)
{
	// Map a page, then unmap it. The address is then definitely in the
	// userspace range and definitely unmapped, which is the condition this
	// test is about.
	unmapped_addr = CHECK_WITH(mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
					MAP_PRIVATE | MAP_ANONYMOUS, -1, 0),
				   _ret != MAP_FAILED);
	CHECK(munmap(unmapped_addr, PAGE_SIZE));
}
END_SETUP()

FN_TEST(unmapped_addr_is_accepted)
{
	// This is the case from the original report: a page that was mapped and
	// has since been unmapped. `set_robust_list` must record the pointer
	// and return success.
	TEST_SUCC(syscall(SYS_set_robust_list, unmapped_addr,
			  ROBUST_LIST_HEAD_LEN));

	// An address that was never mapped must behave the same way.
	void *never_mapped =
		TEST_SUCC(mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
	TEST_SUCC(munmap(never_mapped, PAGE_SIZE));
	TEST_SUCC(syscall(SYS_set_robust_list, never_mapped,
			  ROBUST_LIST_HEAD_LEN));
}
END_TEST()

FN_TEST(unmapped_addr_is_not_interpreted)
{
	// The pointer is recorded, not followed, so its alignment and its page
	// offset do not matter.
	TEST_SUCC(syscall(SYS_set_robust_list, unmapped_addr + 1,
			  ROBUST_LIST_HEAD_LEN));
	TEST_SUCC(syscall(SYS_set_robust_list, unmapped_addr + PAGE_SIZE - 1,
			  ROBUST_LIST_HEAD_LEN));

	// A head that straddles the end of the unmapped page performs no access
	// either.
	TEST_SUCC(syscall(SYS_set_robust_list,
			  unmapped_addr + PAGE_SIZE - ROBUST_LIST_HEAD_LEN,
			  ROBUST_LIST_HEAD_LEN));
}
END_TEST()

FN_TEST(out_of_range_addr_is_recorded)
{
	// Linux imposes no range check on `head` at all: it records whatever
	// value it is given. So every one of these must return success rather
	// than `EFAULT`, and none of them may be dereferenced. A kernel that
	// dereferences or range-checks them fails here, or panics and kills the
	// runner.
	void *addrs[] = {
		NULL,
		(void *)1,
		(void *)-1,
		(void *)(-(long)ROBUST_LIST_HEAD_LEN),
		(void *)ULONG_MAX,
	};

	for (size_t i = 0; i < sizeof(addrs) / sizeof(addrs[0]); ++i) {
		errno = 0;
		long ret = syscall(SYS_set_robust_list, addrs[i],
				   ROBUST_LIST_HEAD_LEN);

		if (ret == 0) {
			__tests_passed++;
			fprintf(stderr,
				"%s: set_robust_list(%p) passed [ret %ld]\n",
				__func__, addrs[i], ret);
		} else {
			__tests_failed++;
			fprintf(stderr,
				"%s: set_robust_list(%p) failed [ret %ld, %s]\n",
				__func__, addrs[i], ret, strerror(errno));
		}
	}
}
END_TEST()

FN_TEST(wrong_len)
{
	// The length is checked before the address is touched, so the address
	// does not change the result.
	TEST_ERRNO(syscall(SYS_set_robust_list, unmapped_addr, 0), EINVAL);
	TEST_ERRNO(syscall(SYS_set_robust_list, unmapped_addr,
			   ROBUST_LIST_HEAD_LEN - 1),
		   EINVAL);
	TEST_ERRNO(syscall(SYS_set_robust_list, unmapped_addr,
			   ROBUST_LIST_HEAD_LEN + 1),
		   EINVAL);

	// The same is true for a valid address.
	void *mapped = TEST_SUCC(mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
				      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
	TEST_ERRNO(syscall(SYS_set_robust_list, mapped, 0), EINVAL);
	TEST_ERRNO(syscall(SYS_set_robust_list, mapped,
			   ROBUST_LIST_HEAD_LEN * 2),
		   EINVAL);
	TEST_SUCC(munmap(mapped, PAGE_SIZE));
}
END_TEST()

FN_TEST(mapped_addr)
{
	// Ordinary usage must keep working: a mapped, initialized head is
	// accepted.
	struct robust_list_head head = {
		.list = { .next = NULL },
		.futex_offset = 0,
		.list_op_pending = NULL,
	};

	TEST_SUCC(syscall(SYS_set_robust_list, &head, ROBUST_LIST_HEAD_LEN));

	// Reset the robust list so that later tests see a clean state.
	TEST_SUCC(syscall(SYS_set_robust_list, NULL, ROBUST_LIST_HEAD_LEN));
}
END_TEST()
