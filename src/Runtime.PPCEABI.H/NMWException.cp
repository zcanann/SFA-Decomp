#include "PowerPC_EABI_Support/Runtime/exception.h"
#include "PowerPC_EABI_Support/Runtime/NMWException.h"
#include "PowerPC_EABI_Support/Runtime/MWCPlusLib.h"

#pragma exceptions on

#define ARRAY_HEADER_SIZE 16

extern "C" {
extern void abort();
extern void __dla__FPv(void*);
}

namespace std {
/**
 * @note Address: TODO
 * @note Size: TODO
 */
static void dthandler() { abort(); }

static terminate_handler thandler = dthandler;

/**
 * @note Address: TODO
 * @note Size: TODO
 */
static void duhandler() { thandler(); }

static unexpected_handler uhandler = duhandler;

/**
 * @note Address: TODO
 * @note Size: TODO
 */
extern void terminate() { thandler(); }

/**
 * @note Address: TODO
 * @note Size: TODO
 */
extern void unexpected() { uhandler(); }
} // namespace std

class __partial_array_destructor;

/**
 * @note Address: TODO
 * @note Size: TODO
 */
extern "C" char __throw_catch_compare(const char* throwtype, const char* catchtype, s32* offset_result)
{
	const char *cptr1, *cptr2;

	*offset_result = 0;

	if ((cptr2 = catchtype) == 0) {
		return true;
	}

	cptr1 = throwtype;

	if (*cptr2 == 'P') {
		cptr2++;
		if (*cptr2 == 'C') {
			cptr2++;
		}
		if (*cptr2 == 'V') {
			cptr2++;
		}
		if (*cptr2 == 'v') {
			if (*cptr1 == 'P' || *cptr1 == '*') {
				return true;
			}
		}
		cptr2 = catchtype;
	}

	switch (*cptr1) {
	case '*':
	case '!':
		if (*cptr1++ != *cptr2++) {
			return false;
		}
		for (;;) {
			if (*cptr1 == *cptr2++) {
				if (*cptr1++ == '!') {
					s32 offset;

					for (offset = 0; *cptr1 != '!';) {
						offset = offset * 10 + *cptr1++ - '0';
					}
					*offset_result = offset;
					return true;
				}
			} else {
				while (*cptr1++ != '!') {}
				while (*cptr1++ != '!') {}
				if (*cptr1 == 0) {
					return false;
				}

				cptr2 = catchtype + 1;
			}
		}
		return false;
	}

	while ((*cptr1 == 'P' || *cptr1 == 'R') && *cptr1 == *cptr2) {
		cptr1++;
		cptr2++;

		if (*cptr2 == 'C') {
			if (*cptr1 == 'C') {
				cptr1++;
			}
			cptr2++;
		}
		if (*cptr1 == 'C') {
			return false;
		}

		if (*cptr2 == 'V') {
			if (*cptr1 == 'V') {
				cptr1++;
			}
			cptr2++;
		}
		if (*cptr1 == 'V') {
			return false;
		}
	}

	for (; *cptr1 == *cptr2; cptr1++, cptr2++) {
		if (*cptr1 == 0) {
			return true;
		}
	}

	return false;
}

class __partial_array_destructor {
private:
	void* p;
	volatile size_t size;
	size_t n;
	ConstructorDestructor dtor;

public:
	size_t i;

	__partial_array_destructor(void* array, size_t elementsize, size_t nelements, ConstructorDestructor destructor)
	{
		p    = array;
		size = elementsize;
		n    = nelements;
		dtor = destructor;
		i    = n;
	}

	~__partial_array_destructor()
	{
		char* ptr;

		if (i < n && dtor) {
			for (ptr = (char*)p + size * i; i > 0; i--) {
				ptr -= size;
				DTORCALL_COMPLETE(dtor, ptr);
			}
		}
	}
};

extern "C" void* __construct_new_array(void* block, ConstructorDestructor ctor, ConstructorDestructor dtor, size_t size, size_t n)
{
	char* ptr;

	if ((ptr = (char*)block) != 0L) {
		size_t* p = (size_t*)ptr;

		p[0] = size;
		p[1] = n;
		ptr += ARRAY_HEADER_SIZE;

		if (ctor) {
			__partial_array_destructor pad(ptr, size, n, dtor);
			char* p;

			for (pad.i = 0, p = (char*)ptr; pad.i < n; pad.i++, p += size) {
				CTORCALL_COMPLETE(ctor, p);
			}
		}
	}

	return ptr;
}

extern "C" void __construct_array(void* ptr, ConstructorDestructor ctor, ConstructorDestructor dtor, size_t size, size_t n)
{
	__partial_array_destructor pad(ptr, size, n, dtor);
	char* p;

	for (pad.i = 0, p = (char*)ptr; pad.i < n; pad.i++, p += size) {
		CTORCALL_COMPLETE(ctor, p);
	}
}

/**
 * @note Address: TODO
 * @note Size: TODO
 */
extern "C" void __destroy_arr(void* block, ConstructorDestructor dtor, size_t size, size_t n) {
	char* current = (char*)block + size * n;
	
	for (; n != 0; n--) {
		current -= size;
		DTORCALL_COMPLETE(dtor, current);
	}
}

/**
 * @note Address: TODO
 * @note Size: TODO
 */
extern "C" void __destroy_new_array(void* block, ConstructorDestructor dtor) {
	size_t i;
	size_t elementCount;
	size_t elementSize;
	char* current;

	if (block != nullptr) {
		if (dtor != nullptr) {
			elementSize = *(size_t*)((char*)block - 0x10);
			i = 0;
			elementCount = *(size_t*)((char*)block - 0xc);
			current = (char*)block + elementSize * elementCount;
			while (i < elementCount) {
				current -= elementSize;
				DTORCALL_COMPLETE(dtor, current);
				i++;
			}
		}
		__dla__FPv((char*)block - 0x10);
	}
}
