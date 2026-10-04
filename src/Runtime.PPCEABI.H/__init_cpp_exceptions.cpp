/* TODO: restore stripped imported address metadata if needed. */

#include "PowerPC_EABI_Support/Runtime/NMWException.h"

#if __MWERKS__
#endif

static int fragmentID = -2;

static asm char* GetR2(void) {
#ifdef __MWERKS__
    nofralloc
    mr r3, r2
    blr
#endif
}

#ifdef __cplusplus
extern "C" {
#endif

void __fini_cpp_exceptions(void) {
    if (fragmentID != -2) {
        __unregister_fragment(fragmentID);
        fragmentID = -2;
    }
}

void __init_cpp_exceptions(void) {
    char* R2;

    if (fragmentID == -2) {
        R2         = GetR2();
        fragmentID = __register_fragment(_eti_init_info, R2);
    }
}

#ifdef __cplusplus
}
#endif

__declspec(section ".ctors") extern void* const __init_cpp_exceptions_reference = __init_cpp_exceptions;

__declspec(section ".dtors") extern void* const __destroy_global_chain_reference = __destroy_global_chain;

__declspec(section ".dtors") extern void* const __fini_cpp_exceptions_reference = __fini_cpp_exceptions;
