#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/abort_exit.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/critical_regions.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/signal.h"
#include "Runtime.PPCEABI.H/NMWException.h"
#include "stddef.h"

void _ExitProcess(void);
void __destroy_global_chain(void);

extern void (*_dtors[])(void);
extern void (*__atexit_funcs_803DAAB8[64])(void);
extern void (*__console_exit)(void);
extern void (*__stdio_exit)(void);

extern int __atexit_curr_func_803DE3F4;
extern int __aborting;

extern unsigned char lbl_803DE400;
extern unsigned int lbl_803DABB8[13];
extern void* memset(void*, int, unsigned int);
extern void __sys_free(void*);

#define __atexit_curr_func __atexit_curr_func_803DE3F4

void exit(int status) {
    (void)status;

    if (!__aborting) {
        int i;

        __destroy_global_chain();
        for (i = 0; _dtors[i] != 0; i++) {
            _dtors[i]();
        }

        if (__stdio_exit != 0) {
            __stdio_exit();
            __stdio_exit = 0;
        }
    }

    while (__atexit_curr_func > 0) {
        __atexit_curr_func--;
        __atexit_funcs_803DAAB8[__atexit_curr_func]();
    }

    if (__console_exit != 0) {
        __console_exit();
        __console_exit = 0;
    }

    _ExitProcess();
}

void SubBlock_merge_next(void* subBlock, void** start) {
    (void)subBlock;
    (void)start;
}

void Block_link(void* block, void* subBlock) {
    (void)block;
    (void)subBlock;
}

void deallocate_from_fixed_pools(void* poolObj, void* ptr, unsigned long size) {
    (void)poolObj;
    (void)size;
    __sys_free(ptr);
}

void fn_8028D574(void* p) {
    if (!lbl_803DE400) {
        memset(lbl_803DABB8, 0, sizeof(lbl_803DABB8));
        lbl_803DE400 = 1;
    }

    if (p != 0) {
        __sys_free(p);
    }
}
