#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/abort_exit.h"
#include "stddef.h"

void _ExitProcess(void);
void __destroy_global_chain(void);

extern void (*_dtors[])(void);

int __aborting = 0;

static void (*__atexit_funcs[64])(void);
static int __atexit_curr_func = 0;

void (*__stdio_exit)(void) = 0;
void (*__console_exit)(void) = 0;

void exit(int status)
{
    void (**dtor)(void);

    (void)status;
    if (!__aborting) {
        __destroy_global_chain();

        dtor = _dtors;
        while (*dtor != NULL) {
            (*dtor)();
            dtor++;
        }

        if (__stdio_exit != NULL) {
            __stdio_exit();
            __stdio_exit = NULL;
        }
    }

    while (__atexit_curr_func > 0) {
        __atexit_funcs[--__atexit_curr_func]();
    }

    if (__console_exit != NULL) {
        __console_exit();
        __console_exit = NULL;
    }

    _ExitProcess();
}
