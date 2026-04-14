#include <stddef.h>
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/signal.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/abort_exit.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/critical_regions.h"

__signal_func_ptr signal_funcs[6];

int raise(int sig) {
    __signal_func_ptr temp_r31;

    if (sig < 1 || sig > 6) {
        return -1;
    }

    __begin_critical_region(4);
    temp_r31 = signal_funcs[sig - 1];
    if ((unsigned long) temp_r31 != 1) {
        signal_funcs[sig - 1] = NULL;
    }
    __end_critical_region(4);

    if ((unsigned long) temp_r31 == 1 || (temp_r31 == NULL && sig == 1)) {
        return 0;
    }
    if (temp_r31 == NULL) {
        exit(0);
    }
    temp_r31(sig);
    return 0;
}
