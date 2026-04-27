#include "TRK_MINNOW_DOLPHIN/MetroTRK/Portable/MWCriticalSection_gc.h"
#include <dolphin/os.h>

void MWInitializeCriticalSection(u32* section) {
    (void)section;
}

void MWEnterCriticalSection(u32* section) {
    *section = OSDisableInterrupts();
}

void MWExitCriticalSection(u32* section) {
    OSRestoreInterrupts(*section);
}
