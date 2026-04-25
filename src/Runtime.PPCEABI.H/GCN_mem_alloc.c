#include "dolphin/os.h"

static int __initialized = 0;

void __sys_free(register void* p) {
    register void* arenaLo;
    register void* arenaHi;

    if (__initialized == 0) {
        arenaLo = OSGetArenaLo();
        arenaHi = OSGetArenaHi();

        arenaLo = OSInitAlloc(arenaLo, arenaHi, 1);
        OSSetArenaLo(arenaLo);

        arenaLo = (void*)(((u32)arenaLo + 0x1f) & ~0x1f);
        arenaHi = (void*)((u32)arenaHi & ~0x1f);

        OSSetCurrentHeap(OSCreateHeap(arenaLo, arenaHi));
        OSSetArenaLo(arenaLo = arenaHi);
        __initialized = 1;
    }

    OSFreeToHeap(0, p);
}
