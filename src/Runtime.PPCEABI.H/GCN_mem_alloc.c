#include "dolphin/os.h"

extern int lbl_803DE3E8;  // was __initialized; lives in sbss outside this TU's range

const double lbl_802C2920[3] = {
    0.0,
    4294967296.0,
    2147483648.0,
};

inline static void InitDefaultHeap(void) {
    void* arenaLo;
    void* arenaHi;

    arenaLo = OSGetArenaLo();
    arenaHi = OSGetArenaHi();
    arenaLo = OSInitAlloc(arenaLo, arenaHi, 1);
    OSSetArenaLo(arenaLo);
    arenaLo = (void*)(((u32)arenaLo + 0x1F) & ~0x1F);
    arenaHi = (void*)((u32)arenaHi & ~0x1F);
    OSSetCurrentHeap(OSCreateHeap(arenaLo, arenaHi));
    OSSetArenaLo(arenaHi);
    lbl_803DE3E8 = 1;
}

void __sys_free(void* p) {
    if (!lbl_803DE3E8) {
        InitDefaultHeap();
    }

    OSFreeToHeap(0, p);
}
