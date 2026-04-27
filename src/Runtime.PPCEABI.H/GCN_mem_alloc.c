#include "dolphin/os.h"

extern int lbl_803DE3E8;  // was __initialized; lives in sbss outside this TU's range

const double lbl_802C2920[3] = {
    0.0,
    4294967296.0,
    2147483648.0,
};

void __sys_free(void* p) {
    if (!lbl_803DE3E8) {
        void* arenaLo = OSGetArenaLo();
        void* arenaHi = OSGetArenaHi();
        void* heapLo = OSInitAlloc(arenaLo, arenaHi, 1);
        void* heapHi = (void*)((u32)arenaHi & ~0x1F);

        OSSetArenaLo(heapLo);
        OSCreateHeap((void*)(((u32)heapLo + 0x1F) & ~0x1F), heapHi);
        OSSetCurrentHeap(0);
        OSSetArenaLo(heapHi);
        lbl_803DE3E8 = 1;
    }

    OSFreeToHeap(0, p);
}
