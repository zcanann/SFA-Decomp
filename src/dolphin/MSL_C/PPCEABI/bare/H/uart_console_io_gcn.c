#include "dolphin.h"

extern int InitializeUART(u32);
extern int WriteUARTN(void* buf, u32 n);

extern s32 lbl_803DE418;

int __write_console(int handle, void* buf, u32* count, void* idle_fn) {
    int result = 0;
    u8 unused[8];

    (void)handle;
    (void)idle_fn;
    (void)unused;

    if (!lbl_803DE418) {
        result = InitializeUART(0xE100);
        if (result == 0) {
            lbl_803DE418 = 1;
        }
    }

    if (result != 0) {
        return 1;
    }

    if (WriteUARTN(buf, *count) != 0) {
        *count = 0;
        return 1;
    }

    return 0;
}
