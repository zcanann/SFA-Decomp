#include "dolphin.h"

extern u8 lbl_803326E8[];

int tolower(int x) {
    if (x == -1) {
        return -1;
    } else {
        return lbl_803326E8[(u8)x];
    }
}
