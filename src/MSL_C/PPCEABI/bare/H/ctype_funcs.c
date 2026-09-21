#include "dolphin.h"

extern u8 __lower_map[];

int tolower(int x) {
    if (x == -1) {
        return -1;
    }

    return __lower_map[(u8)x];
}
