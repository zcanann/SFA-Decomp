#include "PowerPC_EABI_Support/MetroTRK/trk.h"

extern u8 lbl_803DAAB0[8];

void SetUseSerialIO(u8 sio) {
    lbl_803DAAB0[0] = sio;
}

u8 GetUseSerialIO(void) {
    return lbl_803DAAB0[0];
}
