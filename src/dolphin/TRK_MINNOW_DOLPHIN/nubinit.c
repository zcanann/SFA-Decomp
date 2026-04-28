#include "TRK_MINNOW_DOLPHIN/MetroTRK/Portable/nubinit.h"
#include "TRK_MINNOW_DOLPHIN/MetroTRK/Portable/serpoll.h"

extern BOOL gTRKBigEndian;

inline BOOL TRK_InitializeEndian(void) {
    BOOL res = FALSE;
    u8 bendian[4];
    u32 load;

    gTRKBigEndian = TRUE;
    bendian[0] = 0x12;
    bendian[1] = 0x34;
    bendian[2] = 0x56;
    bendian[3] = 0x78;

    load = *(u32*)bendian;
    if (load == 0x12345678) {
        gTRKBigEndian = TRUE;
    } else if (load == 0x78563412) {
        gTRKBigEndian = FALSE;
    } else {
        res = TRUE;
    }
    return res;
}

DSError TRKInitializeNub(void) {
    int error;
    DSError uartError;

    error = TRK_InitializeEndian();

    if (error == DS_NoError)
        usr_put_initialize();
    if (error == DS_NoError)
        error = TRKInitializeEventQueue();
    if (error == DS_NoError)
        error = TRKInitializeMessageBuffers();
    if (error == DS_NoError)
        error = TRKInitializeDispatcher();
    if (error == DS_NoError) {
        uartError = TRKInitializeIntDrivenUART(0xE100, 1, 0, &gTRKInputPendingPtr);
        TRKTargetSetInputPendingPtr(gTRKInputPendingPtr);

        if (uartError != DS_NoError) {
            error = uartError;
        }
    }
    if (error == DS_NoError)
        error = TRKInitializeSerialHandler();
    if (error == DS_NoError)
        error = TRKInitializeTarget();

    return error;
}

DSError TRKTerminateNub(void) {
    TRKTerminateSerialHandler();
    return DS_NoError;
}

void TRKNubWelcome(void) {
    TRK_board_display("MetroTRK for GAMECUBE v0.9");
    return;
}
