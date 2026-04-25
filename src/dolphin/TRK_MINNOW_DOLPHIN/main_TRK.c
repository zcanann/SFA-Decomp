/* TODO: restore stripped imported address metadata if needed. */

/**
 * main_TRK.c
 * Description:
 */

#include "TRK_MINNOW_DOLPHIN/MetroTRK/Portable/main_TRK.h"

extern DSError TRK_mainError_803D8880;

DSError TRK_main(void) {
    TRK_mainError_803D8880 = TRKInitializeNub();

    if (TRK_mainError_803D8880 == DS_NoError) {
        TRKNubWelcome();
        TRKNubMainLoop();
    }

    TRK_mainError_803D8880 = TRKTerminateNub();
    return TRK_mainError_803D8880;
}
