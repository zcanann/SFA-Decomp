#ifndef MAIN_DLL_DLL_00DA_POLLENFRAGMENT_API_H_
#define MAIN_DLL_DLL_00DA_POLLENFRAGMENT_API_H_

#include "global.h"

typedef struct PollenFragmentConfig
{
    s16 spawnSfxId;
    s16 loopSfxId;
    s16 explodeSfxId;
    s16 effectObjectId;
    s16 burstFxId;
    s16 auraFxId;
    f32 scale;
    s16 targetGroup;
    u16 flags;
} PollenFragmentConfig;

extern PollenFragmentConfig lbl_80320538;
extern PollenFragmentConfig lbl_8032054C;
extern PollenFragmentConfig lbl_80320560;
extern PollenFragmentConfig lbl_80320574;
extern PollenFragmentConfig lbl_80320588;
extern PollenFragmentConfig* lbl_8032059C[];

#endif /* MAIN_DLL_DLL_00DA_POLLENFRAGMENT_API_H_ */
