#ifndef MAIN_DLL_CAM_CAMCRAWL_STATE_H_
#define MAIN_DLL_CAM_CAMCRAWL_STATE_H_

#include "ghidra_import.h"
#include "global.h"

typedef struct CameraModeCrawlFlags {
    u8 useDefaultHandler : 1;
    u8 rest : 7;
} CameraModeCrawlFlags;

typedef struct CameraModeCrawlState {
    u8 unk0[8];
    CameraModeCrawlFlags flags;
    u8 unk9[0x0C - 0x09];
} CameraModeCrawlState;

STATIC_ASSERT(sizeof(CameraModeCrawlState) == 0x0C);
STATIC_ASSERT(offsetof(CameraModeCrawlState, flags) == 0x08);

#endif /* MAIN_DLL_CAM_CAMCRAWL_STATE_H_ */
