#ifndef MAIN_DLL_CF_DLL_0131_CFDOORLIGHT_H_
#define MAIN_DLL_CF_DLL_0131_CFDOORLIGHT_H_

#include "global.h"
#include "main/obj_placement.h"

typedef struct CfDoorLightFlags
{
    u8 unk80 : 1;
    u8 done : 1;   /* 0x40: done event granted; frame parked at maxFrame */
    u8 active : 1; /* 0x20: texture animation running */
    u8 rest : 5;
} CfDoorLightFlags;

typedef struct CfDoorLightState
{
    s32 textureId; /* 0x00: texture searched for the frame word (always 0) */
    u8 frameStep;  /* 0x04: frame advance per tick, 1/256 frames */
    u8 pad05[0x8 - 0x5];
    s32 maxFrame;           /* 0x08: last frame, 1/256 frames */
    s32 resetFrame;         /* 0x0C: loop-back frame, 1/256 frames */
    s32 currentFrame;       /* 0x10 */
    CfDoorLightFlags flags; /* 0x14 */
    u8 pad15[0x18 - 0x15];
} CfDoorLightState;

typedef struct CfDoorLightMapData
{
    ObjPlacement base;
    s8 resetFrame;    /* 0x18: loop-back frame in whole frames */
    s8 rotXByte;      /* 0x19: rotX in 1/128 turns */
    s16 maxFrame;     /* 0x1A: last frame in whole frames */
    s16 frameStep;    /* 0x1C: frame advance per tick, 1/256 frames */
    s16 doneEvent;    /* 0x1E: game bit granted at animation end (-1 = loop) */
    s16 triggerEvent; /* 0x20: game bit arming the animation */
} CfDoorLightMapData;

STATIC_ASSERT(offsetof(CfDoorLightState, frameStep) == 0x04);
STATIC_ASSERT(offsetof(CfDoorLightState, maxFrame) == 0x08);
STATIC_ASSERT(offsetof(CfDoorLightState, currentFrame) == 0x10);
STATIC_ASSERT(offsetof(CfDoorLightState, flags) == 0x14);
STATIC_ASSERT(sizeof(CfDoorLightState) == 0x18);
STATIC_ASSERT(offsetof(CfDoorLightMapData, resetFrame) == 0x18);
STATIC_ASSERT(offsetof(CfDoorLightMapData, doneEvent) == 0x1E);
STATIC_ASSERT(offsetof(CfDoorLightMapData, triggerEvent) == 0x20);

#endif /* MAIN_DLL_CF_DLL_0131_CFDOORLIGHT_H_ */
