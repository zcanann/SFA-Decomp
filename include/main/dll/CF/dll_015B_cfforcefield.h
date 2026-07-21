#ifndef MAIN_DLL_CF_DLL_015B_CFFORCEFIELD_H_
#define MAIN_DLL_CF_DLL_015B_CFFORCEFIELD_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

typedef struct CfForceFieldFlags
{
    u8 disabled : 1;
    u8 rest : 7;
} CfForceFieldFlags;

typedef struct CfForceFieldState
{
    CfForceFieldFlags flags;
    u8 pad01[3];
    f32 collapseTimer;
} CfForceFieldState;

typedef struct CfForceFieldMapData
{
    ObjPlacement base;
    s8 rotXByte;
    s8 style;
    s16 unk1A;
    u8 pad1C[2];
    s16 activeEvent;
    s16 collapseEvent;
    u8 pad22[0x28 - 0x22];
} CfForceFieldMapData;

typedef struct CfForceFieldEmitter
{
    int effectId;
    int secondaryEffectId;
    int angleStep;
    int unk0C;
    int unk10;
    f32 waveScale;
} CfForceFieldEmitter;

STATIC_ASSERT(offsetof(CfForceFieldState, collapseTimer) == 0x04);
STATIC_ASSERT(sizeof(CfForceFieldState) == 0x08);
STATIC_ASSERT(offsetof(CfForceFieldMapData, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(CfForceFieldMapData, style) == 0x19);
STATIC_ASSERT(offsetof(CfForceFieldMapData, activeEvent) == 0x1E);
STATIC_ASSERT(offsetof(CfForceFieldMapData, collapseEvent) == 0x20);
STATIC_ASSERT(sizeof(CfForceFieldMapData) == 0x28);
STATIC_ASSERT(offsetof(CfForceFieldEmitter, angleStep) == 0x08);
STATIC_ASSERT(offsetof(CfForceFieldEmitter, waveScale) == 0x14);
STATIC_ASSERT(sizeof(CfForceFieldEmitter) == 0x18);

int cfforcefield_getExtraSize(void);
int cfforcefield_getObjectTypeId(void);
void cfforcefield_free(void);
void cfforcefield_render(void);
void cfforcefield_hitDetect(void);
void cfforcefield_update(GameObject* obj);
void cfforcefield_init(GameObject* obj, CfForceFieldMapData* data);
void cfforcefield_release(void);
void cfforcefield_initialise(void);

extern f32 gCfForceFieldRingRadiusScale;
extern int gCfForceFieldRingJitter;
extern int gCfForceFieldCollapseSpinStep;
extern CfForceFieldEmitter gCfForceFieldEmitters[3];
extern ObjectDescriptor gCFForceFieldObjDescriptor;

#endif /* MAIN_DLL_CF_DLL_015B_CFFORCEFIELD_H_ */
