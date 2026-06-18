#ifndef MAIN_DLL_FIREPIPE_H_
#define MAIN_DLL_FIREPIPE_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"
#include "main/objanim_internal.h"

typedef struct FirePipeExtra {
    int effectObjs[8];
    u8 effectCount;
    u8 pad21[0x24 - 0x21];
    f32 cycleTimer;
    f32 emitTimer;
    u32 glowLight;
    int activeSpawn;
    int effectType;
    f32 effectScale;
    s16 clearVolumeA;
    s16 clearVolumeB;
    u8 effectMode;
    u8 flags;
    u8 pad42[0x44 - 0x42];
} FirePipeExtra;

typedef struct FirePipeMapData {
    ObjPlacement base;
    s8 rotX;
    u8 rotY;
    s16 cycleTime;
    s16 scale;
    s16 gameBit;
    s16 startOffset;
    u8 flags;
} FirePipeMapData;

typedef struct FirePipeObject {
    union {
        ObjAnimComponent anim;
        struct {
            s16 rotX;
            s16 rotY;
            s16 resetTimer;
            u8 pad06[0x08 - 0x06];
            f32 scale;
            u8 pad0C[0x46 - 0x0C];
            s16 objectId;
            u8 pad48[0x4C - 0x48];
            void *objectDef;
            void *model;
            u8 pad54[0xAF - 0x54];
            u8 statusFlags;
        };
    };
    u8 padB0[0xB8 - sizeof(ObjAnimComponent)];
    FirePipeExtra *extra;
    undefined4 (*sequenceCallback)(struct FirePipeObject *obj);
    u8 padC0[0xC4 - 0xC0];
    undefined4 (*callback)(struct FirePipeObject *obj);
} FirePipeObject;

STATIC_ASSERT(offsetof(FirePipeMapData, rotX) == 0x18);
STATIC_ASSERT(offsetof(FirePipeMapData, rotY) == 0x19);
STATIC_ASSERT(offsetof(FirePipeMapData, cycleTime) == 0x1A);
STATIC_ASSERT(offsetof(FirePipeMapData, scale) == 0x1C);
STATIC_ASSERT(offsetof(FirePipeMapData, gameBit) == 0x1E);
STATIC_ASSERT(offsetof(FirePipeMapData, startOffset) == 0x20);
STATIC_ASSERT(offsetof(FirePipeMapData, flags) == 0x22);
STATIC_ASSERT(offsetof(FirePipeObject, anim) == 0x00);
STATIC_ASSERT(offsetof(FirePipeObject, rotX) == offsetof(ObjAnimComponent, rotX));
STATIC_ASSERT(offsetof(FirePipeObject, scale) == offsetof(ObjAnimComponent, rootMotionScale));
STATIC_ASSERT(offsetof(FirePipeObject, objectId) == offsetof(ObjAnimComponent, seqId));
STATIC_ASSERT(offsetof(FirePipeObject, objectDef) == offsetof(ObjAnimComponent, placementData));
STATIC_ASSERT(offsetof(FirePipeObject, model) == offsetof(ObjAnimComponent, modelInstance));
STATIC_ASSERT(offsetof(FirePipeObject, statusFlags) == offsetof(ObjAnimComponent, resetHitboxFlags));
STATIC_ASSERT(offsetof(FirePipeObject, extra) == 0xB8);
STATIC_ASSERT(offsetof(FirePipeObject, sequenceCallback) == 0xBC);
STATIC_ASSERT(offsetof(FirePipeObject, callback) == 0xC4);

int firepipe_spawnEffectObject(FirePipeExtra *extra, FirePipeObject *obj, void *spawnDef);
void firepipe_releaseEffectObject(FirePipeObject *obj);
int firepipe_clearLinkedUpdateFlag(FirePipeObject *obj);
int firepipe_setLinkedUpdateFlag(FirePipeObject *obj);
void firepipe_updateState(FirePipeObject *obj);
int firepipe_getExtraSize(void);
undefined4 firepipe_stateCallback(FirePipeObject *obj);
int firepipe_getObjectTypeId(void);
void firepipe_free(FirePipeObject *obj);
void firepipe_render(FirePipeObject *obj, int param_2, int param_3, int param_4, int param_5, char param_6);
void firepipe_update(FirePipeObject *obj);
void firepipe_init(FirePipeObject *obj, FirePipeMapData *mapData);

extern ObjectDescriptor gFirePipeObjDescriptor;

#endif /* MAIN_DLL_FIREPIPE_H_ */
