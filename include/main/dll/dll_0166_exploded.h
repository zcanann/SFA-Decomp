#ifndef MAIN_DLL_DLL_0166_EXPLODED_H_
#define MAIN_DLL_DLL_0166_EXPLODED_H_

#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/objanim_internal.h"
#include "main/objanim_update.h"

typedef struct ExplodedObjectMapData
{
    u8 pad00[0x08];
    f32 positionX;
    f32 positionY;
    f32 positionZ;
    u8 pad14[0x18 - 0x14];
    u8 objectTypeTag;
    u8 pad19;
    s16 initialAngleX;
    s16 initialAngleY;
    s16 initialAngleZ;
    s16 initialVelocityX;
    s16 initialVelocityY;
    s16 initialVelocityZ;
    s16 accelerationX;
    s16 accelerationY;
    s16 accelerationZ;
    s16 spinX;
    s16 spinY;
    s16 spinZ;
    s16 spinVelocityX;
    s16 spinVelocityY;
    s16 spinVelocityZ;
    s16 lifetimeFrames;
    s16 floorOffset;
    u8 pad3C;
    s8 scaleByte;
} ExplodedObjectMapData;

typedef struct ExplodedObjectState
{
    f32 localCenterX;
    f32 localCenterY;
    f32 localCenterZ;
    f32 initialLocalCenterX;
    f32 initialLocalCenterY;
    f32 initialLocalCenterZ;
    f32 spinX;
    f32 spinY;
    f32 spinZ;
    f32 spinVelocityX;
    f32 spinVelocityY;
    f32 spinVelocityZ;
    f32 accelerationX;
    f32 accelerationY;
    f32 accelerationZ;
    u8 pad3C[0x54 - 0x3C];
    f32 floorHeight;
    s32 elapsedFrames;
    s32 durationFrames;
    u8 pad60[0x66 - 0x60];
    u8 physicsFlags;
    u8 pad67[0x69 - 0x67];
    u8 explodePhase;
    u8 pad6A[0x6C - 0x6A];
} ExplodedObjectState;

typedef struct ExplodedObject
{
    union
    {
        ObjAnimComponent anim;
        struct
        {
            s16 angleX;
            s16 angleY;
            s16 angleZ;
            s16 flags06;
            f32 modelScale;
            f32 x;
            f32 y;
            f32 z;
            u8 pad18[0x24 - 0x18];
            f32 velocityX;
            f32 velocityY;
            f32 velocityZ;
            u8 pad30[0x36 - 0x30];
            u8 alpha;
            u8 pad37[0x4C - 0x37];
            ExplodedObjectMapData* mapData;
            void* modelData;
            u8 pad54[0xAD - 0x54];
            s8 objectTypeTag;
            u8 padAE[0xB8 - 0xAE];
        };
    };
    ExplodedObjectState* state;
} ExplodedObject;

STATIC_ASSERT(offsetof(ExplodedObject, anim) == 0x00);
STATIC_ASSERT(offsetof(ExplodedObject, angleX) == offsetof(ObjAnimComponent, rotX));
STATIC_ASSERT(offsetof(ExplodedObject, modelScale) == offsetof(ObjAnimComponent, rootMotionScale));
STATIC_ASSERT(offsetof(ExplodedObject, x) == offsetof(ObjAnimComponent, localPosX));
STATIC_ASSERT(offsetof(ExplodedObject, velocityX) == offsetof(ObjAnimComponent, velocityX));
STATIC_ASSERT(offsetof(ExplodedObject, alpha) == offsetof(ObjAnimComponent, alpha));
STATIC_ASSERT(offsetof(ExplodedObject, mapData) == offsetof(ObjAnimComponent, placementData));
STATIC_ASSERT(offsetof(ExplodedObject, modelData) == offsetof(ObjAnimComponent, modelInstance));
STATIC_ASSERT(offsetof(ExplodedObject, objectTypeTag) == offsetof(ObjAnimComponent, bankIndex));
STATIC_ASSERT(offsetof(ExplodedObject, state) == 0xB8);

void exploded_initDebrisState(ExplodedObject* obj, ExplodedObjectMapData* data, int computeModelCenter,
                              ExplodedObjectState* state);
void exploded_seedDebrisMotion(ExplodedObject* obj, ExplodedObjectState* state, ExplodedObjectMapData* data);
u8 exploded_setScale(int* obj);
int exploded_getExtraSize(void);
u32 exploded_getObjectTypeId(ExplodedObject* obj);
void exploded_free(void);
void exploded_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void exploded_hitDetect(void);
int exploded_stepDebrisPhysics(ExplodedObject* obj, ExplodedObjectState* state);
void exploded_update(int* obj);
void exploded_init(ExplodedObject* obj, ExplodedObjectMapData* data, int extra);
void exploded_release(void);
void exploded_initialise(void);

#endif /* MAIN_DLL_DLL_0166_EXPLODED_H_ */
