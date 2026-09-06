#ifndef DLLS_OBJECTS_458_DIMEXPLOSIO_H_
#define DLLS_OBJECTS_458_DIMEXPLOSIO_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"
#include "global.h"

#define DIM_EXPLOSION_OBJECT_ID               0x253
#define DIM_EXPLOSION_FLAME_CAPACITY          50
#define DIM_EXPLOSION_RAY_CAPACITY            2
#define DIM_EXPLOSION_GRAVITY_DEBRIS_CAPACITY 6

#define DIM_EXPLOSION_MODEL_KIND_MASK      0x03
#define DIM_EXPLOSION_CONFIG_HAS_GRAVITY   0x04
#define DIM_EXPLOSION_CONFIG_HAS_RAYS      0x08
#define DIM_EXPLOSION_CONFIG_SPAWNS_DEBRIS 0x10
#define DIM_EXPLOSION_CONFIG_HAS_LIGHT     0x20

typedef struct ModelLightStruct ModelLightStruct;

/*
 * Both active-target explosion spawners allocate a fixed 0x24-byte setup and
 * populate the class-specific sound, scale, and configuration fields below.
 */
typedef struct DimExplosionPlacement {
    ObjPlacement base;
    u8 unknown18;
    s8 sfxKind;
    s16 scaleParam;
    s16 configFlags;
    u8 unknown1E[6];
} DimExplosionPlacement;

typedef struct DimExplosionFlame {
    f32 posX;
    f32 posY;
    f32 posZ;
    f32 scale;
    s32 age;
    s32 lifetime;
    f32 baseScale;
    f32 speed;
    s32 spawnTimer;
    s32 spawnInterval;
    s16 spinAngle;
    s16 spinSpeed;
    u8 textureVariant;
    u8 generation;
    u8 alpha;
    u8 active;
} DimExplosionFlame;

typedef struct DimExplosionGravityDebris {
    f32 posX;
    f32 posY;
    f32 posZ;
    f32 velocityX;
    f32 velocityY;
    f32 velocityZ;
    s32 age;
    s32 lifetime;
    u8 active;
    u8 unknown21[3];
} DimExplosionGravityDebris;

/*
 * The descriptor allocates exactly 0xA60 bytes. Runtime bounds prove a
 * 50-element flame pool and a six-element gravity-debris pool.
 */
typedef struct DimExplosionRay {
    u16 yaw;
    u16 pitch;
} DimExplosionRay;

typedef struct DimExplosionState {
    DimExplosionFlame flames[DIM_EXPLOSION_FLAME_CAPACITY];
    f32 groundY;
    DimExplosionGravityDebris debris[DIM_EXPLOSION_GRAVITY_DEBRIS_CAPACITY];
    f32 gravity;
    ModelLightStruct* light;
    DimExplosionRay rays[DIM_EXPLOSION_RAY_CAPACITY];
    s32 frameCounter;
    s32 lifeFrames;
    f32 scale;
    u8 flameCount;
    u8 rayCount;
    u8 debrisCount;
    u8 halfLifeFired;
    u8 nearGround;
    u8 modelKind;
    u8 unknownA5E[2];
} DimExplosionState;

STATIC_ASSERT(offsetof(DimExplosionPlacement, base) == 0x00);
STATIC_ASSERT(offsetof(DimExplosionPlacement, unknown18) == 0x18);
STATIC_ASSERT(offsetof(DimExplosionPlacement, sfxKind) == 0x19);
STATIC_ASSERT(offsetof(DimExplosionPlacement, scaleParam) == 0x1A);
STATIC_ASSERT(offsetof(DimExplosionPlacement, configFlags) == 0x1C);
STATIC_ASSERT(offsetof(DimExplosionPlacement, unknown1E) == 0x1E);
STATIC_ASSERT(sizeof(DimExplosionPlacement) == 0x24);

STATIC_ASSERT(offsetof(DimExplosionFlame, posX) == 0x00);
STATIC_ASSERT(offsetof(DimExplosionFlame, posY) == 0x04);
STATIC_ASSERT(offsetof(DimExplosionFlame, posZ) == 0x08);
STATIC_ASSERT(offsetof(DimExplosionFlame, scale) == 0x0C);
STATIC_ASSERT(offsetof(DimExplosionFlame, age) == 0x10);
STATIC_ASSERT(offsetof(DimExplosionFlame, lifetime) == 0x14);
STATIC_ASSERT(offsetof(DimExplosionFlame, baseScale) == 0x18);
STATIC_ASSERT(offsetof(DimExplosionFlame, speed) == 0x1C);
STATIC_ASSERT(offsetof(DimExplosionFlame, spawnTimer) == 0x20);
STATIC_ASSERT(offsetof(DimExplosionFlame, spawnInterval) == 0x24);
STATIC_ASSERT(offsetof(DimExplosionFlame, spinAngle) == 0x28);
STATIC_ASSERT(offsetof(DimExplosionFlame, spinSpeed) == 0x2A);
STATIC_ASSERT(offsetof(DimExplosionFlame, textureVariant) == 0x2C);
STATIC_ASSERT(offsetof(DimExplosionFlame, generation) == 0x2D);
STATIC_ASSERT(offsetof(DimExplosionFlame, alpha) == 0x2E);
STATIC_ASSERT(offsetof(DimExplosionFlame, active) == 0x2F);
STATIC_ASSERT(sizeof(DimExplosionFlame) == 0x30);

STATIC_ASSERT(offsetof(DimExplosionGravityDebris, posX) == 0x00);
STATIC_ASSERT(offsetof(DimExplosionGravityDebris, posY) == 0x04);
STATIC_ASSERT(offsetof(DimExplosionGravityDebris, posZ) == 0x08);
STATIC_ASSERT(offsetof(DimExplosionGravityDebris, velocityX) == 0x0C);
STATIC_ASSERT(offsetof(DimExplosionGravityDebris, velocityY) == 0x10);
STATIC_ASSERT(offsetof(DimExplosionGravityDebris, velocityZ) == 0x14);
STATIC_ASSERT(offsetof(DimExplosionGravityDebris, age) == 0x18);
STATIC_ASSERT(offsetof(DimExplosionGravityDebris, lifetime) == 0x1C);
STATIC_ASSERT(offsetof(DimExplosionGravityDebris, active) == 0x20);
STATIC_ASSERT(offsetof(DimExplosionGravityDebris, unknown21) == 0x21);
STATIC_ASSERT(sizeof(DimExplosionGravityDebris) == 0x24);

STATIC_ASSERT(offsetof(DimExplosionState, flames) == 0x000);
STATIC_ASSERT(offsetof(DimExplosionState, groundY) == 0x960);
STATIC_ASSERT(offsetof(DimExplosionState, debris) == 0x964);
STATIC_ASSERT(offsetof(DimExplosionState, gravity) == 0xA3C);
STATIC_ASSERT(offsetof(DimExplosionState, light) == 0xA40);
STATIC_ASSERT(offsetof(DimExplosionState, rays) == 0xA44);
STATIC_ASSERT(offsetof(DimExplosionState, frameCounter) == 0xA4C);
STATIC_ASSERT(offsetof(DimExplosionState, lifeFrames) == 0xA50);
STATIC_ASSERT(offsetof(DimExplosionState, scale) == 0xA54);
STATIC_ASSERT(offsetof(DimExplosionState, flameCount) == 0xA58);
STATIC_ASSERT(offsetof(DimExplosionState, rayCount) == 0xA59);
STATIC_ASSERT(offsetof(DimExplosionState, debrisCount) == 0xA5A);
STATIC_ASSERT(offsetof(DimExplosionState, halfLifeFired) == 0xA5B);
STATIC_ASSERT(offsetof(DimExplosionState, nearGround) == 0xA5C);
STATIC_ASSERT(offsetof(DimExplosionState, modelKind) == 0xA5D);
STATIC_ASSERT(offsetof(DimExplosionState, unknownA5E) == 0xA5E);
STATIC_ASSERT(sizeof(DimExplosionState) == 0xA60);

typedef struct DimExplosionPartfxSource {
    s16 rotX;
    s16 rotY;
    s16 rotZ;
    s16 flags;
    f32 rootMotionScale;
    f32 localPosX;
    f32 localPosY;
    f32 localPosZ;
    f32 worldPosX;
    f32 worldPosY;
    f32 worldPosZ;
    f32 velocityX;
    f32 velocityY;
    f32 velocityZ;
    void* parent;
    u8 hostedMapSlot;
    s8 transformMatrixIndex;
    u8 alpha;
    u8 renderAlpha;
} DimExplosionPartfxSource;

typedef struct DimExplosionTextureTable {
    int assetIds[4];
} DimExplosionTextureTable;

STATIC_ASSERT(sizeof(DimExplosionPartfxSource) == 0x38);
STATIC_ASSERT(offsetof(DimExplosionPartfxSource, rootMotionScale) == 0x08);
STATIC_ASSERT(offsetof(DimExplosionPartfxSource, localPosX) == 0x0C);
STATIC_ASSERT(offsetof(DimExplosionPartfxSource, worldPosX) == 0x18);
STATIC_ASSERT(offsetof(DimExplosionPartfxSource, velocityX) == 0x24);
STATIC_ASSERT(sizeof(DimExplosionTextureTable) == 0x10);

void explosion_spawnFlame(GameObject* obj, f32 speed, u8 generation, f32 x, f32 y, f32 z);
void explosion_computeColor(f32 age, f32 lifetime, u8 colorMode, u8* outputColor);
int explosion_getExtraSize(void);
int explosion_getObjectTypeId(GameObject* obj);
void explosion_free(GameObject* obj);
void explosion_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible);
void explosion_hitDetect(void);
void explosion_update(GameObject* obj);
void explosion_init(GameObject* obj, DimExplosionPlacement* placementAddress);
void explosion_release(u32 unused);
void explosion_initialise(void);

extern ObjectDescriptor gExplosionObjDescriptor;

#endif /* DLLS_OBJECTS_458_DIMEXPLOSIO_H_ */
