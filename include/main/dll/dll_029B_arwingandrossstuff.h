#ifndef MAIN_DLL_DLL_029B_ARWINGANDROSSSTUFF_H
#define MAIN_DLL_DLL_029B_ARWINGANDROSSSTUFF_H

#include "global.h"
#include "main/game_object.h"
#include "main/model_light.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

/* defNos handled by this DLL; names read from retail OBJECTS.bin at def+0x91,
   all gating to DLL 0x29B. LASER_BASIC and INVINCIBLE share the one truncated
   name "ARWArwingLa" and are told apart only by their roles in the code below. */
typedef enum ArwSeqId
{
    ARW_SEQID_LASER_BASIC = 0x604,      /* "ARWArwingLa" */
    ARW_SEQID_RAPIDFIRE_LASER = 0x655,  /* "rapidFireLa" */
    ARW_SEQID_INVINCIBLE = 0x6AE,       /* "ARWArwingLa" */
    ARW_SEQID_ANDROSS_RING = 0x7E4,     /* "AndrossRing" */
    ARW_SEQID_ANDROSS_ASTEROID = 0x80D  /* "ANDAsteroid"; seeded with random per-axis tumble */
} ArwSeqId;

typedef union ArwProjectileParam0
{
    f32 scalar;
    struct
    {
        u8 particleKind;
        u8 deflected;
        u8 pad[2];
    };
} ArwProjectileParam0;

typedef struct ArwProjectileState
{
    ArwProjectileParam0 param0;
    f32 lifetime;
    f32 deflectSpeedScale;
    u8 pad0C[4];
    f32 despawnTimer;
    ModelLight* light;
    u8 hitVolumeMode;
    u8 pad19;
    s16 rotZSpeed;
    s16 rotYSpeed;
    u8 pad1E[2];
} ArwProjectileState;

typedef struct ArwProjectileSetup
{
    ObjPlacement base;
    u8 rotZ;
    u8 rotY;
    u8 rotX;
} ArwProjectileSetup;

STATIC_ASSERT(sizeof(ArwProjectileState) == 0x20);
STATIC_ASSERT(offsetof(ArwProjectileState, lifetime) == 0x04);
STATIC_ASSERT(offsetof(ArwProjectileState, deflectSpeedScale) == 0x08);
STATIC_ASSERT(offsetof(ArwProjectileState, despawnTimer) == 0x10);
STATIC_ASSERT(offsetof(ArwProjectileState, light) == 0x14);
STATIC_ASSERT(offsetof(ArwProjectileState, hitVolumeMode) == 0x18);
STATIC_ASSERT(offsetof(ArwProjectileState, rotZSpeed) == 0x1A);
STATIC_ASSERT(offsetof(ArwProjectileState, rotYSpeed) == 0x1C);
STATIC_ASSERT(offsetof(ArwProjectileSetup, rotY) == 0x19);
STATIC_ASSERT(offsetof(ArwProjectileSetup, rotX) == 0x1A);

extern ObjectDescriptor gArwingAndrossStuffObjDescriptor;
extern f32 lbl_803DC3D0;
extern f32 lbl_803DC3D4;
extern f32 lbl_803DC3D8;
extern f32 lbl_803E7008;
extern f32 lbl_803E700C;
extern f32 lbl_803E7010;
extern f32 lbl_803E7014;
extern f32 lbl_803E7018;
extern f32 lbl_803E701C;
extern f32 lbl_803E7028;
extern f32 lbl_803E702C;
extern f32 gArwingAndrossPi;
extern f32 gArwingAndrossBinAngScale;
extern f32 lbl_803E7038;
extern f32 lbl_803E703C;

void arwprojectile_createLinkedEffect(GameObject* obj, u8 enable);
void arwprojectile_placeForward(GameObject* obj, f32 dist);
void arwprojectile_setLifetime(GameObject* obj, int lifetime);
int arwingandrossstuff_getExtraSize(void);
int arwingandrossstuff_getObjectTypeId(void);
void arwingandrossstuff_free(GameObject* obj);
void arwingandrossstuff_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void arwingandrossstuff_hitDetect(GameObject* obj);
void arwingandrossstuff_update(GameObject* obj);
void arwingandrossstuff_init(GameObject* obj, ArwProjectileSetup* setup);
void arwingandrossstuff_release(void);
void arwingandrossstuff_initialise(void);
void arwprojectile_launchForward(GameObject* obj, f32 lifetime);
void arwprojectile_setParamScalar(GameObject* obj, int scalar);

#endif /* MAIN_DLL_DLL_029B_ARWINGANDROSSSTUFF_H */
