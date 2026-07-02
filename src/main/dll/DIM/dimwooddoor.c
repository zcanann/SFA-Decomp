/*
 * dimwooddoor - spinning wooden-door hazard found in DIM (Dinosaur
 * InfernoMountain).  Each door tracks the player and flings debris
 * shards (type 0x1d6) at them.  DIMwooddoor_spawnShard creates one
 * shard projectile per trigger; DIMwooddoor_updateShardAim computes
 * the launch angle and speed from the door's current aim state.
 */
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/sfa_shared_decls.h"

#define DIMWOODDOOR_OBJFLAG_PARENT_SLACK 0x1000

typedef struct DIMWoodDoorConfig
{
    u8 pad00[0x4];
    u8 setup04;
    u8 setup05;
    u8 setup06;
    u8 setup07;
    u8 pad08[0x20];
    s8 angleBias;
    u8 delayMin;
    u8 delayMax;
    u8 targetRadius;
} DIMWoodDoorConfig;

typedef struct DIMWoodDoorState
{
    u8 pad00[0x4];
    f32 posX;
    f32 posY;
    f32 posZ;
    u8 pad10[0x7c];
    f32 targetX;
    f32 targetY;
    f32 targetZ;
    f32 launchSpeed;
    u8 pad9c[0x8];
    s16 launchDelay;
    s16 cooldown;
    u8 padA8[0x4];
    u8 setupId;
    u8 shouldSpawnShard;
} DIMWoodDoorState;

typedef struct DIMWoodDoorShardState
{
    int parent;
    u8 variant;
    u8 lifetime;
    u8 hitRadius;
} DIMWoodDoorShardState;

extern u8 Obj_IsLoadingLocked(void);
extern s16* objModelGetVecFn_800395d8(int obj, int target);
extern void* Obj_AllocObjectSetup(int size, int b);
extern int Obj_SetupObject(u8* setup, int group, int mapLayer, int param4, int param5);
extern int Obj_GetPlayerObject(void);
extern int getAngle(float y, float x);
extern f32 sqrtf(f32 value);


extern int randomGetRange(int lo, int hi);
extern s16 lbl_803DBF02;
extern s16 lbl_803DBF04;
extern f32 lbl_803DBEF0;
extern f32 lbl_803DBF14;
extern f32 lbl_803E48A4;
extern f32 lbl_803E48AC;
extern f32 gDimWoodDoorPi;
extern f32 gDimWoodDoorAngleHalfCircle;
extern f32 lbl_803E48B8;
extern f32 lbl_803E48C8;
extern f32 lbl_803E48CC;
extern f32 lbl_803E48D0;
extern f32 lbl_803E48D4;
extern f32 lbl_803E48D8;

void DIMwooddoor_spawnShard(int obj, u8 variant)
{
    DIMWoodDoorConfig* config;
    DIMWoodDoorState* state;
    DIMWoodDoorShardState* shardState;
    s16* modelVec;
    u8* setup;
    int shard;
    f32 launchSpeed;
    f32 launchScale;
    f32 angle;

    config = *(DIMWoodDoorConfig**)&((GameObject*)obj)->anim.placementData;
    if (Obj_IsLoadingLocked() == 0 ||
        (state = ((GameObject*)obj)->extra)->shouldSpawnShard == 0 ||
        state->launchDelay > 0)
    {
        return;
    }

    modelVec = objModelGetVecFn_800395d8(obj, 0);
    setup = Obj_AllocObjectSetup(0x24, 0x1d6);
    setup[4] = config->setup04;
    setup[6] = config->setup06;
    setup[5] = config->setup05;
    setup[7] = config->setup07;
    ((ObjPlacement*)setup)->posX = state->targetX;
    ((ObjPlacement*)setup)->posY = state->targetY;
    ((ObjPlacement*)setup)->posZ = state->targetZ;

    shard = Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1, 0);
    shardState = *(DIMWoodDoorShardState**)&((GameObject*)shard)->extra;
    shardState->parent = obj;
    shardState->variant = variant;
    if (variant != 0)
    {
        if (((GameObject*)obj)->anim.mapEventSlot == 0x1b)
        {
            shardState->lifetime = 100;
        }
        else
        {
            shardState->lifetime = 60;
        }
        shardState->hitRadius = 100;
    }
    else
    {
        shardState->lifetime = 20;
        shardState->hitRadius = 1;
    }

    launchSpeed = state->launchSpeed;
    launchScale = lbl_803E48AC * launchSpeed;
    *(s16*)shard = ((GameObject*)obj)->anim.rotX + modelVec[1];
    angle = (gDimWoodDoorPi * (f32)(s32) * (s16*)shard) / gDimWoodDoorAngleHalfCircle;
    ((GameObject*)shard)->anim.velocityX = launchScale * -mathSinf(angle);
    ((GameObject*)shard)->anim.velocityY = launchSpeed;
    angle = (gDimWoodDoorPi * (f32)(s32) * (s16*)shard) / gDimWoodDoorAngleHalfCircle;
    ((GameObject*)shard)->anim.velocityZ = launchScale * -mathCosf(angle);

    state->shouldSpawnShard = 0;
    state->cooldown = 50;
    if (state->setupId == 3)
    {
        state->launchDelay = 50;
    }
    else
    {
        state->launchDelay = (s16)(randomGetRange(config->delayMin, config->delayMax) << 2);
    }

    ObjAnim_SetCurrentMove(obj, 0, lbl_803E48B8, 0);
    Sfx_PlayFromObject(obj, SFXfoot_run_jingle4);
}

void DIMwooddoor_updateShardAim(int obj, f32 targetX, f32 targetY, f32 targetZ)
{
    DIMWoodDoorState* state;
    DIMWoodDoorConfig* config;
    s16* modelVec;
    int player;
    f32 dx;
    f32 dz;
    f32 distSq;
    f32 dist;
    f32 heightDelta;
    f32 radiusSq;
    f32 accel;
    f32 accelDenom;
    register int facingAngle;
    int angleDelta;
    int pitchSign;
    int turnSign;
    s16 pitch;
    int turnStep;
    s16 absPitch;

    config = *(DIMWoodDoorConfig**)&((GameObject*)obj)->anim.placementData;
    player = Obj_GetPlayerObject();
    state = ((GameObject*)obj)->extra;
    if (state->cooldown <= 0)
    {
        modelVec = objModelGetVecFn_800395d8(obj, 0);
        facingAngle = modelVec[1] + ((s32)config->angleBias << 8);
        targetX -= ((GameObject*)obj)->anim.localPosX;
        targetZ -= ((GameObject*)obj)->anim.localPosZ;
        angleDelta = ((u16)getAngle(targetX, targetZ) + 0x8000);
        angleDelta = angleDelta - (u16)facingAngle;
        if (angleDelta > 0x8000)
        {
            angleDelta -= 0xffff;
        }
        if (angleDelta < -0x8000)
        {
            angleDelta += 0xffff;
        }
        if ((angleDelta < 0x1200) && (angleDelta > -0x1200))
        {
            state->shouldSpawnShard = 1;
        }
        if (angleDelta > 0x800)
        {
            angleDelta = 0x800;
        }
        if (angleDelta < -0x800)
        {
            angleDelta = -0x800;
        }
        turnStep = angleDelta >> 3;
        if (turnStep != 0)
        {
            pitch = modelVec[1];
            absPitch = (pitch < 0) ? -pitch : pitch;
            if ((s32)absPitch > (s32)lbl_803DBF02 - lbl_803DBF04)
            {
                turnSign = (turnStep < 0) ? -1 : ((turnStep > 0) ? 1 : 0);
                pitchSign = (modelVec[1] < 0) ? -1 : ((modelVec[1] > 0) ? 1 : 0);
                if (pitchSign == turnSign)
                {
                    turnStep *= lbl_803DBF02 - (s32)absPitch;
                    turnStep /= lbl_803DBF04;
                }
            }
            modelVec[1] = (s16)(*(s16*)((char*)modelVec + 2) + turnStep);
        }

        dx = state->targetX - state->posX;
        dz = state->targetZ - state->posZ;
        distSq = dx * dx + dz * dz;
        dist = sqrtf(distSq);
        heightDelta = (lbl_803E48C8 + state->posY) - state->targetY;
        distSq = (distSq < lbl_803E48C8) ? lbl_803E48C8 : distSq;
        if ((distSq < (f32)((s32)(config->targetRadius * 2) * (s32)(config->targetRadius * 2))) ||
            (heightDelta < lbl_803DBF14) ||
            ((((GameObject*)player)->objectFlags & DIMWOODDOOR_OBJFLAG_PARENT_SLACK) != 0))
        {
            state->shouldSpawnShard = 0;
        }
        distSq = (distSq > (f32)((s32)(config->targetRadius * 2) * (s32)(config->targetRadius * 2)))
                     ? distSq
                     : (f32)((s32)(config->targetRadius * 2) * (s32)(config->targetRadius * 2));

        accel = (lbl_803E48A4 * -lbl_803DBEF0) * distSq;
        accelDenom = lbl_803E48CC * heightDelta - lbl_803E48D0 * dist;
        accel = accel / ((accelDenom < lbl_803E48D4) ? accelDenom : lbl_803E48D4);
        accel = (accel > lbl_803E48B8) ? accel : lbl_803E48B8;
        accel = sqrtf(accel);
        state->launchSpeed += (accel - state->launchSpeed) / lbl_803E48D8;
    }
}
