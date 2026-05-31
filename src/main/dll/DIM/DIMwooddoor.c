#include "ghidra_import.h"
#include "main/dll/DIM/DIMwooddoor.h"
#include "main/objanim.h"

#define SFXfoot_run_jingle4 509

typedef struct DIMWoodDoorConfig {
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

typedef struct DIMWoodDoorState {
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

typedef struct DIMWoodDoorShardState {
    int parent;
    u8 variant;
    u8 lifetime;
    u8 hitRadius;
} DIMWoodDoorShardState;

extern u8 Obj_IsLoadingLocked(void);
extern s16 *objModelGetVecFn_800395d8(int obj, int target);
extern u8 *Obj_AllocObjectSetup(int size, int type);
extern int Obj_SetupObject(u8 *setup, int group, int mapLayer, int param4, int param5);
extern int Obj_GetPlayerObject(void);
extern s16 getAngle(f32 dx, f32 dz);
extern f32 sqrtf(f32 value);
extern f32 sin(f32 value);
extern f32 fn_80293E80(f32 value);
extern u32 randomGetRange(int min, int max);
extern void Sfx_PlayFromObject(int obj, int sfxId);

extern s16 lbl_803DBF02;
extern s16 lbl_803DBF04;
extern f32 lbl_803DBEF0;
extern f32 lbl_803DBF14;
extern f32 lbl_803E48A4;
extern f32 lbl_803E48AC;
extern f32 lbl_803E48B0;
extern f32 lbl_803E48B4;
extern f32 lbl_803E48B8;
extern f64 lbl_803E48C0;
extern f32 lbl_803E48C8;
extern f32 lbl_803E48CC;
extern f32 lbl_803E48D0;
extern f32 lbl_803E48D4;
extern f32 lbl_803E48D8;

#pragma scheduling off
#pragma peephole off
void DIMwooddoor_spawnShard(int obj, u8 variant)
{
    DIMWoodDoorConfig *config;
    DIMWoodDoorState *state;
    DIMWoodDoorShardState *shardState;
    s16 *modelVec;
    u8 *setup;
    int shard;
    f32 launchSpeed;
    f32 launchScale;
    f32 angle;

    config = *(DIMWoodDoorConfig **)(obj + 0x4c);
    if (Obj_IsLoadingLocked() != 0) {
        state = *(DIMWoodDoorState **)(obj + 0xb8);
        if ((state->shouldSpawnShard != 0) && (state->launchDelay <= 0)) {
            modelVec = objModelGetVecFn_800395d8(obj, 0);
            setup = Obj_AllocObjectSetup(0x24, 0x1d6);
            setup[4] = config->setup04;
            setup[6] = config->setup06;
            setup[5] = config->setup05;
            setup[7] = config->setup07;
            *(f32 *)(setup + 8) = state->targetX;
            *(f32 *)(setup + 0xc) = state->targetY;
            *(f32 *)(setup + 0x10) = state->targetZ;

            shard = Obj_SetupObject(setup, 5, *(s8 *)(obj + 0xac), -1, 0);
            shardState = *(DIMWoodDoorShardState **)(shard + 0xb8);
            shardState->parent = obj;
            shardState->variant = variant;
            if (variant != 0) {
                if (*(s8 *)(obj + 0xac) == 0x1b) {
                    shardState->lifetime = 100;
                } else {
                    shardState->lifetime = 60;
                }
                shardState->hitRadius = 100;
            } else {
                shardState->lifetime = 20;
                shardState->hitRadius = 1;
            }

            launchSpeed = state->launchSpeed;
            launchScale = lbl_803E48AC * launchSpeed;
            *(s16 *)shard = *(s16 *)obj + modelVec[1];
            angle = (lbl_803E48B0 * (f32)(s32)*(s16 *)shard) / lbl_803E48B4;
            *(f32 *)(shard + 0x24) = launchScale * -fn_80293E80(angle);
            *(f32 *)(shard + 0x28) = launchSpeed;
            angle = (lbl_803E48B0 * (f32)(s32)*(s16 *)shard) / lbl_803E48B4;
            *(f32 *)(shard + 0x2c) = launchScale * -sin(angle);

            state->shouldSpawnShard = 0;
            state->cooldown = 50;
            if (state->setupId == 3) {
                state->launchDelay = 50;
            } else {
                state->launchDelay = (s16)(randomGetRange(config->delayMin, config->delayMax) << 2);
            }

            ObjAnim_SetCurrentMove(obj, 0, lbl_803E48B8, 0);
            Sfx_PlayFromObject(obj, SFXfoot_run_jingle4);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void DIMwooddoor_updateShardAim(int obj, f32 targetX, f32 targetY, f32 targetZ)
{
    DIMWoodDoorState *state;
    DIMWoodDoorConfig *config;
    s16 *modelVec;
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
    int turnStep;
    s16 pitch;
    s16 absPitch;
    int turnSign;
    int pitchSign;

    config = *(DIMWoodDoorConfig **)(obj + 0x4c);
    player = Obj_GetPlayerObject();
    state = *(DIMWoodDoorState **)(obj + 0xb8);
    if (state->cooldown <= 0) {
        modelVec = objModelGetVecFn_800395d8(obj, 0);
        facingAngle = modelVec[1] + ((s32)config->angleBias << 8);
        targetX -= *(f32 *)(obj + 0xc);
        targetZ -= *(f32 *)(obj + 0x14);
        angleDelta = (((u16)getAngle(targetX, targetZ) + 0x8000) - (u16)facingAngle);
        if (angleDelta > 0x8000) {
            angleDelta -= 0xffff;
        }
        if (angleDelta < -0x8000) {
            angleDelta += 0xffff;
        }
        if ((angleDelta < 0x1200) && (angleDelta > -0x1200)) {
            state->shouldSpawnShard = 1;
        }
        if (angleDelta > 0x800) {
            angleDelta = 0x800;
        }
        if (angleDelta < -0x800) {
            angleDelta = -0x800;
        }
        turnStep = angleDelta >> 3;
        if (turnStep != 0) {
            pitch = modelVec[1];
            if (pitch < 0) {
                absPitch = -pitch;
            } else {
                absPitch = pitch;
            }
            if ((s32)lbl_803DBF02 - (s32)lbl_803DBF04 < (s32)absPitch) {
                if (turnStep < 0) {
                    turnSign = -1;
                } else if (turnStep > 0) {
                    turnSign = 1;
                } else {
                    turnSign = 0;
                }
                if (pitch < 0) {
                    pitchSign = -1;
                } else if (pitch > 0) {
                    pitchSign = 1;
                } else {
                    pitchSign = 0;
                }
                if (pitchSign == turnSign) {
                    turnStep = (turnStep * ((s32)lbl_803DBF02 - (s32)absPitch)) / (s32)lbl_803DBF04;
                }
            }
            modelVec[1] = (s16)(modelVec[1] + turnStep);
        }

        dx = state->targetX - state->posX;
        dz = state->targetZ - state->posZ;
        distSq = dx * dx + dz * dz;
        dist = sqrtf(distSq);
        heightDelta = (lbl_803E48C8 + state->posY) - state->targetY;
        if (distSq <= lbl_803E48C8) {
            distSq = lbl_803E48C8;
        }
        radiusSq = (f32)((s32)(config->targetRadius * 2) * (s32)(config->targetRadius * 2));
        if ((distSq < radiusSq) || (heightDelta < lbl_803DBF14) ||
            ((*(u16 *)(player + 0xb0) & 0x1000) != 0)) {
            state->shouldSpawnShard = 0;
        }
        if (distSq <= radiusSq) {
            distSq = radiusSq;
        }

        accel = (lbl_803E48A4 * -lbl_803DBEF0) * distSq;
        accelDenom = lbl_803E48CC * heightDelta - lbl_803E48D0 * dist;
        if (accelDenom > lbl_803E48D4) {
            accelDenom = lbl_803E48D4;
        }
        accel = accel / accelDenom;
        if (accel <= lbl_803E48B8) {
            accel = lbl_803E48B8;
        }
        accel = sqrtf(accel);
        state->launchSpeed += (accel - state->launchSpeed) / lbl_803E48D8;
    }
}
#pragma peephole reset
#pragma scheduling reset
