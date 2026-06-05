#include "main/dll/DR/dr_shared.h"

#include "main/audio/sfx_ids.h"

#define DRAKORMISSILE_EXTRA_SIZE 0x38
#define DRAKORMISSILE_OBJECT_TYPE_ID 0x2
#define DRAKORMISSILE_GROUP_ID 0x2

#define DRAKORMISSILE_STATE_IDLE 0
#define DRAKORMISSILE_STATE_FADEOUT 1
#define DRAKORMISSILE_STATE_EXPLODING 2
#define DRAKORMISSILE_STATE_STRAIGHT 3
#define DRAKORMISSILE_STATE_HOMING 4

#define DRAKORMISSILE_FIELD_LIGHT 0x00
#define DRAKORMISSILE_FIELD_STATE 0x04
#define DRAKORMISSILE_FIELD_FLAGS 0x05
#define DRAKORMISSILE_FIELD_TIMER 0x08
#define DRAKORMISSILE_FIELD_FADE_TIME 0x0c
#define DRAKORMISSILE_FIELD_TRAIL_YAW 0x10
#define DRAKORMISSILE_FIELD_TRAIL_YAW_STEP 0x1a
#define DRAKORMISSILE_FIELD_TRAIL_PITCH 0x24
#define DRAKORMISSILE_FIELD_TRAIL_PITCH_STEP 0x2e

#define DRAKORMISSILE_SETUP_POS_X 0x08
#define DRAKORMISSILE_SETUP_POS_Y 0x0c
#define DRAKORMISSILE_SETUP_POS_Z 0x10
#define DRAKORMISSILE_SETUP_VEL_X 0x18
#define DRAKORMISSILE_SETUP_VEL_Y 0x19
#define DRAKORMISSILE_SETUP_VEL_Z 0x1a

#define DRAKORMISSILE_ACTIVE_TIMER 0x960
#define DRAKORMISSILE_CLEAR_TIMER 0x80
#define DRAKORMISSILE_TRACE_MISS_TIMER 0x258
#define DRAKORMISSILE_IGNORE_OBJECT_TYPE 0x2ab
#define DRAKORMISSILE_RENDER_TRAIL_COUNT 5
#define DRAKORMISSILE_TARGET_MASK 4
#define DRAKORMISSILE_HIT_VOLUME_SLOT 22
#define DRAKORMISSILE_ACTIVE_SFX_A 965
#define DRAKORMISSILE_ACTIVE_SFX_B 966

int drakormissile_getExtraSize(void) { return DRAKORMISSILE_EXTRA_SIZE; }

int drakormissile_getObjectTypeId(void) { return DRAKORMISSILE_OBJECT_TYPE_ID; }

void drakormissile_hitDetect(void) {}

void drakormissile_initialise(void) {}

void drakormissile_release(void) {}

#pragma scheduling off
#pragma peephole off
void drakormissile_startActiveLaunch(int obj) {
    void *light;
    u8 *p = *(u8 **)((char *)obj + 0xb8);

    ObjHits_EnableObject(obj);
    *(u8 *)(p + DRAKORMISSILE_FIELD_STATE) = DRAKORMISSILE_STATE_HOMING;
    *(s16 *)((char *)obj + 4) = 0;
    light = objCreateLight(obj, 1);
    if (light != NULL) {
        modelLightStruct_setLightKind(light, 2);
        modelLightStruct_setDiffuseColor(light, 255, 128, 0, 0);
        lightSetFieldBC_8001db14(light, 1);
        modelLightStruct_setDistanceAttenuation(light, lbl_803E6940, lbl_803E6944);
        modelLightStruct_setupGlow(light, 0, 0, 255, 255, 128, lbl_803E6948);
        modelLightStruct_setGlowProjectionRadius(light, lbl_803E694C);
    }
    *(void **)(p + DRAKORMISSILE_FIELD_LIGHT) = light;
    if (*(void **)(p + DRAKORMISSILE_FIELD_LIGHT) != NULL) {
        modelLightStruct_setDistanceAttenuation(*(void **)(p + DRAKORMISSILE_FIELD_LIGHT), lbl_803E6950,
            lbl_803E6954);
    }
    *(u8 *)((char *)obj + 0x36) = 255;
    *(f32 *)((char *)obj + 8) = lbl_803E6958 * *(f32 *)(*(int *)((char *)obj + 0x50) + 4);
    *(int *)(p + DRAKORMISSILE_FIELD_TIMER) = DRAKORMISSILE_ACTIVE_TIMER;
    ObjHits_SetTargetMask(obj, DRAKORMISSILE_TARGET_MASK);
    ObjHits_SetHitVolumeSlot(obj, DRAKORMISSILE_HIT_VOLUME_SLOT, 1, 0);
    Sfx_PlayFromObject(obj, DRAKORMISSILE_ACTIVE_SFX_A);
    Sfx_PlayFromObject(obj, DRAKORMISSILE_ACTIVE_SFX_B);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void drakormissile_func0B(int obj, int from, int target, f32 speed) {
    u8 *p = *(u8 **)((char *)obj + 0xb8);
    void *light;
    f32 dir[3];
    f32 hitDir[3];
    f32 endPos[3];
    int startGrid[2];
    int endGrid[2];
    int hitGrid[2];
    f32 mag;
    f32 horizDist;

    dir[0] = *(f32 *)((char *)target + 0xc) - *(f32 *)((char *)from + 0xc);
    dir[1] = *(f32 *)((char *)target + 0x10) - *(f32 *)((char *)from + 0x10);
    dir[2] = *(f32 *)((char *)target + 0x14) - *(f32 *)((char *)from + 0x14);
    mag = sqrtf(dir[0] * dir[0] + dir[1] * dir[1] + dir[2] * dir[2]) / speed;
    if (mag != lbl_803E695C) {
        dir[0] = dir[0] / mag;
        dir[1] = dir[1] / mag;
        dir[2] = dir[2] / mag;
    }
    *(f32 *)((char *)obj + 0xc) = *(f32 *)((char *)from + 0xc);
    *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)from + 0x10);
    *(f32 *)((char *)obj + 0x14) = *(f32 *)((char *)from + 0x14);
    *(f32 *)((char *)obj + 0x24) = dir[0];
    *(f32 *)((char *)obj + 0x28) = dir[1];
    *(f32 *)((char *)obj + 0x2c) = dir[2];
    horizDist = sqrtf(*(f32 *)((char *)obj + 0x24) * *(f32 *)((char *)obj + 0x24) +
                      *(f32 *)((char *)obj + 0x2c) * *(f32 *)((char *)obj + 0x2c));
    *(s16 *)obj = getAngle(*(f32 *)((char *)obj + 0x24), *(f32 *)((char *)obj + 0x2c));
    *(s16 *)((char *)obj + 2) = -getAngle(*(f32 *)((char *)obj + 0x28), horizDist);
    *(s16 *)((char *)obj + 4) = 0;
    ObjHits_EnableObject(obj);
    *(u8 *)(p + DRAKORMISSILE_FIELD_STATE) = DRAKORMISSILE_STATE_STRAIGHT;
    endPos[0] = lbl_803E6960 * *(f32 *)((char *)obj + 0x24);
    endPos[1] = lbl_803E6960 * *(f32 *)((char *)obj + 0x28);
    endPos[2] = lbl_803E6960 * *(f32 *)((char *)obj + 0x2c);
    endPos[0] = *(f32 *)((char *)obj + 0xc) + endPos[0];
    endPos[1] = *(f32 *)((char *)obj + 0x10) + endPos[1];
    endPos[2] = *(f32 *)((char *)obj + 0x14) + endPos[2];
    voxmaps_worldToGrid((f32 *)((char *)obj + 0xc), startGrid);
    voxmaps_worldToGrid(endPos, endGrid);
    if (voxmaps_traceLine(startGrid, endGrid, hitGrid, 0, 0) == 0) {
        voxmaps_gridToWorld(endPos, hitGrid);
        hitDir[0] = endPos[0] - *(f32 *)((char *)obj + 0xc);
        hitDir[1] = endPos[1] - *(f32 *)((char *)obj + 0x10);
        hitDir[2] = endPos[2] - *(f32 *)((char *)obj + 0x14);
        *(int *)(p + DRAKORMISSILE_FIELD_TIMER) =
            (int)(sqrtf(hitDir[0] * hitDir[0] + hitDir[1] * hitDir[1] + hitDir[2] * hitDir[2]) / speed);
    } else {
        *(int *)(p + DRAKORMISSILE_FIELD_TIMER) = DRAKORMISSILE_TRACE_MISS_TIMER;
    }
    if (*(void **)(p + DRAKORMISSILE_FIELD_LIGHT) != NULL) {
        ModelLightStruct_free(*(void **)(p + DRAKORMISSILE_FIELD_LIGHT));
        *(void **)(p + DRAKORMISSILE_FIELD_LIGHT) = NULL;
    }
    light = objCreateLight(obj, 1);
    if (light != NULL) {
        modelLightStruct_setLightKind(light, 2);
        modelLightStruct_setDiffuseColor(light, 0, 255, 255, 0);
        lightSetFieldBC_8001db14(light, 1);
        modelLightStruct_setDistanceAttenuation(light, lbl_803E6940, lbl_803E6944);
        modelLightStruct_setupGlow(light, 0, 0, 255, 255, 128, lbl_803E6948);
        modelLightStruct_setGlowProjectionRadius(light, lbl_803E694C);
    }
    *(void **)(p + DRAKORMISSILE_FIELD_LIGHT) = light;
    *(u8 *)((char *)obj + 0x36) = 255;
    *(f32 *)((char *)obj + 8) = lbl_803E6958 * *(f32 *)(*(int *)((char *)obj + 0x50) + 4);
    Sfx_PlayFromObject(obj, SFXwp_barrel_bounce2);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void drakormissile_update(int obj) {
    u8 *p = *(u8 **)((char *)obj + 0xb8);
    int moving;
    f32 toTarget[3];
    f32 dir[3];
    int *hitObj;
    int hit;
    int *near;
    int result;
    int player;
    f32 mag;
    int f5;
    int f3;
    int rem;

    moving = 0;
    switch (*(u8 *)(p + DRAKORMISSILE_FIELD_STATE)) {
    case DRAKORMISSILE_STATE_STRAIGHT:
        moving = 1;
        objMove(obj, *(f32 *)((char *)obj + 0x24) * timeDelta,
                *(f32 *)((char *)obj + 0x28) * timeDelta,
                *(f32 *)((char *)obj + 0x2c) * timeDelta);
        break;
    case DRAKORMISSILE_STATE_EXPLODING:
        *(u8 *)((char *)obj + 0x36) = 0;
        if (*(int *)(p + DRAKORMISSILE_FIELD_TIMER) == 0) {
            ObjHits_DisableObject(obj);
        }
        *(int *)(p + DRAKORMISSILE_FIELD_TIMER) += framesThisStep;
        if (*(int *)(p + DRAKORMISSILE_FIELD_TIMER) > DRAKORMISSILE_CLEAR_TIMER) {
            ObjHits_DisableObject(obj);
            Sfx_StopFromObject(obj, SFXwp_barrel_bounce2);
            Sfx_StopFromObject(obj, DRAKORMISSILE_ACTIVE_SFX_A);
            *(u8 *)(p + DRAKORMISSILE_FIELD_STATE) = DRAKORMISSILE_STATE_FADEOUT;
        }
        break;
    case DRAKORMISSILE_STATE_HOMING:
        player = (int)Obj_GetPlayerObject();
        mag = lbl_803E695C;
        if (*(f32 *)((char *)player + 0x24) != mag || *(f32 *)((char *)player + 0x28) != mag ||
            *(f32 *)((char *)player + 0x2c) != mag) {
            mag = PSVECMag((f32 *)((char *)player + 0x24));
        }
        mag = lbl_803DC2B8 + mag;
        fn_80221C18(player, mag, (f32 *)((char *)obj + 0xc), toTarget);
        PSVECSubtract(toTarget, (f32 *)((char *)obj + 0xc), dir);
        PSVECNormalize(dir, dir);
        PSVECScale(dir, dir, mag * lbl_803DC2B4);
        PSVECScale((f32 *)((char *)obj + 0x24), (f32 *)((char *)obj + 0x24), lbl_803DC2B0);
        PSVECAdd((f32 *)((char *)obj + 0x24), dir, (f32 *)((char *)obj + 0x24));
        mag = sqrtf(*(f32 *)((char *)obj + 0x24) * *(f32 *)((char *)obj + 0x24) +
                    *(f32 *)((char *)obj + 0x2c) * *(f32 *)((char *)obj + 0x2c));
        *(s16 *)obj = getAngle(*(f32 *)((char *)obj + 0x24), *(f32 *)((char *)obj + 0x2c));
        *(s16 *)((char *)obj + 2) = getAngle(*(f32 *)((char *)obj + 0x28), mag);
        objMove(obj, *(f32 *)((char *)obj + 0x24) * timeDelta,
                *(f32 *)((char *)obj + 0x28) * timeDelta,
                *(f32 *)((char *)obj + 0x2c) * timeDelta);
        moving = 1;
        break;
    case DRAKORMISSILE_STATE_FADEOUT: {
        f32 life = *(f32 *)(p + DRAKORMISSILE_FIELD_FADE_TIME) + timeDelta;
        *(f32 *)(p + DRAKORMISSILE_FIELD_FADE_TIME) = life;
        if (life > lbl_803E6968) {
            Obj_FreeObject(obj);
            return;
        }
        break;
    }
    }
    if (moving) {
        near = *(int **)(*(int *)((char *)obj + 0x54) + 0x50);
        hitObj = NULL;
        hit = ObjHits_GetPriorityHit(obj, &hitObj, 0, 0);
        f5 = 0;
        rem = *(int *)(p + DRAKORMISSILE_FIELD_TIMER) - framesThisStep;
        *(int *)(p + DRAKORMISSILE_FIELD_TIMER) = rem;
        if (rem < 0 || hit != 0) {
            f5 = 1;
        }
        f3 = 0;
        if (near != NULL && *(s16 *)((char *)near + 0x46) != DRAKORMISSILE_IGNORE_OBJECT_TYPE) {
            f3 = 1;
        }
        result = f5 | f3;
        result |= *(s8 *)(*(int *)((char *)obj + 0x54) + 0xad);
        if (*(u8 *)(p + DRAKORMISSILE_FIELD_STATE) == DRAKORMISSILE_STATE_HOMING) {
            player = (int)Obj_GetPlayerObject();
            if (Vec_distance((f32 *)((char *)obj + 0x18), (f32 *)((char *)player + 0x18)) <
                lbl_803DC2BC) {
                result |= 1;
            }
        }
        if (hitObj != NULL && *(s16 *)((char *)hitObj + 0x46) == DRAKORMISSILE_IGNORE_OBJECT_TYPE) {
            result = 0;
        }
        if (result != 0) {
            *(u8 *)(p + DRAKORMISSILE_FIELD_STATE) = DRAKORMISSILE_STATE_EXPLODING;
            *(int *)(p + DRAKORMISSILE_FIELD_TIMER) = 0;
            if ((*(s16 *)(*(int *)((char *)obj + 0x54) + 0x60) & 8) != 0) {
                Sfx_PlayFromObject(obj, SFXwp_barrel_bounce1);
            }
            if (*(s8 *)((char *)obj + 0xac) == 2) {
                spawnExplosion(obj, lbl_803E6940, 3, 0, 0, 0, 0, 0, 3);
            } else {
                spawnExplosion(obj, lbl_803E6940, 1, 0, 0, 0, 0, 0, 3);
            }
            if (*(void **)(p + DRAKORMISSILE_FIELD_LIGHT) != NULL) {
                ModelLightStruct_free(*(void **)(p + DRAKORMISSILE_FIELD_LIGHT));
                *(void **)(p + DRAKORMISSILE_FIELD_LIGHT) = NULL;
            }
        }
        *(int *)(*(int *)((char *)obj + 0x54) + 0x4c) = 0x10;
        *(int *)(*(int *)((char *)obj + 0x54) + 0x48) = 0x10;
    }
    if (*(void **)(p + DRAKORMISSILE_FIELD_LIGHT) != NULL && modelLightStruct_getActiveState()) {
        modelLightStruct_updateGlowAlpha(*(void **)(p + DRAKORMISSILE_FIELD_LIGHT));
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int drakormissile_setScale(int obj) {
    u8 *p = *(u8 **)((char *)obj + 0xb8);
    return p[DRAKORMISSILE_FIELD_STATE] == DRAKORMISSILE_STATE_FADEOUT;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void drakormissile_render2(int obj) {
    u8 *p = *(u8 **)((char *)obj + 0xb8);
    if (p[DRAKORMISSILE_FIELD_STATE] == DRAKORMISSILE_STATE_STRAIGHT) {
        p[DRAKORMISSILE_FIELD_STATE] = DRAKORMISSILE_STATE_EXPLODING;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void drakormissile_modelMtxFn(int obj) {
    u8 *p = *(u8 **)((char *)obj + 0xb8);
    p[DRAKORMISSILE_FIELD_FLAGS] |= 1;
    if (p[DRAKORMISSILE_FIELD_STATE] == DRAKORMISSILE_STATE_FADEOUT) {
        Obj_FreeObject(obj);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void drakormissile_free(int obj) {
    char *p = *(char **)((char *)obj + 0xb8);
    void *m = *(void **)(p + DRAKORMISSILE_FIELD_LIGHT);
    if (m != 0) {
        ModelLightStruct_free(m);
        *(void **)(p + DRAKORMISSILE_FIELD_LIGHT) = 0;
    }
    ObjGroup_RemoveObject(obj, DRAKORMISSILE_GROUP_ID);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void drakormissile_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible) {
    char *p = *(char **)((char *)obj + 0xb8);
    if (visible != 0 && *(u8 *)(p + DRAKORMISSILE_FIELD_STATE) != DRAKORMISSILE_STATE_FADEOUT) {
        s16 sv4 = *(s16 *)((char *)obj + 0x4);
        s16 sv2 = *(s16 *)((char *)obj + 0x2);
        f32 sv8 = *(f32 *)((char *)obj + 0x8);
        int *model;
        char *m;
        int i;
        *(u8 *)((char *)obj + 0xad) = 1;
        model = Obj_GetActiveModel();
        m = p;
        for (i = 0; i < DRAKORMISSILE_RENDER_TRAIL_COUNT; i++) {
            *(u16 *)(m + DRAKORMISSILE_FIELD_TRAIL_YAW) =
                *(u16 *)(m + DRAKORMISSILE_FIELD_TRAIL_YAW) + *(u16 *)(m + DRAKORMISSILE_FIELD_TRAIL_YAW_STEP);
            *(u16 *)(m + DRAKORMISSILE_FIELD_TRAIL_PITCH) =
                *(u16 *)(m + DRAKORMISSILE_FIELD_TRAIL_PITCH) + *(u16 *)(m + DRAKORMISSILE_FIELD_TRAIL_PITCH_STEP);
            *(s16 *)((char *)obj + 0x4) = *(u16 *)(m + DRAKORMISSILE_FIELD_TRAIL_YAW);
            *(s16 *)((char *)obj + 0x2) = *(u16 *)(m + DRAKORMISSILE_FIELD_TRAIL_PITCH);
            *(u16 *)((char *)model + 0x18) &= ~8;
            objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E6964);
            m += 2;
        }
        *(s16 *)((char *)obj + 0x4) = sv4;
        *(s16 *)((char *)obj + 0x2) = sv2;
        *(f32 *)((char *)obj + 0x8) = sv8;
        *(u8 *)((char *)obj + 0xad) = 0;
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E6964);
        if (*(void **)(p + DRAKORMISSILE_FIELD_LIGHT) != 0 && modelLightStruct_getActiveState() != 0) {
            queueGlowRender(*(void **)(p + DRAKORMISSILE_FIELD_LIGHT));
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void drakormissile_init(int obj, char *arg) {
    char *p = *(char **)((char *)obj + 0xb8);
    int s;
    int i;
    *(u8 *)(*(int *)((char *)obj + 0x54) + 0x6e) = 0x13;
    *(u8 *)(*(int *)((char *)obj + 0x54) + 0x6f) = 1;
    s = *(int *)((char *)obj + 0x54);
    *(s16 *)(s + 0x60) = *(s16 *)(s + 0x60) & ~1;
    *(f32 *)((char *)obj + 0xc) = *(f32 *)(arg + DRAKORMISSILE_SETUP_POS_X);
    *(f32 *)((char *)obj + 0x10) = *(f32 *)(arg + DRAKORMISSILE_SETUP_POS_Y);
    *(f32 *)((char *)obj + 0x14) = *(f32 *)(arg + DRAKORMISSILE_SETUP_POS_Z);
    *(f32 *)((char *)obj + 0x24) = (f32)(u32)(u8)arg[DRAKORMISSILE_SETUP_VEL_X];
    *(f32 *)((char *)obj + 0x28) = (f32)(u32)(u8)arg[DRAKORMISSILE_SETUP_VEL_Y];
    *(f32 *)((char *)obj + 0x2c) = (f32)(u32)(u8)arg[DRAKORMISSILE_SETUP_VEL_Z];
    {
        int *r = *(int **)((char *)obj + 0x54);
        if (r != 0) {
            *(s16 *)((char *)r + 0xb2) = 1;
        }
    }
    ObjGroup_AddObject(obj, DRAKORMISSILE_GROUP_ID);
    *(u8 *)(p + DRAKORMISSILE_FIELD_STATE) = DRAKORMISSILE_STATE_IDLE;
    *(u8 *)(p + DRAKORMISSILE_FIELD_FLAGS) = 0;
    *(int *)(p + DRAKORMISSILE_FIELD_TIMER) = 0;
    *(int *)(p + DRAKORMISSILE_FIELD_LIGHT) = 0;
    *(f32 *)(p + DRAKORMISSILE_FIELD_FADE_TIME) = lbl_803E695C;
    for (i = 0; i < DRAKORMISSILE_RENDER_TRAIL_COUNT; i++) {
        *(u16 *)(p + DRAKORMISSILE_FIELD_TRAIL_YAW) = (u16)randomGetRange(-0x7fff, 0x7fff);
        *(u16 *)(p + DRAKORMISSILE_FIELD_TRAIL_YAW_STEP) = (u16)randomGetRange(-0x400, 0x400);
        *(u16 *)(p + DRAKORMISSILE_FIELD_TRAIL_PITCH) = (u16)randomGetRange(-0x7fff, 0x7fff);
        *(u16 *)(p + DRAKORMISSILE_FIELD_TRAIL_PITCH_STEP) = (u16)randomGetRange(-0x400, 0x400);
        p += 2;
    }
}
#pragma peephole reset
#pragma scheduling reset
