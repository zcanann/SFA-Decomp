#include "main/dll/DR/dr_shared.h"

#include "main/audio/sfx_ids.h"

#define DR_LASERCANNON_EXTRA_SIZE 0x1ac

#define DR_LASERCANNON_GROUP_ID 0x3
#define DR_LASERCANNON_FIREPIPE_GROUP_ID 0x4a

#define DR_LASERCANNON_PITCH_FLIP_TYPE 0x417
#define DR_LASERCANNON_BEAM_OBJECT_TYPE 0x429
#define DR_LASERCANNON_FIREPIPE_OBJECT_TYPE 0x1b5

#define DR_LASERCANNON_SETUP_SIZE 0x20
#define DR_LASERCANNON_INITIAL_HEALTH 4
#define DR_LASERCANNON_HIDDEN_FLAG 0x4000
#define DR_LASERCANNON_TRICKY_COOLDOWN 0x258
#define DR_LASERCANNON_OPTIONAL_GAMEBIT 0xe90

#define DR_LASERCANNON_SETUP_INITIAL_YAW 0x18
#define DR_LASERCANNON_SETUP_RELOAD_FRAMES 0x19
#define DR_LASERCANNON_SETUP_TARGET_RANGE 0x1a
#define DR_LASERCANNON_SETUP_BEAM_SPEED 0x1c
#define DR_LASERCANNON_SETUP_DESTROYED_GAMEBIT 0x1e
#define DR_LASERCANNON_SETUP_WARNING_OFF_GAMEBIT 0x20

#define DR_LASERCANNON_STATE_BEAM_OBJECT 0x00
#define DR_LASERCANNON_STATE_LAST_HIT_OBJECT 0x0c
#define DR_LASERCANNON_STATE_MUZZLE_X 0x10
#define DR_LASERCANNON_STATE_MUZZLE_Y 0x14
#define DR_LASERCANNON_STATE_MUZZLE_Z 0x18
#define DR_LASERCANNON_STATE_CURVE_FOLLOW 0x1c
#define DR_LASERCANNON_STATE_CURVE_END_X 0x84
#define DR_LASERCANNON_STATE_CURVE_END_Y 0x88
#define DR_LASERCANNON_STATE_CURVE_END_Z 0x8c
#define DR_LASERCANNON_STATE_ANIM_STEP_SCALE 0x124
#define DR_LASERCANNON_STATE_TRICKY_COOLDOWN 0x128
#define DR_LASERCANNON_STATE_RELOAD_TIMER 0x12c
#define DR_LASERCANNON_STATE_AIM 0x130
#define DR_LASERCANNON_STATE_WARNING_OBJECT 0x190
#define DR_LASERCANNON_STATE_FIREPIPE_OBJECT 0x194
#define DR_LASERCANNON_STATE_ACTIVE_FRAMES 0x198
#define DR_LASERCANNON_STATE_HIT_EXCLUDE_TYPE 0x19c
#define DR_LASERCANNON_STATE_BOB_OFFSET 0x1a0
#define DR_LASERCANNON_STATE_OPTIONAL_GAMEBIT 0x1a4
#define DR_LASERCANNON_STATE_HEALTH 0x1a6
#define DR_LASERCANNON_STATE_HAS_FIREPIPE 0x1a7
#define DR_LASERCANNON_STATE_FLAGS 0x1a8
#define DR_LASERCANNON_STATE_BOB_PHASE 0x1aa

#define DR_LASERCANNON_AIM_YAW 0x14
#define DR_LASERCANNON_AIM_PITCH 0x44

#define DR_LASERCANNON_WARNING_ACTIVE_MODE 4
#define DR_LASERCANNON_WARNING_HIDE_MODE 5
#define DR_LASERCANNON_WARNING_HIT_MODE 6

int drlasercannon_getExtraSize(void) { return DR_LASERCANNON_EXTRA_SIZE; }

int drlasercannon_getObjectTypeId(void) { return 0x0; }

void drlasercannon_initialise(void) {}

void drlasercannon_release(void) {}

#pragma scheduling off
int drlasercannon_aimAtTarget(int self, int target, int *out, int maxRate, f32 *eyePos) {
    s16 *vec;
    f32 d[3];
    f32 horiz;
    s16 yaw;
    s16 pitch;
    int clamp;
    int delta;

    vec = (s16 *)objModelGetVecFn_800395d8(self, 0xb);
    if (vec == NULL) {
        return 0;
    }
    if (target == 0) {
        *(s16 *)self = (s16)(*(s16 *)self >> 1);
        *vec = (s16)(*vec >> 1);
        return 0;
    }
    d[0] = *(f32 *)((char *)target + 0xc) - eyePos[0];
    d[1] = *(f32 *)((char *)target + 0x10) - eyePos[1];
    d[2] = *(f32 *)((char *)target + 0x14) - eyePos[2];
    horiz = sqrtf(d[0] * d[0] + d[2] * d[2]);
    yaw = getAngle(d[0], d[2]);
    pitch = getAngle(d[1], horiz);
    if (*(s16 *)((char *)self + 0x46) == DR_LASERCANNON_PITCH_FLIP_TYPE) {
        pitch = -pitch;
    }
    if (maxRate < 0x168) {
        clamp = (s16)(lbl_803E68E0 * (f32)maxRate);
        *(s16 *)((char *)out + DR_LASERCANNON_AIM_YAW) = yaw;
        if (*(s16 *)((char *)out + DR_LASERCANNON_AIM_YAW) > clamp) {
            *(s16 *)((char *)out + DR_LASERCANNON_AIM_YAW) = clamp;
        }
        if (*(s16 *)((char *)out + DR_LASERCANNON_AIM_YAW) < -clamp) {
            *(s16 *)((char *)out + DR_LASERCANNON_AIM_YAW) = -clamp;
        }
        *(s16 *)((char *)out + DR_LASERCANNON_AIM_PITCH) = pitch;
        if (*(s16 *)((char *)out + DR_LASERCANNON_AIM_PITCH) > clamp) {
            *(s16 *)((char *)out + DR_LASERCANNON_AIM_PITCH) = clamp;
        }
        if (*(s16 *)((char *)out + DR_LASERCANNON_AIM_PITCH) < -clamp) {
            *(s16 *)((char *)out + DR_LASERCANNON_AIM_PITCH) = -clamp;
        }
    } else {
        *(s16 *)((char *)out + DR_LASERCANNON_AIM_YAW) = yaw;
        *(s16 *)((char *)out + DR_LASERCANNON_AIM_PITCH) = pitch;
    }
    delta = (s16)(*(s16 *)((char *)out + DR_LASERCANNON_AIM_YAW) - (u16)*(s16 *)self);
    if (delta > 0x8000) {
        delta -= 0xFFFF;
    }
    if (delta < -0x8000) {
        delta += 0xFFFF;
    }
    if (delta < -lbl_803DC2AE) {
        delta = -lbl_803DC2AE;
    } else if (delta > lbl_803DC2AE) {
        delta = lbl_803DC2AE;
    }
    *(s16 *)self = (s16)((f32)*(s16 *)self + interpolate((f32)delta, lbl_803E68E4, timeDelta));
    if (vec != NULL) {
        delta = (s16)(*(s16 *)((char *)out + DR_LASERCANNON_AIM_PITCH) - (u16)*vec);
        if (delta > 0x8000) {
            delta -= 0xFFFF;
        }
        if (delta < -0x8000) {
            delta += 0xFFFF;
        }
        if (delta < -lbl_803DC2AE) {
            delta = -lbl_803DC2AE;
        } else if (delta > lbl_803DC2AE) {
            delta = lbl_803DC2AE;
        }
        *vec = (s16)((f32)*vec + interpolate((f32)delta, lbl_803E68E4, timeDelta));
    }
    delta = *(s16 *)self - *(s16 *)((char *)out + DR_LASERCANNON_AIM_YAW);
    if (delta < 0) {
        delta = -delta;
    }
    return delta > 0x100;
}
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void drlasercannon_free(int obj) {
    char *p = *(char **)((char *)obj + 0xb8);
    if (*(void **)(p + DR_LASERCANNON_STATE_FIREPIPE_OBJECT) != 0) {
        firepipe_clearLinkedUpdateFlag((int)*(void **)(p + DR_LASERCANNON_STATE_FIREPIPE_OBJECT));
        ObjLink_DetachChild(obj, (int)*(void **)(p + DR_LASERCANNON_STATE_FIREPIPE_OBJECT));
    }
    if (*(void **)(p + DR_LASERCANNON_STATE_WARNING_OBJECT) != 0) {
        Obj_FreeObject((int)*(void **)(p + DR_LASERCANNON_STATE_WARNING_OBJECT));
    }
    ObjGroup_RemoveObject(obj, DR_LASERCANNON_GROUP_ID);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void drlasercannon_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible) {
    char *p = *(char **)((char *)obj + 0xb8);
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E68E8);
        ObjPath_GetPointWorldPosition((int)obj, 0, (f32 *)(p + DR_LASERCANNON_STATE_MUZZLE_X),
            (f32 *)(p + DR_LASERCANNON_STATE_MUZZLE_Y), (f32 *)(p + DR_LASERCANNON_STATE_MUZZLE_Z), 0);
        *(f32 *)(p + DR_LASERCANNON_STATE_MUZZLE_Y) =
            *(f32 *)(p + DR_LASERCANNON_STATE_MUZZLE_Y) - lbl_803E68EC;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
int drlasercannon_getTrackedTarget(int obj, int *arg) {
    int *tricky = getTrickyObject();
    void *player;
    void *r;
    int t;
    if (tricky != 0 && arg != 0 &&
        (u8)(*(int (**)(int *))((char *)*(void **)*(void **)((char *)tricky + 0x68) + 0x40))(tricky)) {
        t = *arg - framesThisStep;
        *arg = t;
        if (t < 0) {
            (*(void (**)(int *, int, int))((char *)*(void **)*(void **)((char *)tricky + 0x68) + 0x34))(tricky, 0, 0);
            *arg = DR_LASERCANNON_TRICKY_COOLDOWN;
        }
        return (int)tricky;
    }
    player = Obj_GetPlayerObject();
    if (player != 0) {
        r = (void *)fn_802972A8();
        if (r != 0 && (*(u16 *)((char *)r + 0xb0) & 0x1000) == 0) {
            return (int)r;
        }
        if ((*(u16 *)((char *)player + 0xb0) & 0x1000) == 0) {
            return (int)player;
        }
    }
    return 0;
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void drlasercannon_init(int obj, char *arg) {
    char *p = *(char **)((char *)obj + 0xb8);
    f32 fz;
    *(u8 *)(p + DR_LASERCANNON_STATE_HEALTH) = DR_LASERCANNON_INITIAL_HEALTH;
    ObjHits_EnableObject(obj);
    if (GameBit_Get(*(s16 *)(arg + DR_LASERCANNON_SETUP_DESTROYED_GAMEBIT)) != 0) {
        *(s16 *)((char *)obj + 0x6) |= DR_LASERCANNON_HIDDEN_FLAG;
        objRemoveFromListFn_8002ce88(obj);
        ObjHits_DisableObject(obj);
    }
    ObjGroup_AddObject(obj, DR_LASERCANNON_GROUP_ID);
    *(int *)(p + DR_LASERCANNON_STATE_BEAM_OBJECT) = 0;
    ((BitFlags8 *)(p + DR_LASERCANNON_STATE_FLAGS))->b3 = 0;
    *(s16 *)obj = (s16)((s8)arg[DR_LASERCANNON_SETUP_INITIAL_YAW] << 8);
    *(int *)(p + DR_LASERCANNON_STATE_TRICKY_COOLDOWN) = DR_LASERCANNON_TRICKY_COOLDOWN;
    *(f32 *)(p + DR_LASERCANNON_STATE_ANIM_STEP_SCALE) = lbl_803E6920;
    if (GameBit_Get(*(s16 *)(arg + DR_LASERCANNON_SETUP_DESTROYED_GAMEBIT)) != 0) {
        ((BitFlags8 *)(p + DR_LASERCANNON_STATE_FLAGS))->b0 = 1;
        ((BitFlags8 *)(p + DR_LASERCANNON_STATE_FLAGS))->b4 = 1;
    } else {
        ((BitFlags8 *)(p + DR_LASERCANNON_STATE_FLAGS))->b4 = 0;
    }
    ((BitFlags8 *)(p + DR_LASERCANNON_STATE_FLAGS))->b5 = 0;
    fz = lbl_803E690C;
    *(f32 *)((char *)obj + 0x24) = fz;
    *(f32 *)((char *)obj + 0x28) = fz;
    *(f32 *)((char *)obj + 0x2c) = fz;
    if (GameBit_Get(*(s16 *)(arg + DR_LASERCANNON_SETUP_DESTROYED_GAMEBIT)) == 0) {
        *(int *)(p + DR_LASERCANNON_STATE_WARNING_OBJECT) = fn_801702D4(obj, lbl_803E6938);
        if (*(void **)(p + DR_LASERCANNON_STATE_WARNING_OBJECT) != 0) {
            staffFn_80170380(*(int *)(p + DR_LASERCANNON_STATE_WARNING_OBJECT),
                DR_LASERCANNON_WARNING_ACTIVE_MODE);
        }
        ((BitFlags8 *)(p + DR_LASERCANNON_STATE_FLAGS))->b6 = 1;
    } else {
        ((BitFlags8 *)(p + DR_LASERCANNON_STATE_FLAGS))->b6 = 0;
        *(int *)(p + DR_LASERCANNON_STATE_WARNING_OBJECT) = 0;
    }
    storeZeroToFloatParam((void *)(p + DR_LASERCANNON_STATE_RELOAD_TIMER));
    s16toFloat((void *)(p + DR_LASERCANNON_STATE_RELOAD_TIMER),
        (s16)((s8)arg[DR_LASERCANNON_SETUP_RELOAD_FRAMES] * 4 + 1));
    *(u8 *)(p + DR_LASERCANNON_STATE_HAS_FIREPIPE) = 0;
    ((BitFlags8 *)(p + DR_LASERCANNON_STATE_FLAGS))->b7 = 1;
    *(int *)(p + DR_LASERCANNON_STATE_HIT_EXCLUDE_TYPE) = DR_LASERCANNON_BEAM_OBJECT_TYPE;
    if (*(s8 *)((char *)obj + 0xac) == 2) {
        *(s16 *)(p + DR_LASERCANNON_STATE_OPTIONAL_GAMEBIT) = DR_LASERCANNON_OPTIONAL_GAMEBIT;
    } else {
        *(s16 *)(p + DR_LASERCANNON_STATE_OPTIONAL_GAMEBIT) = -1;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void drlasercannon_hitDetect(int obj) {
    char *p = *(char **)((char *)obj + 0xb8);
    int q = *(int *)((char *)obj + 0x4c);
    f32 a18;
    f32 a14;
    f32 a10;
    int ac;
    int *a8;
    int hit;
    int *tricky;
    if (((BitFlags8 *)(p + DR_LASERCANNON_STATE_FLAGS))->b0 ||
        ((BitFlags8 *)(p + DR_LASERCANNON_STATE_FLAGS))->b3) {
        return;
    }
    hit = ObjHits_GetPriorityHitWithPosition(obj, &a8, 0, &ac, &a10, &a14, &a18);
    if (((BitFlags8 *)(p + DR_LASERCANNON_STATE_FLAGS))->b6 != 0) {
        if (hit != 0 && *(s16 *)((char *)a8 + 0x46) != *(int *)(p + DR_LASERCANNON_STATE_HIT_EXCLUDE_TYPE) &&
            *(void **)(p + DR_LASERCANNON_STATE_WARNING_OBJECT) != 0) {
            staffFn_80170380(*(int *)(p + DR_LASERCANNON_STATE_WARNING_OBJECT),
                DR_LASERCANNON_WARNING_HIT_MODE);
        }
    } else if (((u32)(hit - 0xe) <= 1 || hit == 5) &&
               *(int **)(p + DR_LASERCANNON_STATE_LAST_HIT_OBJECT) != a8 &&
               *(s16 *)((char *)a8 + 0x46) != *(int *)(p + DR_LASERCANNON_STATE_HIT_EXCLUDE_TYPE)) {
        *(int **)(p + DR_LASERCANNON_STATE_LAST_HIT_OBJECT) = a8;
        p[DR_LASERCANNON_STATE_HEALTH] = p[DR_LASERCANNON_STATE_HEALTH] - ac;
        Obj_SpawnHitLightAndFade(obj, &a10, lbl_803E68F0);
        fn_8009A8C8(obj, lbl_803E68F4);
        Sfx_PlayFromObject(obj, 0x3cc);
        if (p[DR_LASERCANNON_STATE_HEALTH] <= 0) {
            tricky = getTrickyObject();
            Sfx_PlayFromObject(obj, 0x4b6);
            spawnExplosion(obj, lbl_803E68F8, 0, 1, 1, 1, 0, 1, 0);
            ((BitFlags8 *)(p + DR_LASERCANNON_STATE_FLAGS))->b0 = 1;
            GameBit_Set(*(s16 *)(q + DR_LASERCANNON_SETUP_DESTROYED_GAMEBIT), 1);
            if (tricky != 0) {
                (*(void (**)(int *, int, int))((char *)*(void **)*(void **)((char *)tricky + 0x68) + 0x34))(tricky, 0, 0);
            }
            *(s16 *)((char *)obj + 0x6) |= DR_LASERCANNON_HIDDEN_FLAG;
        }
    }
    if (hit == 0) {
        *(int *)(p + DR_LASERCANNON_STATE_LAST_HIT_OBJECT) = 0;
    } else {
        *(int **)(p + DR_LASERCANNON_STATE_LAST_HIT_OBJECT) = a8;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void drlasercannon_update(int obj) {
    int *state = *(int **)((char *)obj + 0xb8);
    int *sub = *(int **)((char *)obj + 0x4c);
    int player = (int)Obj_GetPlayerObject();
    int target;
    int hit;
    int spawned;
    f32 dist;
    f32 nearDist;
    int spawnFlag;
    f32 hitPos[3];
    f32 inv[6];
    f32 outv[6];
    *(f32 *)((char *)obj + 0x10) -= *(f32 *)((char *)state + DR_LASERCANNON_STATE_BOB_OFFSET);
    if (((BitFlags8 *)((char *)state + DR_LASERCANNON_STATE_FLAGS))->b7 != 0) {
        nearDist = lbl_803E68F8;
        *(int *)((char *)state + DR_LASERCANNON_STATE_FIREPIPE_OBJECT) =
            ObjGroup_FindNearestObject(DR_LASERCANNON_FIREPIPE_GROUP_ID, obj, &nearDist);
        if (*(int *)((char *)state + DR_LASERCANNON_STATE_FIREPIPE_OBJECT) != 0) {
            *(u8 *)((char *)state + DR_LASERCANNON_STATE_HAS_FIREPIPE) = 1;
            ObjLink_AttachChild(obj, *(int *)((char *)state + DR_LASERCANNON_STATE_FIREPIPE_OBJECT), 0);
            firepipe_setLinkedUpdateFlag(*(int *)((char *)state + DR_LASERCANNON_STATE_FIREPIPE_OBJECT));
        }
        ((BitFlags8 *)((char *)state + DR_LASERCANNON_STATE_FLAGS))->b7 = 0;
    }
    if (((BitFlags8 *)((char *)state + DR_LASERCANNON_STATE_FLAGS))->b4 == 0) {
        if (GameBit_Get(*(s16 *)((char *)sub + DR_LASERCANNON_SETUP_DESTROYED_GAMEBIT)) != 0) {
            ((BitFlags8 *)((char *)state + DR_LASERCANNON_STATE_FLAGS))->b4 = 1;
            ((BitFlags8 *)((char *)state + DR_LASERCANNON_STATE_FLAGS))->b0 = 1;
            *(s16 *)((char *)obj + 0x6) |= DR_LASERCANNON_HIDDEN_FLAG;
        }
    }
    if (((BitFlags8 *)((char *)state + DR_LASERCANNON_STATE_FLAGS))->b0 != 0) {
        return;
    }
    if (*(int *)((char *)state + DR_LASERCANNON_STATE_WARNING_OBJECT) != 0) {
        *(f32 *)(*(int *)((char *)state + DR_LASERCANNON_STATE_WARNING_OBJECT) + 0xc) =
            *(f32 *)((char *)obj + 0xc);
        *(f32 *)(*(int *)((char *)state + DR_LASERCANNON_STATE_WARNING_OBJECT) + 0x10) =
            *(f32 *)((char *)obj + 0x10) - lbl_803E68FC;
        *(f32 *)(*(int *)((char *)state + DR_LASERCANNON_STATE_WARNING_OBJECT) + 0x14) =
            *(f32 *)((char *)obj + 0x14);
    }
    if (((BitFlags8 *)((char *)state + DR_LASERCANNON_STATE_FLAGS))->b6 != 0) {
        if (GameBit_Get(*(s16 *)((char *)sub + DR_LASERCANNON_SETUP_WARNING_OFF_GAMEBIT)) != 0) {
            ((BitFlags8 *)((char *)state + DR_LASERCANNON_STATE_FLAGS))->b6 = 0;
            if (*(int *)((char *)state + DR_LASERCANNON_STATE_WARNING_OBJECT) != 0) {
                staffFn_80170380(*(int *)((char *)state + DR_LASERCANNON_STATE_WARNING_OBJECT),
                    DR_LASERCANNON_WARNING_HIDE_MODE);
            }
        }
    } else {
        objfx_spawnFrameTimedHitPulse(obj, lbl_803E6900, 1,
            5 - *(u8 *)((char *)state + DR_LASERCANNON_STATE_HEALTH), lbl_803E6904);
        if (*(int *)((char *)state + DR_LASERCANNON_STATE_WARNING_OBJECT) != 0) {
            staffFn_80170380(*(int *)((char *)state + DR_LASERCANNON_STATE_WARNING_OBJECT),
                DR_LASERCANNON_WARNING_HIDE_MODE);
        }
        *(int *)((char *)state + DR_LASERCANNON_STATE_ACTIVE_FRAMES) += 1;
        if ((s8)*(u8 *)((char *)state + DR_LASERCANNON_STATE_HEALTH) == 0) {
            return;
        }
    }
    target = drlasercannon_getTrackedTarget(obj, (int *)((char *)state + DR_LASERCANNON_STATE_TRICKY_COOLDOWN));
    if (target != 0 && (*(s16 *)((char *)state + DR_LASERCANNON_STATE_OPTIONAL_GAMEBIT) == -1 ||
                           GameBit_Get(*(s16 *)((char *)state + DR_LASERCANNON_STATE_OPTIONAL_GAMEBIT)) == 0)) {
        hit = 1;
        dist = Vec_xzDistance((f32 *)((char *)target + 0x18), (f32 *)((char *)obj + 0x18));
        if (dist < (f32)*(s16 *)((char *)sub + DR_LASERCANNON_SETUP_TARGET_RANGE)) {
            hit = drlasercannon_aimAtTarget(obj, target, (int *)((char *)state + DR_LASERCANNON_STATE_AIM),
                0x168, (f32 *)((char *)state + DR_LASERCANNON_STATE_MUZZLE_X));
            if (hit != 0) {
                Sfx_PlayFromObject(obj, SFXfoot_dirt_run_3);
            }
        } else {
            s16 *v;
            *(s16 *)obj += lbl_803DC2AC;
            v = (s16 *)objModelGetVecFn_800395d8(obj, 0xb);
            v[0] = (s16)(v[0] >> 1);
        }
        if (hit != 0) {
            if (*(int *)((char *)state + DR_LASERCANNON_STATE_FIREPIPE_OBJECT) != 0) {
                firepipe_clearLinkedUpdateFlag(*(int *)((char *)state + DR_LASERCANNON_STATE_FIREPIPE_OBJECT));
            }
        } else if (dist < (f32)*(s16 *)((char *)sub + DR_LASERCANNON_SETUP_TARGET_RANGE)) {
            if (target == player) {
                fn_802966CC(player);
            }
            if (*(u8 *)((char *)state + DR_LASERCANNON_STATE_HAS_FIREPIPE) == 1) {
                *(int *)((char *)state + DR_LASERCANNON_STATE_HIT_EXCLUDE_TYPE) =
                    DR_LASERCANNON_FIREPIPE_OBJECT_TYPE;
                firepipe_setLinkedUpdateFlag(*(int *)((char *)state + DR_LASERCANNON_STATE_FIREPIPE_OBJECT));
            } else if (*(u8 *)((char *)state + DR_LASERCANNON_STATE_HAS_FIREPIPE) == 0) {
                *(int *)((char *)state + DR_LASERCANNON_STATE_HIT_EXCLUDE_TYPE) =
                    DR_LASERCANNON_BEAM_OBJECT_TYPE;
                if (timerCountDown((char *)state + DR_LASERCANNON_STATE_RELOAD_TIMER) != 0) {
                    if (fn_80221C18(target,
                            (f32)*(s16 *)((char *)sub + DR_LASERCANNON_SETUP_BEAM_SPEED) / lbl_803E6908,
                            (f32 *)((char *)state + DR_LASERCANNON_STATE_MUZZLE_X), hitPos) != 0) {
                        spawned = *(int *)((char *)obj + 0xb8);
                        if (Obj_IsLoadingLocked() == 0) {
                            spawned = 0;
                        } else {
                            int o =
                                Obj_AllocObjectSetup(DR_LASERCANNON_SETUP_SIZE, DR_LASERCANNON_BEAM_OBJECT_TYPE);
                            *(s16 *)o = DR_LASERCANNON_BEAM_OBJECT_TYPE;
                            *(u8 *)(o + 0x2) = 8;
                            *(u8 *)(o + 0x4) = 1;
                            *(u8 *)(o + 0x6) = 0xff;
                            *(u8 *)(o + 0x5) = 1;
                            *(u8 *)(o + 0x7) = 0xff;
                            *(f32 *)(o + 0x8) = *(f32 *)((char *)state + DR_LASERCANNON_STATE_MUZZLE_X);
                            *(f32 *)(o + 0xc) = *(f32 *)((char *)state + DR_LASERCANNON_STATE_MUZZLE_Y);
                            *(f32 *)(o + 0x10) = *(f32 *)((char *)state + DR_LASERCANNON_STATE_MUZZLE_Z);
                            spawned = Obj_SetupObject(o, 5, (s8)*(s8 *)((char *)obj + 0xac), -1, 0);
                        }
                        if (spawned != 0) {
                            outv[3] = *(f32 *)((char *)state + DR_LASERCANNON_STATE_MUZZLE_X);
                            outv[4] = *(f32 *)((char *)state + DR_LASERCANNON_STATE_MUZZLE_Y);
                            outv[5] = *(f32 *)((char *)state + DR_LASERCANNON_STATE_MUZZLE_Z);
                            inv[3] = hitPos[0];
                            inv[4] = hitPos[1];
                            inv[5] = hitPos[2];
                            (*(void (**)(int, f32 *, f32 *, f32))(*(int *)(*(int *)((char *)spawned + 0x68)) + 0x24))(
                                spawned, outv, inv,
                                (f32)*(s16 *)((char *)sub + DR_LASERCANNON_SETUP_BEAM_SPEED) / lbl_803E6908);
                            *(int *)((char *)state + DR_LASERCANNON_STATE_BEAM_OBJECT) = spawned;
                            ObjAnim_SetCurrentMove(obj, 1, lbl_803E690C, 0);
                            *(f32 *)((char *)state + DR_LASERCANNON_STATE_ANIM_STEP_SCALE) = lbl_803E6910;
                            Sfx_PlayFromObject(obj, SFXfoot_dirt_run_1);
                            Sfx_PlayFromObject(obj, SFXfoot_dirt_run_2);
                        }
                    }
                    s16toFloat((char *)state + DR_LASERCANNON_STATE_RELOAD_TIMER,
                        (s16)((s8)*(s8 *)((char *)sub + DR_LASERCANNON_SETUP_RELOAD_FRAMES) << 2));
                }
            }
        }
    }
    spawned = *(int *)((char *)state + DR_LASERCANNON_STATE_FIREPIPE_OBJECT);
    if (spawned != 0) {
        if ((*(u16 *)((char *)spawned + 0xb0) & 0x40) != 0) {
            *(int *)((char *)state + DR_LASERCANNON_STATE_FIREPIPE_OBJECT) = 0;
        } else {
            s16 *v = (s16 *)objModelGetVecFn_800395d8(obj, 0xb);
            *(s16 *)spawned = (s16)(int)((f32)*(s16 *)obj + lbl_803DDD68);
            *(s16 *)((char *)spawned + 0x2) = v[0];
        }
    }
    if (((BitFlags8 *)((char *)state + DR_LASERCANNON_STATE_FLAGS))->b5 != 0) {
        Obj_UpdateRomCurveFollowVelocity(obj, (f32 *)((char *)state + DR_LASERCANNON_STATE_CURVE_FOLLOW),
            lbl_803E6914 * lbl_803DC2A8, lbl_803E6918, lbl_803E6908, 1);
        objMove(obj, *(f32 *)((char *)obj + 0x24) * timeDelta, *(f32 *)((char *)obj + 0x28) * timeDelta,
            *(f32 *)((char *)obj + 0x2c) * timeDelta);
    } else {
        spawnFlag = 1;
        if ((u8)(*(int (**)(int, int, f32, int *, int))((char *)*gRomCurveInterface + 0x8c))(
                (int)((char *)state + DR_LASERCANNON_STATE_CURVE_FOLLOW), obj, lbl_803E691C, &spawnFlag, 0) == 0) {
            ((BitFlags8 *)((char *)state + DR_LASERCANNON_STATE_FLAGS))->b5 = 1;
            *(f32 *)((char *)obj + 0xc) = *(f32 *)((char *)state + DR_LASERCANNON_STATE_CURVE_END_X);
            *(f32 *)((char *)obj + 0x14) = *(f32 *)((char *)state + DR_LASERCANNON_STATE_CURVE_END_Z);
            *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)state + DR_LASERCANNON_STATE_CURVE_END_Y);
        }
    }
    {
        int tricky = (int)getTrickyObject();
        if (tricky != 0) {
            (*(void (**)(int, int, int, int))(*(int *)(*(int *)((char *)tricky + 0x68)) + 0x28))(tricky, obj, 1, 2);
        }
    }
    hit = ObjAnim_AdvanceCurrentMove(*(f32 *)((char *)state + DR_LASERCANNON_STATE_ANIM_STEP_SCALE), timeDelta, obj, 0);
    if (*(s16 *)((char *)obj + 0xa0) == 1 && hit != 0) {
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E690C, 0);
        *(f32 *)((char *)state + DR_LASERCANNON_STATE_ANIM_STEP_SCALE) = lbl_803E6920;
    }
    *(u16 *)((char *)state + DR_LASERCANNON_STATE_BOB_PHASE) =
        (u16)(int)(lbl_803E6924 * timeDelta +
                   (f32)(u32)*(u16 *)((char *)state + DR_LASERCANNON_STATE_BOB_PHASE));
    *(f32 *)((char *)state + DR_LASERCANNON_STATE_BOB_OFFSET) =
        lbl_803E68EC *
        fn_80293E80(lbl_803E6928 * (f32)(u32)*(u16 *)((char *)state + DR_LASERCANNON_STATE_BOB_PHASE) /
                    lbl_803E692C);
    *(f32 *)((char *)obj + 0x10) += *(f32 *)((char *)state + DR_LASERCANNON_STATE_BOB_OFFSET);
}
#pragma peephole reset
#pragma scheduling reset
