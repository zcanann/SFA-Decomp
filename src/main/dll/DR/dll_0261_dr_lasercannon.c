#include "main/dll/DR/dll_80211C24_shared.h"

int drlasercannon_getExtraSize(void) { return 0x1ac; }

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
    if (*(s16 *)((char *)self + 0x46) == 0x417) {
        pitch = -pitch;
    }
    if (maxRate < 0x168) {
        clamp = (s16)(lbl_803E68E0 * (f32)maxRate);
        *(s16 *)((char *)out + 0x14) = yaw;
        if (*(s16 *)((char *)out + 0x14) > clamp) {
            *(s16 *)((char *)out + 0x14) = clamp;
        }
        if (*(s16 *)((char *)out + 0x14) < -clamp) {
            *(s16 *)((char *)out + 0x14) = -clamp;
        }
        *(s16 *)((char *)out + 0x44) = pitch;
        if (*(s16 *)((char *)out + 0x44) > clamp) {
            *(s16 *)((char *)out + 0x44) = clamp;
        }
        if (*(s16 *)((char *)out + 0x44) < -clamp) {
            *(s16 *)((char *)out + 0x44) = -clamp;
        }
    } else {
        *(s16 *)((char *)out + 0x14) = yaw;
        *(s16 *)((char *)out + 0x44) = pitch;
    }
    delta = (s16)(*(s16 *)((char *)out + 0x14) - (u16)*(s16 *)self);
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
        delta = (s16)(*(s16 *)((char *)out + 0x44) - (u16)*vec);
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
    delta = *(s16 *)self - *(s16 *)((char *)out + 0x14);
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
    if (*(void **)(p + 0x194) != 0) {
        firepipe_clearLinkedUpdateFlag((int)*(void **)(p + 0x194));
        ObjLink_DetachChild(obj, (int)*(void **)(p + 0x194));
    }
    if (*(void **)(p + 0x190) != 0) {
        Obj_FreeObject((int)*(void **)(p + 0x190));
    }
    ObjGroup_RemoveObject(obj, 0x3);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void drlasercannon_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible) {
    char *p = *(char **)((char *)obj + 0xb8);
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E68E8);
        ObjPath_GetPointWorldPosition((int)obj, 0, (f32 *)(p + 0x10), (f32 *)(p + 0x14), (f32 *)(p + 0x18), 0);
        *(f32 *)(p + 0x14) = *(f32 *)(p + 0x14) - lbl_803E68EC;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
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
            *arg = 0x258;
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
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void drlasercannon_init(int obj, char *arg) {
    char *p = *(char **)((char *)obj + 0xb8);
    f32 fz;
    *(u8 *)(p + 0x1a6) = 4;
    ObjHits_EnableObject(obj);
    if (GameBit_Get(*(s16 *)(arg + 0x1e)) != 0) {
        *(s16 *)((char *)obj + 0x6) |= 0x4000;
        objRemoveFromListFn_8002ce88(obj);
        ObjHits_DisableObject(obj);
    }
    ObjGroup_AddObject(obj, 0x3);
    *(int *)p = 0;
    ((BitFlags8 *)(p + 0x1a8))->b3 = 0;
    *(s16 *)obj = (s16)((s8)arg[0x18] << 8);
    *(int *)(p + 0x128) = 0x258;
    *(f32 *)(p + 0x124) = lbl_803E6920;
    if (GameBit_Get(*(s16 *)(arg + 0x1e)) != 0) {
        ((BitFlags8 *)(p + 0x1a8))->b0 = 1;
        ((BitFlags8 *)(p + 0x1a8))->b4 = 1;
    } else {
        ((BitFlags8 *)(p + 0x1a8))->b4 = 0;
    }
    ((BitFlags8 *)(p + 0x1a8))->b5 = 0;
    fz = lbl_803E690C;
    *(f32 *)((char *)obj + 0x24) = fz;
    *(f32 *)((char *)obj + 0x28) = fz;
    *(f32 *)((char *)obj + 0x2c) = fz;
    if (GameBit_Get(*(s16 *)(arg + 0x1e)) == 0) {
        *(int *)(p + 0x190) = fn_801702D4(obj, lbl_803E6938);
        if (*(void **)(p + 0x190) != 0) {
            staffFn_80170380(*(int *)(p + 0x190), 4);
        }
        ((BitFlags8 *)(p + 0x1a8))->b6 = 1;
    } else {
        ((BitFlags8 *)(p + 0x1a8))->b6 = 0;
        *(int *)(p + 0x190) = 0;
    }
    storeZeroToFloatParam((void *)(p + 0x12c));
    s16toFloat((void *)(p + 0x12c), (s16)((s8)arg[0x19] * 4 + 1));
    *(u8 *)(p + 0x1a7) = 0;
    ((BitFlags8 *)(p + 0x1a8))->b7 = 1;
    *(int *)(p + 0x19c) = 0x429;
    if (*(s8 *)((char *)obj + 0xac) == 2) {
        *(s16 *)(p + 0x1a4) = 0xe90;
    } else {
        *(s16 *)(p + 0x1a4) = -1;
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
    if (((BitFlags8 *)(p + 0x1a8))->b0 || ((BitFlags8 *)(p + 0x1a8))->b3) {
        return;
    }
    hit = ObjHits_GetPriorityHitWithPosition(obj, &a8, 0, &ac, &a10, &a14, &a18);
    if (((BitFlags8 *)(p + 0x1a8))->b6 != 0) {
        if (hit != 0 && *(s16 *)((char *)a8 + 0x46) != *(int *)(p + 0x19c) &&
            *(void **)(p + 0x190) != 0) {
            staffFn_80170380(*(int *)(p + 0x190), 6);
        }
    } else if (((u32)(hit - 0xe) <= 1 || hit == 5) &&
               *(int **)(p + 0xc) != a8 &&
               *(s16 *)((char *)a8 + 0x46) != *(int *)(p + 0x19c)) {
        *(int **)(p + 0xc) = a8;
        p[0x1a6] = p[0x1a6] - ac;
        fn_80221E94(obj, &a10, lbl_803E68F0);
        fn_8009A8C8(obj, lbl_803E68F4);
        Sfx_PlayFromObject(obj, 0x3cc);
        if (p[0x1a6] <= 0) {
            tricky = getTrickyObject();
            Sfx_PlayFromObject(obj, 0x4b6);
            spawnExplosion(obj, lbl_803E68F8, 0, 1, 1, 1, 0, 1, 0);
            ((BitFlags8 *)(p + 0x1a8))->b0 = 1;
            GameBit_Set(*(s16 *)(q + 0x1e), 1);
            if (tricky != 0) {
                (*(void (**)(int *, int, int))((char *)*(void **)*(void **)((char *)tricky + 0x68) + 0x34))(tricky, 0, 0);
            }
            *(s16 *)((char *)obj + 0x6) |= 0x4000;
        }
    }
    if (hit == 0) {
        *(int *)(p + 0xc) = 0;
    } else {
        *(int **)(p + 0xc) = a8;
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
    *(f32 *)((char *)obj + 0x10) -= *(f32 *)((char *)state + 0x1a0);
    if (((BitFlags8 *)((char *)state + 0x1a8))->b7 != 0) {
        nearDist = lbl_803E68F8;
        *(int *)((char *)state + 0x194) = ObjGroup_FindNearestObject(0x4a, obj, &nearDist);
        if (*(int *)((char *)state + 0x194) != 0) {
            *(u8 *)((char *)state + 0x1a7) = 1;
            ObjLink_AttachChild(obj, *(int *)((char *)state + 0x194), 0);
            firepipe_setLinkedUpdateFlag(*(int *)((char *)state + 0x194));
        }
        ((BitFlags8 *)((char *)state + 0x1a8))->b7 = 0;
    }
    if (((BitFlags8 *)((char *)state + 0x1a8))->b4 == 0) {
        if (GameBit_Get(*(s16 *)((char *)sub + 0x1e)) != 0) {
            ((BitFlags8 *)((char *)state + 0x1a8))->b4 = 1;
            ((BitFlags8 *)((char *)state + 0x1a8))->b0 = 1;
            *(s16 *)((char *)obj + 0x6) |= 0x4000;
        }
    }
    if (((BitFlags8 *)((char *)state + 0x1a8))->b0 != 0) {
        return;
    }
    if (*(int *)((char *)state + 0x190) != 0) {
        *(f32 *)(*(int *)((char *)state + 0x190) + 0xc) = *(f32 *)((char *)obj + 0xc);
        *(f32 *)(*(int *)((char *)state + 0x190) + 0x10) = *(f32 *)((char *)obj + 0x10) - lbl_803E68FC;
        *(f32 *)(*(int *)((char *)state + 0x190) + 0x14) = *(f32 *)((char *)obj + 0x14);
    }
    if (((BitFlags8 *)((char *)state + 0x1a8))->b6 != 0) {
        if (GameBit_Get(*(s16 *)((char *)sub + 0x20)) != 0) {
            ((BitFlags8 *)((char *)state + 0x1a8))->b6 = 0;
            if (*(int *)((char *)state + 0x190) != 0) {
                staffFn_80170380(*(int *)((char *)state + 0x190), 5);
            }
        }
    } else {
        fn_80098270(obj, lbl_803E6900, 1, 5 - *(u8 *)((char *)state + 0x1a6), lbl_803E6904);
        if (*(int *)((char *)state + 0x190) != 0) {
            staffFn_80170380(*(int *)((char *)state + 0x190), 5);
        }
        *(int *)((char *)state + 0x198) += 1;
        if ((s8)*(u8 *)((char *)state + 0x1a6) == 0) {
            return;
        }
    }
    target = drlasercannon_getTrackedTarget(obj, (int *)((char *)state + 0x128));
    if (target != 0 && (*(s16 *)((char *)state + 0x1a4) == -1 || GameBit_Get(*(s16 *)((char *)state + 0x1a4)) == 0)) {
        hit = 1;
        dist = Vec_xzDistance((f32 *)((char *)target + 0x18), (f32 *)((char *)obj + 0x18));
        if (dist < (f32)*(s16 *)((char *)sub + 0x1a)) {
            hit = drlasercannon_aimAtTarget(obj, target, (int *)((char *)state + 0x130), 0x168, (f32 *)((char *)state + 0x10));
            if (hit != 0) {
                Sfx_PlayFromObject(obj, 0x1ad);
            }
        } else {
            s16 *v;
            *(s16 *)obj += lbl_803DC2AC;
            v = (s16 *)objModelGetVecFn_800395d8(obj, 0xb);
            v[0] = (s16)(v[0] >> 1);
        }
        if (hit != 0) {
            if (*(int *)((char *)state + 0x194) != 0) {
                firepipe_clearLinkedUpdateFlag(*(int *)((char *)state + 0x194));
            }
        } else if (dist < (f32)*(s16 *)((char *)sub + 0x1a)) {
            if (target == player) {
                fn_802966CC(player);
            }
            if (*(u8 *)((char *)state + 0x1a7) == 1) {
                *(int *)((char *)state + 0x19c) = 0x1b5;
                firepipe_setLinkedUpdateFlag(*(int *)((char *)state + 0x194));
            } else if (*(u8 *)((char *)state + 0x1a7) == 0) {
                *(int *)((char *)state + 0x19c) = 0x429;
                if (timerCountDown((char *)state + 0x12c) != 0) {
                    if (fn_80221C18(target, (f32)*(s16 *)((char *)sub + 0x1c) / lbl_803E6908,
                            (f32 *)((char *)state + 0x10), hitPos) != 0) {
                        spawned = *(int *)((char *)obj + 0xb8);
                        if (Obj_IsLoadingLocked() == 0) {
                            spawned = 0;
                        } else {
                            int o = Obj_AllocObjectSetup(0x20, 0x429);
                            *(s16 *)o = 0x429;
                            *(u8 *)(o + 0x2) = 8;
                            *(u8 *)(o + 0x4) = 1;
                            *(u8 *)(o + 0x6) = 0xff;
                            *(u8 *)(o + 0x5) = 1;
                            *(u8 *)(o + 0x7) = 0xff;
                            *(f32 *)(o + 0x8) = *(f32 *)((char *)state + 0x10);
                            *(f32 *)(o + 0xc) = *(f32 *)((char *)state + 0x14);
                            *(f32 *)(o + 0x10) = *(f32 *)((char *)state + 0x18);
                            spawned = Obj_SetupObject(o, 5, (s8)*(s8 *)((char *)obj + 0xac), -1, 0);
                        }
                        if (spawned != 0) {
                            outv[3] = *(f32 *)((char *)state + 0x10);
                            outv[4] = *(f32 *)((char *)state + 0x14);
                            outv[5] = *(f32 *)((char *)state + 0x18);
                            inv[3] = hitPos[0];
                            inv[4] = hitPos[1];
                            inv[5] = hitPos[2];
                            (*(void (**)(int, f32 *, f32 *, f32))(*(int *)(*(int *)((char *)spawned + 0x68)) + 0x24))(
                                spawned, outv, inv, (f32)*(s16 *)((char *)sub + 0x1c) / lbl_803E6908);
                            *(int *)state = spawned;
                            ObjAnim_SetCurrentMove(obj, 1, lbl_803E690C, 0);
                            *(f32 *)((char *)state + 0x124) = lbl_803E6910;
                            Sfx_PlayFromObject(obj, 0x1ab);
                            Sfx_PlayFromObject(obj, 0x1ac);
                        }
                    }
                    s16toFloat((char *)state + 0x12c, (s16)((s8)*(s8 *)((char *)sub + 0x19) << 2));
                }
            }
        }
    }
    spawned = *(int *)((char *)state + 0x194);
    if (spawned != 0) {
        if ((*(u16 *)((char *)spawned + 0xb0) & 0x40) != 0) {
            *(int *)((char *)state + 0x194) = 0;
        } else {
            s16 *v = (s16 *)objModelGetVecFn_800395d8(obj, 0xb);
            *(s16 *)spawned = (s16)(int)((f32)*(s16 *)obj + lbl_803DDD68);
            *(s16 *)((char *)spawned + 0x2) = v[0];
        }
    }
    if (((BitFlags8 *)((char *)state + 0x1a8))->b5 != 0) {
        fn_80222358(obj, (f32 *)((char *)state + 0x1c), lbl_803E6914 * lbl_803DC2A8, lbl_803E6918, lbl_803E6908, 1);
        objMove(obj, *(f32 *)((char *)obj + 0x24) * timeDelta, *(f32 *)((char *)obj + 0x28) * timeDelta,
            *(f32 *)((char *)obj + 0x2c) * timeDelta);
    } else {
        spawnFlag = 1;
        if ((u8)(*(int (**)(int, int, f32, int *, int))((char *)*gRomCurveInterface + 0x8c))(
                (int)((char *)state + 0x1c), obj, lbl_803E691C, &spawnFlag, 0) == 0) {
            ((BitFlags8 *)((char *)state + 0x1a8))->b5 = 1;
            *(f32 *)((char *)obj + 0xc) = *(f32 *)((char *)state + 0x84);
            *(f32 *)((char *)obj + 0x14) = *(f32 *)((char *)state + 0x8c);
            *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)state + 0x88);
        }
    }
    {
        int tricky = (int)getTrickyObject();
        if (tricky != 0) {
            (*(void (**)(int, int, int, int))(*(int *)(*(int *)((char *)tricky + 0x68)) + 0x28))(tricky, obj, 1, 2);
        }
    }
    hit = ObjAnim_AdvanceCurrentMove(*(f32 *)((char *)state + 0x124), timeDelta, obj, 0);
    if (*(s16 *)((char *)obj + 0xa0) == 1 && hit != 0) {
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E690C, 0);
        *(f32 *)((char *)state + 0x124) = lbl_803E6920;
    }
    *(u16 *)((char *)state + 0x1aa) =
        (u16)(int)(lbl_803E6924 * timeDelta + (f32)(u32)*(u16 *)((char *)state + 0x1aa));
    *(f32 *)((char *)state + 0x1a0) =
        lbl_803E68EC * fn_80293E80(lbl_803E6928 * (f32)(u32)*(u16 *)((char *)state + 0x1aa) / lbl_803E692C);
    *(f32 *)((char *)obj + 0x10) += *(f32 *)((char *)state + 0x1a0);
}
#pragma peephole reset
#pragma scheduling reset
