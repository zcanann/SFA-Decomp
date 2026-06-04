#include "ghidra_import.h"
#include "main/dll/NW/NWsfx.h"
#include "main/dll/SH/SHthorntail_internal.h"

extern undefined8 ObjGroup_RemoveObject();
extern int hitDetectFn_80065e50(void *obj, f32 x, f32 y, f32 z, void *hitsOut, int p6, int p7);
extern int objBboxFn_800640cc(void *from, void *to, f32 radius, int mode, void *hit, void *obj,
                              int p7, int p8, int p9, int p10);

extern void *Obj_GetPlayerObject(void);
extern int getAngle(f32 dx, f32 dz);
extern f32 fn_80293E80(f32 x);
extern f32 sin(f32 x);
extern int Curve_AdvanceAlongPath(u8 *curve, f32 t);
extern void Sfx_PlayFromObject(u8 *obj, int sfxId);
extern void Sfx_KeepAliveLoopedObjectSound(u8 *obj, int sfxId);
extern void ObjHits_ClearSourceMask(u8 *obj, int mask);
extern void ObjHits_SetSourceMask(u8 *obj, int mask);
extern u32 randomGetRange(int min, int max);
extern u32 GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern f32 Vec_xzDistance(f32 *a, f32 *b);
extern void itemPickupDoParticleFx(u8 *obj, f32 scale, int mode, int count);
extern undefined4 ObjMsg_SendToObject(u8 *obj, int msg, u8 *sender, void *data);
extern void ObjAnim_SetCurrentMove(u8 *obj, int moveId, f32 blend, int flag);
extern int ObjAnim_AdvanceCurrentMove(u8 *obj, f32 moveStepScale, f32 deltaTime, void *events);
extern void objMove(u8 *obj, f32 vx, f32 vy, f32 vz);

extern int *gRomCurveInterface;
extern int *gPartfxInterface;
extern int *gExpgfxInterface;

extern f32 timeDelta;
extern f32 oneOverTimeDelta;

extern f32 lbl_803E5288;
extern f32 lbl_803E528C;
extern f32 lbl_803E5290;
extern f32 lbl_803E5294;
extern f32 lbl_803E5298;
extern f32 lbl_803E529C;
extern f32 lbl_803E52A0;
extern f32 lbl_803E52A4;
extern f32 lbl_803E52A8;
extern f32 lbl_803E52AC;
extern f32 lbl_803E52B0;
extern f32 lbl_803E52B4;
extern f32 lbl_803E52B8;
extern f32 lbl_803E52D0;
extern f32 lbl_803E52D4;
extern f32 lbl_803E52D8;
extern f32 lbl_803E52DC;

extern s16 lbl_80326BD0[];
extern f32 lbl_80326BE8[];

s16 fn_801D129C(u8 *obj, u8 *player, u8 *state, f32 dist);

/*
 * --INFO--
 *
 * Function: edibleMushroomFn_801d083c
 * EN v1.0 Address: 0x801D083C
 * EN v1.0 Size: 2656b
 */
#pragma push
#pragma scheduling off
#pragma peephole off
void edibleMushroomFn_801d083c(u8 *obj, u8 *state, u8 *other) {
    u8 sval;
    int curMove;
    int moveId;
    int bit;
    f32 dz;
    f32 dx;
    f32 speed;
    f32 rangeSq;
    f32 t;
    s16 ang;
    f32 animOut[7];
    struct {
        u8 pad[0xc];
        f32 x;
        f32 y;
        f32 z;
    } fx;
    int thorntailOut;
    u8 *player;

    player = Obj_GetPlayerObject();

    if (state[0x137] & 4) {
        state[0x136] = 6;
    }

    speed = oneOverTimeDelta * (*(f32 *)(state + 0x10c) - *(f32 *)(state + 0x108));

    sval = state[0x136];
    switch (sval) {
    case 0:
        if (state[0x137] & 0x10) {
            state[0x136] = 9;
        } else if ((*gSHthorntailAnimationInterface)->isTailSwingQueued(&thorntailOut) == 0) {
            if (*(f32 *)(state + 0x108) < (f32)other[0x19]) {
                if (state[0x137] & 2) {
                    rangeSq = *(f32 *)(state + 0x118) * *(f32 *)(state + 0x118);
                    while (1) {
                        dx = *(f32 *)(state + 0x68) - *(f32 *)(obj + 0xc);
                        dz = *(f32 *)(state + 0x70) - *(f32 *)(obj + 0x14);
                        if (dx * dx + dz * dz < rangeSq) {
                            if (Curve_AdvanceAlongPath(state, *(f32 *)(state + 0x120)) != 0 ||
                                *(int *)(state + 0x10) != 0) {
                                (*(code *)(*(int *)gRomCurveInterface + 0x90))(state);
                            }
                        } else {
                            break;
                        }
                    }
                    ang = getAngle(-dx, -dz);
                    *(s16 *)(state + 0x130) = ang;
                } else {
                    *(s16 *)(state + 0x130) =
                        fn_801D129C(obj, player, state, *(f32 *)(state + 0x118));
                }
                state[0x136] = 1;
                Sfx_PlayFromObject(obj, 0xa0);
                *(s16 *)obj = (s16)(*(s16 *)(state + 0x130) - 0x4000);
            } else if (*(f32 *)(state + 0x108) < (f32)other[0x1f]) {
                state[0x136] = 3;
            }
        } else {
            t = *(f32 *)(state + 0x12c) - timeDelta;
            *(f32 *)(state + 0x12c) = t;
            if (t <= lbl_803E5288) {
                if (*(u16 *)(obj + 0xb0) & 0x800) {
                    fx.x = *(f32 *)(obj + 0x18);
                    fx.y = lbl_803E528C + *(f32 *)(obj + 0x1c);
                    fx.z = *(f32 *)(obj + 0x20);
                    (*(code *)(*(int *)gPartfxInterface + 0x8))(obj, 0x7f0, &fx, 0x200001, -1,
                                                                0);
                }
                *(f32 *)(state + 0x12c) = lbl_803E5290;
            }
        }
        break;
    case 1:
        if (state[0x137] & 0x10) {
            state[0x136] = 9;
        } else if (state[0x137] & 1) {
            state[0x136] = 0;
        }
        break;
    case 3:
    case 7:
        if (state[0x137] & 0x10) {
            state[0x136] = 9;
        } else if (state[0x137] & 1) {
            if (sval == 3) {
                state[0x136] = 4;
            } else {
                state[0x136] = 0;
            }
        }
        break;
    case 4:
        if (state[0x137] & 0x10) {
            state[0x136] = 9;
        } else {
            ang = getAngle(-(*(f32 *)(obj + 0xc) - *(f32 *)(player + 0xc)),
                           -(*(f32 *)(obj + 0x14) - *(f32 *)(player + 0x14)));
            *(s16 *)obj = ang;
            if (*(f32 *)(state + 0x108) > lbl_803E5294 + (f32)other[0x1f]) {
                state[0x136] = 7;
            } else if (*(f32 *)(state + 0x108) < (f32)other[0x19]) {
                Sfx_PlayFromObject(obj, 0xa0);
                if (speed >= lbl_803E5298) {
                    if (state[0x137] & 2) {
                        rangeSq = *(f32 *)(state + 0x118) * *(f32 *)(state + 0x118);
                        while (1) {
                            dx = *(f32 *)(state + 0x68) - *(f32 *)(obj + 0xc);
                            dz = *(f32 *)(state + 0x70) - *(f32 *)(obj + 0x14);
                            if (dx * dx + dz * dz < rangeSq) {
                                if (Curve_AdvanceAlongPath(state, *(f32 *)(state + 0x120)) != 0 ||
                                    *(int *)(state + 0x10) != 0) {
                                    (*(code *)(*(int *)gRomCurveInterface + 0x90))(state);
                                }
                            } else {
                                break;
                            }
                        }
                        ang = getAngle(-dx, -dz);
                        *(s16 *)(state + 0x130) = ang;
                    } else {
                        *(s16 *)(state + 0x130) =
                            fn_801D129C(obj, player, state, *(f32 *)(state + 0x118));
                    }
                    state[0x136] = 1;
                    *(s16 *)obj = (s16)(*(s16 *)(state + 0x130) - 0x4000);
                } else {
                    if (state[0x137] & 2) {
                        rangeSq = *(f32 *)(state + 0x11c) * *(f32 *)(state + 0x11c);
                        while (1) {
                            dx = *(f32 *)(state + 0x68) - *(f32 *)(obj + 0xc);
                            dz = *(f32 *)(state + 0x70) - *(f32 *)(obj + 0x14);
                            if (dx * dx + dz * dz < rangeSq) {
                                if (Curve_AdvanceAlongPath(state, *(f32 *)(state + 0x120)) != 0 ||
                                    *(int *)(state + 0x10) != 0) {
                                    (*(code *)(*(int *)gRomCurveInterface + 0x90))(state);
                                }
                            } else {
                                break;
                            }
                        }
                        ang = getAngle(-dx, -dz);
                        *(s16 *)(state + 0x130) = ang;
                    } else {
                        *(s16 *)(state + 0x130) =
                            fn_801D129C(obj, player, state, *(f32 *)(state + 0x11c));
                    }
                    state[0x136] = 5;
                    *(s16 *)obj = *(s16 *)(state + 0x130);
                }
            }
        }
        break;
    case 5:
        if ((state[0x137] & 0x11) == 0x11) {
            state[0x136] = 9;
        }
        if (*(f32 *)(state + 0x108) > lbl_803E5294 + (f32)other[0x19] && (state[0x137] & 1)) {
            state[0x136] = 4;
        } else if (speed >= lbl_803E5298) {
            if (state[0x137] & 2) {
                rangeSq = *(f32 *)(state + 0x118) * *(f32 *)(state + 0x118);
                while (1) {
                    dx = *(f32 *)(state + 0x68) - *(f32 *)(obj + 0xc);
                    dz = *(f32 *)(state + 0x70) - *(f32 *)(obj + 0x14);
                    if (dx * dx + dz * dz < rangeSq) {
                        if (Curve_AdvanceAlongPath(state, *(f32 *)(state + 0x120)) != 0 ||
                            *(int *)(state + 0x10) != 0) {
                            (*(code *)(*(int *)gRomCurveInterface + 0x90))(state);
                        }
                    } else {
                        break;
                    }
                }
                ang = getAngle(-dx, -dz);
                *(s16 *)(state + 0x130) = ang;
            } else {
                *(s16 *)(state + 0x130) = fn_801D129C(obj, player, state, *(f32 *)(state + 0x118));
            }
            state[0x136] = 1;
            Sfx_PlayFromObject(obj, 0xa0);
            *(s16 *)obj = (s16)(*(s16 *)(state + 0x130) - 0x4000);
        }
        break;
    case 9:
        ObjHits_ClearSourceMask(obj, 1);
        Sfx_KeepAliveLoopedObjectSound(obj, 0x9b);
        if (*(f32 *)(state + 0x124) <= lbl_803E5288) {
            *(f32 *)(state + 0x124) = (f32)(int)randomGetRange(0xf0, 0x12c);
        }
        t = *(f32 *)(state + 0x124) - timeDelta;
        *(f32 *)(state + 0x124) = t;
        if (t <= lbl_803E5288) {
            ObjHits_SetSourceMask(obj, 1);
            (*(code *)(*(int *)gExpgfxInterface + 0x14))(obj);
            state[0x136] = 0;
            state[0x137] &= ~0x10;
        } else {
            t = *(f32 *)(state + 0x128) - timeDelta;
            *(f32 *)(state + 0x128) = t;
            if (t <= lbl_803E5288) {
                fx.x = lbl_803E5294;
                fx.y = lbl_803E529C;
                if (*(u16 *)(obj + 0xb0) & 0x800) {
                    (*(code *)(*(int *)gPartfxInterface + 0x8))(obj, 0x51d, &fx, 2, -1, 0);
                }
                *(f32 *)(state + 0x128) = lbl_803E52A0;
            }
            if (GameBit_Get(0x12e) == 0) {
                if (!(*(u16 *)(player + 0xb0) & 0x1000)) {
                    if (Vec_xzDistance((f32 *)(player + 0x18), (f32 *)(obj + 0x18)) <
                        lbl_803E52A4) {
                        (*(code *)(*(int *)gExpgfxInterface + 0x14))(obj);
                        if (*(s16 *)(obj + 0x46) == 0x658) {
                            *(s16 *)(state + 0x13c) = 0x18a;
                            itemPickupDoParticleFx(obj, lbl_803E52A8, 0xff, 0x28);
                        } else {
                            *(s16 *)(state + 0x13c) = 0x119;
                            itemPickupDoParticleFx(obj, lbl_803E52A8, 6, 0x28);
                        }
                        *(s16 *)(state + 0x13e) = 0;
                        *(f32 *)(state + 0x140) = lbl_803E52AC;
                        ObjMsg_SendToObject(player, 0x7000a, obj, state + 0x13c);
                        bit = *(s16 *)(other + 0x1a);
                        if (bit != -1) {
                            GameBit_Set(bit, 1);
                        }
                        state[0x136] = 8;
                        GameBit_Set(0x12e, 1);
                    }
                }
            }
        }
        break;
    case 6:
        if (state[0x137] & 0x10) {
            state[0x136] = 9;
        }
        break;
    case 2:
    case 8:
    case 10:
        break;
    }

    curMove = *(s16 *)(obj + 0xa0);
    moveId = lbl_80326BD0[state[0x136]];
    if (curMove != moveId && moveId != -1) {
        ObjAnim_SetCurrentMove(obj, moveId, lbl_803E52B0, 0);
    }

    if (ObjAnim_AdvanceCurrentMove(obj, lbl_80326BE8[state[0x136]], timeDelta, animOut) !=
        0) {
        state[0x137] |= 1;
    } else {
        state[0x137] &= ~1;
    }

    if (state[0x136] == 1) {
        speed = *(f32 *)(state + 0x110) * (animOut[0] * oneOverTimeDelta);
    } else if (state[0x136] == 5) {
        speed = animOut[2] * oneOverTimeDelta;
    } else {
        speed = lbl_803E5288;
    }

    if (lbl_803E5288 != speed) {
        state[0x137] |= 8;
    } else {
        state[0x137] &= ~8;
    }

    *(f32 *)(obj + 0x24) =
        speed * fn_80293E80((lbl_803E52B4 * (f32)*(s16 *)(state + 0x130)) / lbl_803E52B8);
    *(f32 *)(obj + 0x2c) =
        speed * sin((lbl_803E52B4 * (f32)*(s16 *)(state + 0x130)) / lbl_803E52B8);

    objMove(obj, *(f32 *)(obj + 0x24) * timeDelta, lbl_803E5288,
            *(f32 *)(obj + 0x2c) * timeDelta);
}
#pragma pop

/*
 * --INFO--
 *
 * Function: fn_801D129C
 * EN v1.0 Address: 0x801D129C
 * EN v1.0 Size: 704b
 */
#pragma push
#pragma scheduling off
#pragma peephole off
s16 fn_801D129C(u8 *obj, u8 *player, u8 *state, f32 dist) {
    s16 angle;
    int anglePlus;
    int angleMinus;
    int i;
    f32 rad;
    f32 c;
    f32 s;
    f32 cosP;
    f32 cosM;
    f32 sinM;
    f32 cosStepP;
    f32 cosStepM;
    f32 sinStepP;
    f32 sinStepM;
    f32 vec[3];

    angle = getAngle(-(*(f32 *)(obj + 0xc) - *(f32 *)(player + 0xc)),
                     -(*(f32 *)(obj + 0x14) - *(f32 *)(player + 0x14)));
    rad = (lbl_803E52B4 * (f32)angle) / lbl_803E52B8;
    c = fn_80293E80(rad);
    s = sin(rad);
    vec[0] = *(f32 *)(obj + 0xc) - dist * c;
    vec[1] = *(f32 *)(obj + 0x10);
    vec[2] = *(f32 *)(obj + 0x14) - dist * s;
    if (objBboxFn_800640cc(obj + 0xc, vec, lbl_803E52D0, 3, 0, obj, 8, -1, 0xff, 0) != 0) {
        anglePlus = angle;
        angleMinus = angle;
        cosM = c;
        cosP = c;
        cosStepP = fn_80293E80(lbl_803E52D4);
        cosStepM = fn_80293E80(lbl_803E52D8);
        sinM = s;
        sinStepP = sin(lbl_803E52D4);
        sinStepM = sin(lbl_803E52D8);
        for (i = 0; i < 8; i++) {
            f32 t;

            anglePlus += 0xe38;
            t = cosP * sinStepP + s * cosStepP;
            s = s * sinStepP - cosP * cosStepP;
            cosP = t;
            vec[0] = *(f32 *)(obj + 0xc) - dist * t;
            vec[2] = *(f32 *)(obj + 0x14) - dist * s;
            if (objBboxFn_800640cc(obj + 0xc, vec, lbl_803E52D0, 1, 0, obj, 8, -1, 0xff, 0) == 0) {
                return anglePlus;
            }
            angleMinus -= 0xe38;
            t = cosM * sinStepM + sinM * cosStepM;
            sinM = sinM * sinStepM - cosM * cosStepM;
            cosM = t;
            vec[0] = *(f32 *)(obj + 0xc) - dist * t;
            vec[2] = *(f32 *)(obj + 0x14) - dist * sinM;
            if (objBboxFn_800640cc(obj + 0xc, vec, lbl_803E52D0, 1, 0, obj, 8, -1, 0xff, 0) == 0) {
                return angleMinus;
            }
        }
    }
    return angle;
}
#pragma pop

/*
 * --INFO--
 *
 * Function: ediblemushroom_free
 * EN v1.0 Address: 0x801D1564
 * EN v1.0 Size: 60b
 */
#pragma push
#pragma scheduling off
#pragma peephole off
void ediblemushroom_free(int obj) {
    ObjGroup_RemoveObject(obj, 0x47);
    ObjGroup_RemoveObject(obj, 0x31);
}
#pragma pop

/*
 * --INFO--
 *
 * Function: ediblemushroom_getExtraSize
 * EN v1.0 Address: 0x801D155C
 * EN v1.0 Size: 8b
 */
int ediblemushroom_getExtraSize(void) {
    return 0x144;
}

/*
 * --INFO--
 *
 * Function: ediblemushroom_hitDetect
 * EN v1.0 Address: 0x801D15A0
 * EN v1.0 Size: 332b
 */
#pragma push
#pragma scheduling off
#pragma peephole off
void ediblemushroom_hitDetect(u8 *obj) {
    u8 *state;
    u8 *mapObj;
    int hitCount;
    f32 **hitIter;
    f32 **hits;
    int i;
    u8 bboxHit[0x54];

    state = *(u8 **)(obj + 0xb8);
    mapObj = *(u8 **)(obj + 0x4c);

    if (((*(u16 *)(obj + 0xb0) & 0x1000) == 0) &&
        (((state[0x137] & 8) != 0) || ((*(s16 *)(*(int *)(obj + 0x54) + 0x60) & 8) != 0))) {
        hitCount = hitDetectFn_80065e50(obj, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10),
                                        *(f32 *)(obj + 0x14), &hits, 0, 0);
        i = 0;
        hitIter = hits;
        for (; i < hitCount; i++) {
            if (**hitIter < lbl_803E5294 + *(f32 *)(obj + 0x10)) {
                *(f32 *)(obj + 0x10) = *hits[i];
                break;
            }
            hitIter++;
        }

        hitCount = objBboxFn_800640cc(obj + 0x80, obj + 0xc, lbl_803E52DC, 2, bboxHit, obj, 8,
                                      -1, 0xff, 0x14);
        if ((mapObj[0x18] == 4) && (hitCount != 0) && ((s8)bboxHit[0x50] == 13)) {
            state[0x137] |= 4;
        }
    }
}
#pragma pop
