#include "main/dll/DR/dll_80209FE0_shared.h"

/*
 * Function: bossdrakor_release
 * EN v1.0 Address: 0x8020BAAC
 * EN v1.0 Size: 4b
 */
void bossdrakor_release(void)
{
}

/*
 * Function: bossdrakor_initialise
 * EN v1.0 Address: 0x8020BAB0
 * EN v1.0 Size: 4b
 */
void bossdrakor_initialise(void)
{
}

int bossdrakor_getExtraSize(void)
{
    return 0x1a4;
}

#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off

void bossdrakor_update(int obj)
{
    int state;
    int state2;
    int moveResult;
    int adv;
    int player;
    int i;
    int moveId;
    s8 *p;
    u16 *uvec;
    int *tbl;
    int v27;
    int v28;
    f32 v178;
    f32 v180;
    f32 v;
    f32 t;
    s16 d;
    int step;
    s16 *vec;
    s8 buf[0x1c];
    f32 hz;
    f32 hy;
    f32 hx;
    int curveArg;

    state = *(int *)((char *)obj + 0xb8);
    curveArg = 0x29;
    if (((DrakorFlags *)((char *)state + 0x198))->b10) {
        getEnvfxActImmediately(obj, obj, 0x144, 0);
        getEnvfxActImmediately(obj, obj, 0x10d, 0);
        getEnvfxActImmediately(obj, obj, 0x10e, 0);
        skyFn_80088e54(1, lbl_803E6510);
        timeOfDayFn_80055038();
        if ((*(u8 (**)(void *, int, f32, int *, int))(*gRomCurveInterface + 0x8c))((void *)((char *)state + 0x28), obj, lbl_803E6560, &curveArg, 0xd) != 0) {
            (*(u8 (**)(void *, int, f32, int *, int))(*gRomCurveInterface + 0x8c))((void *)((char *)state + 0x28), obj, lbl_803E6560, &curveArg, 0);
        }
        *(f32 *)((char *)obj + 0xc) = *(f32 *)((char *)state + 0x90);
        *(f32 *)((char *)obj + 0x14) = *(f32 *)((char *)state + 0x98);
        *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)state + 0x94);
        ((DrakorFlags *)((char *)state + 0x198))->b20 = 1;
        *(u8 *)((char *)state + 0x190) = 0;
        state2 = *(int *)((char *)obj + 0xb8);
        ((DrakorFlags *)((char *)state2 + 0x198))->b20 = 1;
        (*(void (**)(int, int))(*gGameUIInterface + 0x58))(*(int *)((char *)state2 + 0x170), 0x63e);
        (*(void (**)(int))(*gGameUIInterface + 0x5c))(*(int *)((char *)state2 + 0x170));
        ((DrakorFlags *)((char *)state + 0x198))->b10 = 0;
        *(int *)((char *)state + 0x160) = objCreateLight(0, 1);
        if (*(void **)((char *)state + 0x160) != NULL) {
            modelLightStruct_setLightKind(*(int *)((char *)state + 0x160), 2);
            modelLightStruct_setDiffuseColor(*(int *)((char *)state + 0x160), 0x40, 0, 0xff, 0xff);
            modelLightStruct_setSpecularColor(*(int *)((char *)state + 0x160), 0x40, 0, 0xff, 0xff);
            modelLightStruct_setupGlow(*(int *)((char *)state + 0x160), 0, 0x40, 0, 0x80, 0x5a, lbl_803E6564);
            modelLightStruct_setDistanceAttenuation(*(int *)((char *)state + 0x160), lbl_803E6544, lbl_803E6540);
            lightSetField4D(*(int *)((char *)state + 0x160), 0);
            modelLightStruct_setEnabled(*(void **)((char *)state + 0x160), 1, lbl_803E6520);
            modelLightStruct_setDiffuseTargetColor(*(int *)((char *)state + 0x160), 0x40, 0, 0x80, 0x40);
            modelLightStruct_setSpecularTargetColor(*(int *)((char *)state + 0x160), 0x40, 0, 0x80, 0x40);
            modelLightStruct_startColorFade(*(int *)((char *)state + 0x160), 2, 0x28);
            modelLightStruct_setAffectsAabbLightSelection(*(int *)((char *)state + 0x160), 1);
            modelLightStruct_setGlowProjectionRadius(*(int *)((char *)state + 0x160), lbl_803E6550);
        }
    }
    moveResult = Obj_UpdateRomCurveFollowVelocityIndexed(*(f32 *)state, lbl_803E6568, lbl_803E6520, obj, (void *)((char *)state + 0x28), 1, (void *)((char *)state + 0x194));
    if (((DrakorFlags *)((char *)state + 0x198))->b40) {
        player = (int)Obj_GetPlayerObject();
        if ((void *)player != NULL) {
            d = Obj_GetYawDeltaToObject(obj, player, 0);
            *(s16 *)obj += (d < -0x200) ? -0x200 : ((d > 0x200) ? 0x200 : d);
            d = *(s16 *)((char *)obj + 2);
            if (d != 0) {
                *(s16 *)((char *)obj + 2) -= (d < -0x100) ? -0x100 : ((d > 0x100) ? 0x100 : d);
            }
            d = *(s16 *)((char *)obj + 4);
            if (d != 0) {
                *(s16 *)((char *)obj + 4) -= (d < -0x100) ? -0x100 : ((d > 0x100) ? 0x100 : d);
            }
        }
    } else {
        Obj_SmoothTurnAnglesTowardVelocity(obj, (void *)((char *)obj + 0x24), 0x2d, lbl_803E6548, lbl_803E656C);
    }
    if (moveResult != 0) {
        bossdrakor_handleActionEvent(obj, state, moveResult);
    }
    adv = ((int (*)(f32, int, f32, void *))ObjAnim_AdvanceCurrentMove)(lbl_803E6570 + PSVECMag((f32 *)((char *)obj + 0x24)) / *(f32 *)((char *)state + 0x164), obj, timeDelta, buf);
    if (adv != 0) {
        if (*(int *)((char *)state + 0x168) == 0) {
            ObjHits_ClearHitVolumes(obj);
            ((DrakorFlags *)((char *)state + 0x198))->b04 = 0;
            ((DrakorFlags *)((char *)state + 0x198))->b08 = 0;
            if (!((DrakorFlags *)((char *)state + 0x198))->b40) {
                *(f32 *)((char *)state + 0x164) = lbl_803E6534;
                ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)obj, 0x28);
                moveId = 0x10;
            } else {
                moveId = bossdrakor_chooseNextMove(obj, (f32 *)((char *)state + 0x164));
            }
            ObjAnim_SetCurrentMove(obj, moveId, lbl_803E6510, 0);
        } else {
            ObjAnim_SetCurrentMove(obj, *(int *)((char *)state + 0x168), lbl_803E6510, 0);
        }
        if (arrayIndexOf(lbl_80329FB8, 5, *(int *)((char *)state + 0x168)) != -1) {
            switch (*(int *)((char *)state + 0x168)) {
            case 0x12:
                ((DrakorFlags *)((char *)state + 0x198))->b40 = 0;
                *(int *)((char *)state + 0x168) = 0;
                break;
            case 0x13:
                *(int *)((char *)state + 0x168) = 0x16;
                *(f32 *)((char *)state + 0x164) = lbl_803E6534;
                break;
            case 0x16:
                *(int *)((char *)state + 0x168) = 0x16;
                *(f32 *)((char *)state + 0x164) = lbl_803E6574;
                break;
            case 0x14:
                if (((DrakorFlags *)((char *)state + 0x198))->b08) {
                    *(int *)((char *)state + 0x168) = 0;
                } else {
                    ObjHits_SetHitVolumeSlot(obj, 5, 1, 0);
                    *(int *)((char *)state + 0x168) = 0x15;
                    *(f32 *)((char *)state + 0x164) = lbl_803E6574;
                }
                break;
            case 0x15:
                *(int *)((char *)state + 0x168) = 0;
                *(f32 *)((char *)state + 0x164) = lbl_803E6514;
                ((DrakorFlags *)((char *)state + 0x198))->b04 = 1;
                break;
            }
        }
    }
    for (i = 0, p = buf; i < buf[0x1b]; i++) {
        switch (p[0x13]) {
        case 0:
            Sfx_PlayFromObject(obj, 0x481);
            break;
        case 7:
            Sfx_PlayFromObject(obj, 0x481);
            break;
        }
        p++;
    }
    if (timerCountDown((f32 *)((char *)state + 0x10)) != 0) {
        bossdrakor_spawnAttackObjects(obj, state, *(int *)((char *)state + 0x174));
        if (*(f32 *)((char *)state + 0x14) != lbl_803E6510) {
            s16toFloat((void *)((char *)state + 0x10), (int)*(f32 *)((char *)state + 0x14));
        }
    }
    if ((*(u16 *)((char *)obj + 0xb0) & 0x800) == 0) {
        *(f32 *)((char *)state + 0x1c) = *(f32 *)((char *)obj + 0xc);
        *(f32 *)((char *)state + 0x20) = *(f32 *)((char *)obj + 0x10) - lbl_803E655C;
        *(f32 *)((char *)state + 0x24) = *(f32 *)((char *)obj + 0x14);
    }
    objMove(obj, *(f32 *)((char *)obj + 0x24), *(f32 *)((char *)obj + 0x28), *(f32 *)((char *)obj + 0x2c));
    if (((DrakorFlags *)((char *)state + 0x198))->b20) {
        (*(void (**)(int))(*gGameUIInterface + 0x5c))(*(int *)((char *)state + 0x170));
    }
    t = lbl_803E6510;
    if (t != *(f32 *)((char *)state + 0x178)) {
        *(f32 *)((char *)state + 0x17c) = -(lbl_803E6578 * timeDelta - *(f32 *)((char *)state + 0x17c));
        *(f32 *)((char *)state + 0x178) = *(f32 *)((char *)state + 0x178) + *(f32 *)((char *)state + 0x17c);
        v = *(f32 *)((char *)state + 0x178);
        t = (v < t) ? t : ((v > lbl_803E6550) ? lbl_803E6550 : v);
        *(f32 *)((char *)state + 0x178) = t;
        v180 = *(f32 *)((char *)state + 0x180);
        v178 = *(f32 *)((char *)state + 0x178);
        tbl = seqFn_800394a0();
        v27 = (int)(lbl_803E6530 * v178);
        v28 = (int)(lbl_803E6530 * (v178 * v180));
        i = 0;
        do {
            uvec = (u16 *)objModelGetVecFn_800395d8(obj, tbl[0]);
            if (uvec != NULL) {
                uvec[1] = v28;
                uvec[0] = v27;
                uvec[2] = 0;
            }
            tbl++;
            i++;
        } while (i < 5);
    }
    if (randFn_80080100(200) != 0 && ((DrakorFlags *)((char *)state + 0x198))->b40) {
        objAudioFn_80039270(obj, state + 0x130, 0x2ff);
    }
    objAnimFn_80038f38(obj, state + 0x130);
    if (((DrakorFlags *)((char *)state + 0x198))->b04) {
        player = (int)Obj_GetPlayerObject();
        vec = objModelGetVecFn_800395d8(obj, 0xe);
        if (vec != NULL) {
            ObjPath_GetPointWorldPosition(obj, 4, &hx, &hy, &hz, 0);
            PSVECSubtract((f32 *)((char *)player + 0xc), &hx, &hx);
            d = (s16)getAngle(hy, sqrtf(hx * hx + hz * hz)) - (u16)vec[0];
            if (d > 0x8000) {
                d = (s16)((int)d - 0xffff);
            }
            if (d < -0x8000) {
                d += 0xffff;
            }
            step = (d < -(framesThisStep << 8)) ? -(framesThisStep << 8) : ((d > (framesThisStep << 8)) ? (framesThisStep << 8) : d);
            vec[0] += (s16)step;
        }
    } else {
        bossdrakor_updateHeadTracking(obj, state);
    }
}

void bossdrakor_updateHeadTracking(int obj, int state)
{
    s16 *neck;
    s16 *vecF;
    s16 *vec10;
    int step;
    int step2;
    int v;
    s16 d;
    struct {
        u8 pad[6];
        s16 mode;
        f32 val;
        f32 vec[3];
    } prm;

    neck = objModelGetVecFn_800395d8(obj, 0xe);
    if (neck != NULL) {
        v = (s16)-neck[0];
        step = (v < -(framesThisStep << 8)) ? -(framesThisStep << 8) : ((v > (framesThisStep << 8)) ? (framesThisStep << 8) : v);
        neck[0] += (s16)step;
        PSVECSubtract((f32 *)((char *)state + 0x1c), (f32 *)((char *)obj + 0xc), prm.vec);
        prm.val = lbl_803E651C;
        if (fn_80080150((int)((char *)state + 0x18)) != 0) {
            vecF = objModelGetVecFn_800395d8(obj, 0xf);
            if (vecF != NULL) {
                vec10 = objModelGetVecFn_800395d8(obj, 0x10);
                if (vec10 != NULL) {
                    d = (int)(*(f32 *)((char *)state + 0x18) * (f32)lbl_803DC19A) - (u16)vecF[1];
                    if (d > 0x8000) {
                        d = (s16)((int)d - 0xffff);
                    }
                    if (d < -0x8000) {
                        d += 0xffff;
                    }
                    step2 = (d < -lbl_803DC198 * framesThisStep) ? -lbl_803DC198 * framesThisStep : ((d > lbl_803DC198 * framesThisStep) ? lbl_803DC198 * framesThisStep : d);
                    vecF[1] += (s16)step2;
                    vec10[1] -= (s16)step2;
                    if (timerCountDown((f32 *)((char *)state + 0x18)) != 0) {
                        storeZeroToFloatParam((f32 *)((char *)state + 0x18));
                    }
                    if (*(f32 *)((char *)state + 0x18) > lbl_803E6520) {
                        prm.mode = 45000;
                        (*(void (**)(int, int, void *, int, int, int))(*gPartfxInterface + 0x8))(obj, 0x7ad, &prm, 1, -1, 0);
                    }
                }
            }
        }
    }
}

int bossdrakor_chooseNextMove(int obj, f32 *speedOut)
{
    int state;
    int idx;
    int v;
    s16 d;
    u16 a;
    f32 dir[3];

    state = *(int *)((char *)obj + 0xb8);
    PSVECNormalize((f32 *)((char *)obj + 0x24), dir);
    if (*(int *)((char *)state + 0x168) != 0) {
        *speedOut = lbl_803E6534;
        return *(int *)((char *)state + 0x168);
    }
    idx = 0;
    if (dir[1] > lbl_803E6538) {
        idx = 3;
    } else if (dir[1] < lbl_803E653C) {
        idx = 4;
    } else {
        a = (u16)(s16)getAngle(dir[0], dir[2]);
        d = *(s16 *)obj - a;
        if (d > 0x8000) {
            d = (s16)((int)d - 0xffff);
        }
        if (d < -0x8000) {
            d += 0xffff;
        }
        v = (d < 0) ? -d : d;
        if (v > 0x2000) {
            v = (d < 0) ? -d : d;
            if (v < 0x6000) {
                if (d > 0) {
                    idx = 1;
                } else {
                    idx = 2;
                }
            }
        }
    }
    v = lbl_80329F90[idx];
    *speedOut = (f32)lbl_80329FA4[idx];
    return v;
}

void bossdrakor_spawnAttackObjects(int obj, int state, int action)
{
    int player;
    int missile;
    int lo;
    int hi;
    f32 spd;
    f32 prod;
    f32 *mstate;
    u8 *setup;
    f32 target[3];
    f32 vecA[3];
    f32 vecB[3];
    f32 vecC[3];

    if (action < 0) {
        return;
    }
    if (action < 4) {
        switch (action) {
        case 4:
            break;
        case 1:
            player = (int)Obj_GetPlayerObject();
            if (((DrakorFlags *)((char *)state + 0x198))->b40) {
                if (Obj_IsLoadingLocked() != 0) {
                    setup = Obj_AllocObjectSetup(0x20, 0x70f);
                    *(f32 *)(setup + 8) = *(f32 *)((char *)state + 0x1c);
                    *(f32 *)(setup + 0xc) = *(f32 *)((char *)state + 0x20);
                    *(f32 *)(setup + 0x10) = *(f32 *)((char *)state + 0x24);
                    setup[4] = 1;
                    setup[5] = 1;
                    setup[6] = 0xff;
                    setup[7] = 0xff;
                    if ((void *)player != NULL) {
                        missile = loadObjectAtObject(obj, setup);
                        if ((void *)missile != NULL) {
                            prod = lbl_803DC188 * Vec_distance((int *)((char *)obj + 0x18), (int *)((char *)player + 0x18));
                            lo = (int)-prod;
                            hi = (int)prod;
                            target[0] = *(f32 *)((char *)player + 0xc) + (f32)(s32)randomGetRange(lo, hi);
                            target[1] = *(f32 *)((char *)player + 0x10) + (f32)(s32)randomGetRange(lo, hi);
                            target[2] = *(f32 *)((char *)player + 0x14) + (f32)(s32)randomGetRange(lo, hi);
                            PSVECSubtract((f32 *)((char *)player + 0xc), (f32 *)((char *)state + 0x1c), vecA);
                            PSVECSubtract(target, (f32 *)((char *)state + 0x1c), vecB);
                            PSVECNormalize(vecA, vecA);
                            spd = *(f32 *)((char *)state + 0x188) * PSVECDotProduct((f32 *)((char *)player + 0x24), vecA) + *(f32 *)((char *)state + 0x184);
                            PSVECScale(vecA, (f32 *)((char *)missile + 0x24), spd);
                            mstate = *(f32 **)((char *)missile + 0xb8);
                            PSVECScale(vecA, vecC, PSVECDotProduct(vecA, vecB));
                            PSVECSubtract(vecB, vecC, vecC);
                            PSVECNormalize(vecC, vecC);
                            PSVECScale(vecC, (f32 *)((char *)missile + 0x24), *(f32 *)((char *)state + 0x184) * lbl_803DC18C);
                            *mstate = spd;
                            drakormissile_startActiveLaunch(missile);
                            storeZeroToFloatParam((f32 *)((char *)state + 0x18));
                            s16toFloat((void *)((char *)state + 0x18), 0x1e);
                            Sfx_PlayFromObject(obj, 0x477);
                            Sfx_PlayFromObject(obj, 0x3c8);
                        }
                    }
                }
            }
            break;
        case 2:
            if (!((DrakorFlags *)((char *)state + 0x198))->b40) {
                if (Obj_IsLoadingLocked() != 0) {
                    setup = Obj_AllocObjectSetup(0x24, 0x709);
                    setup[4] = 2;
                    setup[5] = 1;
                    setup[6] = 0xff;
                    setup[7] = 0xff;
                    *(f32 *)(setup + 8) = *(f32 *)((char *)state + 0x1c);
                    *(f32 *)(setup + 0xc) = *(f32 *)((char *)state + 0x20);
                    *(f32 *)(setup + 0x10) = *(f32 *)((char *)state + 0x24);
                    *(s16 *)(setup + 0x1a) = 0x3c;
                    *(s16 *)(setup + 0x1c) = lbl_803DC194;
                    *(s8 *)(setup + 0x19) = lbl_803DC190;
                    loadObjectAtObject(obj, setup);
                    Sfx_PlayFromObject(obj, 0x477);
                }
            }
            break;
        }
    }
}

void bossdrakor_free(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    ObjGroup_RemoveObject(obj, 0x45);
    if (*(void **)((char *)obj + 0xc8) != NULL) {
        ObjLink_DetachChild(obj, *(int *)((char *)obj + 0xc8));
    }
    if (*(void **)((char *)inner + 0x160) != NULL) {
        ModelLightStruct_free(*(int *)((char *)inner + 0x160));
    }
    Music_Trigger(0x26, 0);
    Music_Trigger(0x96, 0);
}

void bossdrakor_handleActionEvent(int obj, int state, int action)
{
    int *tbl = lbl_80329F90;
    f32 t;
    int found;
    switch (action) {
    case 1:
        if (((DrakorFlags *)((char *)state + 0x198))->b40) {
            *(int *)((char *)state + 0x168) = 0x12;
            if (*(void **)((char *)state + 0x160) != NULL) {
                modelLightStruct_setEnabled(*(void **)((char *)state + 0x160), 0, lbl_803E651C);
            }
        } else {
            ((DrakorFlags *)((char *)state + 0x198))->b40 = 1;
            if (*(void **)((char *)state + 0x160) != NULL) {
                modelLightStruct_setEnabled(*(void **)((char *)state + 0x160), 1, lbl_803E651C);
            }
        }
        break;
    case 2:
        storeZeroToFloatParam((f32 *)((char *)state + 0x10));
        s16toFloat((void *)((char *)state + 0x10), 0x1e);
        *(int *)((char *)state + 0x174) = 2;
        *(f32 *)((char *)state + 0x14) = lbl_803E6510;
        break;
    case 3:
        storeZeroToFloatParam((f32 *)((char *)state + 0x10));
        s16toFloat((void *)((char *)state + 0x10), 0x5a);
        *(f32 *)((char *)state + 0x14) = lbl_803E6540;
        *(int *)((char *)state + 0x174) = 1;
        *(f32 *)((char *)state + 0x184) = *(f32 *)((char *)tbl + 0x84);
        *(f32 *)((char *)state + 0x188) = *(f32 *)((char *)tbl + 0x90);
        break;
    case 4:
        storeZeroToFloatParam((f32 *)((char *)state + 0x10));
        s16toFloat((void *)((char *)state + 0x10), 0x3c);
        *(f32 *)((char *)state + 0x14) = lbl_803E6544;
        *(int *)((char *)state + 0x174) = 1;
        *(f32 *)((char *)state + 0x184) = *(f32 *)((char *)tbl + 0x88);
        *(f32 *)((char *)state + 0x188) = *(f32 *)((char *)tbl + 0x94);
        break;
    case 5:
        storeZeroToFloatParam((f32 *)((char *)state + 0x10));
        s16toFloat((void *)((char *)state + 0x10), 0x1e);
        *(f32 *)((char *)state + 0x14) = lbl_803E6548;
        *(int *)((char *)state + 0x174) = 1;
        *(f32 *)((char *)state + 0x184) = *(f32 *)((char *)tbl + 0x8c);
        *(f32 *)((char *)state + 0x188) = *(f32 *)((char *)tbl + 0x98);
        break;
    case 6:
        t = lbl_803E6510;
        *(f32 *)((char *)state + 0x14) = t;
        *(f32 *)((char *)state + 0x10) = t;
        storeZeroToFloatParam((f32 *)((char *)state + 0x10));
        break;
    case 7:
        *(int *)((char *)state + 0x168) = 0x13;
        *(f32 *)((char *)state + 0x164) = lbl_803E654C;
        ((DrakorFlags *)((char *)state + 0x198))->b08 = 0;
        break;
    case 25:
        *(int *)((char *)state + 0x168) = 0x14;
        *(f32 *)((char *)state + 0x164) = lbl_803E654C;
        break;
    case 8:
        *(int *)((char *)state + 0x168) = 0x11;
        break;
    case 9:
        *(int *)((char *)state + 0x168) = 0;
        break;
    case 10:
    case 11:
    case 12:
        if (*(int *)((char *)state + 0x170) < *(int *)((char *)tbl + action * 4 + 0x74)) {
            *(int *)((char *)state + 0x194) = 1;
        }
        break;
    case 14:
    case 15:
    case 16:
    case 17:
    case 18:
    case 19:
        *(u8 *)((char *)state + 0x190) = *(u8 *)((char *)state + 0x190) + 1;
        if (*(u8 *)((char *)state + 0x190) > action - 0xd) {
            *(u8 *)((char *)state + 0x190) = 0;
            *(int *)((char *)state + 0x194) = 1;
        }
        break;
    case 20:
    case 21:
    case 22:
    case 23:
        if (GameBit_Get((s16)(action + 0xbe5)) != 0) {
            *(int *)((char *)state + 0x194) = 1;
        }
        /* fall through */
    case 24:
        found = ObjGroup_FindNearestObject(0x46, obj, 0);
        if (found != 0) {
            drakorhoverpad_resetPendingMotion(found);
        }
        break;
    }
}

void bossdrakor_hitDetect(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int setup = *(int *)((char *)obj + 0x4c);
    f32 hz;
    f32 hy;
    f32 hx;
    f32 t518;
    int hit = ObjHits_GetPriorityHitWithPosition(obj, 0, 0, 0, &hx, &hy, &hz);
    if (hit == 0xf || hit == 0xe) {
        if (((DrakorFlags *)((char *)inner + 0x198))->b40) {
            *(int *)((char *)inner + 0x170) -= 1;
            ((DrakorFlags *)((char *)inner + 0x198))->b08 = 1;
            if (*(int *)((char *)inner + 0x170) < 0) {
                GameBit_Set(*(s16 *)((char *)setup + 0x1e), 1);
                spawnExplosion((int *)obj, lbl_803E6550, 1, 1, 1, 1, 1, 1, 1);
                Obj_RemoveFromUpdateList((int *)obj);
                (*(void (*)(int, int))(*(int *)(*gMapEventInterface + 0x44)))(0x1d, 3);
                GameBit_Set(0x83c, 1);
            } else {
                Obj_SpawnHitLightAndFade(obj, &hx, lbl_803E6554);
            }
            if (*(f32 *)((char *)inner + 0x19c) <= lbl_803E6510) {
                *(f32 *)((char *)inner + 0x19c) = lbl_803E6558;
                Sfx_PlayFromObject(obj, 0x478);
            }
            if (*(f32 *)((char *)inner + 0x1a0) <= lbl_803E6510) {
                *(f32 *)((char *)inner + 0x1a0) = lbl_803E6520;
                Sfx_PlayFromObject(obj, 0x4af);
            }
            t518 = lbl_803E6518;
            *(f32 *)((char *)inner + 0x17c) = t518;
            *(f32 *)((char *)inner + 0x178) = t518;
            *(f32 *)((char *)inner + 0x180) = (f32)(s32)randomGetRange(-0x32, 0x32) / lbl_803E655C;
        } else {
            if (*(f32 *)((char *)inner + 0x1a0) < lbl_803E6510) {
                *(f32 *)((char *)inner + 0x1a0) = lbl_803E6520;
                Sfx_PlayFromObject(obj, 0x4b0);
            }
        }
    }
    *(f32 *)((char *)inner + 0x19c) -= timeDelta;
    *(f32 *)((char *)inner + 0x1a0) -= timeDelta;
}

int bossdrakor_animEventCallback(int obj, int a2, int events)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int i;
    int target;
    int eventOffset;
    int eventId;
    ((DrakorFlags *)((char *)inner + 0x198))->b10 = 1;
    if (*(f32 *)((char *)inner + 0x18c) > lbl_803E6510) {
        gameTextShow(0x569);
        *(f32 *)((char *)inner + 0x18c) -= timeDelta;
        if (*(f32 *)((char *)inner + 0x18c) < lbl_803E6510) {
            *(f32 *)((char *)inner + 0x18c) = lbl_803E6510;
        }
    }
    for (i = 0; i < *(u8 *)((char *)events + 0x8b); i++) {
        eventOffset = i + 0x81;
        eventId = *(u8 *)((char *)events + eventOffset);
        switch (eventId) {
        case 6:
            target = ObjGroup_FindNearestObject(0x1e, obj, 0);
            if ((void *)target != NULL && *(u8 *)((char *)obj + 0xeb) != 0) {
                (*(void (*)(int, int))(*(int *)(*(int *)(*(int *)((char *)target + 0x68)) + 0x20)))(target, 2);
                ObjLink_DetachChild(obj, target);
            }
            break;
        case 7:
            target = ObjGroup_FindNearestObject(0x1e, obj, 0);
            if ((void *)target != NULL) {
                (*(void (*)(int, int))(*(int *)(*(int *)(*(int *)((char *)target + 0x68)) + 0x20)))(target, 0);
                ObjLink_AttachChild(obj, target, 1);
                *(f32 *)((char *)inner + 0x18c) = lbl_803E6514;
            }
            break;
        case 9:
            ((DrakorFlags *)((char *)inner + 0x198))->b02 = 1;
            break;
        case 8:
            GameBit_Set(0x5db, 0);
            (*(void (*)(int, int, int))(*(int *)(*gMapEventInterface + 0x50)))(2, 0xf, 1);
            (*(void (*)(int, int, int))(*(int *)(*gMapEventInterface + 0x50)))(2, 0x10, 1);
            GameBit_Set(0xe7b, 0);
            warpToMap(0x79, 0);
            timeOfDayFn_80055000();
            break;
        }
    }
    if (((DrakorFlags *)((char *)inner + 0x198))->b02) {
        objParticleFn_80099d84(lbl_803E6518, lbl_803E651C, obj, 6, 0);
    }
    return 0;
}

void bossdrakor_init(int obj, u8 *init)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 fz;
    if (*(u8 *)((char *)init + 0x19) == 0) {
        *(u8 *)((char *)init + 0x19) = 0xa;
    }
    if (*(s16 *)((char *)init + 0x1a) <= 0) {
        *(s16 *)((char *)init + 0x1a) = 0x1e;
    }
    *(int *)((char *)inner + 0xc) = 0;
    ((DrakorFlags *)((char *)inner + 0x198))->b80 = 0;
    *(f32 *)((char *)inner + 0) = (f32)(u32)*(u8 *)((char *)init + 0x19);
    *(int *)((char *)inner + 0x170) = *(s16 *)((char *)init + 0x1a);
    fz = lbl_803E6510;
    *(f32 *)((char *)inner + 0x14) = fz;
    *(int *)((char *)inner + 0x168) = 0;
    *(int *)((char *)inner + 0x16c) = -1;
    *(int *)((char *)inner + 0x174) = 0;
    *(f32 *)((char *)inner + 0x164) = lbl_803E657C;
    ((DrakorFlags *)((char *)inner + 0x198))->b40 = 1;
    *(f32 *)((char *)inner + 0x178) = fz;
    *(f32 *)((char *)inner + 0x17c) = fz;
    *(int *)((char *)inner + 0x194) = 0;
    *(f32 *)((char *)inner + 0x18c) = fz;
    ((DrakorFlags *)((char *)inner + 0x198))->b10 = 1;
    storeZeroToFloatParam((f32 *)((char *)inner + 0x10));
    ObjGroup_AddObject(obj, 0x45);
    storeZeroToFloatParam((f32 *)((char *)inner + 0x18));
    *(void **)((char *)obj + 0xbc) = (void *)bossdrakor_animEventCallback;
    Music_Trigger(0x26, 1);
    Music_Trigger(0x96, 1);
    *(int *)((char *)inner + 0x160) = 0;
}

void bossdrakor_render(int p1, int p2, int p3, int p4, int p5, s8 vis)
{
    int inner = *(int *)((char *)p1 + 0xb8);
    f32 pos2;
    f32 pos1;
    f32 pos0;
    int light;
    int val;
    objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E651C);
    ObjPath_GetPointWorldPosition(p1, 0, (char *)inner + 0x1c, (char *)inner + 0x20, (char *)inner + 0x24, 0);
    if (*(void **)((char *)inner + 0x160) != NULL) {
        ObjPath_GetPointWorldPosition(p1, 5, &pos0, &pos1, &pos2, 0);
        modelLightStruct_setPosition(*(int *)((char *)inner + 0x160), pos0, pos1, pos2);
        light = *(int *)((char *)inner + 0x160);
        if (*(u8 *)((char *)light + 0x2f8) != 0 && *(u8 *)((char *)light + 0x4c) != 0) {
            val = *(u8 *)((char *)light + 0x2f9) + (s8)*(u8 *)((char *)light + 0x2fa);
            if (val < 0) {
                val = 0;
                *(u8 *)((char *)light + 0x2fa) = 0;
            } else if (val > 0xc) {
                val += randomGetRange(-0xc, 0xc);
                if (val > 0xff) {
                    val = 0xff;
                    *(u8 *)((char *)*(int *)((char *)inner + 0x160) + 0x2fa) = 0;
                }
            }
            *(u8 *)((char *)*(int *)((char *)inner + 0x160) + 0x2f9) = (u8)val;
        }
        light = *(int *)((char *)inner + 0x160);
        if (*(u8 *)((char *)light + 0x2f8) != 0 && *(u8 *)((char *)light + 0x4c) != 0) {
            queueGlowRender(light);
        }
    }
}

#pragma opt_common_subs reset
#pragma peephole reset
#pragma scheduling reset
