#include "main/dll/DR/dr_shared.h"
#include "main/audio/sfx_ids.h"
#include "main/mapEvent.h"

int ktrex_stateHandlerA00(void) { return 0x0; }

void ktrex_func0B(void) {}

int ktrex_getExtraSize(void) { return 0x5a4; }

int ktrex_getObjectTypeId(void) { return 0x49; }

void ktrex_release(void) {}

#pragma scheduling off
#pragma peephole off
int ktrex_animEventCallback(int obj, int p2, u8 *arg) {
    int i;
    arg[0x56] = 0;
    for (i = 0; i < arg[0x8b]; i++) {
        switch (arg[0x81 + i]) {
        case 1:
            *(int *)((char *)gKTRexState + 0x104) |= 4;
            break;
        case 2:
            *(int *)((char *)gKTRexState + 0x104) |= 8;
            break;
        case 3:
            *(int *)((char *)gKTRexState + 0x104) |= 0x800;
            break;
        case 4:
            *(int *)((char *)gKTRexState + 0x104) |= 0x1000;
            break;
        case 5:
            *(int *)((char *)gKTRexState + 0x104) |= 0x20000;
            break;
        case 6:
            if (*(void **)((char *)gKTRexState + 0x178) != NULL) {
                ModelLightStruct_free(*(void **)((char *)gKTRexState + 0x178));
                *(void **)((char *)gKTRexState + 0x178) = NULL;
            }
            break;
        }
    }
    ktrex_updateAttackEffects(obj);
    if (*(int *)((char *)obj + 0xf8) == 0) {
        *(int *)((char *)obj + 0xf8) = 1;
    } else if (*(int *)((char *)obj + 0xf8) == 3) {
        *(int *)((char *)obj + 0xf8) = 4;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
void ktrex_spawnRandomEnergyArc(int obj, u16 angle, int slot) {
    int *model;
    f32 point1[3];
    f32 point2[3];
    f32 localPoint[3];

    if (*(void **)((char *)gKTRexState + slot * 4 + 0x17c) != NULL) {
        mm_free(*(void **)((char *)gKTRexState + slot * 4 + 0x17c));
        *(void **)((char *)gKTRexState + slot * 4 + 0x17c) = NULL;
    }
    model = Obj_GetActiveModel(obj);
    localPoint[0] = lbl_803E67B8;
    localPoint[1] = lbl_803E67B8;
    localPoint[2] = lbl_803E67B8;

    PSMTXMultVec(ObjModel_GetJointMatrix(model, randomGetRange(0, *(u8 *)(*(int *)model + 0xf3) - 1)),
                 localPoint, point1);
    point1[0] = point1[0] + playerMapOffsetX;
    point1[1] = point1[1] + lbl_803E67BC;
    point1[2] = point1[2] + playerMapOffsetZ;

    PSMTXMultVec(ObjModel_GetJointMatrix(model, randomGetRange(0, *(u8 *)(*(int *)model + 0xf3) - 1)),
                 localPoint, point2);
    point2[0] = point2[0] + playerMapOffsetX;
    point2[2] = point2[2] + playerMapOffsetZ;

    *(void **)((char *)gKTRexState + slot * 4 + 0x17c) =
        fn_8008FB20(point1, point2, lbl_803E67B4, lbl_803E67C0, angle, 96, 0);
}
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int ktrex_stateHandlerA06(int obj, int runtime) {
    int slot;
    if (*(s8 *)((char *)runtime + 0x27b) != 0) {
        (*(void (**)(int, int, int))((char *)*gPlayerInterface + 0x14))(obj, runtime, 5);
    } else if (*(s8 *)((char *)runtime + 0x346) != 0) {
        slot = 0;
        if (Stack_IsEmpty(*(int *)gKTRexState) == 0) {
            Stack_Pop(*(int *)gKTRexState, &slot);
        }
        return slot + 1;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
int ktrex_isPlayerInLaneThreatRange(int obj) {
    u8 state = *(u8 *)((char *)gKTRexState + 0x100);
    f32 center;
    f32 lo;
    f32 hi;
    if (state == 0) {
        return 0;
    }
    switch (state) {
    case 1:
    case 2:
        center = *(f32 *)((char *)obj + 0x14);
        lo = (center - lbl_803E683C) - *(f32 *)((char *)lbl_803DDD50 + 0x28);
        hi = (lbl_803E683C + center) - *(f32 *)((char *)lbl_803DDD50 + 0x28);
        if (lo > lbl_803E6840) {
            return 0;
        }
        if (hi >= lbl_803E6840) {
            return 1;
        }
        return 0;
    case 4:
    case 8:
        center = *(f32 *)((char *)obj + 0xc);
        lo = (center - lbl_803E683C) - *(f32 *)((char *)lbl_803DDD50 + 0x24);
        hi = (lbl_803E683C + center) - *(f32 *)((char *)lbl_803DDD50 + 0x24);
        if (lo > lbl_803E6844) {
            return 0;
        }
        if (hi >= lbl_803E6844) {
            return 1;
        }
        return 0;
    }
    return 0;
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int ktrex_setScale(int obj) {
    void *p = *(void **)((char *)obj + 0xb8);
    gKTRexRuntime = p;
    return *(s16 *)((char *)p + 0x274);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void ktrex_initialise(void) {
    ktrex_initialiseStateHandlerTables();
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int ktrex_stateHandlerB00(int obj, u8 *p2) {
    if ((s8)p2[0x27a] != 0) {
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E67B8, 0);
    }
    *(f32 *)(p2 + 0x2a0) = lbl_803E6808;
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void ktrex_hitDetect(int obj) {
    f32 z, y, x;
    if (*(void **)((char *)gKTRexState + 0x178) != 0) {
        ObjPath_GetPointWorldPosition(obj, 5, &x, &y, &z, 0);
        modelLightStruct_setPosition(*(void **)((char *)gKTRexState + 0x178), x, y, z);
        modelLightStruct_updateGlowAlpha(*(void **)((char *)gKTRexState + 0x178));
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void ktrex_free(int obj) {
    int i;
    gKTRexRuntime = *(void **)((char *)obj + 0xb8);
    ObjGroup_RemoveObject(obj, 0x3);
    (*(void (**)(int, void *, int))((char *)*gBaddieControlInterface + 0x40))(obj, gKTRexRuntime, 0);
    Stack_Free(*(void **)gKTRexState);
    if (lbl_803DDD48 != 0) {
        Resource_Release(lbl_803DDD48);
    }
    if (*(void **)((char *)gKTRexState + 0x178) != 0) {
        ModelLightStruct_free(*(void **)((char *)gKTRexState + 0x178));
    }
    for (i = 0; i < 5; i++) {
        void *m = *(void **)((char *)gKTRexState + i * 4 + 0x17c);
        if (m != 0) {
            mm_free(m);
        }
    }
    lbl_803DDD48 = 0;
    Music_Trigger(0x28, 0);
    Music_Trigger(0x93, 0);
    Music_Trigger(0x94, 0);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int ktrex_shouldAdvanceArenaPhase(void) {
    int *s = gKTRexState;
    u8 a;
    u8 b;
    int r6;
    r6 = *(u16 *)((char *)s + 0xfa) & 1;
    a = *(u8 *)((char *)s + 0xfe);
    b = *(u8 *)((char *)s + 0xff);
    if ((a & b) != 0) {
        if (r6 != 0) {
            if (*(f32 *)((char *)s + 0x8) < *(f32 *)((char *)s + 0xf4)) {
                return 1;
            }
        } else {
            if (*(f32 *)((char *)s + 0x8) > *(f32 *)((char *)s + 0xf4)) {
                return 1;
            }
        }
        return 0;
    }
    if (r6 != 0) {
        if (a == 8 && (b & 1)) {
            return 1;
        }
        if (a == 2 && (b & 8)) {
            return 1;
        }
        if (a == 4 && (b & 2)) {
            return 1;
        }
        if (a == 1 && (b & 4)) {
            return 1;
        }
        return 0;
    }
    if (a == 1 && (b & 8)) {
        return 1;
    }
    if (a == 4 && (b & 1)) {
        return 1;
    }
    if (a == 2 && (b & 4)) {
        return 1;
    }
    if (a == 8 && (b & 2)) {
        return 1;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void ktrex_initialiseStateHandlerTables(void) {
    gKTRexStateHandlersB[0] = (void *)ktrex_stateHandlerB00;
    gKTRexStateHandlersB[1] = (void *)ktrex_stateHandlerB01;
    gKTRexStateHandlersB[2] = (void *)ktrex_stateHandlerB02;
    gKTRexStateHandlersB[3] = (void *)ktrex_stateHandlerB03;
    gKTRexStateHandlersB[4] = (void *)ktrex_stateHandlerB04;
    gKTRexStateHandlersB[5] = (void *)ktrex_stateHandlerB05;
    gKTRexStateHandlersB[6] = (void *)ktrex_stateHandlerB06;
    gKTRexStateHandlersB[7] = (void *)ktrex_stateHandlerB07;
    gKTRexStateHandlersB[8] = (void *)ktrex_stateHandlerB08;
    gKTRexStateHandlersA[0] = (void *)ktrex_stateHandlerA00;
    gKTRexStateHandlersA[1] = (void *)ktrex_stateHandlerA01;
    gKTRexStateHandlersA[2] = (void *)ktrex_stateHandlerA02;
    gKTRexStateHandlersA[3] = (void *)ktrex_stateHandlerA03;
    gKTRexStateHandlersA[4] = (void *)ktrex_stateHandlerA04;
    gKTRexStateHandlersA[5] = (void *)ktrex_stateHandlerA05;
    gKTRexStateHandlersA[6] = (void *)ktrex_stateHandlerA06;
    gKTRexStateHandlersA[7] = (void *)ktrex_stateHandlerA07;
    gKTRexStateHandlersA[8] = (void *)ktrex_stateHandlerA08;
    gKTRexStateHandlersA[9] = (void *)ktrex_stateHandlerA09;
    gKTRexStateHandlersA[10] = (void *)ktrex_stateHandlerA10;
    gKTRexStateHandlersA[11] = (void *)ktrex_stateHandlerA11;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
int ktrex_updateArenaPathProgress(int obj) {
    u16 flags;
    int phase;
    int dir;
    f32 speed;
    int changed;

    changed = 0;
    flags = *(u16 *)((char *)gKTRexState + 0xfa);
    dir = flags & 1;
    phase = (flags >> 1) & 3;
    if (dir != 0) {
        speed = -*(f32 *)((char *)obj + 0x294);
    } else {
        speed = *(f32 *)((char *)obj + 0x294);
    }
    *(f32 *)((char *)gKTRexState + 8) = speed * timeDelta + *(f32 *)((char *)gKTRexState + 8);
    if ((*(f32 *)((char *)gKTRexState + 8) > lbl_8032A540[*(u8 *)((char *)gKTRexState + 0xfc)] && speed > lbl_803E67B8) ||
        (*(f32 *)((char *)gKTRexState + 8) < lbl_8032A534[*(u8 *)((char *)gKTRexState + 0xfc)] && speed < lbl_803E67B8)) {
        if (dir != 0) {
            phase--;
            if (phase < 0) {
                phase = 3;
            }
        } else {
            phase++;
            if (phase >= 4) {
                phase = 0;
            }
        }
        *(u16 *)((char *)gKTRexState + 0xfa) = *(u16 *)((char *)gKTRexState + 0xfa) & ~6;
        *(u16 *)((char *)gKTRexState + 0xfa) = *(u16 *)((char *)gKTRexState + 0xfa) | (phase << 1);
        if (*(f32 *)((char *)gKTRexState + 8) > lbl_8032A540[*(u8 *)((char *)gKTRexState + 0xfc)]) {
            *(f32 *)((char *)gKTRexState + 8) = lbl_8032A540[*(u8 *)((char *)gKTRexState + 0xfc)];
        } else if (*(f32 *)((char *)gKTRexState + 8) < lbl_8032A534[*(u8 *)((char *)gKTRexState + 0xfc)]) {
            *(f32 *)((char *)gKTRexState + 8) = lbl_8032A534[*(u8 *)((char *)gKTRexState + 0xfc)];
        }
        changed = 1;
    }
    *(f32 *)((char *)gKTRexState + 0xe8) = *(f32 *)((char *)gKTRexState + 8) * (((f32 *)*(int *)((char *)gKTRexState + 0xdc))[phase] - ((f32 *)*(int *)((char *)gKTRexState + 0xd0))[phase]) + ((f32 *)*(int *)((char *)gKTRexState + 0xd0))[phase];
    *(f32 *)((char *)gKTRexState + 0xec) = *(f32 *)((char *)gKTRexState + 8) * (((f32 *)*(int *)((char *)gKTRexState + 0xe0))[phase] - ((f32 *)*(int *)((char *)gKTRexState + 0xd4))[phase]) + ((f32 *)*(int *)((char *)gKTRexState + 0xd4))[phase];
    *(f32 *)((char *)gKTRexState + 0xf0) = *(f32 *)((char *)gKTRexState + 8) * (((f32 *)*(int *)((char *)gKTRexState + 0xe4))[phase] - ((f32 *)*(int *)((char *)gKTRexState + 0xd8))[phase]) + ((f32 *)*(int *)((char *)gKTRexState + 0xd8))[phase];
    return changed;
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void ktrex_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible) {
    f32 m[12];
    void *e;
    int i;

    gKTRexRuntime = *(void **)((char *)obj + 0xb8);
    if (visible == 0) {
        return;
    }
    if (*(int *)((char *)obj + 0xf4) != 0) {
        return;
    }
    if (*(void **)((char *)gKTRexState + 0x178) != NULL) {
        queueGlowRender(*(void **)((char *)gKTRexState + 0x178));
    }
    for (i = 0; i < 5; i++) {
        e = *(void **)((char *)gKTRexState + 380 + i * 4);
        if (e != NULL) {
            renderFn_8008f904(e);
            *(u16 *)((char *)*(void **)((char *)gKTRexState + 380 + i * 4) + 0x20) =
                (f32)(u32)*(u16 *)((char *)*(void **)((char *)gKTRexState + 380 + i * 4) + 0x20) + timeDelta;
            if (*(u16 *)((char *)*(void **)((char *)gKTRexState + 380 + i * 4) + 0x20) >=
                *(u16 *)((char *)*(void **)((char *)gKTRexState + 380 + i * 4) + 0x22)) {
                mm_free(*(void **)((char *)gKTRexState + 380 + i * 4));
                *(int *)((char *)gKTRexState + 380 + i * 4) = 0;
            }
        }
    }
    if (*(f32 *)((char *)gKTRexRuntime + 0x3e8) != lbl_803E67B8) {
        fn_8003B5E0(200, 0, 0, (int)*(f32 *)((char *)gKTRexRuntime + 0x3e8));
    }
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E6818);
    ObjPath_GetPointWorldPosition((int)obj, 1, (f32 *)((char *)gKTRexState + 0x130), (f32 *)((char *)gKTRexState + 0x134), (f32 *)((char *)gKTRexState + 0x138), 0);
    ObjPath_GetPointWorldPosition((int)obj, 2, (f32 *)((char *)gKTRexState + 0x148), (f32 *)((char *)gKTRexState + 0x14c), (f32 *)((char *)gKTRexState + 0x150), 0);
    ObjPath_GetPointWorldPosition((int)obj, 3, (f32 *)((char *)gKTRexState + 0x160), (f32 *)((char *)gKTRexState + 0x164), (f32 *)((char *)gKTRexState + 0x168), 0);
    ObjPath_GetPointWorldPosition((int)obj, 0, (f32 *)((char *)gKTRexState + 0x118), (f32 *)((char *)gKTRexState + 0x11c), (f32 *)((char *)gKTRexState + 0x120), 0);
    memcpy(m, ObjPath_GetPointModelMtx((int)obj, 4), 48);
    *(f32 *)((char *)gKTRexState + 0x16c) = lbl_803E67B4 * (f32)(int)randomGetRange(-50, 50);
    *(f32 *)((char *)gKTRexState + 0x170) = lbl_803E67B4 * (f32)(int)randomGetRange(60, 120);
    *(f32 *)((char *)gKTRexState + 0x174) = lbl_803E6848 * (f32)(int)randomGetRange(100, 150);
    PSMTXMultVecSR(m, (f32 *)((char *)gKTRexState + 0x16c), (f32 *)((char *)gKTRexState + 0x16c));
    *(int *)((char *)gKTRexState + 0x104) |= 0x100000;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void ktrex_update(int obj) {
    void *runtime;
    void *player;
    f32 d[3];
    u32 tmp;
    u8 maskA;
    u8 maskB;
    u8 flags;
    int phase;
    int i;
    f32 dz, dx;

    if (*(int *)((char *)obj + 0xf4) != 0) {
        return;
    }
    runtime = *(void **)((char *)obj + 0xb8);
    gKTRexRuntime = runtime;
    if (*(int *)((char *)obj + 0xf8) == 1) {
        Music_Trigger(40, 1);
        *(int *)((char *)obj + 0xf8) = 2;
        *(s16 *)((char *)runtime + 0x270) = 11;
        *(u8 *)((char *)runtime + 0x27b) = 1;
    }
    ObjHits_RegisterActiveHitVolumeObject(obj);
    *(void **)((char *)runtime + 0x2d0) = Obj_GetPlayerObject();
    if (*(void **)((char *)runtime + 0x2d0) != NULL) {
        player = *(void **)((char *)runtime + 0x2d0);
        d[0] = *(f32 *)((char *)player + 0x18) - *(f32 *)((char *)obj + 0x18);
        d[1] = *(f32 *)((char *)player + 0x1c) - *(f32 *)((char *)obj + 0x1c);
        d[2] = *(f32 *)((char *)player + 0x20) - *(f32 *)((char *)obj + 0x20);
        *(f32 *)((char *)runtime + 0x2c0) = sqrtf(d[2] * d[2] + (d[0] * d[0] + d[1] * d[1]));
    }
    characterDoEyeAnims(obj, (char *)gKTRexRuntime + 0x3ac);
    maskA = 0;
    for (i = 0; i < 4; i++) {
        if (GameBit_Get(lbl_803DC290[i]) != 0) {
            maskA |= 1 << i;
        }
    }
    *(u8 *)((char *)gKTRexState + 0xff) = maskA;
    player = *(void **)((char *)runtime + 0x2d0);
    phase = (*(u16 *)((char *)gKTRexState + 0xfa) >> 1) & 3;
    dz = ((f32 *)*(int *)((char *)gKTRexState + 0xdc))[phase] - ((f32 *)*(int *)((char *)gKTRexState + 0xd0))[phase];
    dx = ((f32 *)*(int *)((char *)gKTRexState + 0xe4))[phase] - ((f32 *)*(int *)((char *)gKTRexState + 0xd8))[phase];
    if ((f32)__fabs(dz) > (f32)__fabs(dx)) {
        *(f32 *)((char *)gKTRexState + 0xf4) =
            (*(f32 *)((char *)player + 0xc) - ((f32 *)*(int *)((char *)gKTRexState + 0xd0))[phase]) / dz;
    } else {
        *(f32 *)((char *)gKTRexState + 0xf4) =
            (*(f32 *)((char *)player + 0x14) - ((f32 *)*(int *)((char *)gKTRexState + 0xd8))[phase]) / dx;
    }
    tmp = lbl_803E67B0;
    *(u8 *)((char *)gKTRexState + 0xfe) = ((u8 *)&tmp)[(*(u16 *)((char *)gKTRexState + 0xfa) >> 1) & 3];
    flags = *(u8 *)((char *)gKTRexState + 0xfe);
    maskB = 0;
    for (i = 0; i < 4; i++) {
        if ((flags & (1 << i)) != 0 && GameBit_Get(lbl_803DC298[i]) != 0) {
            maskB |= 1 << i;
        }
    }
    *(u8 *)((char *)gKTRexState + 0x100) = maskB;
    (*(void (**)(int, void *, void *, int, void *, int, int, int))((char *)*gBaddieControlInterface + 0x54))(
        obj, runtime, (char *)gKTRexRuntime + 0x35c, *(s16 *)((char *)gKTRexRuntime + 0x3f4),
        (char *)gKTRexRuntime + 0x405, 2, 2, 0);
    ktrex_updateContactEffects(obj, runtime);
    ktrex_updateAttackEffects(obj);
    (*(void (**)(int, void *, int, f32))((char *)*gBaddieControlInterface + 0x2c))(obj, runtime, 0, lbl_803E67B8);
    ObjHits_SetHitVolumeMasks(obj, 24, 2, 0x1fffff);
    (*(void (**)(int, void *, f32, f32, void **, void *))((char *)*gPlayerInterface + 0x8))(
        obj, runtime, timeDelta, timeDelta, gKTRexStateHandlersB, gKTRexStateHandlersA);
    *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)gKTRexState + 0xec);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int ktrex_stateHandlerB05(int obj, int runtime) {
    f32 z;
    if ((s8)*(u8 *)((char *)runtime + 0x27a) != 0) {
        ObjAnim_SetCurrentMove(obj, (&lbl_803DC250)[*(u8 *)((char *)gKTRexState + 0xfc)], lbl_803E67B8, 0);
        *(f32 *)((char *)runtime + 0x2a0) = lbl_803E6810;
        z = lbl_803E67B8;
        *(f32 *)((char *)runtime + 0x280) = z;
        *(f32 *)((char *)runtime + 0x284) = z;
    }
    if ((*(int *)((char *)gKTRexRuntime + 0x314) & 1) != 0) {
        *(int *)((char *)gKTRexRuntime + 0x314) &= ~1;
        *(int *)((char *)gKTRexState + 0x104) |= 0x200;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int ktrex_stateHandlerB07(int obj, int runtime) {
    if ((s8)*(u8 *)((char *)runtime + 0x27a) != 0) {
        ObjAnim_SetCurrentMove(obj, 12, lbl_803E67B8, 0);
        *(f32 *)((char *)runtime + 0x2a0) = lbl_803E6808;
    }
    if ((*(int *)((char *)gKTRexRuntime + 0x314) & 1) != 0) {
        *(int *)((char *)gKTRexRuntime + 0x314) &= ~1;
        *(int *)((char *)gKTRexState + 0x104) |= 0x2000;
    }
    if ((*(int *)((char *)gKTRexRuntime + 0x314) & 0x80) != 0) {
        *(int *)((char *)gKTRexRuntime + 0x314) &= ~0x80;
        *(int *)((char *)gKTRexState + 0x104) |= 0x40000;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int ktrex_stateHandlerB08(int obj, int runtime) {
    if ((s8)*(u8 *)((char *)runtime + 0x27a) != 0) {
        ObjAnim_SetCurrentMove(obj, 13, lbl_803E67B8, 0);
        *(f32 *)((char *)runtime + 0x2a0) =
            lbl_803E67F4 + lbl_803E67F8 * (f32)(int)(*(u8 *)((char *)gKTRexState + 0x101) >> 1);
        Sfx_PlayFromObject(obj, SFXmv_cagesqk11);
    }
    if ((*(int *)((char *)gKTRexRuntime + 0x314) & 1) != 0) {
        *(int *)((char *)gKTRexRuntime + 0x314) &= ~1;
        *(int *)((char *)gKTRexState + 0x104) |= 0x2000;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int ktrex_stateHandlerB06(int obj, int runtime) {
    f32 z;
    if ((s8)*(u8 *)((char *)runtime + 0x27a) != 0) {
        ObjAnim_SetCurrentMove(obj, 11, lbl_803E67B8, 0);
        Sfx_PlayFromObject(obj, 1108);
        *(f32 *)((char *)runtime + 0x2a0) = lbl_803E680C;
        z = lbl_803E67B8;
        *(f32 *)((char *)runtime + 0x280) = z;
        *(f32 *)((char *)runtime + 0x284) = z;
    }
    if ((*(int *)((char *)gKTRexRuntime + 0x314) & 1) != 0) {
        *(int *)((char *)gKTRexRuntime + 0x314) &= ~1;
        *(int *)((char *)gKTRexState + 0x104) |= 0x80000;
    }
    if ((*(int *)((char *)gKTRexRuntime + 0x314) & 0x80) != 0) {
        *(int *)((char *)gKTRexRuntime + 0x314) &= ~0x80;
        *(int *)((char *)gKTRexState + 0x104) |= 0x20000;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int ktrex_stateHandlerB03(int obj, int runtime) {
    f32 z;
    u16 dir;
    dir = *(u16 *)((char *)gKTRexState + 0xfa) & 1;
    if ((s8)*(u8 *)((char *)runtime + 0x27a) != 0) {
        ObjAnim_SetCurrentMove(obj, 15, lbl_803E67B8, 0);
        *(f32 *)((char *)runtime + 0x2a0) = lbl_803E6810;
        z = lbl_803E67B8;
        *(f32 *)((char *)runtime + 0x280) = z;
        *(f32 *)((char *)runtime + 0x284) = z;
        *(s16 *)((char *)gKTRexState + 0xf8) = *(s16 *)obj;
    }
    if (dir != 0) {
        *(s16 *)obj = lbl_803E6814 * *(f32 *)((char *)obj + 0x98) + (f32)(int)*(s16 *)((char *)gKTRexState + 0xf8);
    } else {
        *(s16 *)obj = (f32)(int)*(s16 *)((char *)gKTRexState + 0xf8) - lbl_803E6814 * *(f32 *)((char *)obj + 0x98);
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int ktrex_stateHandlerB04(int obj, int runtime) {
    f32 z;
    u16 mask;
    if ((s8)*(u8 *)((char *)runtime + 0x27a) != 0) {
        ObjAnim_SetCurrentMove(obj, (&lbl_803DC260)[*(u8 *)((char *)gKTRexState + 0xfd)], lbl_803E67B8, 0);
        *(f32 *)((char *)runtime + 0x2a0) = lbl_8032A51C[*(u8 *)((char *)gKTRexState + 0xfd)];
        z = lbl_803E67B8;
        *(f32 *)((char *)runtime + 0x280) = z;
        *(f32 *)((char *)runtime + 0x284) = z;
    }
    mask = (&lbl_803DC288)[*(u8 *)((char *)gKTRexState + 0xfd)];
    if ((*(int *)((char *)gKTRexRuntime + 0x314) & 1) != 0) {
        *(int *)((char *)gKTRexRuntime + 0x314) &= ~1;
        *(int *)((char *)gKTRexState + 0x104) |= mask;
    }
    if ((*(int *)((char *)gKTRexRuntime + 0x314) & 0x200) != 0) {
        *(int *)((char *)gKTRexRuntime + 0x314) &= ~0x200;
        *(int *)((char *)gKTRexState + 0x104) |= 0x800;
    }
    if ((*(int *)((char *)gKTRexRuntime + 0x314) & 0x400) != 0) {
        *(int *)((char *)gKTRexRuntime + 0x314) &= ~0x400;
        *(int *)((char *)gKTRexState + 0x104) |= 0x1000;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int ktrex_stateHandlerB01(int obj, int runtime) {
    f32 z;
    u16 mask;
    f32 dx;
    f32 dz;
    if ((s8)*(u8 *)((char *)runtime + 0x27a) != 0) {
        ObjAnim_SetCurrentMove(obj, (&lbl_803DC258)[*(u8 *)((char *)gKTRexState + 0xfc)], lbl_803E67B8, 0);
        z = lbl_803E67B8;
        *(f32 *)((char *)runtime + 0x280) = z;
        *(f32 *)((char *)runtime + 0x284) = z;
    }
    mask = (&lbl_803DC268)[*(u8 *)((char *)gKTRexState + 0xfc)];
    if ((*(int *)((char *)gKTRexRuntime + 0x314) & 4) != 0) {
        *(int *)((char *)gKTRexRuntime + 0x314) &= ~4;
        *(int *)((char *)gKTRexState + 0x104) |= mask;
    }
    mask = (&lbl_803DC270)[*(u8 *)((char *)gKTRexState + 0xfc)];
    if ((*(int *)((char *)gKTRexRuntime + 0x314) & 2) != 0) {
        *(int *)((char *)gKTRexRuntime + 0x314) &= ~2;
        *(int *)((char *)gKTRexState + 0x104) |= mask;
    }
    if (*(u8 *)((char *)gKTRexState + 0x108) != 0) {
        mask = (&lbl_803DC278)[*(u8 *)((char *)gKTRexState + 0xfc)];
    } else {
        mask = (&lbl_803DC280)[*(u8 *)((char *)gKTRexState + 0xfc)];
    }
    if ((*(int *)((char *)gKTRexRuntime + 0x314) & 1) != 0) {
        *(int *)((char *)gKTRexRuntime + 0x314) &= ~1;
        *(int *)((char *)gKTRexState + 0x104) |= mask;
    }
    dx = oneOverTimeDelta * (*(f32 *)((char *)gKTRexState + 0xe8) - *(f32 *)((char *)obj + 0xc));
    dz = oneOverTimeDelta * (*(f32 *)((char *)gKTRexState + 0xf0) - *(f32 *)((char *)obj + 0x14));
    ObjAnim_SampleRootCurvePhase(sqrtf(dx * dx + dz * dz), (ObjAnimComponent *)obj, (f32 *)((char *)runtime + 0x2a0));
    *(f32 *)((char *)obj + 0xc) = *(f32 *)((char *)gKTRexState + 0xe8);
    *(f32 *)((char *)obj + 0x14) = *(f32 *)((char *)gKTRexState + 0xf0);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int ktrex_stateHandlerB02(int obj, int runtime) {
    u16 dir;
    f32 tmpY;
    ObjPosParams pos;
    f32 mtx[16];

    dir = *(u16 *)((char *)gKTRexState + 0xfa) & 1;
    if ((s8)*(u8 *)((char *)runtime + 0x27a) != 0) {
        ObjAnim_SetCurrentMove(obj, lbl_8032A510[*(u8 *)((char *)gKTRexState + 0xfc) * 2 + dir], lbl_803E67B8, 0);
        *(f32 *)((char *)runtime + 0x2a0) = lbl_8032A528[*(u8 *)((char *)gKTRexState + 0xfc)];
        *(s16 *)((char *)gKTRexState + 0xf8) = *(s16 *)obj;
    }
    if ((*(int *)((char *)gKTRexRuntime + 0x314) & 4) != 0) {
        *(int *)((char *)gKTRexRuntime + 0x314) &= ~4;
        *(int *)((char *)gKTRexState + 0x104) |= 1;
    }
    if ((*(int *)((char *)gKTRexRuntime + 0x314) & 2) != 0) {
        *(int *)((char *)gKTRexRuntime + 0x314) &= ~2;
        *(int *)((char *)gKTRexState + 0x104) |= 2;
    }
    if ((*(int *)((char *)gKTRexRuntime + 0x314) & 1) != 0) {
        *(int *)((char *)gKTRexRuntime + 0x314) &= ~1;
        *(int *)((char *)gKTRexState + 0x104) |= 0x40;
    }
    if ((*(int *)((char *)gKTRexRuntime + 0x314) & 0x80) != 0) {
        *(int *)((char *)gKTRexRuntime + 0x314) &= ~0x80;
        *(int *)((char *)gKTRexState + 0x104) |= 0x10000;
    }
    *(s8 *)((char *)runtime + 0x34c) |= 1;
    (*(void (**)(int, int, f32, int))((char *)*gPlayerInterface + 0x20))(obj, runtime, timeDelta, 3);
    pos.rx = *(s16 *)((char *)gKTRexState + 0xf8);
    pos.ry = 0;
    pos.rz = 0;
    pos.scale = lbl_803E6818;
    pos.x = lbl_803E67B8;
    pos.y = lbl_803E67B8;
    pos.z = lbl_803E67B8;
    setMatrixFromObjectPos(mtx, &pos);
    Matrix_TransformPoint(mtx, *(f32 *)((char *)runtime + 0x284), lbl_803E67B8, -*(f32 *)((char *)runtime + 0x280),
                          (f32 *)((char *)obj + 0x24), &tmpY, (f32 *)((char *)obj + 0x2c));
    if (dir != 0) {
        *(s16 *)obj = lbl_803E681C * *(f32 *)((char *)obj + 0x98) + (f32)(int)*(s16 *)((char *)gKTRexState + 0xf8);
    } else {
        *(s16 *)obj = (f32)(int)*(s16 *)((char *)gKTRexState + 0xf8) - lbl_803E681C * *(f32 *)((char *)obj + 0x98);
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void ktrex_init(int obj, char *arg) {
    int i;
    int cp;
    gKTRexRuntime = *(void **)((char *)obj + 0xb8);
    (*(void (**)(int, char *, void *, int, int, int, int, f32))((char *)*gBaddieControlInterface + 0x58))(
        obj, arg, gKTRexRuntime, 9, 0xc, 0x100, 0x10 | (arg != 0), lbl_803E684C);
    *(void **)((char *)obj + 0xbc) = (void *)ktrex_animEventCallback;
    (*(void (**)(int, void *, int))((char *)*gPlayerInterface + 0x14))(obj, gKTRexRuntime, 0);
    *(s16 *)((char *)gKTRexRuntime + 0x270) = 2;
    *(int *)((char *)gKTRexRuntime + 0x2d0) = 0;
    *(u8 *)((char *)gKTRexRuntime + 0x25f) = 0;
    *(u8 *)((char *)gKTRexRuntime + 0x349) = 0;
    *(u8 *)((char *)obj + 0xaf) |= 0x88;
    ObjHits_EnableObject(obj);
    if (*(int *)((char *)obj + 0x64) != 0) {
        *(int *)(*(int *)((char *)obj + 0x64) + 0x30) |= 0x810;
    }
    gKTRexState = *(void **)((char *)gKTRexRuntime + 0x40c);
    *(int *)gKTRexState = allocModelStruct_800139e8(4, 4);
    *(s16 *)obj = (s16)((s8)arg[0x2a] << 8);
    *(s16 *)((char *)gKTRexState + 0xf8) = (s16)((s8)arg[0x2a] << 8);
    for (i = 0; i < 4; i++) {
        cp = (*(int (**)(int))((char *)*gRomCurveInterface + 0x1c))(*(int *)((char *)lbl_8032A510 + 0x4c + i * 4));
        if (cp != 0) {
            *(f32 *)((char *)gKTRexState + i * 4 + 0x10) = *(f32 *)((char *)cp + 0x8);
            *(f32 *)((char *)gKTRexState + i * 4 + 0x20) = *(f32 *)((char *)cp + 0xc);
            *(f32 *)((char *)gKTRexState + i * 4 + 0x30) = *(f32 *)((char *)cp + 0x10);
            cp = (*(int (**)(int))((char *)*gRomCurveInterface + 0x1c))(*(int *)((char *)lbl_8032A510 + 0x3c + i * 4));
            *(f32 *)((char *)gKTRexState + i * 4 + 0x40) = *(f32 *)((char *)cp + 0x8);
            *(f32 *)((char *)gKTRexState + i * 4 + 0x50) = *(f32 *)((char *)cp + 0xc);
            *(f32 *)((char *)gKTRexState + i * 4 + 0x60) = *(f32 *)((char *)cp + 0x10);
            cp = (*(int (**)(int))((char *)*gRomCurveInterface + 0x1c))(*(int *)((char *)lbl_8032A510 + 0x6c + i * 4));
            *(f32 *)((char *)gKTRexState + i * 4 + 0x70) = *(f32 *)((char *)cp + 0x8);
            *(f32 *)((char *)gKTRexState + i * 4 + 0x80) = *(f32 *)((char *)cp + 0xc);
            *(f32 *)((char *)gKTRexState + i * 4 + 0x90) = *(f32 *)((char *)cp + 0x10);
            cp = (*(int (**)(int))((char *)*gRomCurveInterface + 0x1c))(*(int *)((char *)lbl_8032A510 + 0x5c + i * 4));
            *(f32 *)((char *)gKTRexState + i * 4 + 0xa0) = *(f32 *)((char *)cp + 0x8);
            *(f32 *)((char *)gKTRexState + i * 4 + 0xb0) = *(f32 *)((char *)cp + 0xc);
            *(f32 *)((char *)gKTRexState + i * 4 + 0xc0) = *(f32 *)((char *)cp + 0x10);
        }
    }
    *(void **)((char *)gKTRexState + 0xd0) = (char *)gKTRexState + 0x10;
    *(void **)((char *)gKTRexState + 0xd4) = (char *)gKTRexState + 0x20;
    *(void **)((char *)gKTRexState + 0xd8) = (char *)gKTRexState + 0x30;
    *(void **)((char *)gKTRexState + 0xdc) = (char *)gKTRexState + 0x40;
    *(void **)((char *)gKTRexState + 0xe0) = (char *)gKTRexState + 0x50;
    *(void **)((char *)gKTRexState + 0xe4) = (char *)gKTRexState + 0x60;
    *(u8 *)((char *)gKTRexState + 0x102) = 4;
    *(u8 *)((char *)gKTRexRuntime + 0x354) = 3;
    lbl_803DDD48 = (void *)Resource_Acquire(0x5a, 1);
    *(int *)((char *)obj + 0xf8) = 0;
    lbl_803DDD50 = (void *)mapBlockFn_800592e4();
    *(void **)((char *)gKTRexState + 0x178) = objCreateLight(0, 1);
    if (*(void **)((char *)gKTRexState + 0x178) != 0) {
        modelLightStruct_setLightKind(*(void **)((char *)gKTRexState + 0x178), 2);
        modelLightStruct_setPosition(*(void **)((char *)gKTRexState + 0x178), *(f32 *)((char *)obj + 0xc),
            *(f32 *)((char *)obj + 0x10), *(f32 *)((char *)obj + 0x14));
        modelLightStruct_setDiffuseColor(*(void **)((char *)gKTRexState + 0x178), 0xff, 0, 0, 0);
        modelLightStruct_setDistanceAttenuation(*(void **)((char *)gKTRexState + 0x178), lbl_803E6850, lbl_803E67F0);
        modelLightStruct_setupGlow(*(void **)((char *)gKTRexState + 0x178), 0, 0xff, 0, 0, 0x50, lbl_803E67F0);
        modelLightStruct_setGlowProjectionRadius(*(void **)((char *)gKTRexState + 0x178), lbl_803E67BC);
    }
    streamFn_8000a380(3, 2, 0x1f4);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void ktrex_updateAttackEffects(int obj) {
    int i;
    f32 mag;
    mag = lbl_803E6818 - *(f32 *)((char *)gKTRexRuntime + 0x2c0) / lbl_803E6824;
    if (mag < lbl_803E67B8) {
        mag = lbl_803E67B8;
    } else if (mag > lbl_803E6818) {
        mag = lbl_803E6818;
    }
    if ((*(u32 *)((char *)gKTRexState + 0x104) & 0x40) != 0) {
        Sfx_PlayFromObject(obj, SFXmv_bodyf4_c);
    }
    if ((*(u32 *)((char *)gKTRexState + 0x104) & 0x80) != 0) {
        Sfx_PlayFromObject(obj, SFXmv_cagerat01);
    }
    if ((*(u32 *)((char *)gKTRexState + 0x104) & 0x100) != 0) {
        Sfx_PlayFromObject(obj, SFXmv_cagesqk11);
    }
    if ((*(u32 *)((char *)gKTRexState + 0x104) & 0x200) != 0) {
        Sfx_PlayFromObject(obj, SFXmv_canras_c);
    }
    if ((*(u32 *)((char *)gKTRexState + 0x104) & 0x10000) != 0) {
        Sfx_PlayFromObject(obj, SFXmv_cogstr_c);
    }
    if ((*(u32 *)((char *)gKTRexState + 0x104) & 0x40000) != 0) {
        Sfx_PlayFromObject(obj, SFXmv_curtainopen16);
    }
    if ((*(u32 *)((char *)gKTRexState + 0x104) & 0x80000) != 0) {
        Sfx_PlayFromObject(obj, SFXmv_deaththud16);
    }
    if ((*(u32 *)((char *)gKTRexState + 0x104) & 0x2000) != 0) {
        Sfx_PlayFromObject(obj, SFXmv_deaththud16);
    }
    if ((*(u32 *)((char *)gKTRexState + 0x104) & 0x1000) != 0) {
        *(u32 *)((char *)gKTRexState + 0x104) &= ~0x1800;
    }
    if ((*(u32 *)((char *)gKTRexState + 0x104) & 0x20000) != 0) {
        Sfx_PlayFromObject(obj, SFXmv_cogstr_c);
        Camera_EnableViewYOffset();
        CameraShake_SetAllMagnitudes(lbl_803E67C8 * mag);
    }
    if ((*(u16 *)((char *)gKTRexState + 0xfa) & 0x10) != 0) {
        for (i = 0; i < 5; i++) {
            if (randomGetRange(0, 5) == 0 && *(int *)((char *)gKTRexState + i * 4 + 0x17c) == 0) {
                ktrex_spawnRandomEnergyArc(obj, randomGetRange(8, 0xc), i);
            }
        }
    }
    if ((*(u32 *)((char *)gKTRexState + 0x104) & 0x4000) != 0) {
        Sfx_PlayFromObject(obj, SFXmv_dive4_c);
        *(u8 *)((char *)gKTRexState + 0x108) ^= 1;
    }
    if ((*(u32 *)((char *)gKTRexState + 0x104) & 0x8000) != 0) {
        Sfx_PlayFromObject(obj, SFXmv_gdtur2_c);
        *(u8 *)((char *)gKTRexState + 0x108) ^= 1;
    }
    if ((*(u32 *)((char *)gKTRexState + 0x104) & 0x3) != 0) {
        Sfx_PlayFromObject(obj, SFXmv_icesmash16);
        doRumble(lbl_803E67CC);
        if (mag > lbl_803E67B4) {
            Camera_EnableViewYOffset();
            CameraShake_SetAllMagnitudes(mag);
            GameBit_Set(0x554, 1);
        }
    }
    if ((*(u32 *)((char *)gKTRexState + 0x104) & 0xc) != 0) {
        doRumble(lbl_803E682C);
        Sfx_PlayFromObject(obj, SFXmv_ladderslide16);
        if (mag > lbl_803E67B4) {
            Camera_EnableViewYOffset();
            CameraShake_SetAllMagnitudes(lbl_803E67C8 * mag);
            GameBit_Set(0x554, 1);
        }
    }
    if ((*(u32 *)((char *)gKTRexState + 0x104) & 0x30) != 0) {
        doRumble(lbl_803E6830);
        Sfx_PlayFromObject(obj, SFXmv_persquk1);
        if (mag > lbl_803E67B4) {
            Camera_EnableViewYOffset();
            CameraShake_SetAllMagnitudes(lbl_803E6834 * mag);
            GameBit_Set(0x554, 1);
        }
    }
    if ((*(u32 *)((char *)gKTRexState + 0x104) & 0x100000) == 0) {
        *(u32 *)((char *)gKTRexState + 0x104) &= 0x1800;
        return;
    }
    if ((*(u32 *)((char *)gKTRexState + 0x104) & 0x1) != 0) {
        *(f32 *)((char *)gKTRexState + 0x12c) = lbl_803E6818;
        for (i = 0; i < 10; i++) {
            (*(void (**)(int, int, void *, int, int, int))((char *)*gPartfxInterface + 0x8))(obj, 0x483, (char *)gKTRexState + 0x124, 0x200001, -1, 0);
            (*(void (**)(int, int, void *, int, int, int))((char *)*gPartfxInterface + 0x8))(obj, 0x483, (char *)gKTRexState + 0x124, 0x200001, -1, 0);
            (*(void (**)(int, int, void *, int, int, int))((char *)*gPartfxInterface + 0x8))(obj, 0x484, (char *)gKTRexState + 0x124, 0x200001, -1, 0);
        }
    }
    if ((*(u32 *)((char *)gKTRexState + 0x104) & 0x2) != 0) {
        *(f32 *)((char *)gKTRexState + 0x144) = lbl_803E6818;
        for (i = 0; i < 10; i++) {
            (*(void (**)(int, int, void *, int, int, int))((char *)*gPartfxInterface + 0x8))(obj, 0x483, (char *)gKTRexState + 0x13c, 0x200001, -1, 0);
            (*(void (**)(int, int, void *, int, int, int))((char *)*gPartfxInterface + 0x8))(obj, 0x483, (char *)gKTRexState + 0x13c, 0x200001, -1, 0);
            (*(void (**)(int, int, void *, int, int, int))((char *)*gPartfxInterface + 0x8))(obj, 0x484, (char *)gKTRexState + 0x13c, 0x200001, -1, 0);
        }
    }
    if ((*(u32 *)((char *)gKTRexState + 0x104) & 0x4) != 0) {
        *(f32 *)((char *)gKTRexState + 0x12c) = lbl_803E6838;
        for (i = 0; i < 13; i++) {
            (*(void (**)(int, int, void *, int, int, int))((char *)*gPartfxInterface + 0x8))(obj, 0x483, (char *)gKTRexState + 0x124, 0x200001, -1, 0);
            (*(void (**)(int, int, void *, int, int, int))((char *)*gPartfxInterface + 0x8))(obj, 0x483, (char *)gKTRexState + 0x124, 0x200001, -1, 0);
            (*(void (**)(int, int, void *, int, int, int))((char *)*gPartfxInterface + 0x8))(obj, 0x484, (char *)gKTRexState + 0x124, 0x200001, -1, 0);
        }
    }
    if ((*(u32 *)((char *)gKTRexState + 0x104) & 0x8) != 0) {
        *(f32 *)((char *)gKTRexState + 0x144) = lbl_803E6838;
        for (i = 0; i < 13; i++) {
            (*(void (**)(int, int, void *, int, int, int))((char *)*gPartfxInterface + 0x8))(obj, 0x483, (char *)gKTRexState + 0x13c, 0x200001, -1, 0);
            (*(void (**)(int, int, void *, int, int, int))((char *)*gPartfxInterface + 0x8))(obj, 0x483, (char *)gKTRexState + 0x13c, 0x200001, -1, 0);
            (*(void (**)(int, int, void *, int, int, int))((char *)*gPartfxInterface + 0x8))(obj, 0x484, (char *)gKTRexState + 0x13c, 0x200001, -1, 0);
        }
    }
    if ((*(u32 *)((char *)gKTRexState + 0x104) & 0x10) != 0) {
        *(f32 *)((char *)gKTRexState + 0x12c) = lbl_803E67C8;
        for (i = 0; i < 16; i++) {
            (*(void (**)(int, int, void *, int, int, int))((char *)*gPartfxInterface + 0x8))(obj, 0x483, (char *)gKTRexState + 0x124, 0x200001, -1, 0);
            (*(void (**)(int, int, void *, int, int, int))((char *)*gPartfxInterface + 0x8))(obj, 0x483, (char *)gKTRexState + 0x124, 0x200001, -1, 0);
            (*(void (**)(int, int, void *, int, int, int))((char *)*gPartfxInterface + 0x8))(obj, 0x484, (char *)gKTRexState + 0x124, 0x200001, -1, 0);
        }
    }
    if ((*(u32 *)((char *)gKTRexState + 0x104) & 0x20) != 0) {
        *(f32 *)((char *)gKTRexState + 0x144) = lbl_803E67C8;
        for (i = 0; i < 16; i++) {
            (*(void (**)(int, int, void *, int, int, int))((char *)*gPartfxInterface + 0x8))(obj, 0x483, (char *)gKTRexState + 0x13c, 0x200001, -1, 0);
            (*(void (**)(int, int, void *, int, int, int))((char *)*gPartfxInterface + 0x8))(obj, 0x483, (char *)gKTRexState + 0x13c, 0x200001, -1, 0);
            (*(void (**)(int, int, void *, int, int, int))((char *)*gPartfxInterface + 0x8))(obj, 0x484, (char *)gKTRexState + 0x13c, 0x200001, -1, 0);
        }
    }
    if ((*(u32 *)((char *)gKTRexState + 0x104) & 0x800) != 0) {
        (*(void (**)(int, int, void *, int, int, void *))((char *)*gPartfxInterface + 0x8))(
            obj, 0x487, (char *)gKTRexState + 0x10c, 0x200001, -1, (char *)gKTRexState + 0x16c);
    }
    *(u32 *)((char *)gKTRexState + 0x104) &= 0x1800;
    if (*(int *)(*(int *)((char *)obj + 0x54) + 0x50) == (int)Obj_GetPlayerObject()) {
        Sfx_PlayFromObject((int)Obj_GetPlayerObject(), SFXbaddie_haga_talk1);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void ktrex_updateContactEffects(int obj, void *runtime) {
    int hitA;
    int hitC;
    int hitType;
    int msg[4];
    int hit;
    int row;
    f32 *pt;
    msg[0] = lbl_802C2550[0];
    msg[1] = lbl_802C2550[1];
    msg[2] = lbl_802C2550[2];
    msg[3] = lbl_802C2550[3];
    if (lbl_803DDD4C != 0) {
        lbl_803DDD4C -= 1;
    }
    if (*(f32 *)((char *)gKTRexRuntime + 0x3e8) > lbl_803E67B8) {
        *(f32 *)((char *)gKTRexRuntime + 0x3e8) =
            timeDelta * *(f32 *)((char *)gKTRexRuntime + 0x3ec) + *(f32 *)((char *)gKTRexRuntime + 0x3e8);
        if (*(f32 *)((char *)gKTRexRuntime + 0x3e8) < lbl_803E67B8) {
            *(f32 *)((char *)gKTRexRuntime + 0x3e8) = lbl_803E67B8;
        } else if (*(f32 *)((char *)gKTRexRuntime + 0x3e8) > lbl_803E6820) {
            *(f32 *)((char *)gKTRexRuntime + 0x3e8) =
                lbl_803E6820 - (*(f32 *)((char *)gKTRexRuntime + 0x3e8) - lbl_803E6820);
            *(f32 *)((char *)gKTRexRuntime + 0x3ec) = -*(f32 *)((char *)gKTRexRuntime + 0x3ec);
        }
    }
    hit = ObjHits_GetPriorityHit(obj, &hitA, (int)&hitType, (int)&hitC);
    if (hit == 0) {
        return;
    }
    row = *(int *)(*(int *)(*(int *)((char *)obj + 0x7c) + (s8)*(s8 *)((char *)obj + 0xad) * 4) + 0x50);
    if ((s8)*(u8 *)((char *)runtime + 0x354) != 0 && (hitType == 3 || hitType == 2) &&
        (*(u16 *)((char *)gKTRexState + 0xfa) & 0x10) != 0 && hit == 5) {
        pt = (f32 *)((char *)row + hitType * 16);
        *(f32 *)((char *)lbl_803AD158 + 0xc) = playerMapOffsetX + pt[1];
        *(f32 *)((char *)lbl_803AD158 + 0x10) = pt[2];
        *(f32 *)((char *)lbl_803AD158 + 0x14) = playerMapOffsetZ + pt[3];
        Sfx_PlayFromObject(obj, SFXmv_deaththud16);
        Sfx_PlayFromObject(obj, SFXmv_roothack16);
        (*(void (**)(int, int, void *, int, int, int))((char *)*gPartfxInterface + 0x8))(
            obj, 0x4b2, lbl_803AD158, 0x200001, -1, 0);
        (*(void (**)(int, int, void *, int, int, int))((char *)*gPartfxInterface + 0x8))(
            obj, 0x4b3, lbl_803AD158, 0x200001, -1, 0);
        if (hit == 0xe) {
            *(u8 *)((char *)runtime + 0x354) -= 1;
        } else {
            *(u8 *)((char *)runtime + 0x354) = 0;
        }
        if ((s8)*(u8 *)((char *)runtime + 0x354) <= 0) {
            *(u8 *)((char *)runtime + 0x354) = 0;
            *(u16 *)((char *)gKTRexState + 0xfa) &= ~0x10;
            *(u16 *)((char *)gKTRexState + 0xfa) |= 0x8;
        }
        *(u8 *)((char *)runtime + 0x34f) = (s8)hit;
    } else if (lbl_803DDD4C == 0) {
        Sfx_PlayFromObject(obj, SFXmv_ropecreak22);
        row = *(int *)(*(int *)(*(int *)((char *)obj + 0x7c) + (s8)*(s8 *)((char *)obj + 0xad) * 4) + 0x50);
        pt = (f32 *)((char *)row + hitType * 16);
        *(f32 *)((char *)lbl_803AD158 + 0xc) = playerMapOffsetX + pt[1];
        *(f32 *)((char *)lbl_803AD158 + 0x10) = pt[2];
        *(f32 *)((char *)lbl_803AD158 + 0x14) = playerMapOffsetZ + pt[3];
        (*(void (**)(int, int, void *, int, int, int))((char *)*gPartfxInterface + 0x8))(
            obj, 0x328, lbl_803AD158, 0x200001, -1, 0);
        *(f32 *)((char *)lbl_803AD158 + 0xc) -= *(f32 *)((char *)obj + 0x18);
        *(f32 *)((char *)lbl_803AD158 + 0x10) -= *(f32 *)((char *)obj + 0x1c);
        *(f32 *)((char *)lbl_803AD158 + 0x14) -= *(f32 *)((char *)obj + 0x20);
        *(f32 *)((char *)lbl_803AD158 + 0x8) = lbl_803E6818;
        *(s16 *)((char *)lbl_803AD158 + 0x0) = 0;
        *(s16 *)((char *)lbl_803AD158 + 0x2) = 0;
        *(s16 *)((char *)lbl_803AD158 + 0x4) = 0;
        msg[1] += randomGetRange(0, 0x9b);
        msg[2] += randomGetRange(0, 0x9b);
        (*(void (**)(int, int, void *, int, int, int *))(*(int *)lbl_803DDD48 + 0x4))(
            obj, 0, lbl_803AD158, 1, -1, msg);
        lbl_803DDD4C = 0x3c;
    }
    if ((s8)*(u8 *)((char *)runtime + 0x354) < 1) {
        *(u8 *)((char *)runtime + 0x354) = 0;
    }
    ObjMsg_SendToObject(hitA, 0xe0001, obj, 0);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int ktrex_stateHandlerA02(int obj, int runtime) {
    void *p;
    int phase;
    int idx;
    u16 flags;
    p = *(void **)((char *)obj + 0x4c);
    if ((s8)*(u8 *)((char *)runtime + 0x27b) != 0) {
        (*(void (**)(int, int, int))((char *)*gPlayerInterface + 0x14))(obj, runtime, 1);
        *(u8 *)((char *)gKTRexState + 0xfc) = 0;
        *(u16 *)((char *)gKTRexState + 0xfa) &= ~0x20;
        *(f32 *)((char *)runtime + 0x294) =
            *(f32 *)((char *)p + *(u8 *)((char *)gKTRexState + 0xfc) * 4 + 0x38) / lbl_803E67C4;
    }
    if (ktrex_updateArenaPathProgress(runtime) != 0) {
        int push = 2;
        if (Stack_IsFull(*(int *)gKTRexState) == 0) {
            Stack_Push(*(int *)gKTRexState, &push);
        }
        return 4;
    }
    flags = *(u16 *)((char *)gKTRexState + 0xfa);
    phase = *(u8 *)((char *)gKTRexState + 0x101);
    if (*(u8 *)((char *)gKTRexState + 0xfc) == 0 && phase >= 2 && (flags & 0x20) == 0 &&
        (((flags & 1) == 0 && *(f32 *)((char *)gKTRexState + 8) >= lbl_803E67E8) ||
         ((flags & 1) != 0 && *(f32 *)((char *)gKTRexState + 8) <= lbl_803E67C0))) {
        idx = phase >> 1;
        if (randomGetRange(0, 0x64) <= *(u8 *)((char *)p + idx + 0x56)) {
            int push = 5;
            *(u8 *)((char *)gKTRexState + 0x103) = 2;
            if (Stack_IsFull(*(int *)gKTRexState) == 0) {
                Stack_Push(*(int *)gKTRexState, &push);
            }
            *(u8 *)((char *)gKTRexState + 0xfd) = 1;
            return 5;
        }
        if (randomGetRange(0, 0x64) <= *(u8 *)((char *)p + idx + 0x52)) {
            int cond;
            u8 fe = *(u8 *)((char *)gKTRexState + 0xfe);
            if (fe == 1) {
                cond = *(u8 *)((char *)gKTRexState + 0xff) == 2;
            } else if (fe == 2) {
                cond = *(u8 *)((char *)gKTRexState + 0xff) == 1;
            } else if (fe == 4) {
                cond = *(u8 *)((char *)gKTRexState + 0xff) == 8;
            } else {
                cond = *(u8 *)((char *)gKTRexState + 0xff) == 4;
            }
            if (cond && (*(u16 *)((char *)gKTRexState + 0xfa) & 0x40) == 0) {
                int push = 0xb;
                *(u8 *)((char *)gKTRexState + 0xfd) = 0;
                if (Stack_IsFull(*(int *)gKTRexState) == 0) {
                    Stack_Push(*(int *)gKTRexState, &push);
                }
                return 5;
            }
        }
        *(u16 *)((char *)gKTRexState + 0xfa) |= 0x20;
    }
    if ((*(u8 *)((char *)gKTRexState + 0xfe) & *(u8 *)((char *)gKTRexState + 0xff)) != 0) {
        *(u16 *)((char *)gKTRexState + 0xfa) &= ~0x40;
        if ((*(u8 *)((char *)gKTRexState + 0xfe) & *(u8 *)((char *)gKTRexState + 0xff)) != 0) {
            int result;
            if ((*(u16 *)((char *)gKTRexState + 0xfa) & 1) != 0) {
                if (*(f32 *)((char *)gKTRexState + 8) - *(f32 *)((char *)gKTRexState + 0xf4) > lbl_803E67B4) {
                    result = 1;
                } else {
                    result = 0;
                }
            } else {
                if (*(f32 *)((char *)gKTRexState + 0xf4) - *(f32 *)((char *)gKTRexState + 8) > lbl_803E67B4) {
                    result = 1;
                } else {
                    result = 0;
                }
            }
            if (result != 0) {
                int push = 5;
                *(u8 *)((char *)gKTRexState + 0x103) = 1;
                if (Stack_IsFull(*(int *)gKTRexState) == 0) {
                    Stack_Push(*(int *)gKTRexState, &push);
                }
                *(u8 *)((char *)gKTRexState + 0xfd) = 1;
                return 5;
            }
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int ktrex_stateHandlerA03(int obj, int runtime) {
    int phase;
    f32 f4;
    f32 f5;
    int popped;
    if ((s8)*(u8 *)((char *)runtime + 0x27b) != 0) {
        (*(void (**)(int, int, int))((char *)*gPlayerInterface + 0x14))(obj, runtime, 2);
        return 0;
    }
    if ((s8)*(u8 *)((char *)runtime + 0x346) != 0) {
        phase = (*(u16 *)((char *)gKTRexState + 0xfa) >> 1) & 3;
        f5 = ((f32 *)*(int *)((char *)gKTRexState + 0xdc))[phase] - ((f32 *)*(int *)((char *)gKTRexState + 0xd0))[phase];
        f4 = ((f32 *)*(int *)((char *)gKTRexState + 0xe4))[phase] - ((f32 *)*(int *)((char *)gKTRexState + 0xd8))[phase];
        if (__fabs(f5) > __fabs(f4)) {
            *(f32 *)((char *)gKTRexState + 8) =
                (*(f32 *)((char *)obj + 0xc) - ((f32 *)*(int *)((char *)gKTRexState + 0xd0))[phase]) / f5;
        } else {
            *(f32 *)((char *)gKTRexState + 8) =
                (*(f32 *)((char *)obj + 0x14) - ((f32 *)*(int *)((char *)gKTRexState + 0xd8))[phase]) / f4;
        }
        popped = 0;
        if (Stack_IsEmpty(*(int *)gKTRexState) == 0) {
            Stack_Pop(*(int *)gKTRexState, &popped);
        }
        return popped + 1;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int ktrex_stateHandlerA07(int obj, int runtime) {
    if ((s8)*(u8 *)((char *)runtime + 0x27b) != 0) {
        (*(void (**)(int, int, int))((char *)*gPlayerInterface + 0x14))(obj, runtime, 6);
        *(u8 *)((char *)obj + 0xaf) &= ~8;
        *(u8 *)((char *)gKTRexState + 0x101) += 1;
        ktrexlevel_clearPathGameBits();
        GameBit_Set(1394, *(u8 *)((char *)gKTRexState + 0x101));
        *(u16 *)((char *)gKTRexState + 0xfa) |= 0x10;
        *(u16 *)((char *)gKTRexState + 0xfa) &= ~8;
        Music_Trigger(148, 0);
        Music_Trigger(40, 0);
        Music_Trigger(147, 1);
        return 0;
    }
    if ((s8)*(u8 *)((char *)runtime + 0x346) != 0 || (*(u16 *)((char *)gKTRexState + 0xfa) & 8) != 0) {
        return 9;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int ktrex_stateHandlerA04(int obj, int runtime) {
    void *p;
    int popped;
    f32 t;
    p = *(void **)((char *)obj + 0x4c);
    if ((s8)*(u8 *)((char *)runtime + 0x27b) != 0) {
        (*(void (**)(int, int, int))((char *)*gPlayerInterface + 0x14))(obj, runtime, 4);
        *(f32 *)((char *)gKTRexState + 4) =
            (f32)(u32)*(u16 *)((char *)p + *(u8 *)((char *)gKTRexState + 0xfd) * 2 + 0x44);
        return 0;
    }
    t = *(f32 *)((char *)gKTRexState + 4) - timeDelta;
    *(f32 *)((char *)gKTRexState + 4) = t;
    if (t < lbl_803E67B8) {
        *(f32 *)((char *)gKTRexState + 4) = lbl_803E67B8;
    }
    if ((s8)*(u8 *)((char *)runtime + 0x346) != 0) {
        if (*(f32 *)((char *)gKTRexState + 4) <= lbl_803E67B8) {
            popped = 0;
            if (Stack_IsEmpty(*(int *)gKTRexState) == 0) {
                Stack_Pop(*(int *)gKTRexState, &popped);
            }
            return popped + 1;
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int ktrex_stateHandlerA05(int obj, int runtime) {
    void *p;
    int pushHi;
    int pushLo;
    p = *(void **)((char *)obj + 0x4c);
    if ((s8)*(u8 *)((char *)runtime + 0x27b) != 0) {
        (*(void (**)(int, int, int))((char *)*gPlayerInterface + 0x14))(obj, runtime, 1);
        *(u8 *)((char *)gKTRexState + 0xfc) = 1;
        *(f32 *)((char *)runtime + 0x294) =
            *(f32 *)((char *)p + *(u8 *)((char *)gKTRexState + 0xfc) * 4 + 0x38) / lbl_803E67C4;
    }
    if (RandomTimer_UpdateRangeTrigger((char *)gKTRexState + 0x190, lbl_803E67C8, lbl_803E67CC) != 0) {
        Sfx_PlayFromObject(obj, SFXmv_gdtur2_c);
    }
    if (ktrex_updateArenaPathProgress(runtime) != 0) {
        *(u8 *)((char *)gKTRexState + 0x103) -= 1;
        if ((s8)*(u8 *)((char *)gKTRexState + 0x103) <= 0) {
            pushLo = 2;
            if (Stack_IsFull(*(int *)gKTRexState) == 0) {
                Stack_Push(*(int *)gKTRexState, &pushLo);
            }
        } else {
            pushHi = 5;
            if (Stack_IsFull(*(int *)gKTRexState) == 0) {
                Stack_Push(*(int *)gKTRexState, &pushHi);
            }
        }
        return 4;
    }
    if (ktrex_isPlayerInLaneThreatRange(obj) != 0) {
        return 8;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int ktrex_stateHandlerA08(int obj, int runtime) {
    void *p;
    f32 t;
    p = *(void **)((char *)obj + 0x4c);
    if ((s8)*(u8 *)((char *)runtime + 0x27b) != 0) {
        (*(void (**)(int, int, int))((char *)*gPlayerInterface + 0x14))(obj, runtime, 7);
        *(f32 *)((char *)gKTRexState + 4) =
            (f32)(u32)*(u16 *)((char *)p + (*(u8 *)((char *)gKTRexState + 0x101) & ~1) + 0x4a);
        *(u8 *)((char *)obj + 0xaf) &= ~8;
        return 0;
    }
    if ((*(u16 *)((char *)gKTRexState + 0xfa) & 8) == 0) {
        t = *(f32 *)((char *)gKTRexState + 4) - timeDelta;
        *(f32 *)((char *)gKTRexState + 4) = t;
        if (!(t <= lbl_803E67B8)) {
            return 0;
        }
    }
    if ((*(u16 *)((char *)gKTRexState + 0xfa) & 8) != 0) {
        *(u8 *)((char *)gKTRexState + 0x102) -= 1;
        *(u8 *)((char *)runtime + 0x354) = 3;
    }
    *(u16 *)((char *)gKTRexState + 0xfa) &= ~0x10;
    if (*(u8 *)((char *)gKTRexState + 0x102) == 0) {
        return 2;
    }
    *(u8 *)((char *)obj + 0xaf) |= 8;
    return 10;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int ktrex_stateHandlerA11(int obj, int runtime) {
    int phase;
    f32 f4;
    f32 f5;
    if ((*(u16 *)((char *)gKTRexState + 0xfa) & 1) != 0) {
        *(s16 *)obj += 0x8000;
    } else {
        *(s16 *)obj -= 0x8000;
    }
    *(u16 *)((char *)gKTRexState + 0xfa) ^= 1;
    if ((*(u16 *)((char *)gKTRexState + 0xfa) & 1) != 0) {
        *(void **)((char *)gKTRexState + 0xd0) = (char *)gKTRexState + 0x70;
        *(void **)((char *)gKTRexState + 0xd4) = (char *)gKTRexState + 0x80;
        *(void **)((char *)gKTRexState + 0xd8) = (char *)gKTRexState + 0x90;
        *(void **)((char *)gKTRexState + 0xdc) = (char *)gKTRexState + 0xa0;
        *(void **)((char *)gKTRexState + 0xe0) = (char *)gKTRexState + 0xb0;
        *(void **)((char *)gKTRexState + 0xe4) = (char *)gKTRexState + 0xc0;
    } else {
        *(void **)((char *)gKTRexState + 0xd0) = (char *)gKTRexState + 0x10;
        *(void **)((char *)gKTRexState + 0xd4) = (char *)gKTRexState + 0x20;
        *(void **)((char *)gKTRexState + 0xd8) = (char *)gKTRexState + 0x30;
        *(void **)((char *)gKTRexState + 0xdc) = (char *)gKTRexState + 0x40;
        *(void **)((char *)gKTRexState + 0xe0) = (char *)gKTRexState + 0x50;
        *(void **)((char *)gKTRexState + 0xe4) = (char *)gKTRexState + 0x60;
    }
    phase = (*(u16 *)((char *)gKTRexState + 0xfa) >> 1) & 3;
    f5 = ((f32 *)*(int *)((char *)gKTRexState + 0xdc))[phase] - ((f32 *)*(int *)((char *)gKTRexState + 0xd0))[phase];
    f4 = ((f32 *)*(int *)((char *)gKTRexState + 0xe4))[phase] - ((f32 *)*(int *)((char *)gKTRexState + 0xd8))[phase];
    if (__fabs(f5) > __fabs(f4)) {
        *(f32 *)((char *)gKTRexState + 8) =
            (*(f32 *)((char *)obj + 0xc) - ((f32 *)*(int *)((char *)gKTRexState + 0xd0))[phase]) / f5;
    } else {
        *(f32 *)((char *)gKTRexState + 8) =
            (*(f32 *)((char *)obj + 0x14) - ((f32 *)*(int *)((char *)gKTRexState + 0xd8))[phase]) / f4;
    }
    *(u16 *)((char *)gKTRexState + 0xfa) |= 0x40;
    return 3;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int ktrex_stateHandlerA09(int obj, int runtime) {
    if ((s8)*(u8 *)((char *)runtime + 0x27b) != 0) {
        (*(void (**)(int, int, int))((char *)*gPlayerInterface + 0x14))(obj, runtime, 8);
        if ((*(int (**)(void))((char *)*gCameraInterface + 0x10))() == 66) {
            (*(void (**)(int, int, int))((char *)*gCameraInterface + 0x24))(2, 0, 0);
        }
        return 0;
    }
    if ((s8)*(u8 *)((char *)runtime + 0x346) != 0) {
        *(int *)((char *)gKTRexState + 0xc) = (*(u16 *)((char *)gKTRexState + 0xfa) >> 1) & 3;
        *(f32 *)((char *)gKTRexState + 4) = lbl_803E67D8;
        Music_Trigger(147, 0);
        Music_Trigger(148, 1);
        return 11;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int ktrex_stateHandlerA10(int obj, int runtime) {
    void *p;
    u16 flags;
    int phase;
    int laneBit;
    p = *(void **)((char *)obj + 0x4c);
    flags = *(u16 *)((char *)gKTRexState + 0xfa);
    phase = (flags >> 1) & 3;
    laneBit = flags & 1;
    if ((s8)*(u8 *)((char *)runtime + 0x27b) != 0) {
        (*(void (**)(int, int, int))((char *)*gPlayerInterface + 0x14))(obj, runtime, 1);
        *(u8 *)((char *)gKTRexState + 0xfc) = 2;
        *(f32 *)((char *)runtime + 0x294) =
            *(f32 *)((char *)p + *(u8 *)((char *)gKTRexState + 0xfc) * 4 + 0x38) / lbl_803E67C4;
    }
    if (ktrex_updateArenaPathProgress(runtime) != 0) {
        int push = 0xa;
        if (Stack_IsFull(*(int *)gKTRexState) == 0) {
            Stack_Push(*(int *)gKTRexState, &push);
        }
        return 4;
    }
    if ((u8)ktrex_shouldAdvanceArenaPhase() != 0) {
        (*(void (**)(int, int, int))((char *)*gCameraInterface + 0x24))(3, 0, 0);
    }
    if (RandomTimer_UpdateRangeTrigger((char *)gKTRexState + 0x190, lbl_803E67C8, lbl_803E67CC) != 0) {
        Sfx_PlayFromObject(obj, SFXmv_gdtur2_c);
    }
    *(f32 *)((char *)gKTRexState + 4) -= timeDelta;
    if (*(f32 *)((char *)gKTRexState + 4) <= lbl_803E67B8) {
        *(f32 *)((char *)gKTRexState + 4) = lbl_803E67B8;
    }
    if (*(f32 *)((char *)gKTRexState + 4) <= lbl_803E67B8 &&
        *(int *)((char *)gKTRexState + 0xc) == phase &&
        ((laneBit == 0 && *(f32 *)((char *)gKTRexState + 8) >= lbl_803E67D0) ||
         (laneBit != 0 && *(f32 *)((char *)gKTRexState + 8) <= lbl_803E67D4))) {
        if ((*(u16 *)((char *)gKTRexState + 0xfa) & 8) != 0) {
            int cond;
            u8 fe;
            *(u8 *)((char *)gKTRexState + 0x101) += 1;
            GameBit_Set(0x572, *(u8 *)((char *)gKTRexState + 0x101));
            *(u8 *)((char *)gKTRexState + 0xfd) = 0;
            *(u16 *)((char *)gKTRexState + 0xfa) &= ~0x8;
            fe = *(u8 *)((char *)gKTRexState + 0xfe);
            if (fe == 1) {
                cond = *(u8 *)((char *)gKTRexState + 0xff) == 2;
            } else if (fe == 2) {
                cond = *(u8 *)((char *)gKTRexState + 0xff) == 1;
            } else if (fe == 4) {
                cond = *(u8 *)((char *)gKTRexState + 0xff) == 8;
            } else {
                cond = *(u8 *)((char *)gKTRexState + 0xff) == 4;
            }
            if (cond && (*(u16 *)((char *)gKTRexState + 0xfa) & 0x40) == 0) {
                int push = 0xb;
                if (Stack_IsFull(*(int *)gKTRexState) == 0) {
                    Stack_Push(*(int *)gKTRexState, &push);
                }
            } else {
                int push = 2;
                if (Stack_IsFull(*(int *)gKTRexState) == 0) {
                    Stack_Push(*(int *)gKTRexState, &push);
                }
            }
            {
                int push = 4;
                if (Stack_IsFull(*(int *)gKTRexState) == 0) {
                    Stack_Push(*(int *)gKTRexState, &push);
                }
            }
        } else {
            int push = 2;
            *(u8 *)((char *)gKTRexState + 0x101) -= 1;
            if (Stack_IsFull(*(int *)gKTRexState) == 0) {
                Stack_Push(*(int *)gKTRexState, &push);
            }
        }
        ktrexlevel_updatePathGameBits();
        (*(void (**)(int, int, int))((char *)*gCameraInterface + 0x24))(3, 0, 0);
        GameBit_Set(0x572, *(u8 *)((char *)gKTRexState + 0x101));
        {
            int popped = 0;
            if (Stack_IsEmpty(*(int *)gKTRexState) == 0) {
                Stack_Pop(*(int *)gKTRexState, &popped);
            }
            return popped + 1;
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int ktrex_stateHandlerA01(int obj, int runtime) {
    if ((s8)*(u8 *)((char *)runtime + 0x27b) != 0) {
        *(u8 *)((char *)obj + 0xaf) |= 8;
        *(u8 *)((char *)runtime + 0x349) = 0;
        *(u8 *)((char *)runtime + 0x25f) = 0;
        *(f32 *)((char *)gKTRexState + 4) = lbl_803E67EC;
        return 0;
    }
    *(f32 *)((char *)gKTRexState + 4) -= timeDelta;
    if (*(f32 *)((char *)gKTRexState + 4) <= lbl_803E67F0) {
        if (*(int *)((char *)obj + 0xf8) != 3) {
            (*(void (**)(int, int))((char *)*gScreenTransitionInterface + 8))(30, 1);
            *(int *)((char *)obj + 0xf8) = 3;
        }
    }
    if (*(f32 *)((char *)gKTRexState + 4) <= lbl_803E67B8) {
        Obj_SetModelColorFadeRecursive((int)Obj_GetPlayerObject(), 0, 0, 0, 0, 0);
        Music_Trigger(40, 0);
        Music_Trigger(147, 0);
        Music_Trigger(148, 0);
        *(u8 *)((char *)obj + 0xad) = 1;
        GameBit_Set(1380, 1);
        GameBit_Set(874, 0);
        ((MapEventInterface *)*gMapEventInterface)->setAnimEvent(13, 0, 1);
        ((MapEventInterface *)*gMapEventInterface)->setAnimEvent(13, 1, 1);
        ((MapEventInterface *)*gMapEventInterface)->setAnimEvent(13, 5, 1);
        ((MapEventInterface *)*gMapEventInterface)->setAnimEvent(13, 10, 1);
        ((MapEventInterface *)*gMapEventInterface)->setAnimEvent(13, 11, 1);
        GameBit_Set(3589, 0);
        unlockLevel(53, 1, 0);
        GameBit_Set(2107, 1);
        ((MapEventInterface *)*gMapEventInterface)->setMode(4, 2);
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset
