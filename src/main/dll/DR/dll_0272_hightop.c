#include "main/dll/DR/dr_shared.h"
#include "main/game_object.h"
#include "main/dll/baddie_state.h"
#include "main/objseq.h"

typedef struct HighTopRuntime {
    BaddieState baddie;
    u8 pad35C[0x3ec - 0x35c];
    u8 lookController[0x9fd - 0x3ec]; /* dll_2E look-controller block at 0x3EC (start evidenced; true extent unknown) */
    u8 unk9FD;
    u8 pad9FE[0xb18 - 0x9fe];
    f32 pathPointWorldPositions[12];
    u8 padB48[0xb6c - 0xb48];
    f32 pathPoint2X;
    f32 pathPoint2Y;
    f32 pathPoint2Z;
    f32 pathPoint0X;
    f32 pathPoint0Y;
    f32 pathPoint0Z;
    u8 padB84[0xc16 - 0xb84];
    s16 unkC16;
    s16 unkC18;
    u8 padC1A[2];
    f32 lookTargetX;
    f32 lookTargetY;
    f32 lookTargetZ;
    f32 unkC28;
    u8 padC2C[4];
    f32 unkC30;
    u8 padC34[4];
    f32 unkC38;
    s32 unkC3C;
    u16 unkC40;
    u8 unkC42;
    u8 unkC43;
    u8 padC44;
    u8 unkC45;
    u8 padC46[3];
    BitFlags8 flagsC49;
    BitFlags8 flagsC4A;
    u8 unkC4B;
} HighTopRuntime;

STATIC_ASSERT(sizeof(HighTopRuntime) == 0xC4C);
STATIC_ASSERT(offsetof(HighTopRuntime, unk9FD) == 0x9FD);
STATIC_ASSERT(offsetof(HighTopRuntime, unkC16) == 0xC16);
STATIC_ASSERT(offsetof(HighTopRuntime, unkC4B) == 0xC4B);

typedef struct HighTopObject {
    s16 yaw;
    u8 pad02[0xc - 0x2];
    f32 x;
    f32 y;
    f32 z;
    u8 pad18[0xb8 - 0x18];
    HighTopRuntime *runtime;
} HighTopObject;

int hightop_defaultStateHandler(void) { return 0x0; }

void hightop_func15(void) {}

int hightop_func14(void) { return 0x0; }

int hightop_func10(void) { return 0x0; }

int hightop_func0E(void) { return 0x1; }

int hightop_func0B(void) { return 0x1; }

int hightop_getExtraSize(void) { return 0xc4c; }

int hightop_getObjectTypeId(void) { return 0x43; }

void hightop_release(void) {}

int hightop_render2(void) { return 0x0; }

int hightop_setScale(void) { return 0x0; }

#pragma scheduling off
#pragma peephole off
void hightop_func11(int obj, int val) {
    u8 v = val;
    HighTopRuntime *p = ((GameObject *)obj)->extra;
    p->unkC43 = v;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
f32 hightop_func13(int obj, f32 *out) {
    *out = lbl_803E6B34;
    return lbl_803E6AA8;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void hightop_func12(int obj, f32 *a, int *b) {
    *a = lbl_803E6AA8;
    *b = 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void hightop_modelMtxFn(int obj, f32 *a, f32 *b, f32 *c) {
    HighTopRuntime *runtime = ((HighTopObject *)obj)->runtime;
    *a = runtime->pathPoint2X;
    *b = runtime->pathPoint2Y;
    *c = runtime->pathPoint2Z;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void hightop_free(int obj) {
    void *ui;
    ObjGroup_RemoveObject(obj, 0x26);
    ObjGroup_RemoveObject(obj, 0xa);
    ui = *gGameUIInterface;
    (*(void (**)(void *))((char *)ui + 0x60))(ui);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int hightop_stateHandler00(int obj) {
    int p = *(int *)&((GameObject *)obj)->anim.placementData;
    if (*(s8 *)(p + 0x19) != 0) {
        return 0xa;
    }
    if (GameBit_Get(0x631) != 0) {
        return 8;
    }
    return 5;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int hightop_stateHandler06(int obj, u8 *p2) {
    HighTopRuntime *p = ((GameObject *)obj)->extra;
    if ((s8)p2[0x27a] != 0) {
        p->unk9FD |= 1;
    }
    if (GameBit_Get(0x632) != 0) {
        return 8;
    }
    return 2;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void hightop_func0F(int obj, f32 *ox, f32 *oy, f32 *oz) {
    int *player;
    ObjPosParams pos;
    f32 mtx[16];
    player = Obj_GetPlayerObject();
    pos.x = *(f32 *)((char *)player + 0xc);
    pos.y = *(f32 *)((char *)player + 0x10);
    pos.z = *(f32 *)((char *)player + 0x14);
    pos.rx = *(s16 *)player;
    pos.ry = *(s16 *)((char *)player + 0x2);
    pos.rz = *(s16 *)((char *)player + 0x4);
    pos.scale = lbl_803E6AB8;
    setMatrixFromObjectPos(mtx, &pos);
    Matrix_TransformPoint(mtx, lbl_803E6AA8, lbl_803E6B38, lbl_803E6B3C, ox, oy, oz);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int hightop_stateHandler03(int obj, u8 *p2) {
    HighTopRuntime *p = ((GameObject *)obj)->extra;
    f32 zero = lbl_803E6AA8;
    *(f32 *)(p2 + 0x294) = zero;
    *(f32 *)(p2 + 0x284) = zero;
    *(f32 *)(p2 + 0x280) = zero;
    ((GameObject *)obj)->anim.velocityX = zero;
    ((GameObject *)obj)->anim.velocityY = zero;
    ((GameObject *)obj)->anim.velocityZ = zero;
    if ((s8)p2[0x27a] != 0) {
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)obj, 0x78);
        if (*(u32 *)&p->unkC3C == 4) {
            ObjAnim_SetCurrentMove(obj, 0x13, lbl_803E6AA8, 0);
            *(f32 *)(p2 + 0x2a0) = lbl_803E6AC8;
        } else {
            ObjAnim_SetCurrentMove(obj, 0x13, lbl_803E6AA8, 0);
            *(f32 *)(p2 + 0x2a0) = lbl_803E6AC8;
        }
    }
    if (((GameObject *)obj)->anim.currentMoveProgress > lbl_803E6B00) {
        return p->unkC3C + 1;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int hightop_stateHandler05(int obj, u8 *p2) {
    HighTopRuntime *p = ((GameObject *)obj)->extra;
    if ((s8)p2[0x27a] != 0) {
        p->flagsC49.b1 = 0;
        p->unkC4B = 0xa;
    }
    switch ((s8)p->unkC4B) {
    case 1:
        if (GameBit_Get(0x62c) != 0) {
            p->unkC4B = 2;
        }
        break;
    case 0xa:
        if (GameBit_Get(0x630) != 0) {
            return 7;
        }
        break;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int hightop_interactionCallback(int obj) {
    HighTopRuntime *p;
    seqFn_800394a0(obj);
    p = ((GameObject *)obj)->extra;
    p->unk9FD &= ~1;
    p->flagsC49.b4 = 0;
    p->flagsC49.b6 = 1;
    if ((s8)p->unkC4B == 0) {
        p->flagsC4A.b0 = 1;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void hightop_playMovementSfx(int obj, int p2, int p3) {
    int flags = *(int *)((char *)p3 + 0x314);
    int idx;
    if ((flags & 0x81) != 0) {
        if (flags & 1) {
            idx = 0;
        }
        if (flags & 0x80) {
            idx = 1;
        }
        Sfx_PlayFromObject(obj, (u16)(&lbl_803DC310)[idx]);
    }
    if (*(int *)((char *)p3 + 0x314) & 0x100) {
        fn_8009A8C8(obj, lbl_803E6B30);
        Sfx_PlayFromObject(obj, (u16)lbl_803DC310);
    }
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void hightop_getLookTargetYaw(int obj, int mode, int *out) {
    f32 buf[6];
    HighTopRuntime *p;
    int yaw;
    switch (mode) {
    case 2:
        if (dll_2E_func0A(0x11, buf) != 0) {
            yaw = getAngle(buf[3] - ((GameObject *)obj)->anim.localPosX, buf[5] - ((GameObject *)obj)->anim.localPosZ);
            *out = yaw + lbl_803DC328;
            p = ((GameObject *)obj)->extra;
            p->lookTargetX = buf[3];
            p->lookTargetY = buf[4];
            p->lookTargetZ = buf[5];
        } else {
            *out = *(s16 *)obj + 0x4000;
        }
        break;
    case 3:
        *out = 1;
        break;
    case 4:
        *out = 0;
        break;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void hightop_renderGroundMarker(int obj, f32 scale) {
    f32 *mtx;
    f32 lx, ly, lz;
    ObjPosParams pos;
    mtx = (f32 *)ObjPath_GetPointModelMtx(obj, 2);
    ObjPath_GetPointLocalPosition(obj, 2, &lx, &ly, &lz);
    pos.x = lx;
    pos.y = ly;
    pos.z = lz;
    pos.rx = -0x8000;
    pos.ry = 0;
    pos.rz = 0;
    pos.scale = scale / *(f32 *)(*(int *)&((GameObject *)obj)->anim.modelInstance + 0x4);
    setMatrixFromObjectPos(lbl_803AD208, &pos);
    mtx44_mult(lbl_803AD208, mtx, lbl_803AD208);
    fn_8003B950(lbl_803AD208);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void hightop_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible) {
    HighTopRuntime *runtime = ((HighTopObject *)obj)->runtime;
    if (visible != 0) {
        int count;
        int **list;
        int i;
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E6AB8);
        ObjPath_GetPointWorldPosition((int)obj, 2, &runtime->pathPoint2X, &runtime->pathPoint2Y, &runtime->pathPoint2Z, 0);
        ObjPath_GetPointWorldPositionArray((int)obj, 3, 4, runtime->pathPointWorldPositions);
        ObjPath_GetPointWorldPosition((int)obj, 0, &runtime->pathPoint0X, &runtime->pathPoint0Y, &runtime->pathPoint0Z, 0);
        runtime->flagsC49.b5 = 1;
        dll_2E_func06((int)obj, runtime->lookController, 0);
        if (runtime->flagsC49.b1 != 0) {
            list = (int **)ObjGroup_GetObjects(55, &count);
            for (i = 0; i < count; i++) {
                int idx = (*(int (**)(int *))((char *)**(int ***)((char *)*list + 0x68) + 0x24))(*list);
                (*(void (**)(int *, void *, int, undefined4, undefined4, undefined4, undefined4))((char *)**(int ***)((char *)*list + 0x68) + 0x20))(
                    *list, obj, lbl_8032AB48[idx], p2, p3, p4, p5);
                list++;
            }
        }
    } else {
        runtime->flagsC49.b5 = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void hightop_init(void *obj, u8 *arg) {
    u8 *base = lbl_8032AAB0;
    HighTopRuntime *runtime = ((GameObject *)obj)->extra;
    char *pathObj;
    int *node;
    HtInitData local1;
    HtInitData local2;
    int local8;
    local8 = lbl_803E6AA0;
    local1 = lbl_802C2590;
    local2 = lbl_802C25A4;
    *(s16 *)obj = (s16)((s8)arg[0x18] << 8);
    ((GameObject *)obj)->animEventCallback = (void *)hightop_interactionCallback;
    runtime->unkC45 = arg[0x19];
    runtime->unkC16 = 5;
    *(s8 *)&runtime->unkC4B = -1;
    node = *(int **)((char *)obj + 0x64);
    if (node != 0) {
        *(int *)((char *)node + 0x30) |= 0xa10;
    }
    ObjGroup_AddObject((int)obj, 38);
    ObjGroup_AddObject((int)obj, 10);
    (*(void (**)(void *, char *, int, int))((char *)*gPlayerInterface + 4))(obj, (char *)runtime, 11, 1);
    runtime->baddie.unk2A4 = lbl_803E6B4C;
    pathObj = (char *)runtime + 4;
    *(u8 *)(pathObj + 0x25b) = 1;
    (*(void (**)(char *, int, int, int))((char *)*gPathControlInterface + 4))(pathObj, 3, 1024, 0);
    (*(void (**)(char *, int, u8 *, int *, int))((char *)*gPathControlInterface + 8))(pathObj, 2, &base[0xe8], &lbl_803DC318, 8);
    (*(void (**)(char *, int, u8 *, u8 *, int *))((char *)*gPathControlInterface + 12))(pathObj, 4, &base[0xa8], &base[0xd8], &local8);
    (*(void (**)(void *, char *))((char *)*gPathControlInterface + 32))(obj, pathObj);
    dll_2E_func05((int)obj, (char *)runtime->lookController, -4551, 23665, 6);
    dll_2E_func08((char *)runtime->lookController, 300, 120);
    dll_2E_func09((char *)runtime->lookController, &local2, &local1, 6);
    runtime->unk9FD |= 2;
    runtime->unk9FD |= 8;
    runtime->unkC18 = *(s16 *)(arg + 0x1a);
    runtime->unk9FD |= 1;
    *(u8 *)(*(int *)&((GameObject *)obj)->anim.modelInstance + 0x71) = 127;
    runtime->flagsC49.b4 = 0;
    runtime->flagsC49.b7 = 0;
    lbl_803DC320 = *(s16 *)(arg + 0x1a);
    if (*(s16 *)(arg + 0x1c) == 0) {
        runtime->unkC28 = lbl_803E6B50;
    } else {
        runtime->unkC28 = (f32)*(s16 *)(arg + 0x1c) / lbl_803E6B54;
    }
    runtime->flagsC49.b6 = 0;
    runtime->flagsC4A.b0 = 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int hightop_stateHandler08(int obj, u8 *p2) {
    HighTopRuntime *state = ((GameObject *)obj)->extra;
    if ((s8)p2[0x27a] != 0) {
        f32 zero;
        state->unkC30 = lbl_803E6AB4;
        zero = lbl_803E6AA8;
        *(f32 *)(p2 + 0x294) = zero;
        *(f32 *)(p2 + 0x284) = zero;
        *(f32 *)(p2 + 0x280) = zero;
        ((GameObject *)obj)->anim.velocityX = zero;
        ((GameObject *)obj)->anim.velocityY = zero;
        ((GameObject *)obj)->anim.velocityZ = zero;
    }
    if ((s8)p2[0x346] != 0) {
        s16 cur = ((GameObject *)obj)->anim.currentMove;
        switch (cur) {
        case 10:
            if (*(f32 *)(p2 + 0x2a0) > lbl_803E6AA8) {
                ObjAnim_SetCurrentMove(obj, 5, lbl_803E6AA8, 0);
            } else {
                return 8;
            }
            break;
        case 5:
            if (state->unkC30 < lbl_803E6AA8) {
                ObjAnim_SetCurrentMove(obj, 10, lbl_803E6AB8, 0);
                *(f32 *)(p2 + 0x2a0) = lbl_803E6ABC;
            }
            break;
        default:
            ObjAnim_SetCurrentMove(obj, 10, lbl_803E6AA8, 0);
            *(f32 *)(p2 + 0x2a0) = lbl_803E6AC0;
            break;
        }
    }
    if (((GameObject *)obj)->anim.currentMove == 10) {
        if (*(f32 *)(p2 + 0x2a0) < lbl_803E6AA8) {
            if (((GameObject *)obj)->anim.currentMoveProgress < lbl_803E6AC4) {
                ObjAnim_SetCurrentMove(obj, 0, lbl_803E6AA8, 0);
                *(f32 *)(p2 + 0x2a0) = lbl_803E6AC8;
                return 8;
            }
        }
    }
    state->unkC30 -= (f32)(u32)framesThisStep;
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void hightop_initialise(void) {
    void **t = gHighTopStateHandlers;
    t[0] = (void *)hightop_stateHandler00;
    t[1] = (void *)hightop_stateHandler01;
    t[2] = (void *)hightop_stateHandler02;
    t[3] = (void *)hightop_stateHandler03;
    t[4] = (void *)hightop_stateHandler04;
    t[5] = (void *)hightop_stateHandler05;
    t[6] = (void *)hightop_stateHandler06;
    t[7] = (void *)hightop_stateHandler07;
    t[8] = (void *)hightop_stateHandler08;
    t[9] = (void *)hightop_stateHandler09;
    t[10] = (void *)hightop_stateHandler10;
    gHighTopDefaultStateHandler = (void *)hightop_defaultStateHandler;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
int hightop_handleMotionEvent(int obj, u8 event) {
    HighTopRuntime *runtime = ((GameObject *)obj)->extra;
    switch (event) {
    case 5:
        (*(void (**)(int, char *, int))((char *)*gPlayerInterface + 0x14))(obj, (char *)runtime, 8);
        break;
    case 6:
        GameBit_Set(0x634, 1);
        (*gObjectTriggerInterface)->runSequence(4, (void *)obj, -1);
        break;
    case 7:
        GameBit_Set(0x634, 0);
        GameBit_Set(0x631, 1);
        *(u8 *)(*(int *)&((GameObject *)obj)->anim.modelInstance + 0x71) |= 1;
        runtime->unkC40 &= ~0x140;
        runtime->unk9FD &= ~2;
        (*(void (**)(int, char *, int))((char *)*gPlayerInterface + 0x14))(obj, (char *)runtime, 7);
        break;
    case 8:
        (*gObjectTriggerInterface)->runSequence(7, (void *)obj, -1);
        break;
    case 9:
        (*(void (**)(int, char *, int))((char *)*gPlayerInterface + 0x14))(obj, (char *)runtime, 7);
        break;
    }
    return 0;
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void hightop_hitDetect(int obj) {
    HighTopRuntime *p = ((GameObject *)obj)->extra;
    f32 l10;
    f32 lc;
    f32 l8;
    int hit;
    s16 st;
    hit = ObjHits_GetPriorityHitWithPosition(obj, 0, 0, 0, &l8, &lc, &l10);
    if (hit == 0) {
        return;
    }
    st = p->baddie.controlMode;
    if (st != 4 && (u16)(st - 9) > 1) {
        if (hit == 0xf || hit == 0xe) {
            return;
        }
    }
    if (p->unkC18 == 0) {
        return;
    }
    Obj_SpawnHitLightAndFade(obj, &l8, lbl_803E6B40);
    objSoundFn_800392f0(obj, (int)((char *)p + 0x3bc), &lbl_803DC308 + randomGetRange(0, 0) * 6, 1);
    st = p->baddie.controlMode;
    if (st != 3) {
        p->unkC3C = st;
    }
    st = p->baddie.controlMode;
    if (st == 2 || st == 8) {
        p->unkC18 -= 1;
        fn_8009A8C8(obj, lbl_803E6B30);
        if (p->unkC18 <= 0) {
            (*(void (**)(void *))((char *)*gGameUIInterface + 0x60))(*gGameUIInterface);
            p->flagsC49.b7 = 0;
            GameBit_Set(0x634, 0);
            if (Obj_IsLoadingLocked() != 0) {
                int spawn = Obj_AllocObjectSetup(0x2c, 0xd4);
                *(u8 *)(spawn + 0x4) = 2;
                *(f32 *)(spawn + 0x8) = ((GameObject *)obj)->anim.localPosX;
                *(f32 *)(spawn + 0xc) = ((GameObject *)obj)->anim.localPosY;
                *(f32 *)(spawn + 0x10) = ((GameObject *)obj)->anim.localPosZ;
                *(s16 *)(spawn + 0x1a) = 0x675;
                *(s16 *)(spawn + 0x1c) = 0;
                *(s16 *)(spawn + 0x1e) = -1;
                Obj_SetupObject(spawn, 5, *(s8 *)((char *)obj + 0xac), -1, *(int *)&((GameObject *)obj)->anim.parent);
            }
            ((GameObject *)obj)->anim.rotY = 0;
            ((GameObject *)obj)->anim.rotZ = 0;
            p->baddie.unk25F = 0;
            *(int *)p |= 0x1000000;
            GameBit_Set(0xb48, 1);
            (*(void (**)(void *))((char *)*gGameUIInterface + 0x60))(*gGameUIInterface);
        }
    } else {
        (*(void (**)(int, char *, int))((char *)*gPlayerInterface + 0x14))(obj, (char *)p, 3);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void hightop_update(int obj) {
    char *p = ((GameObject *)obj)->extra;
    *(s16 *)(p + 0xc16) = 5;
    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~8;
    *(s8 *)(p + 0x25f) = !((BitFlags8 *)(p + 0xc49))->b4;
    *(u8 *)(p + 0x354) = 0;
    *(int *)p &= ~0x8000;
    if ((*(u16 *)(p + 0xc40) & 0x40) != 0) {
        int ev = Obj_UpdateRomCurveFollowVelocity(obj, (f32 *)(p + 0xa10),
                             lbl_803DC324 * (*(f32 *)(p + 0xc28) * timeDelta),
                             lbl_803E6B44, lbl_803E6ADC * timeDelta, 0);
        if (ev != 0) {
            if (ev == -1) {
                *(u16 *)(p + 0xc40) &= ~0x140;
                *(u8 *)(p + 0x9fd) &= ~2;
            } else {
                hightop_handleMotionEvent(obj, (u8)ev);
            }
        }
    } else {
        *(f32 *)(p + 0x290) = lbl_803E6AA8;
        *(f32 *)(p + 0x28c) = lbl_803E6AA8;
    }
    *(int *)(p + 0x31c) = 0;
    *(int *)(p + 0x318) = 0;
    *(s16 *)(p + 0x330) = 0;
    *(int *)p &= ~0x400000;
    (*(void (**)(int, char *, f32, f32, void **, void *))((char *)*gPlayerInterface + 0x8))(
        obj, (char *)p, (f32)(u32)framesThisStep, timeDelta, gHighTopStateHandlers, &gHighTopDefaultStateHandler);
    hightop_playMovementSfx(obj, (int)p, (int)p);
    characterDoEyeAnims(obj, (void *)(p + 0x38c));
    objAnimFn_80038f38(obj, (void *)(p + 0x3bc));
    dll_2E_func03(obj, (void *)(p + 0x3ec));
    if (ObjTrigger_IsSet(obj) != 0) {
        s8 v;
        buttonDisable(0, 0x100);
        v = (s8)*(u8 *)(p + 0xc4b);
        if (v != -1) {
            if (v < 0xa) {
                (*gObjectTriggerInterface)
                    ->runSequence(v, (void *)obj, -1);
            } else {
                GameBit_Set(*(s16 *)((char *)&lbl_803DC314 + v * 2 - 0x14), 1);
            }
        }
    }
    if ((int)randomGetRange(0, 0x64) == 0) {
        objSoundFn_800392f0(obj, (int)(p + 0x3bc), &lbl_8032AAB0[randomGetRange(0, 2) * 6], 0);
    }
    if (((BitFlags8 *)(p + 0xc49))->b7 != 0) {
        (*(void (**)(int, void *))((char *)*gGameUIInterface + 0x5c))(*(s16 *)(p + 0xc18), *gGameUIInterface);
        *(f32 *)(p + 0xc38) += timeDelta;
        if (*(f32 *)(p + 0xc38) > lbl_803E6B48) {
            *(f32 *)(p + 0xc38) -= lbl_803E6B48;
            Sfx_PlayFromObject(obj, 0x47f);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int hightop_stateHandler01(int obj, int p) {
    f32 v;
    v = lbl_803E6AA8;
    *(f32 *)((char *)p + 0x294) = v;
    *(f32 *)((char *)p + 0x284) = v;
    *(f32 *)((char *)p + 0x280) = v;
    ((GameObject *)obj)->anim.velocityX = v;
    ((GameObject *)obj)->anim.velocityY = v;
    ((GameObject *)obj)->anim.velocityZ = v;
    *(int *)((char *)p + 0) |= 0x200000;
    if ((s8)*(u8 *)((char *)p + 0x27a) != 0) {
        *(s16 *)((char *)p + 0x338) = 0;
        *(f32 *)((char *)p + 0x2a0) = lbl_803E6B24;
        *(f32 *)((char *)p + 0x2b8) = lbl_803E6B28;
        if (((GameObject *)obj)->anim.currentMove != lbl_803DC32C) {
            ObjAnim_SetCurrentMove(obj, lbl_803DC32C, lbl_803E6AA8, 0);
        }
    }
    if (*(f32 *)((char *)p + 0x298) < lbl_803E6B2C) {
        *(s16 *)((char *)p + 0x334) = 0;
        *(s16 *)((char *)p + 0x336) = 0;
        *(f32 *)((char *)p + 0x298) = lbl_803E6AA8;
    }
    if (*(f32 *)((char *)p + 0x29c) > lbl_803E6AA8 && *(f32 *)((char *)p + 0x298) > lbl_803E6AA8) {
        return 3;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int hightop_stateHandler07(int obj, int p) {
    HighTopRuntime *rt = ((GameObject *)obj)->extra;
    f32 v;
    if ((s8)*(u8 *)((char *)p + 0x27a) != 0) {
        v = lbl_803E6AA8;
        *(f32 *)((char *)p + 0x294) = v;
        *(f32 *)((char *)p + 0x284) = v;
        *(f32 *)((char *)p + 0x280) = v;
        ((GameObject *)obj)->anim.velocityX = v;
        ((GameObject *)obj)->anim.velocityY = v;
        ((GameObject *)obj)->anim.velocityZ = v;
        ObjHits_SyncObjectPositionIfDirty(obj);
        (*(void (**)(void))((char *)*gGameUIInterface + 0x60))();
        rt->flagsC49.b7 = 0;
        rt->flagsC49.b1 = 0;
        rt->unkC4B = 5;
        *(f32 *)((char *)p + 0x2a0) = lbl_803E6AAC;
        rt->unk9FD &= ~1;
        ObjGroup_RemoveObject(obj, 10);
    }
    if ((s8)*(u8 *)((char *)p + 0x346) != 0) {
        if (((GameObject *)obj)->anim.currentMove != 0) {
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E6AA8, 0);
            *(f32 *)((char *)p + 0x2a0) = lbl_803E6AC8;
        }
    }
    if ((s32)randomGetRange(0, 1000) != 0) {
        return 0;
    }
    return 9;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int hightop_stateHandler04(int obj, int p) {
    HighTopRuntime *state = ((GameObject *)obj)->extra;
    int move = -1;
    int count;
    int *player;
    if ((s8)*(u8 *)((char *)p + 0x27a) != 0) {
        state->flagsC49.b1 = 1;
        state->unkC30 = (f32)(int)randomGetRange(0x1f4, 0x3e8);
        state->unkC4B = 0;
        if (((GameObject *)obj)->anim.currentMove != 2) {
            move = 2;
            *(f32 *)((char *)p + 0x2a0) = lbl_803E6AAC;
        }
        fn_80039264((char *)state + 0xb48);
    }
    count = GameBit_Get(0x9c9) + GameBit_Get(0x9c7) + GameBit_Get(0x9cb) + GameBit_Get(0x9cd);
    if (GameBit_Get(0x62b) != 0) {
        HighTopRuntime *state2;
        GameBit_Set(0x62f, 1);
        ObjHits_MarkObjectPositionDirty(obj);
        ObjHits_ClearSourceMask(obj, 1);
        *(u8 *)(*(int *)&((GameObject *)obj)->anim.modelInstance + 0x71) &= ~1;
        state->unkC4B = -1;
        state->unkC40 |= 0x40;
        state->unkC40 |= 0x20;
        state->flagsC49.b1 = 0;
        (*(void (**)(void *, int, int, void *))((char *)*gRomCurveInterface + 0xa8))(
            (char *)state + 0xa10, obj, 0x3463a, *gRomCurveInterface);
        state2 = ((GameObject *)obj)->extra;
        state2->flagsC49.b7 = 1;
        (*(void (**)(int, int, void *))((char *)*gGameUIInterface + 0x58))(lbl_803DC320, 0x5ce, *gGameUIInterface);
        (*(void (**)(int, void *))((char *)*gGameUIInterface + 0x5c))(
            state2->unkC18, *gGameUIInterface);
        fn_80039264((char *)state + 0xb48);
        return 7;
    }
    if (count == 4) {
        GameBit_Set(0x62a, 1);
        return 0;
    }
    objModelAndSoundFn_80039118(obj, (char *)state + 0xb48);
    state->unkC30 -= (f32)(u32)framesThisStep;
    if (((GameObject *)obj)->anim.currentMove != 9 && ((GameObject *)obj)->anim.currentMove != 0x11) {
        RandomTimer_UpdateRangeTrigger((char *)state + 0xc34, lbl_803E6AD8, lbl_803E6ADC);
        if (count == 0) {
            if (state->unkC30 < lbl_803E6AA8) {
                *(f32 *)((char *)p + 0x2a0) = lbl_803E6AE0 * (f32)count + lbl_803E6AB0;
                move = 9;
                state->unkC30 = (f32)(int)(randomGetRange(0x2bc, 0x3e8) - count * 0x12c);
            }
        } else {
            if (randFn_80080100((4 - count) * 0xa) != 0) {
                *(f32 *)((char *)p + 0x2a0) = lbl_803E6AE8 * (f32)count + lbl_803E6AE4;
                move = 9;
                state->unkC30 = (f32)(int)(randomGetRange(0x2bc, 0x3e8) - count * 0x12c);
            }
        }
    }
    if ((s8)*(u8 *)((char *)p + 0x346) != 0) {
        if (((GameObject *)obj)->anim.currentMove != 2) {
            move = 2;
            *(f32 *)((char *)p + 0x2a0) = lbl_803E6AAC;
        }
    }
    if (move != -1) {
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)obj, 0x78);
        ObjAnim_SetCurrentMove(obj, move, lbl_803E6AA8, 0);
    }
    player = (int *)Obj_GetPlayerObject();
    if (player == 0) {
        state->unk9FD &= ~1;
    } else {
        f32 dy = *(f32 *)((char *)player + 0x10) - ((GameObject *)obj)->anim.localPosY;
        f32 a = dy >= lbl_803E6AA8 ? dy : -dy;
        int doBlock;
        if (a < lbl_803E6AEC) {
            doBlock = 1;
        } else {
            f32 b = dy >= lbl_803E6AA8 ? dy : -dy;
            doBlock = b > lbl_803E6AF0;
        }
        if (doBlock == 0) {
            state->unk9FD &= ~1;
        } else {
            state->unk9FD |= 1;
            if (randomGetRange(0, 0x64) == 0 && ((GameObject *)obj)->anim.currentMove != 9) {
                f32 c = *(f32 *)((char *)player + 0x10) - ((GameObject *)obj)->anim.localPosY;
                f32 ac = c >= lbl_803E6AA8 ? c : -c;
                if (ac < lbl_803E6AEC) {
                    (*(void (**)(int, int, int, void *))((char *)*gObjectTriggerInterface + 0x48))(
                        9, obj, -1, *gObjectTriggerInterface);
                }
            }
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int hightop_stateHandler02(int obj, int p, f32 t) {
    HighTopRuntime *state = ((GameObject *)obj)->extra;
    int cont = 1;
    s16 d336;
    int absd;
    int conv;
    u32 band;
    int idx;
    int changed;
    f32 v;
    f32 f31;
    f32 ang;
    f32 moveSpeed;
    s16 *vec;
    *(u32 *)p = *(u32 *)p | 0x200000;
    if (*(f32 *)((char *)p + 0x298) < lbl_803E6B04) {
        *(s16 *)((char *)p + 0x334) = 0;
        *(s16 *)((char *)p + 0x336) = 0;
        *(f32 *)((char *)p + 0x298) = 0.0f;
    }
    d336 = *(s16 *)((char *)p + 0x336);
    if (d336 >= 0) {
        absd = d336;
    } else {
        absd = -d336;
    }
    if (state->unkC16 < absd) {
        conv = (int)(lbl_803E6B08 * ((f32)d336 * t));
        *(s16 *)obj = (s16)(*(s16 *)obj + ((s16)conv >> 5));
    } else {
        *(s16 *)obj = (lbl_803E6B0C * (((f32)d336 * t) / lbl_803E6B10) + (f32)*(s16 *)obj);
    }
    conv = (int)(lbl_803E6B08 * ((f32)*(s16 *)((char *)p + 0x336) * t));
    vec = (s16 *)objModelGetVecFn_800395d8(obj, 9);
    if (vec != 0) {
        vec[1] = (s16)(vec[1] + (((s16)conv - vec[1]) >> 3));
        vec[0] = (s16)(vec[0] + ((-vec[0]) >> 3));
        vec[1] = (vec[1] < -0x1555) ? -0x1555 : ((vec[1] > 0x1555) ? 0x1555 : vec[1]);
        vec[1] = (vec[1] < -0x1555) ? -0x1555 : ((vec[1] > 0x1555) ? 0x1555 : vec[1]);
    }
    v = *(f32 *)((char *)p + 0x298);
    if (v < 0.0f) {
        v = 0.0f;
    }
    if (v > lbl_803E6AB8) {
        v = lbl_803E6AB8;
    }
    f31 = lbl_803E6ADC * v;
    if (f31 < 0.0f) {
        f31 = 0.0f;
    }
    *(f32 *)((char *)p + 0x294) =
        t * ((f31 - *(f32 *)((char *)p + 0x294)) / *(f32 *)((char *)p + 0x2b8)) + *(f32 *)((char *)p + 0x294);
    if (((GameObject *)obj)->anim.rotY > 0) {
        ang = f31 - lbl_803E6B14 * mathSinf(lbl_803E6B18 * (f32)((GameObject *)obj)->anim.rotY / lbl_803E6B1C);
    } else {
        ang = f31 - lbl_803E6B20 * mathSinf(lbl_803E6B18 * (f32)((GameObject *)obj)->anim.rotY / lbl_803E6B1C);
    }
    *(f32 *)((char *)p + 0x280) =
        t * ((ang - *(f32 *)((char *)p + 0x280)) / *(f32 *)((char *)p + 0x2b8)) + *(f32 *)((char *)p + 0x280);
    changed = 0;
    moveSpeed = ((GameObject *)obj)->anim.currentMoveProgress;
    band = 0;
    while ((&lbl_803DC32C)[band] != ((GameObject *)obj)->anim.currentMove && band < 2) {
        band++;
    }
    if (band >= 2) {
        band = 0;
    }
    idx = band * 2;
    while (cont != 0) {
        f32 spd = *(f32 *)((char *)p + 0x294);
        if (spd < lbl_8032ABB0[idx]) {
            if ((int)band == 1) {
                return 2;
            }
            band -= 1;
            idx -= 2;
            changed = 1;
        } else if (spd >= lbl_8032ABB0[idx + 1]) {
            if ((int)band == 0) {
                moveSpeed = 0.0f;
            }
            band += 1;
            idx += 2;
            changed = 1;
        } else {
            cont = 0;
        }
    }
    if (changed != 0) {
        ObjAnim_SetCurrentMove(obj, (&lbl_803DC32C)[band], moveSpeed, 0);
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)obj, 0xa);
    }
    ObjAnim_SampleRootCurvePhase(*(f32 *)((char *)p + 0x280), (ObjAnimComponent *)obj, (f32 *)((char *)p + 0x2a0));
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int hightop_stateHandler09(int obj, int p) {
    HighTopRuntime *state = ((GameObject *)obj)->extra;
    int *sub = *(int **)&((GameObject *)obj)->anim.placementData;
    int r25;
    int i;
    if ((s8)*(u8 *)((char *)p + 0x27a) != 0 || state->flagsC49.b6 != 0) {
        if (state->flagsC4A.b0 != 0) {
            state->unkC4B = 9;
        } else {
            state->unkC4B = 0;
        }
        state->unk9FD &= ~1;
        state->flagsC49.b1 = 0;
        state->unkC42 = 0;
        state->flagsC49.b6 = 0;
        *(u32 *)p |= 0x1000000;
        storeZeroToFloatParam((char *)state + 0xc2c);
        ObjHits_EnableObject(obj);
        if (((GameObject *)obj)->anim.currentMove != 2) {
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)obj, 0x78);
            ObjAnim_SetCurrentMove(obj, 2, lbl_803E6AA8, 0);
            *(f32 *)((char *)p + 0x2a0) = lbl_803E6AAC;
        }
        *(f32 *)((char *)p + 0x2a0) = lbl_803E6AAC;
        r25 = GameBit_Get(0x3f0) - 1;
        state->unkC3C = 9;
        for (i = 0; i < 4; i++) {
            GameBit_Set((&lbl_803DC330)[i], i > r25);
        }
        if (r25 == 3) {
            GameBit_Set(0x3f4, 1);
            return 0xb;
        }
    }
    if (GameBit_Get(*(s16 *)((char *)sub + 0x1e)) == 0) {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
        if (randFn_80080100(0x64) != 0) {
            objSoundFn_800392f0(obj, (int)((char *)state + 0x3bc), &lbl_803DC308 + randomGetRange(0, 0) * 6, 1);
        }
        if ((s8)*(u8 *)((char *)p + 0x346) != 0) {
            if (randFn_80080100(2) != 0) {
                ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)obj, 0x78);
                ObjAnim_SetCurrentMove(obj, 9, lbl_803E6AA8, 0);
                *(f32 *)((char *)p + 0x2a0) = lbl_803E6AB0;
            } else {
                ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)obj, 0x78);
                ObjAnim_SetCurrentMove(obj, 2, lbl_803E6AA8, 0);
                *(f32 *)((char *)p + 0x2a0) = lbl_803E6AAC;
            }
        }
        return 0;
    }
    {
        s16 yItem;
        getYButtonItem(&yItem);
        if ((GameBit_Get(0xaf7) != 0 && cMenuGetSelectedItem() != -1) || yItem == 0xaf7) {
            fn_8002B6D8(obj, 0, 0, 0, 0, 4);
        } else {
            fn_8002B6D8(obj, 0, 0, 0, 0, 2);
        }
    }
    if (ObjTrigger_IsSetById(obj, 0xaf7) != 0) {
        int total = GameBit_Get(0x3f0) + GameBit_Get(0xaf7);
        GameBit_Set(0x3f0, total);
        GameBit_Set(0xaf7, 0);
        if (randFn_80080100(5 - total) != 0) {
            state->unkC4B = 2;
        } else {
            state->unkC4B = 9;
        }
        objModelClearVecFn_8003aa40(obj);
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)obj, 0);
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E6AA8, 0);
        ObjHits_DisableObject(obj);
        fn_8002B6D8(obj, 0, 0, 0, 0, 2);
        (*(void (**)(int, int, int, void *))((char *)*gObjectTriggerInterface + 0x48))(
            1, obj, -1, *gObjectTriggerInterface);
        return 0;
    }
    if ((s8)*(u8 *)((char *)p + 0x346) != 0) {
        if (((GameObject *)obj)->anim.currentMove != 2) {
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)obj, 0x78);
            ObjAnim_SetCurrentMove(obj, 2, lbl_803E6AA8, 0);
            *(f32 *)((char *)p + 0x2a0) = lbl_803E6AAC;
        }
    }
    if (fn_80080150((char *)state + 0xc2c) != 0) {
        if (timerCountDown((char *)state + 0xc2c) != 0) {
            state->unkC4B = -1;
            (*(void (**)(int, int, int, void *))((char *)*gObjectTriggerInterface + 0x48))(
                lbl_8032AB30[state->unkC42], obj, -1, *gObjectTriggerInterface);
        }
    } else {
        if (Vec_distance((f32 *)((char *)Obj_GetPlayerObject() + 0x18), (f32 *)((char *)obj + 0x18)) > lbl_803E6AA4) {
            if (randFn_80080100(0x1f4) != 0) {
                int roll = randomGetRange(0, 0x64);
                int idx = 0;
                while (lbl_8032AB3C[idx] < roll) {
                    roll -= lbl_8032AB3C[idx];
                    idx++;
                }
                state->unkC42 = (u8)idx;
                state->unk9FD |= 1;
                s16toFloat((char *)state + 0xc2c, 0x14);
            }
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int hightop_stateHandler10(int obj, int p) {
    HighTopRuntime *rt = ((GameObject *)obj)->extra;
    int r;
    int i;
    if ((s8)*(u8 *)((char *)p + 0x27a) != 0) {
        rt->unkC4B = 3;
        *(int *)((char *)p + 0) |= 0x1000000;
    }
    if (GameBit_Get(451) != 0) {
        if ((int)GameBit_Get(238) == 2) {
            rt->unkC4B = 7;
        } else {
            rt->unkC4B = 9;
        }
    } else {
        rt->unkC4B = 3;
    }
    if (Vec_distance((f32 *)((char *)Obj_GetPlayerObject() + 0x18), (f32 *)((char *)obj + 0x18)) > lbl_803E6AA4) {
        if (randFn_80080100(500) != 0) {
            int *weights;
            int *weight;

            r = randomGetRange(0, 100);
            i = 0;
            weights = lbl_8032AB3C;
            weight = weights;
            while (*weight < r) {
                weight++;
                r -= weights[i];
                i++;
            }
            (*gObjectTriggerInterface)
                ->runSequence(lbl_8032AB30[i], (void *)obj, -1);
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset
