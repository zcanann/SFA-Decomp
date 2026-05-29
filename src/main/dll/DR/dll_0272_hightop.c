#include "main/dll/DR/dr_shared.h"

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
    u8 *p = *(u8 **)((char *)obj + 0xb8);
    p[0xc43] = v;
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
    f32 *p = *(f32 **)((char *)obj + 0xb8);
    *a = *(f32 *)((char *)p + 0xb6c);
    *b = *(f32 *)((char *)p + 0xb70);
    *c = *(f32 *)((char *)p + 0xb74);
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
    int p = *(int *)((char *)obj + 0x4c);
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
    u8 *p = *(u8 **)((char *)obj + 0xb8);
    if ((s8)p2[0x27a] != 0) {
        p[0x9fd] |= 1;
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
    int p = *(int *)((char *)obj + 0xb8);
    f32 zero = lbl_803E6AA8;
    *(f32 *)(p2 + 0x294) = zero;
    *(f32 *)(p2 + 0x284) = zero;
    *(f32 *)(p2 + 0x280) = zero;
    *(f32 *)((char *)obj + 0x24) = zero;
    *(f32 *)((char *)obj + 0x28) = zero;
    *(f32 *)((char *)obj + 0x2c) = zero;
    if ((s8)p2[0x27a] != 0) {
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)obj, 0x78);
        if (*(u32 *)(p + 0xc3c) == 4) {
            ObjAnim_SetCurrentMove(obj, 0x13, lbl_803E6AA8, 0);
            *(f32 *)(p2 + 0x2a0) = lbl_803E6AC8;
        } else {
            ObjAnim_SetCurrentMove(obj, 0x13, lbl_803E6AA8, 0);
            *(f32 *)(p2 + 0x2a0) = lbl_803E6AC8;
        }
    }
    if (*(f32 *)((char *)obj + 0x98) > lbl_803E6B00) {
        return *(int *)(p + 0xc3c) + 1;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int hightop_stateHandler05(int obj, u8 *p2) {
    u8 *p = *(u8 **)((char *)obj + 0xb8);
    if ((s8)p2[0x27a] != 0) {
        ((BitFlags8 *)(p + 0xc49))->b1 = 0;
        p[0xc4b] = 0xa;
    }
    switch ((s8)p[0xc4b]) {
    case 1:
        if (GameBit_Get(0x62c) != 0) {
            p[0xc4b] = 2;
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
    char *p;
    seqFn_800394a0(obj);
    p = *(char **)((char *)obj + 0xb8);
    *(u8 *)(p + 0x9fd) &= ~1;
    ((BitFlags8 *)(p + 0xc49))->b4 = 0;
    ((BitFlags8 *)(p + 0xc49))->b6 = 1;
    if ((s8)p[0xc4b] == 0) {
        ((BitFlags8 *)(p + 0xc4a))->b0 = 1;
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
    char *p;
    switch (mode) {
    case 2:
        if (dll_2E_func0A(0x11, buf) != 0) {
            *out = getAngle(buf[3] - *(f32 *)((char *)obj + 0xc), buf[5] - *(f32 *)((char *)obj + 0x14)) + lbl_803DC328;
            p = *(char **)((char *)obj + 0xb8);
            *(f32 *)(p + 0xc1c) = buf[3];
            *(f32 *)(p + 0xc20) = buf[4];
            *(f32 *)(p + 0xc24) = buf[5];
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
    pos.scale = scale / *(f32 *)(*(int *)((char *)obj + 0x50) + 0x4);
    setMatrixFromObjectPos(lbl_803AD208, &pos);
    mtx44_mult(lbl_803AD208, mtx, lbl_803AD208);
    fn_8003B950(lbl_803AD208);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void hightop_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible) {
    char *runtime = *(char **)((char *)obj + 0xb8);
    if (visible != 0) {
        int count;
        int **list;
        int i;
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E6AB8);
        ObjPath_GetPointWorldPosition((int)obj, 2, (f32 *)(runtime + 0xb6c), (f32 *)(runtime + 0xb70), (f32 *)(runtime + 0xb74), 0);
        ObjPath_GetPointWorldPositionArray((int)obj, 3, 4, (f32 *)(runtime + 0xb18));
        ObjPath_GetPointWorldPosition((int)obj, 0, (f32 *)(runtime + 0xb78), (f32 *)(runtime + 0xb7c), (f32 *)(runtime + 0xb80), 0);
        ((BitFlags8 *)(runtime + 0xc49))->b5 = 1;
        dll_2E_func06((int)obj, runtime + 0x3ec, 0);
        if (((BitFlags8 *)(runtime + 0xc49))->b1 != 0) {
            list = (int **)ObjGroup_GetObjects(55, &count);
            for (i = 0; i < count; i++) {
                int idx = (*(int (**)(int *))((char *)**(int ***)((char *)*list + 0x68) + 0x24))(*list);
                (*(void (**)(int *, void *, int, undefined4, undefined4, undefined4, undefined4))((char *)**(int ***)((char *)*list + 0x68) + 0x20))(
                    *list, obj, lbl_8032AB48[idx], p2, p3, p4, p5);
                list++;
            }
        }
    } else {
        ((BitFlags8 *)(runtime + 0xc49))->b5 = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void hightop_init(void *obj, u8 *arg) {
    u8 *base = lbl_8032AAB0;
    char *runtime = *(char **)((char *)obj + 0xb8);
    char *pathObj;
    int *node;
    HtInitData local1;
    HtInitData local2;
    int local8;
    local8 = lbl_803E6AA0;
    local1 = lbl_802C2590;
    local2 = lbl_802C25A4;
    *(s16 *)obj = (s16)((s8)arg[0x18] << 8);
    *(int *)((char *)obj + 0xbc) = (int)hightop_interactionCallback;
    *(u8 *)(runtime + 0xc45) = arg[0x19];
    *(s16 *)(runtime + 0xc16) = 5;
    *(s8 *)(runtime + 0xc4b) = -1;
    node = *(int **)((char *)obj + 0x64);
    if (node != 0) {
        *(int *)((char *)node + 0x30) |= 0xa10;
    }
    ObjGroup_AddObject((int)obj, 38);
    ObjGroup_AddObject((int)obj, 10);
    (*(void (**)(void *, char *, int, int))((char *)*gPlayerInterface + 4))(obj, runtime, 11, 1);
    *(f32 *)(runtime + 0x2a4) = lbl_803E6B4C;
    pathObj = runtime + 4;
    *(u8 *)(pathObj + 0x25b) = 1;
    (*(void (**)(char *, int, int, int))((char *)*gPathControlInterface + 4))(pathObj, 3, 1024, 0);
    (*(void (**)(char *, int, u8 *, int *, int))((char *)*gPathControlInterface + 8))(pathObj, 2, &base[0xe8], &lbl_803DC318, 8);
    (*(void (**)(char *, int, u8 *, u8 *, int *))((char *)*gPathControlInterface + 12))(pathObj, 4, &base[0xa8], &base[0xd8], &local8);
    (*(void (**)(void *, char *))((char *)*gPathControlInterface + 32))(obj, pathObj);
    dll_2E_func05((int)obj, runtime + 0x3ec, -4551, 23665, 6);
    dll_2E_func08(runtime + 0x3ec, 300, 120);
    dll_2E_func09(runtime + 0x3ec, &local2, &local1, 6);
    *(u8 *)(runtime + 0x9fd) |= 2;
    *(u8 *)(runtime + 0x9fd) |= 8;
    *(s16 *)(runtime + 0xc18) = *(s16 *)(arg + 0x1a);
    *(u8 *)(runtime + 0x9fd) |= 1;
    *(u8 *)(*(int *)((char *)obj + 0x50) + 0x71) = 127;
    ((BitFlags8 *)(runtime + 0xc49))->b4 = 0;
    ((BitFlags8 *)(runtime + 0xc49))->b7 = 0;
    lbl_803DC320 = *(s16 *)(arg + 0x1a);
    if (*(s16 *)(arg + 0x1c) == 0) {
        *(f32 *)(runtime + 0xc28) = lbl_803E6B50;
    } else {
        *(f32 *)(runtime + 0xc28) = (f32)*(s16 *)(arg + 0x1c) / lbl_803E6B54;
    }
    ((BitFlags8 *)(runtime + 0xc49))->b6 = 0;
    ((BitFlags8 *)(runtime + 0xc4a))->b0 = 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int hightop_stateHandler08(int obj, u8 *p2) {
    int *state = *(int **)((char *)obj + 0xb8);
    if ((s8)p2[0x27a] != 0) {
        f32 zero;
        *(f32 *)((char *)state + 0xc30) = lbl_803E6AB4;
        zero = lbl_803E6AA8;
        *(f32 *)(p2 + 0x294) = zero;
        *(f32 *)(p2 + 0x284) = zero;
        *(f32 *)(p2 + 0x280) = zero;
        *(f32 *)((char *)obj + 0x24) = zero;
        *(f32 *)((char *)obj + 0x28) = zero;
        *(f32 *)((char *)obj + 0x2c) = zero;
    }
    if ((s8)p2[0x346] != 0) {
        s16 cur = *(s16 *)((char *)obj + 0xa0);
        switch (cur) {
        case 10:
            if (*(f32 *)(p2 + 0x2a0) > lbl_803E6AA8) {
                ObjAnim_SetCurrentMove(obj, 5, lbl_803E6AA8, 0);
            } else {
                return 8;
            }
            break;
        case 5:
            if (*(f32 *)((char *)state + 0xc30) < lbl_803E6AA8) {
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
    if (*(s16 *)((char *)obj + 0xa0) == 10) {
        if (*(f32 *)(p2 + 0x2a0) < lbl_803E6AA8) {
            if (*(f32 *)((char *)obj + 0x98) < lbl_803E6AC4) {
                ObjAnim_SetCurrentMove(obj, 0, lbl_803E6AA8, 0);
                *(f32 *)(p2 + 0x2a0) = lbl_803E6AC8;
                return 8;
            }
        }
    }
    *(f32 *)((char *)state + 0xc30) -= (f32)(u32)framesThisStep;
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
    char *runtime = *(char **)((char *)obj + 0xb8);
    switch (event) {
    case 5:
        (*(void (**)(int, char *, int))((char *)*gPlayerInterface + 0x14))(obj, runtime, 8);
        break;
    case 6:
        GameBit_Set(0x634, 1);
        (*(void (**)(int, int, int))((char *)*gObjectTriggerInterface + 0x48))(4, obj, -1);
        break;
    case 7:
        GameBit_Set(0x634, 0);
        GameBit_Set(0x631, 1);
        *(u8 *)(*(int *)((char *)obj + 0x50) + 0x71) |= 1;
        *(u16 *)(runtime + 0xc40) &= ~0x140;
        *(u8 *)(runtime + 0x9fd) &= ~2;
        (*(void (**)(int, char *, int))((char *)*gPlayerInterface + 0x14))(obj, runtime, 7);
        break;
    case 8:
        (*(void (**)(int, int, int))((char *)*gObjectTriggerInterface + 0x48))(7, obj, -1);
        break;
    case 9:
        (*(void (**)(int, char *, int))((char *)*gPlayerInterface + 0x14))(obj, runtime, 7);
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
    char *p = *(char **)((char *)obj + 0xb8);
    f32 l10;
    f32 lc;
    f32 l8;
    int hit;
    s16 st;
    hit = ObjHits_GetPriorityHitWithPosition(obj, 0, 0, 0, &l8, &lc, &l10);
    if (hit == 0) {
        return;
    }
    st = *(s16 *)(p + 0x274);
    if (st != 4 && (u16)(st - 9) > 1) {
        if (hit == 0xf || hit == 0xe) {
            return;
        }
    }
    if (*(s16 *)(p + 0xc18) == 0) {
        return;
    }
    Obj_SpawnHitLightAndFade(obj, &l8, lbl_803E6B40);
    objSoundFn_800392f0(obj, (int)(p + 0x3bc), &lbl_803DC308 + randomGetRange(0, 0) * 6, 1);
    st = *(s16 *)(p + 0x274);
    if (st != 3) {
        *(int *)(p + 0xc3c) = st;
    }
    st = *(s16 *)(p + 0x274);
    if (st == 2 || st == 8) {
        *(s16 *)(p + 0xc18) -= 1;
        fn_8009A8C8(obj, lbl_803E6B30);
        if (*(s16 *)(p + 0xc18) <= 0) {
            (*(void (**)(void *))((char *)*gGameUIInterface + 0x60))(*gGameUIInterface);
            ((BitFlags8 *)(p + 0xc49))->b7 = 0;
            GameBit_Set(0x634, 0);
            if (Obj_IsLoadingLocked() != 0) {
                int spawn = Obj_AllocObjectSetup(0x2c, 0xd4);
                *(u8 *)(spawn + 0x4) = 2;
                *(f32 *)(spawn + 0x8) = *(f32 *)((char *)obj + 0xc);
                *(f32 *)(spawn + 0xc) = *(f32 *)((char *)obj + 0x10);
                *(f32 *)(spawn + 0x10) = *(f32 *)((char *)obj + 0x14);
                *(s16 *)(spawn + 0x1a) = 0x675;
                *(s16 *)(spawn + 0x1c) = 0;
                *(s16 *)(spawn + 0x1e) = -1;
                Obj_SetupObject(spawn, 5, *(s8 *)((char *)obj + 0xac), -1, *(int *)((char *)obj + 0x30));
            }
            *(s16 *)((char *)obj + 0x2) = 0;
            *(s16 *)((char *)obj + 0x4) = 0;
            *(u8 *)(p + 0x25f) = 0;
            *(int *)p |= 0x1000000;
            GameBit_Set(0xb48, 1);
            (*(void (**)(void *))((char *)*gGameUIInterface + 0x60))(*gGameUIInterface);
        }
    } else {
        (*(void (**)(int, char *, int))((char *)*gPlayerInterface + 0x14))(obj, p, 3);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void hightop_update(int obj) {
    char *p = *(char **)((char *)obj + 0xb8);
    *(s16 *)(p + 0xc16) = 5;
    *(u8 *)((char *)obj + 0xaf) &= ~8;
    *(s8 *)(p + 0x25f) = !((BitFlags8 *)(p + 0xc49))->b4;
    *(u8 *)(p + 0x354) = 0;
    *(int *)p &= ~0x8000;
    if ((*(u16 *)(p + 0xc40) & 0x40) != 0) {
        int ev = fn_80222358(obj, (f32 *)(p + 0xa10),
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
        obj, p, (f32)(u32)framesThisStep, timeDelta, gHighTopStateHandlers, &gHighTopDefaultStateHandler);
    hightop_playMovementSfx(obj, (int)p, (int)p);
    characterDoEyeAnims(obj, (void *)(p + 0x38c));
    objAnimFn_80038f38(obj, (void *)(p + 0x3bc));
    dll_2E_func03(obj, (void *)(p + 0x3ec));
    if (ObjTrigger_IsSet(obj) != 0) {
        s8 v;
        buttonDisable(0, 0x100);
        v = (s8)p[0xc4b];
        if (v != -1) {
            if (v < 0xa) {
                (*(void (**)(int, int, int))((char *)*gObjectTriggerInterface + 0x48))(v, obj, -1);
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
    *(f32 *)((char *)obj + 0x24) = v;
    *(f32 *)((char *)obj + 0x28) = v;
    *(f32 *)((char *)obj + 0x2c) = v;
    *(int *)((char *)p + 0) |= 0x200000;
    if ((s8)*(u8 *)((char *)p + 0x27a) != 0) {
        *(s16 *)((char *)p + 0x338) = 0;
        *(f32 *)((char *)p + 0x2a0) = lbl_803E6B24;
        *(f32 *)((char *)p + 0x2b8) = lbl_803E6B28;
        if (*(s16 *)((char *)obj + 0xa0) != lbl_803DC32C) {
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
    u8 *rt = *(u8 **)((char *)obj + 0xb8);
    f32 v;
    if ((s8)*(u8 *)((char *)p + 0x27a) != 0) {
        v = lbl_803E6AA8;
        *(f32 *)((char *)p + 0x294) = v;
        *(f32 *)((char *)p + 0x284) = v;
        *(f32 *)((char *)p + 0x280) = v;
        *(f32 *)((char *)obj + 0x24) = v;
        *(f32 *)((char *)obj + 0x28) = v;
        *(f32 *)((char *)obj + 0x2c) = v;
        ObjHits_SyncObjectPositionIfDirty(obj);
        (*(void (**)(void))((char *)*gGameUIInterface + 0x60))();
        ((BitFlags8 *)(rt + 0xc49))->b7 = 0;
        ((BitFlags8 *)(rt + 0xc49))->b1 = 0;
        *(u8 *)(rt + 0xc4b) = 5;
        *(f32 *)((char *)p + 0x2a0) = lbl_803E6AAC;
        *(u8 *)(rt + 0x9fd) &= ~1;
        ObjGroup_RemoveObject(obj, 10);
    }
    if ((s8)*(u8 *)((char *)p + 0x346) != 0) {
        if (*(s16 *)((char *)obj + 0xa0) != 0) {
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
    int *state = *(int **)((char *)obj + 0xb8);
    int move = -1;
    int count;
    int *player;
    if ((s8)*(u8 *)((char *)p + 0x27a) != 0) {
        ((BitFlags8 *)((char *)state + 0xc49))->b1 = 1;
        *(f32 *)((char *)state + 0xc30) = (f32)(int)randomGetRange(0x1f4, 0x3e8);
        *(u8 *)((char *)state + 0xc4b) = 0;
        if (*(s16 *)((char *)obj + 0xa0) != 2) {
            move = 2;
            *(f32 *)((char *)p + 0x2a0) = lbl_803E6AAC;
        }
        fn_80039264((char *)state + 0xb48);
    }
    count = GameBit_Get(0x9c9) + GameBit_Get(0x9c7) + GameBit_Get(0x9cb) + GameBit_Get(0x9cd);
    if (GameBit_Get(0x62b) != 0) {
        int *state2;
        GameBit_Set(0x62f, 1);
        ObjHits_MarkObjectPositionDirty(obj);
        ObjHits_ClearSourceMask(obj, 1);
        *(u8 *)(*(int *)((char *)obj + 0x50) + 0x71) &= ~1;
        *(u8 *)((char *)state + 0xc4b) = -1;
        *(u16 *)((char *)state + 0xc40) |= 0x40;
        *(u16 *)((char *)state + 0xc40) |= 0x20;
        ((BitFlags8 *)((char *)state + 0xc49))->b1 = 0;
        (*(void (**)(void *, int, int, void *))((char *)*gRomCurveInterface + 0xa8))(
            (char *)state + 0xa10, obj, 0x3463a, *gRomCurveInterface);
        state2 = *(int **)((char *)obj + 0xb8);
        ((BitFlags8 *)((char *)state2 + 0xc49))->b7 = 1;
        (*(void (**)(int, int, void *))((char *)*gGameUIInterface + 0x58))(lbl_803DC320, 0x5ce, *gGameUIInterface);
        (*(void (**)(int, void *))((char *)*gGameUIInterface + 0x5c))(
            *(s16 *)((char *)state2 + 0xc18), *gGameUIInterface);
        fn_80039264((char *)state + 0xb48);
        return 7;
    }
    if (count == 4) {
        GameBit_Set(0x62a, 1);
        return 0;
    }
    objModelAndSoundFn_80039118(obj, (char *)state + 0xb48);
    *(f32 *)((char *)state + 0xc30) -= (f32)(u32)framesThisStep;
    if (*(s16 *)((char *)obj + 0xa0) != 9 && *(s16 *)((char *)obj + 0xa0) != 0x11) {
        RandomTimer_UpdateRangeTrigger((char *)state + 0xc34, lbl_803E6AD8, lbl_803E6ADC);
        if (count == 0) {
            if (*(f32 *)((char *)state + 0xc30) < lbl_803E6AA8) {
                *(f32 *)((char *)p + 0x2a0) = lbl_803E6AE0 * (f32)count + lbl_803E6AB0;
                move = 9;
                *(f32 *)((char *)state + 0xc30) = (f32)(int)(randomGetRange(0x2bc, 0x3e8) - count * 0x12c);
            }
        } else {
            if (randFn_80080100((4 - count) * 0xa) != 0) {
                *(f32 *)((char *)p + 0x2a0) = lbl_803E6AE8 * (f32)count + lbl_803E6AE4;
                move = 9;
                *(f32 *)((char *)state + 0xc30) = (f32)(int)(randomGetRange(0x2bc, 0x3e8) - count * 0x12c);
            }
        }
    }
    if ((s8)*(u8 *)((char *)p + 0x346) != 0) {
        if (*(s16 *)((char *)obj + 0xa0) != 2) {
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
        *(u8 *)((char *)state + 0x9fd) &= ~1;
    } else {
        f32 dy = *(f32 *)((char *)player + 0x10) - *(f32 *)((char *)obj + 0x10);
        f32 a = dy >= lbl_803E6AA8 ? dy : -dy;
        int doBlock;
        if (a < lbl_803E6AEC) {
            doBlock = 1;
        } else {
            f32 b = dy >= lbl_803E6AA8 ? dy : -dy;
            doBlock = b > lbl_803E6AF0;
        }
        if (doBlock == 0) {
            *(u8 *)((char *)state + 0x9fd) &= ~1;
        } else {
            *(u8 *)((char *)state + 0x9fd) |= 1;
            if (randomGetRange(0, 0x64) == 0 && *(s16 *)((char *)obj + 0xa0) != 9) {
                f32 c = *(f32 *)((char *)player + 0x10) - *(f32 *)((char *)obj + 0x10);
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
    int *state = *(int **)((char *)obj + 0xb8);
    s16 d336;
    int absd;
    int conv;
    int band;
    int changed;
    int cont;
    f32 v;
    f32 f31;
    f32 ang;
    f32 moveSpeed;
    s16 *vec;
    *(u32 *)p = *(u32 *)p | 0x200000;
    if (*(f32 *)((char *)p + 0x298) < lbl_803E6B04) {
        *(s16 *)((char *)p + 0x334) = 0;
        *(s16 *)((char *)p + 0x336) = 0;
        *(f32 *)((char *)p + 0x298) = lbl_803E6AA8;
    }
    d336 = *(s16 *)((char *)p + 0x336);
    absd = d336 < 0 ? -d336 : d336;
    if (*(s16 *)((char *)state + 0xc16) < absd) {
        conv = (int)(lbl_803E6B08 * ((f32)d336 * t));
        *(s16 *)obj = (s16)(*(s16 *)obj + ((s16)conv >> 5));
    } else {
        *(s16 *)obj = (s16)(int)(lbl_803E6B0C * (((f32)d336 * t) / lbl_803E6B10) + (f32)*(s16 *)obj);
    }
    conv = (int)(lbl_803E6B08 * ((f32)*(s16 *)((char *)p + 0x336) * t));
    vec = (s16 *)objModelGetVecFn_800395d8(obj, 9);
    if (vec != 0) {
        vec[1] = (s16)(vec[1] + (((s16)conv - vec[1]) >> 3));
        vec[0] = (s16)(vec[0] + ((-vec[0]) >> 3));
        if (vec[1] < -0x1555) {
            vec[1] = -0x1555;
        } else if (vec[1] > 0x1555) {
            vec[1] = 0x1555;
        }
        if (vec[1] < -0x1555) {
            vec[1] = -0x1555;
        } else if (vec[1] > 0x1555) {
            vec[1] = 0x1555;
        }
    }
    v = *(f32 *)((char *)p + 0x298);
    if (v < lbl_803E6AA8) {
        v = lbl_803E6AA8;
    }
    if (v > lbl_803E6AB8) {
        v = lbl_803E6AB8;
    }
    f31 = lbl_803E6ADC * v;
    if (f31 < lbl_803E6AA8) {
        f31 = lbl_803E6AA8;
    }
    *(f32 *)((char *)p + 0x294) =
        t * ((f31 - *(f32 *)((char *)p + 0x294)) / *(f32 *)((char *)p + 0x2b8)) + *(f32 *)((char *)p + 0x294);
    if (*(s16 *)((char *)obj + 0x2) > 0) {
        ang = f31 - lbl_803E6B14 * fn_80293E80(lbl_803E6B18 * (f32)*(s16 *)((char *)obj + 0x2) / lbl_803E6B1C);
    } else {
        ang = f31 - lbl_803E6B20 * fn_80293E80(lbl_803E6B18 * (f32)*(s16 *)((char *)obj + 0x2) / lbl_803E6B1C);
    }
    *(f32 *)((char *)p + 0x280) =
        t * ((ang - *(f32 *)((char *)p + 0x280)) / *(f32 *)((char *)p + 0x2b8)) + *(f32 *)((char *)p + 0x280);
    moveSpeed = *(f32 *)((char *)obj + 0x98);
    band = 0;
    while ((&lbl_803DC32C)[band] != *(s16 *)((char *)obj + 0xa0) && band < 2) {
        band++;
    }
    if (band >= 2) {
        band = 0;
    }
    changed = 0;
    cont = 1;
    while (cont != 0) {
        f32 spd = *(f32 *)((char *)p + 0x294);
        if (spd < lbl_8032ABB0[band * 2]) {
            if (band == 1) {
                return 2;
            }
            band -= 1;
            changed = 1;
        } else if (spd >= lbl_8032ABB0[band * 2 + 1]) {
            if (band == 0) {
                moveSpeed = lbl_803E6AA8;
            }
            band += 1;
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
    int *state = *(int **)((char *)obj + 0xb8);
    int *sub = *(int **)((char *)obj + 0x4c);
    int r25;
    int i;
    if ((s8)*(u8 *)((char *)p + 0x27a) != 0 || ((BitFlags8 *)((char *)state + 0xc49))->b6 != 0) {
        if (((BitFlags8 *)((char *)state + 0xc4a))->b0 != 0) {
            *(u8 *)((char *)state + 0xc4b) = 9;
        } else {
            *(u8 *)((char *)state + 0xc4b) = 0;
        }
        *(u8 *)((char *)state + 0x9fd) &= ~1;
        ((BitFlags8 *)((char *)state + 0xc49))->b1 = 0;
        *(u8 *)((char *)state + 0xc42) = 0;
        ((BitFlags8 *)((char *)state + 0xc49))->b6 = 0;
        *(u32 *)p |= 0x1000000;
        storeZeroToFloatParam((char *)state + 0xc2c);
        ObjHits_EnableObject(obj);
        if (*(s16 *)((char *)obj + 0xa0) != 2) {
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)obj, 0x78);
            ObjAnim_SetCurrentMove(obj, 2, lbl_803E6AA8, 0);
            *(f32 *)((char *)p + 0x2a0) = lbl_803E6AAC;
        }
        *(f32 *)((char *)p + 0x2a0) = lbl_803E6AAC;
        r25 = GameBit_Get(0x3f0) - 1;
        *(int *)((char *)state + 0xc3c) = 9;
        for (i = 0; i < 4; i++) {
            GameBit_Set((&lbl_803DC330)[i], i > r25);
        }
        if (r25 == 3) {
            GameBit_Set(0x3f4, 1);
            return 0xb;
        }
    }
    if (GameBit_Get(*(s16 *)((char *)sub + 0x1e)) == 0) {
        *(u8 *)((char *)obj + 0xaf) |= 8;
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
            *(u8 *)((char *)state + 0xc4b) = 2;
        } else {
            *(u8 *)((char *)state + 0xc4b) = 9;
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
        if (*(s16 *)((char *)obj + 0xa0) != 2) {
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)obj, 0x78);
            ObjAnim_SetCurrentMove(obj, 2, lbl_803E6AA8, 0);
            *(f32 *)((char *)p + 0x2a0) = lbl_803E6AAC;
        }
    }
    if (fn_80080150((char *)state + 0xc2c) != 0) {
        if (timerCountDown((char *)state + 0xc2c) != 0) {
            *(u8 *)((char *)state + 0xc4b) = -1;
            (*(void (**)(int, int, int, void *))((char *)*gObjectTriggerInterface + 0x48))(
                lbl_8032AB30[*(u8 *)((char *)state + 0xc42)], obj, -1, *gObjectTriggerInterface);
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
                *(u8 *)((char *)state + 0xc42) = (u8)idx;
                *(u8 *)((char *)state + 0x9fd) |= 1;
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
    u8 *rt = *(u8 **)((char *)obj + 0xb8);
    int r;
    int i;
    if ((s8)*(u8 *)((char *)p + 0x27a) != 0) {
        *(u8 *)(rt + 0xc4b) = 3;
        *(int *)((char *)p + 0) |= 0x1000000;
    }
    if (GameBit_Get(451) != 0) {
        if ((int)GameBit_Get(238) == 2) {
            *(u8 *)(rt + 0xc4b) = 7;
        } else {
            *(u8 *)(rt + 0xc4b) = 9;
        }
    } else {
        *(u8 *)(rt + 0xc4b) = 3;
    }
    if (Vec_distance((f32 *)((char *)Obj_GetPlayerObject() + 0x18), (f32 *)((char *)obj + 0x18)) > lbl_803E6AA4) {
        if (randFn_80080100(500) != 0) {
            r = randomGetRange(0, 100);
            i = 0;
            while (lbl_8032AB3C[i] < r) {
                r -= lbl_8032AB3C[i];
                i++;
            }
            (*(void (**)(int, int, int))((char *)*gObjectTriggerInterface + 0x48))(lbl_8032AB30[i], obj, -1);
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset
