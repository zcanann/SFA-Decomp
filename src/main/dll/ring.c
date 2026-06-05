#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling on
int ring_getExtraSize(void) { return 0x24; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int ring_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void ring_free(int obj)
{
    int state = *(int *)(obj + 0xb8);
    if (*(void **)(state + 0x20) != NULL) {
        ModelLightStruct_free(*(void **)(state + 0x20));
        *(void **)(state + 0x20) = NULL;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void ring_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void ring_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    int state = *(int *)(obj + 0xb8);
    if (*(void **)(state + 0x20) != NULL && modelLightStruct_getActiveState(*(void **)(state + 0x20)) != 0) {
        queueGlowRender(*(void **)(state + 0x20));
    }
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E70B0);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void ring_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void ring_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void ring_init(int obj, int setup) {
    int state = *(int *)(obj + 0xb8);
    RingFlags *f = (RingFlags *)(state + 0x14);
    s16 type = *(s16 *)(obj + 0x46);
    if (type == 1548) {
        *(u8 *)(state + 0) = 0;
    } else if (type == 2073) {
        *(u8 *)(state + 0) = 0;
        f->bit10 = 1;
    } else if (type == 1547) {
        *(u8 *)(state + 0) = 2;
    } else if (type == 2044) {
        *(u8 *)(state + 0) = 3;
    } else if (type == 2043) {
        *(u8 *)(state + 0) = 4;
    } else {
        *(u8 *)(state + 0) = 2;
    }
    *(u8 *)(state + 1) = *(u8 *)(setup + 0x19);
    if (*(u8 *)(state + 1) == 2 || *(u8 *)(state + 1) == 3 || *(u8 *)(state + 1) == 5) {
        f->bit80 = 0;
        Obj_SetActiveModelIndex(obj, 1);
    } else {
        f->bit80 = 1;
        ObjHits_DisableObject(obj);
    }
    *(u16 *)(state + 2) = *(s16 *)(setup + 0x1a);
    *(f32 *)(state + 4) = (f32)*(s16 *)(setup + 0x1c) / lbl_803E70C4;
    *(f32 *)(state + 8) = *(f32 *)(obj + 12);
    *(f32 *)(state + 0xc) = *(f32 *)(obj + 16);
    if (*(s8 *)(setup + 0x18) != 0)
        f->bit20 = 1;
    else
        f->bit20 = 0;
    *(s16 *)obj = -32768;
    if (*(u8 *)(state + 0) == 3 || *(u8 *)(state + 0) == 4) {
        f->bit10 = 1;
        *(f32 *)(state + 0x10) = lbl_803E70D8;
    } else {
        *(s16 *)(obj + 6) |= 0x4000;
        *(u8 *)(obj + 0x36) = 0;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void ring_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int arwing;
    int setup = *(int *)(obj + 0x4c);
    int bit;
    int r;
    int hitA;
    int hitB;
    int hit;
    int ang;
    f32 dir[3];
    f32 spawnBuf[6];
    f32 mtx[12];

    arwing = getArwing();
    if (arwing == 0)
        arwing = Obj_GetPlayerObject();

    switch (*(u8 *)(state + 0x15)) {
    case 0:
        r = (int)((f32)(u32) * (u8 *)(obj + 0x36) - lbl_803E70B4 * timeDelta);
        if (r < 0) {
            r = 0;
            *(s16 *)(obj + 6) = (s16)(*(s16 *)(obj + 6) | 0x4000);
        }
        *(u8 *)(obj + 0x36) = (u8)r;
        bit = *(s16 *)(setup + 0x20);
        if (bit > -1) {
            if (GameBit_Get(bit) != 0) {
                *(s16 *)(obj + 6) = (s16)(*(s16 *)(obj + 6) & ~0x4000);
                *(u8 *)(state + 0x15) = 1;
            }
        } else {
            if (getArwing() != 0) {
                *(s16 *)(obj + 6) = (s16)(*(s16 *)(obj + 6) & ~0x4000);
                *(u8 *)(state + 0x15) = 1;
            }
        }
        return;
    case 1:
        r = (int)((f32)(u32) * (u8 *)(obj + 0x36) + lbl_803E70B4 * timeDelta);
        if (r > 0xff) r = 0xff;
        *(u8 *)(obj + 0x36) = (u8)r;
        bit = *(s16 *)(setup + 0x20);
        if (bit > -1) {
            if (GameBit_Get(bit) == 0)
                *(u8 *)(state + 0x15) = 1;
        }
        switch (*(u8 *)(state + 1)) {
        case 3:
        case 5:
            if (ObjHits_GetPriorityHit(obj, &hitA, 0, 0) != 0 && (hit = hitA) != 0 &&
                (*(s16 *)(hit + 0x46) == 0x604 || *(s16 *)(hit + 0x46) == 0x605)) {
                getArwing();
                arwarwing_addScore(getArwing(), 0xf);
                *(f32 *)(obj + 8) = *(f32 *)(*(int *)(obj + 0x50) + 4);
                Obj_SetActiveModelIndex(obj, 0);
                ObjHits_DisableObject(obj);
                *(u8 *)(state + 0x14) |= 0x80;
                if (*(void **)(state + 0x20) != NULL) {
                    ModelLightStruct_free(*(void **)(state + 0x20));
                    *(int *)(state + 0x20) = 0;
                }
            }
            arwbombcoll_updateMovingAxis(obj, state);
            break;
        case 2:
            if (ObjHits_GetPriorityHit(obj, &hitB, 0, 0) != 0 && (hit = hitB) != 0 &&
                (*(s16 *)(hit + 0x46) == 0x604 || *(s16 *)(hit + 0x46) == 0x605)) {
                getArwing();
                arwarwing_addScore(getArwing(), 0xf);
                *(f32 *)(obj + 8) = *(f32 *)(*(int *)(obj + 0x50) + 4);
                Obj_SetActiveModelIndex(obj, 0);
                ObjHits_DisableObject(obj);
                *(u8 *)(state + 0x14) |= 0x80;
                if (*(void **)(state + 0x20) != NULL) {
                    ModelLightStruct_free(*(void **)(state + 0x20));
                    *(int *)(state + 0x20) = 0;
                }
            }
            break;
        case 1:
        case 4:
            arwbombcoll_updateMovingAxis(obj, state);
            break;
        }
        if ((*(u8 *)(state + 0x14) & 0x80) != 0) {
            if (fn_8022D750(arwing) == 0 && fn_8022D710(arwing) == 0 &&
                arwbombcoll_checkArwingCollision(obj, state, arwing) != 0) {
                arwbombcoll_handleArwingHit(obj, state, arwing);
            }
        }
        *(s16 *)(obj + 0) =
            (s16)(int)((f32)(int) * (s16 *)(obj + 0) + lbl_803E70B8 * timeDelta);
        break;
    case 2:
        if (*(f32 *)(state + 0x18) > lbl_803E70A0) {
            if (arwing != 0) {
                *(f32 *)(obj + 0x24) =
                    oneOverTimeDelta * (*(f32 *)(arwing + 0xc) - *(f32 *)(obj + 0xc));
                *(f32 *)(obj + 0x28) =
                    oneOverTimeDelta *
                    (*(f32 *)(state + 0x10) + (*(f32 *)(arwing + 0x10) - *(f32 *)(obj + 0x10)));
                *(f32 *)(obj + 0x2c) =
                    oneOverTimeDelta * (*(f32 *)(arwing + 0x14) - *(f32 *)(obj + 0x14));
                objMove(obj, *(f32 *)(obj + 0x24) * timeDelta, *(f32 *)(obj + 0x28) * timeDelta,
                        *(f32 *)(obj + 0x2c) * timeDelta);
            }
            if (*(f32 *)(state + 0x18) > lbl_803E70BC) {
                *(s16 *)(obj + 0) =
                    (s16)(*(s16 *)(obj + 0) + lbl_8032B720[*(u8 *)(state)].f10);
                *(f32 *)(obj + 8) = (*(f32 *)(state + 0x18) - lbl_803E70BC) / lbl_803E70BC *
                                    *(f32 *)(*(int *)(obj + 0x50) + 4);
                if (lbl_803E70C0 != *(f32 *)(state + 0x18)) {
                    Obj_BuildWorldTransformMatrix(obj, mtx, 0);
                    for (ang = -0x7fff; ang < 0x7fff;
                         ang += lbl_8032B720[*(u8 *)(state)].f8) {
                        dir[0] = lbl_803E70C4 *
                                 sin(lbl_803E70C8 *
                                     (f32)(ang +
                                           (int)(*(f32 *)(state + 0x18) *
                                                 lbl_8032B720[*(u8 *)(state)].f14)) /
                                     lbl_803E70CC);
                        dir[1] = lbl_803E70C4 *
                                 fn_80293E80(lbl_803E70C8 *
                                             (f32)(ang +
                                                   (int)(*(f32 *)(state + 0x18) *
                                                         lbl_8032B720[*(u8 *)(state)].f14)) /
                                             lbl_803E70CC);
                        dir[2] = lbl_803E70A0;
                        PSMTXMultVecSR(mtx, dir, dir);
                        spawnBuf[3] = dir[0] + *(f32 *)(obj + 0xc);
                        spawnBuf[4] = dir[1] + *(f32 *)(obj + 0x10);
                        spawnBuf[5] = dir[2] + *(f32 *)(obj + 0x14);
                        (*(void (**)(int, int, f32 *, int, int, int))(*gPartfxInterface + 8))(
                            obj, lbl_8032B720[*(u8 *)(state)].f0, spawnBuf, 0x200001, -1,
                            obj + 0x24);
                        (*(void (**)(int, int, f32 *, int, int, int))(*gPartfxInterface + 8))(
                            obj, lbl_8032B720[*(u8 *)(state)].f0, spawnBuf, 0x200001, -1,
                            obj + 0x24);
                    }
                }
                *(u8 *)(state + 0x14) |= 0x40;
            } else {
                if ((*(u8 *)(state + 0x14) & 0x40) != 0) {
                    for (ang = 0; ang < lbl_8032B720[*(u8 *)(state)].fc; ang++) {
                        (*(void (**)(int, int, int, int, int, int))(*gPartfxInterface + 8))(
                            obj, lbl_8032B720[*(u8 *)(state)].f4, 0, 2, -1, 0);
                    }
                }
                *(u8 *)(state + 0x14) &= ~0x40;
                *(u8 *)(obj + 0x36) = 0;
            }
            *(f32 *)(state + 0x18) -= timeDelta;
            if (*(f32 *)(state + 0x18) <= lbl_803E70A0) {
                *(f32 *)(state + 0x18) = lbl_803E70A0;
                *(f32 *)(obj + 0xc) = *(f32 *)(setup + 8);
                *(f32 *)(obj + 0x10) = *(f32 *)(setup + 0xc);
                *(f32 *)(obj + 0x14) = *(f32 *)(setup + 0x10);
                *(s16 *)(obj + 0) = 0;
                *(u8 *)(obj + 0x36) = 0xff;
                *(f32 *)(obj + 8) = *(f32 *)(*(int *)(obj + 0x50) + 4);
                *(f32 *)(obj + 0x24) = lbl_803E70A0;
                *(f32 *)(obj + 0x28) = lbl_803E70A0;
                *(f32 *)(obj + 0x2c) = lbl_803E70A0;
                *(u8 *)(state + 0x15) = 3;
                *(s16 *)(obj + 6) = (s16)(*(s16 *)(obj + 6) | 0x4000);
            }
        } else {
            *(f32 *)(state + 0x18) = lbl_803E70C0;
        }
        break;
    }

    if (*(void **)(state + 0x20) != NULL && modelLightStruct_getActiveState(*(void **)(state + 0x20)) != 0) {
        modelLightStruct_updateGlowAlpha(*(void **)(state + 0x20));
    }
}
#pragma scheduling reset
#pragma peephole reset
