#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"
#include "main/dll/ARW/arwing_state.h"

#include "main/audio/sfx_ids.h"
#include "main/objhits_types.h"
#pragma peephole on
#pragma scheduling on
/* wcfloortile_getExtraSize == 0x8. */
typedef struct WcFloorTileState {
    f32 shakeTime;
    s16 shakeMag;
    u8 phase;   /* 0x6 */
    u8 flags;   /* 0x7: 1|2 done, 4 armed */
} WcFloorTileState;

typedef struct WcFloorTileSetup {
    u8 pad00[0x0C];
    f32 homeY;
    u8 pad10[0x1A - 0x10];
    s16 eventId;
} WcFloorTileSetup;

STATIC_ASSERT(sizeof(WcFloorTileState) == 0x8);
STATIC_ASSERT(offsetof(WcFloorTileState, shakeTime) == 0x00);
STATIC_ASSERT(offsetof(WcFloorTileState, shakeMag) == 0x04);
STATIC_ASSERT(offsetof(WcFloorTileState, phase) == 0x06);
STATIC_ASSERT(offsetof(WcFloorTileState, flags) == 0x07);

STATIC_ASSERT(offsetof(WcFloorTileSetup, homeY) == 0x0C);
STATIC_ASSERT(offsetof(WcFloorTileSetup, eventId) == 0x1A);

int wcfloortile_getExtraSize(void) { return 8; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int wcfloortile_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wcfloortile_free(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling on
void wcfloortile_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6E98);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wcfloortile_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wcfloortile_init(int obj)
{
    WcFloorTileState *state = ((GameObject *)obj)->extra;

    *(s16 *)obj = -0x4000;
    (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->flags |= 0x1800;
    state->flags |= 2;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wcfloortile_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wcfloortile_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wcfloortile_update(int obj)
{
    ObjAnimComponent *objAnim = &((GameObject *)obj)->anim;
    WcFloorTileState *state = ((GameObject *)obj)->extra;
    WcFloorTileSetup *setup = (WcFloorTileSetup *)((GameObject *)obj)->anim.placementData;

    if ((u32)GameBit_Get(824) != 0) {
        ((GameObject *)obj)->anim.localPosY = setup->homeY;
        state->phase = 3;
    }
    switch (state->phase) {
    case 0:
    default:
        if (state->flags & 4) {
            f32 z = lbl_803E6E9C;
            int i, off;
            for (i = 0, off = 0; i < *(s8 *)(*(int *)(obj + 0x58) + 0x10f); i++, off += 4) {
                int e = *(int *)(*(int *)(obj + 0x58) + off + 0x100);
                if (*(s16 *)(e + 0x44) == 1) {
                    Sfx_PlayFromObject(obj, SFXsc_strafe_active);
                    state->phase = 1;
                    state->shakeTime = z;
                    ((GameObject *)obj)->anim.velocityY = z;
                }
            }
        } else if ((u32)GameBit_Get(613) != 0) {
            state->flags |= 4;
        }
        break;
    case 1:
        state->shakeTime = state->shakeTime + timeDelta;
        if (state->shakeTime > lbl_803E6EA0) {
            state->flags |= 3;
            state->shakeTime = lbl_803E6EA0;
            ((GameObject *)obj)->anim.velocityY = lbl_803E6EA4 * timeDelta + ((GameObject *)obj)->anim.velocityY;
        }
        state->shakeMag = lbl_803E6EA8 * (state->shakeTime / lbl_803E6EA0);
        ((GameObject *)obj)->anim.rotY = (s16)randomGetRange(-state->shakeMag, state->shakeMag);
        ((GameObject *)obj)->anim.rotZ = (s16)randomGetRange(-state->shakeMag, state->shakeMag);
        ((GameObject *)obj)->anim.localPosY = ((GameObject *)obj)->anim.velocityY * timeDelta + ((GameObject *)obj)->anim.localPosY;
        {
            f32 d = setup->homeY - ((GameObject *)obj)->anim.localPosY;
            f32 t;
            if (d < lbl_803E6EAC) {
                t = lbl_803E6EB0;
            } else if (d > lbl_803E6EB4) {
                t = lbl_803E6E9C;
            } else {
                t = lbl_803E6E98 - (d - lbl_803E6EAC) / lbl_803E6EB8;
                if (t > lbl_803E6E98) {
                    t = lbl_803E6E98;
                } else if (t < lbl_803E6E9C) {
                    t = lbl_803E6E9C;
                }
                t = t * lbl_803E6EB0;
            }
            objAnim->alpha = (int)t;
        }
        if (objAnim->alpha == 0) {
            state->phase = 2;
        }
        break;
    case 2:
        objAnim->alpha = 0;
        ObjHits_DisableObject(obj);
        state->flags |= 3;
        break;
    case 3:
        {
            f32 a = lbl_803E6EBC * timeDelta + (f32)(u32)objAnim->alpha;
            if (a > lbl_803E6EB0) {
                a = lbl_803E6EB0;
            }
            objAnim->alpha = (int)a;
        }
        ObjHits_EnableObject(obj);
        break;
    }
    {
        if (fn_80065640() != 0) {
            state->flags |= 2;
        }
        if (state->flags & 2) {
            if (fn_80065640() == 0) {
                fn_80065574(setup->eventId, *(int *)&((GameObject *)obj)->anim.parent, state->flags & 1);
                state->flags &= ~2;
            }
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma scheduling off
void fn_8022AE1C(int obj, int bounds) {
    f32 cx = *(f32 *)(bounds + 0x14);
    f32 hx = cx + *(f32 *)(bounds + 0x20);
    f32 lx = cx - *(f32 *)(bounds + 0x20);
    f32 cy = *(f32 *)(bounds + 0x18);
    f32 hy = cy + *(f32 *)(bounds + 0x28);
    f32 ly = cy - *(f32 *)(bounds + 0x24);
    if (((GameObject *)obj)->anim.localPosX > hx) {
        ((GameObject *)obj)->anim.localPosX = hx;
        *(f32 *)(bounds + 0x48) = lbl_803E6ECC;
    } else if (((GameObject *)obj)->anim.localPosX < lx) {
        ((GameObject *)obj)->anim.localPosX = lx;
        *(f32 *)(bounds + 0x48) = lbl_803E6ECC;
    }
    if (((GameObject *)obj)->anim.localPosY > hy) {
        ((GameObject *)obj)->anim.localPosY = hy;
        *(f32 *)(bounds + 0x4c) = lbl_803E6ECC;
    } else if (((GameObject *)obj)->anim.localPosY < ly) {
        ((GameObject *)obj)->anim.localPosY = ly;
        *(f32 *)(bounds + 0x4c) = lbl_803E6ECC;
    }
    *(f32 *)(bounds + 0x2c) = ((GameObject *)obj)->anim.localPosX - *(f32 *)(bounds + 0x14);
    *(f32 *)(bounds + 0x30) = ((GameObject *)obj)->anim.localPosY - *(f32 *)(bounds + 0x18);
    *(f32 *)(bounds + 0x34) = lbl_803E6ECC;
}
#pragma scheduling reset

#pragma peephole off
#pragma scheduling off
void fn_8022AECC(int obj, int p)
{
    f32 v[3];
    f32 cz;
    int diff;
    int iv;

    if (*(s8 *)(obj + 0xac) == 0x26) {
        *(f32 *)(p + 0x44) = lbl_803E6ECC;
    }
    PSVECSubtract((void *)(p + 0x3c), (void *)(p + 0x48), v);
    v[0] = v[0] * *(f32 *)(p + 0x60);
    v[1] = v[1] * *(f32 *)(p + 0x64);
    v[2] = v[2] * *(f32 *)(p + 0x68);
    v[2] = v[2] < *(f32 *)(p + 0x84) ? *(f32 *)(p + 0x84)
         : (v[2] > *(f32 *)(p + 0x78) ? *(f32 *)(p + 0x78) : v[2]);
    PSVECScale(v, v, timeDelta);
    PSVECAdd((int)(p + 0x48), (int)v, (int)(p + 0x48));
    objMove(obj, *(f32 *)(p + 0x48) * timeDelta, *(f32 *)(p + 0x4c) * timeDelta,
            *(f32 *)(p + 0x50) * timeDelta);

    diff = *(int *)(p + 0x340) - (u16) * (int *)(p + 0x344);
    if (diff > 0x8000) diff -= 0xffff;
    if (diff < -0x8000) diff += 0xffff;
    iv = (int)(f32)((int)((f32)diff * *(f32 *)(p + 0x34c)) - *(int *)(p + 0x350));
    iv = (iv < -0x32) ? -0x32 : ((iv > 0x32) ? 0x32 : iv);
    *(int *)(p + 0x350) = (int)((f32)iv * timeDelta + (f32)*(int *)((u8 *)p + 0x350));
    *(int *)(p + 0x344) =
        (int)((f32) * (int *)(p + 0x350) * timeDelta + (f32)*(int *)((u8 *)p + 0x344));

    diff = *(int *)(p + 0x354) - (u16) * (int *)(p + 0x358);
    if (diff > 0x8000) diff -= 0xffff;
    if (diff < -0x8000) diff += 0xffff;
    iv = (int)(f32)((int)((f32)diff * *(f32 *)(p + 0x360)) - *(int *)(p + 0x364));
    iv = (iv < -0x32) ? -0x32 : ((iv > 0x32) ? 0x32 : iv);
    *(int *)(p + 0x364) = (int)((f32)iv * timeDelta + (f32)*(int *)((u8 *)p + 0x364));
    *(int *)(p + 0x358) =
        (int)((f32) * (int *)(p + 0x364) * timeDelta + (f32)*(int *)((u8 *)p + 0x358));

    diff = *(int *)(p + 0x368) - (u16) * (int *)(p + 0x36c);
    if (diff > 0x8000) diff -= 0xffff;
    if (diff < -0x8000) diff += 0xffff;
    iv = (int)((f32)(int)((f32)diff * *(f32 *)(p + 0x374)) - *(f32 *)(p + 0x378));
    iv = (iv < -0x64) ? -0x64 : ((iv > 0x64) ? 0x64 : iv);
    *(f32 *)(p + 0x378) = (f32)iv * timeDelta + *(f32 *)((u8 *)p + 0x378);
    *(int *)(p + 0x36c) =
        (int)(*(f32 *)(p + 0x378) * timeDelta + (f32)*(int *)((u8 *)p + 0x36c));

    if (*(u8 *)(p + 0x478) == 0) {
        diff = *(int *)(p + 0x37c) - (u16) * (int *)(p + 0x380);
        if (diff > 0x8000) diff -= 0xffff;
        if (diff < -0x8000) diff += 0xffff;
        *(int *)(p + 0x380) =
            (int)(timeDelta * ((f32)diff * *(f32 *)(p + 0x388)) + (f32)*(int *)((u8 *)p + 0x380));
        if ((f32) * (int *)(p + 0x380) > *(f32 *)(p + 0x394) ||
            (f32) * (int *)(p + 0x380) < -*(f32 *)(p + 0x394)) {
            *(f32 *)(p + 0x38c) = *(f32 *)(p + 0x38c) - *(f32 *)(p + 0x390) * timeDelta;
        } else {
            *(f32 *)(p + 0x38c) = *(f32 *)(p + 0x390) * timeDelta + *(f32 *)(p + 0x38c);
        }
    } else {
        *(f32 *)(p + 0x38c) = *(f32 *)(p + 0x38c) - *(f32 *)(p + 0x390) * timeDelta;
    }
    if (*(f32 *)(p + 0x38c) < lbl_803E6ECC) {
        *(f32 *)(p + 0x38c) = lbl_803E6ECC;
    } else if (*(f32 *)(p + 0x38c) > lbl_803E6ED0) {
        *(f32 *)(p + 0x38c) = lbl_803E6ED0;
    }

    ((GameObject *)obj)->anim.rotX = (s16) * (int *)(p + 0x344);
    ((GameObject *)obj)->anim.rotY = (s16) * (int *)(p + 0x358);
    if (*(u8 *)(p + 0x478) == 1) {
        fn_8022AB68(obj, p);
    } else {
        ((GameObject *)obj)->anim.rotZ = ((f32) * (int *)(p + 0x36c) * *(f32 *)(p + 0x38c) +
                                        (f32) * (int *)(p + 0x380));
        if (((GameObject *)obj)->anim.rotZ < -0x4000) {
            ((GameObject *)obj)->anim.rotZ = -0x4000;
        } else if (((GameObject *)obj)->anim.rotZ > 0x4000) {
            ((GameObject *)obj)->anim.rotZ = 0x4000;
        }
    }

    if (sqrtf(*(f32 *)(p + 0x48) * *(f32 *)(p + 0x48) +
              *(f32 *)(p + 0x4c) * *(f32 *)(p + 0x4c)) < *(f32 *)(p + 0x3b4) &&
        *(u8 *)(p + 0x478) == 0) {
        *(f32 *)(p + 0x3dc) = *(f32 *)(p + 0x3e0) * timeDelta + *(f32 *)(p + 0x3dc);
    } else {
        *(f32 *)(p + 0x3dc) = *(f32 *)(p + 0x3dc) - *(f32 *)(p + 0x3e0) * timeDelta;
    }
    if (*(f32 *)(p + 0x3dc) < lbl_803E6ECC) {
        *(f32 *)(p + 0x3dc) = lbl_803E6ECC;
    } else if (*(f32 *)(p + 0x3dc) > lbl_803E6ED0) {
        *(f32 *)(p + 0x3dc) = lbl_803E6ED0;
    }

    ((GameObject *)obj)->anim.rotZ = (*(f32 *)(p + 0x3dc) *
                                       (*(f32 *)(p + 0x3bc) *
                                        mathSinf(lbl_803E6EFC * (f32)(u32) * (u16 *)(p + 0x3c0) /
                                                    lbl_803E6F00)) +
                                   (f32) * (s16 *)(obj + 4));
    ((GameObject *)obj)->anim.localPosX =
        *(f32 *)(p + 0x3dc) *
            (*(f32 *)(p + 0x3c8) *
             mathSinf(lbl_803E6EFC * (f32)(u32) * (u16 *)(p + 0x3cc) / lbl_803E6F00)) +
        ((GameObject *)obj)->anim.localPosX;
    ((GameObject *)obj)->anim.localPosY =
        *(f32 *)(p + 0x3dc) *
            (*(f32 *)(p + 0x3d4) *
             mathSinf(lbl_803E6EFC * (f32)(u32) * (u16 *)(p + 0x3d8) / lbl_803E6F00)) +
        ((GameObject *)obj)->anim.localPosY;
    *(u16 *)(p + 0x3c0) =
        (*(f32 *)(p + 0x3b8) * timeDelta + (f32)(u32) * (u16 *)(p + 0x3c0));
    *(u16 *)(p + 0x3cc) =
        (*(f32 *)(p + 0x3c4) * timeDelta + (f32)(u32) * (u16 *)(p + 0x3cc));
    *(u16 *)(p + 0x3d8) =
        (*(f32 *)(p + 0x3d0) * timeDelta + (f32)(u32) * (u16 *)(p + 0x3d8));
    fn_8022AE1C(obj, p);
}
#pragma scheduling reset
#pragma peephole reset

#pragma scheduling off
void fn_8022B8A0(int p, int q) {
    if (*(void * *)&((ArwingState *)q)->activeBombObj != NULL)
        return;
    {
        f32 t = ((ArwingState *)q)->bombCooldown;
        if (t > lbl_803E6ECC) {
            ((ArwingState *)q)->bombCooldown = t - timeDelta;
            if (((ArwingState *)q)->bombCooldown >= lbl_803E6ECC)
                return;
            ((ArwingState *)q)->bombCooldown = lbl_803E6ECC;
        }
    }
    if (((ArwingState *)q)->inputFlags & 0x200) {
        if ((s8) ((ArwingState *)q)->bombVolleyMode == 1) {
            fn_8022B764(p, q, 0);
            fn_8022B764(p, q, 1);
        } else {
            fn_8022B764(p, q, ((ArwingState *)q)->bombSide);
            ((ArwingState *)q)->bombSide = (((ArwingState *)q)->bombSide ^ 1) & 0xff;
        }
        ((ArwingState *)q)->bombCooldown = (f32)(u32) *(u16 *)&((ArwingState *)q)->bombFireDelay;
    }
}
#pragma scheduling reset

#pragma peephole off
#pragma scheduling on
#pragma scheduling off
void fn_8022B764(int p, int q, int idx) {
    f32 pz, py, px;
    int setup;
    u8 cnt;
    if (Obj_IsLoadingLocked() == 0)
        return;
    cnt = ((ArwingState *)q)->bombCount;
    if (cnt == 0)
        return;
    ((ArwingState *)q)->bombCount = cnt - 1;
    if (idx == 0)
        ObjPath_GetPointWorldPosition(p, 5, &px, &py, &pz, 0);
    else
        ObjPath_GetPointWorldPosition(p, 6, &px, &py, &pz, 0);
    setup = Obj_AllocObjectSetup(0x20, 0x605);
    *(f32 *)(setup + 8) = px;
    *(f32 *)(setup + 0xc) = py;
    *(f32 *)(setup + 0x10) = pz;
    *(u8 *)(setup + 0x1a) = *(s16 *)(p + 0) >> 8;
    *(u8 *)(setup + 0x19) = *(s16 *)(p + 2) >> 8;
    *(u8 *)(setup + 0x18) = *(s16 *)(p + 4) >> 8;
    *(u8 *)(setup + 4) = 1;
    *(u8 *)(setup + 5) = 1;
    ((ArwingState *)q)->activeBombObj = loadObjectAtObject(p);
    fn_8022ED74(((ArwingState *)q)->activeBombObj, *(u16 *)&((ArwingState *)q)->bombProjectileParam);
    fn_8022ECE0(((ArwingState *)q)->activeBombObj, ((ArwingState *)q)->bombProjectileLifetime);
    Sfx_PlayFromObject(p, SFXbaddie_rach_call3);
}
#pragma scheduling reset
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void fn_8022A9C8(int obj, int state)
{
    extern void Matrix_TransformPoint(f32 *mtx, f32 x, f32 y, f32 z, f32 *ox, f32 *oy, f32 *oz);
    int slot;
    f32 mtx[16];
    ArwProjPosSrc src;

    slot = Camera_GetCurrentViewSlot();
    src.pos[0] = ((GameObject *)obj)->anim.localPosX;
    src.pos[1] = ((GameObject *)obj)->anim.localPosY;
    src.pos[2] = ((GameObject *)obj)->anim.localPosZ;
    src.rot[0] = *(s16 *)obj;
    src.rot[1] = ((GameObject *)obj)->anim.rotY;
    src.rot[2] = 0;
    src.scale = lbl_803E6ED0;
    setMatrixFromObjectPos(mtx, &src);

    Matrix_TransformPoint(mtx, lbl_803E6ECC, *(f32 *)&lbl_803E6ECC, lbl_803E6EF0,
                          (f32 *)(((ArwingState *)state)->thrusterL + 0xc),
                          (f32 *)(((ArwingState *)state)->thrusterL + 0x10),
                          (f32 *)(((ArwingState *)state)->thrusterL + 0x14));
    *(f32 *)(((ArwingState *)state)->thrusterL + 0x18) = *(f32 *)(((ArwingState *)state)->thrusterL + 0xc);
    *(f32 *)(((ArwingState *)state)->thrusterL + 0x1c) = *(f32 *)(((ArwingState *)state)->thrusterL + 0x10);
    *(f32 *)(((ArwingState *)state)->thrusterL + 0x20) = *(f32 *)(((ArwingState *)state)->thrusterL + 0x14);
    *(s16 *)(((ArwingState *)state)->thrusterL + 4) = -*(s16 *)(slot + 4);
    *(s16 *)(((ArwingState *)state)->thrusterL + 2) = -*(s16 *)(slot + 2);
    *(s16 *)(((ArwingState *)state)->thrusterL + 0) = 0x8000 - *(s16 *)slot;

    Matrix_TransformPoint(mtx, lbl_803E6ECC, *(f32 *)&lbl_803E6ECC, lbl_803E6EF4,
                          (f32 *)(((ArwingState *)state)->thrusterR + 0xc),
                          (f32 *)(((ArwingState *)state)->thrusterR + 0x10),
                          (f32 *)(((ArwingState *)state)->thrusterR + 0x14));
    *(f32 *)(((ArwingState *)state)->thrusterR + 0x18) = *(f32 *)(((ArwingState *)state)->thrusterR + 0xc);
    *(f32 *)(((ArwingState *)state)->thrusterR + 0x1c) = *(f32 *)(((ArwingState *)state)->thrusterR + 0x10);
    *(f32 *)(((ArwingState *)state)->thrusterR + 0x20) = *(f32 *)(((ArwingState *)state)->thrusterR + 0x14);
    *(s16 *)(((ArwingState *)state)->thrusterR + 4) = -*(s16 *)(slot + 4);
    *(s16 *)(((ArwingState *)state)->thrusterR + 2) = -*(s16 *)(slot + 2);
    *(s16 *)(((ArwingState *)state)->thrusterR + 0) = 0x8000 - *(s16 *)slot;
}
#pragma scheduling reset
#pragma peephole reset

#pragma scheduling off
void fn_8022A670(int obj, int state)
{
    f32 nx;
    f32 ny;
    f32 tv;
    int btn;

    debugPrintSetColor(0xff, 0xff, 0xff, 0xff);
    ((ArwingState *)state)->stickX = (f32)(s8)padGetStickX(0) / lbl_803E6EC8;
    ((ArwingState *)state)->stickY = (f32)(s8)padGetStickY(0) / lbl_803E6EC8;
    if (((ArwingState *)state)->damageFlashTimer > lbl_803E6ECC) {
        nx = -((ArwingState *)state)->knockVelX;
        ny = -((ArwingState *)state)->knockVelZ;
        ((ArwingState *)state)->damageFlashTimer = ((ArwingState *)state)->damageFlashTimer - timeDelta;
        tv = lbl_8032B4A8[(int)((ArwingState *)state)->damageFlashTimer];
        if (((ArwingState *)state)->damageFlashTimer <= lbl_803E6ECC) {
            ((ArwingState *)state)->hitShake = 0;
            (*(void (**)(int, int))(*gPathControlInterface + 0x20))(obj, state + 0xc0);
        }
        ((ArwingState *)state)->stickX =
            ((ArwingState *)state)->stickX * (lbl_803E6ED0 - tv) + nx * tv;
        ((ArwingState *)state)->stickY =
            ((ArwingState *)state)->stickY * (lbl_803E6ED0 - tv) + ny * tv;
    }
    ((ArwingState *)state)->rTriggerTrim = (f32)(u32)(u8)padGetRTrigger(0) / lbl_803E6ED4;
    {
        f32 rt = ((ArwingState *)state)->rTriggerTrim;
        ((ArwingState *)state)->rTriggerTrim =
            (rt < lbl_803E6ECC) ? lbl_803E6ECC : ((rt > lbl_803E6ED0) ? lbl_803E6ED0 : rt);
    }
    ((ArwingState *)state)->lTriggerTrim = -(f32)(u32)(u8)padGetLTrigger(0) / lbl_803E6ED4;
    {
        f32 lt = ((ArwingState *)state)->lTriggerTrim;
        ((ArwingState *)state)->lTriggerTrim =
            (lt < lbl_803E6ED8) ? lbl_803E6ED8 : ((lt > lbl_803E6ECC) ? lbl_803E6ECC : lt);
    }
    ((ArwingState *)state)->inputFlags = (u16)getButtonsJustPressed(0);
    ((ArwingState *)state)->inputFlagsPrev = (u16)getButtonsJustPressedIfNotBusy(0);
    ((ArwingState *)state)->inputFlags2 = (u16)getButtonsHeld(0);
    if (((ArwingState *)state)->mode == 0) {
        btn = ((ArwingState *)state)->inputFlags;
        if ((btn & 0x20) != 0) {
            Sfx_PlayFromObject(obj, SFXbaddie_rach_death);
            ((ArwingState *)state)->mode = 1;
            ((ArwingState *)state)->barrelRollAngle = ((GameObject *)obj)->anim.rotZ;
            ((ArwingState *)state)->barrelRollDirection = ((ArwingState *)state)->barrelRollSpeed;
            ((ArwingState *)state)->barrelRollSpeedScale = lbl_803E6ED0;
            ((ArwingState *)state)->maxSpeedX = ((ArwingState *)state)->maxSpeedX * ((ArwingState *)state)->barrelRollMaxSpeedScale;
            ((ArwingState *)state)->accelX = ((ArwingState *)state)->accelX * ((ArwingState *)state)->barrelRollAccelScale;
            arwarwingbo_setActiveVisible(((ArwingState *)state)->bombObj, 1, 0);
        } else if ((btn & 0x40) != 0) {
            Sfx_PlayFromObject(obj, SFXbaddie_rach_death);
            ((ArwingState *)state)->mode = 1;
            ((ArwingState *)state)->barrelRollAngle = ((GameObject *)obj)->anim.rotZ;
            ((ArwingState *)state)->barrelRollDirection = -((ArwingState *)state)->barrelRollSpeed;
            ((ArwingState *)state)->barrelRollSpeedScale = lbl_803E6ED0;
            ((ArwingState *)state)->maxSpeedX = ((ArwingState *)state)->maxSpeedX * ((ArwingState *)state)->barrelRollMaxSpeedScale;
            ((ArwingState *)state)->accelX = ((ArwingState *)state)->accelX * ((ArwingState *)state)->barrelRollAccelScale;
            arwarwingbo_setActiveVisible(((ArwingState *)state)->bombObj, 1, 1);
        }
    }
}
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_8022AB68(int obj, int state)
{
    int tgt;
    int cur;
    int d;

    ((ArwingState *)state)->barrelRollAngle =
        (int)(timeDelta * (((ArwingState *)state)->barrelRollDirection * ((ArwingState *)state)->barrelRollSpeedScale) +
              (f32) ((ArwingState *)state)->barrelRollAngle);
    ((GameObject *)obj)->anim.rotZ =
        (s16)(int)(timeDelta * (((ArwingState *)state)->barrelRollDirection * ((ArwingState *)state)->barrelRollSpeedScale) +
                   (f32) * (s16 *)(obj + 4));
    if (((ArwingState *)state)->barrelRollDirection > lbl_803E6ECC) {
        tgt = ((ArwingState *)state)->rotZTrimCur;
        cur = ((ArwingState *)state)->barrelRollAngle;
        if (cur > tgt + 0xffff) {
            ((ArwingState *)state)->mode = 0;
            ((ArwingState *)state)->rotZTrimCur = ((ArwingState *)state)->barrelRollAngle - 0xffff;
            ((ArwingState *)state)->rotZBlend = lbl_803E6ECC;
            ((ArwingState *)state)->maxSpeedX = ((ArwingState *)state)->maxSpeedX / ((ArwingState *)state)->barrelRollMaxSpeedScale;
            ((ArwingState *)state)->accelX = ((ArwingState *)state)->accelX / ((ArwingState *)state)->barrelRollAccelScale;
            arwarwingbo_setActiveVisible(((ArwingState *)state)->bombObj, 0, 0);
        } else if (cur > tgt + 0x8000) {
            d = cur - (u16)tgt;
            if (d > 0x8000) d -= 0xffff;
            if (d < -0x8000) d += 0xffff;
            if (d < 0) d = -d;
            ((ArwingState *)state)->barrelRollSpeedScale = (f32)d / ((ArwingState *)state)->barrelRollDecelRange;
            if (((ArwingState *)state)->barrelRollSpeedScale < lbl_803E6EF8)
                ((ArwingState *)state)->barrelRollSpeedScale = lbl_803E6EF8;
            else if (((ArwingState *)state)->barrelRollSpeedScale > lbl_803E6ED0)
                ((ArwingState *)state)->barrelRollSpeedScale = lbl_803E6ED0;
        }
    } else {
        tgt = ((ArwingState *)state)->rotZTrimCur;
        cur = ((ArwingState *)state)->barrelRollAngle;
        if (cur < tgt - 0xffff) {
            ((ArwingState *)state)->mode = 0;
            ((ArwingState *)state)->rotZTrimCur = ((ArwingState *)state)->barrelRollAngle + 0xffff;
            ((ArwingState *)state)->rotZBlend = lbl_803E6ECC;
            ((ArwingState *)state)->maxSpeedX = ((ArwingState *)state)->maxSpeedX / ((ArwingState *)state)->barrelRollMaxSpeedScale;
            ((ArwingState *)state)->accelX = ((ArwingState *)state)->accelX / ((ArwingState *)state)->barrelRollAccelScale;
            arwarwingbo_setActiveVisible(((ArwingState *)state)->bombObj, 0, 0);
        } else if (cur > tgt - 0x8000) {
            d = cur - (u16)tgt;
            if (d > 0x8000) d -= 0xffff;
            if (d < -0x8000) d += 0xffff;
            if (d < 0) d = -d;
            ((ArwingState *)state)->barrelRollSpeedScale = (f32)d / ((ArwingState *)state)->barrelRollDecelRange;
            if (((ArwingState *)state)->barrelRollSpeedScale < lbl_803E6EF8)
                ((ArwingState *)state)->barrelRollSpeedScale = lbl_803E6EF8;
            else if (((ArwingState *)state)->barrelRollSpeedScale > lbl_803E6ED0)
                ((ArwingState *)state)->barrelRollSpeedScale = lbl_803E6ED0;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
