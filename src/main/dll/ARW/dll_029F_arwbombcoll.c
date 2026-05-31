#include "main/dll/dll_80220608_shared.h"

#define SFXbaddie_eba_hit 0x2a6
#define SFXbaddie_eba_leavesclose 0x2a7
#define SFXbaddie_eba_leavesopen 0x2a8
#define SFXbaddie_eba_pollenspin 0x2a9
#define SFXbaddie_vambat_attack 0x2ab

#pragma peephole on
#pragma scheduling on
int arwbombcoll_getExtraSize(void) { return 8; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int arwbombcoll_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwbombcoll_free(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwbombcoll_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwbombcoll_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7078);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwbombcoll_init(int obj, int setup)
{
    *(s16 *)(obj + 0) = (s16)(*(s8 *)(setup + 0x18) << 8);
    *(u8 *)(obj + 0x36) = 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwbombcoll_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwbombcoll_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void arwbombcoll_updateMovingAxis(int obj, int state) {
    u8 mode = *(u8 *)(state + 1);
    u16 raw = *(u16 *)(state + 2);
    if (mode == 1 || mode == 3) {
        f32 cur, lim, edge;
        *(f32 *)(obj + 0xc) = *(f32 *)(state + 4) * timeDelta + *(f32 *)(obj + 0xc);
        cur = *(f32 *)(obj + 0xc);
        lim = *(f32 *)(state + 8);
        edge = lim + (f32)(u32)raw;
        if (cur > edge) {
            *(f32 *)(obj + 0xc) = edge - (cur - edge);
            *(f32 *)(state + 4) = -*(f32 *)(state + 4);
        } else {
            edge = lim - (f32)(u32)raw;
            if (cur < edge) {
                *(f32 *)(obj + 0xc) = edge - (cur - edge);
                *(f32 *)(state + 4) = -*(f32 *)(state + 4);
            }
        }
    } else if (mode == 4 || mode == 5) {
        f32 cur, lim, edge;
        *(f32 *)(obj + 0x10) = *(f32 *)(state + 4) * timeDelta + *(f32 *)(obj + 0x10);
        cur = *(f32 *)(obj + 0x10);
        lim = *(f32 *)(state + 0xc);
        edge = lim + (f32)(u32)raw;
        if (cur > edge) {
            *(f32 *)(obj + 0x10) = edge - (cur - edge);
            *(f32 *)(state + 4) = -*(f32 *)(state + 4);
        } else {
            edge = lim - (f32)(u32)raw;
            if (cur < edge) {
                *(f32 *)(obj + 0x10) = edge - (cur - edge);
                *(f32 *)(state + 4) = -*(f32 *)(state + 4);
            }
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void arwbombcoll_handleArwingHit(int obj, int state, int arwing) {
    int setup = *(int *)(obj + 0x4c);
    u8 mode = *(u8 *)(state + 0);
    if (mode == 0) {
        Sfx_PlayFromObject(arwing, SFXbaddie_eba_pollenspin);
        if (*(s16 *)(arwing + 0x46) == 0x601) {
            arwarwing_addShield(arwing, 1);
            arwarwing_addScore(arwing, 0xa);
        }
    } else if (mode == 1) {
        Sfx_PlayFromObject(arwing, SFXbaddie_eba_pollenspin);
        if (*(s16 *)(arwing + 0x46) == 0x601) {
            arwarwing_addMaxShield(arwing, 1);
            arwarwing_addShield(arwing, arwarwing_getMaxShield(arwing));
        }
    } else if (mode == 3 || mode == 4) {
        Sfx_PlayFromObject(arwing, SFXbaddie_eba_pollenspin);
        gameBitIncrement(*(s16 *)(setup + 0x1e));
    } else {
        Sfx_PlayFromObject(arwing, SFXbaddie_vambat_attack);
        if (*(s16 *)(arwing + 0x46) == 0x601) {
            int seg;
            fn_8022D5F0(arwing);
            arwarwing_addShield(arwing, 1);
            arwarwing_addScore(arwing, 0x14);
            seg = arwarwing_getRequiredRingCount(arwing);
            if (arwarwing_getCollectedRingCount(arwing) == seg) {
                if (((RingFlags *)(state + 0x14))->bit20)
                    gameTextFn_80125ba4(7);
            } else {
                if (((RingFlags *)(state + 0x14))->bit20)
                    gameTextFn_80125ba4(9);
            }
        }
    }
    *(u8 *)(state + 0x15) = 2;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int arwbombcoll_checkArwingCollision(int obj, int state, int arwing) {
    RingFlags *f = (RingFlags *)(state + 0x14);
    if (f->bit10) {
        f32 dx = *(f32 *)(obj + 0xc) - *(f32 *)(arwing + 0xc);
        f32 dy = *(f32 *)(obj + 0x10) - *(f32 *)(arwing + 0x10);
        f32 dz;
        if (dy < lbl_803E70A0)
            dy = -dy;
        dz = *(f32 *)(obj + 0x14) - *(f32 *)(arwing + 0x14);
        if (dy <= lbl_803E70A4) {
            if (dx * dx + dz * dz < lbl_803E70A8)
                return 1;
        }
    } else {
        f32 objZ = *(f32 *)(obj + 0x14);
        f32 currentZDelta = objZ - *(f32 *)(arwing + 0x14);
        f32 previousZDelta = objZ - *(f32 *)(arwing + 0x88);
        if (currentZDelta <= lbl_803E70A0 && previousZDelta >= lbl_803E70A0) {
            f32 dx = *(f32 *)(obj + 0xc) - *(f32 *)(arwing + 0xc);
            f32 dy = *(f32 *)(obj + 0x10) - *(f32 *)(arwing + 0x10);
            if (sqrtf(dx * dx + dy * dy) < lbl_803E70AC)
                return 1;
            if (*(u8 *)(state + 0) == 2 && f->bit20)
                gameTextFn_80125ba4(0xa);
        }
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwbombcoll_update(int obj)
{
    ArwBombFlags *flags;
    int arw;
    int s;
    int a2;

    arw = getArwing();
    s = *(int *)(obj + 0xb8);
    flags = (ArwBombFlags *)(s + 0x4);

    if (*(f32 *)(s + 0x0) > lbl_803E707C) {
        *(f32 *)(s + 0x0) -= timeDelta;
        if (*(f32 *)(s + 0x0) <= lbl_803E707C) {
            Obj_FreeObject(obj);
            return;
        }
    }

    if ((u32)arw != 0 && fn_8022D710(arw) != 0) {
        flags->b80 = 0;
        *(s16 *)(obj + 0x6) &= ~0x4000;
        ObjHits_EnableObject(obj);
        return;
    }

    if (flags->b80 == 0) {
        a2 = getArwing();
        if ((((u32)a2 != 0) ? (*(f32 *)(obj + 0x14) - *(f32 *)(a2 + 0x14) < lbl_803E7080) : 0) != 0) {
            goto active;
        }
    }
    *(s16 *)(obj + 0x6) |= 0x4000;
    *(u8 *)(obj + 0x36) = 0;
    return;
active : {
        int v;
        v = (int)(lbl_803E7084 * timeDelta + (f32)(u32) * (u8 *)(obj + 0x36));
        if (v > 0xff) {
            v = 0xff;
        }
        *(u8 *)(obj + 0x36) = v;
        *(s16 *)(obj + 0x6) &= ~0x4000;
        *(s16 *)(obj + 0x0) = (int)(lbl_803E7088 * timeDelta + (f32) * (s16 *)(obj + 0x0));
        ObjHits_SetHitVolumeSlot(obj, 0x13, 0, 0);
        if (flags->b40 != 0) {
            if (*(void **)(*(int *)(obj + 0x54) + 0x50) != 0 &&
                *(void **)(*(int *)(obj + 0x54) + 0x50) == (void *)getArwing()) {
                arwarwing_addScore(arw, 0x19);
                flags->b80 = 1;
                *(s16 *)(obj + 0x6) |= 0x4000;
                ObjHits_DisableObject(obj);
            }
        } else {
            int hit;
            if (ObjHits_GetPriorityHit(obj, &hit, 0, 0) != 0 && (u32)hit != 0 &&
                (*(s16 *)(hit + 0x46) == 0x604 || *(s16 *)(hit + 0x46) == 0x605)) {
                arwarwing_addScore(arw, 0xf);
                flags->b40 = 1;
                Obj_SetActiveModelIndex(obj, 1);
                spawnExplosion(obj, lbl_803E708C, 1, 0, 0, 0, 0, 0, 2);
            }
            if (*(void **)(*(int *)(obj + 0x54) + 0x50) != 0 &&
                *(void **)(*(int *)(obj + 0x54) + 0x50) == (void *)getArwing()) {
                *(s16 *)(obj + 0x6) |= 0x4000;
                ObjHits_DisableObject(obj);
                spawnExplosion(obj, lbl_803E708C, 1, 0, 0, 0, 0, 0, 2);
            }
        }
        if ((u32)arw != 0 && flags->b80 != 0) {
            switch (*(s16 *)(obj + 0x46)) {
            case 0x609:
                Sfx_PlayFromObject(obj, SFXbaddie_eba_hit);
                fn_8022D6F0(arw);
                break;
            case 0x608:
                Sfx_PlayFromObject(obj, SFXbaddie_eba_leavesclose);
                fn_8022D6D0(arw);
                break;
            case 0x6d8:
                Sfx_PlayFromObject(obj, SFXbaddie_eba_leavesopen);
                fn_8022D5DC(arw);
                break;
            case 0x6d9:
                Sfx_PlayFromObject(obj, SFXbaddie_eba_leavesopen);
                fn_8022D5C8(arw);
                break;
            case 0x6db:
                Sfx_PlayFromObject(obj, SFXbaddie_eba_leavesopen);
                fn_8022D5B4(arw);
                break;
            case 0x6da:
                Sfx_PlayFromObject(obj, SFXbaddie_eba_leavesopen);
                fn_8022D5A0(arw);
                break;
            }
        }
    }
}
#pragma scheduling reset
#pragma peephole reset
