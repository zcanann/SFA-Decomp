#include "main/dll/dll_80220608_shared.h"
#include "main/mapEventTypes.h"

#define SFXbaddie_rach_bite 0x2a0
#define SFXbaddie_rach_call1 0x2a1
#define SFXbaddie_rach_call2 0x2a2
#define SFXbaddie_vambat_death 0x2ac
#define SFXbaddie_eba_bigswipe 0x2b4
#define SFXbaddie_eggsnatch_movelp 0x2c0

#pragma peephole on
#pragma scheduling on
int getArwing(void) { return lbl_803DDD88; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int arwarwing_getExtraSize(void) { return 0x498; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int arwarwing_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void arwarwing_free(int obj)
{
    int state = *(int *)(obj + 0xb8);

    ObjGroup_RemoveObject(obj, 0x26);
    lbl_803DDD88 = 0;
    if (*(void **)(state + 0x450) != NULL) {
        ModelLightStruct_free(*(void **)(state + 0x450));
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwarwing_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwarwing_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwarwing_render(int obj, int p2, int p3, int p4, int p5)
{
    int state = *(int *)(obj + 0xb8);
    int dx, dy;

    if (*(u8 *)(state + 0x338) != 0) {
        dx = (int)(lbl_803E6FF4 *
                   fn_80293E80(lbl_803E6EFC * (f32)(u32) * (u16 *)(state + 0x33c) / lbl_803E6F00));
        dy = (int)(lbl_803E6F5C *
                   fn_80293E80(lbl_803E6EFC * (f32)(u32) * (u16 *)(state + 0x33a) / lbl_803E6F00));
        *(s16 *)(obj + 2) = (s16)(*(s16 *)(obj + 2) + dx);
        *(s16 *)(obj + 4) = (s16)(*(s16 *)(obj + 4) + dy);
    }
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6ED0);
    if (*(u8 *)(state + 0x338) != 0) {
        *(s16 *)(obj + 2) = (s16)(*(s16 *)(obj + 2) - dx);
        *(s16 *)(obj + 4) = (s16)(*(s16 *)(obj + 4) - dy);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwarwing_hitDetect(int obj)
{
    int state = *(int *)(obj + 0xb8);
    f32 pos[3];
    f32 mtx[12];

    if ((*(u16 *)(obj + 0xb0) & 0x1000) != 0 && *(u8 *)(state + 0x47f) != 0) {
        Obj_BuildWorldTransformMatrix(obj, mtx, 0);
        PSMTXMultVec(mtx, (void *)(state + 0x484), pos);
        pos[0] += playerMapOffsetX;
        pos[2] += playerMapOffsetZ;
        fn_8008020C((s16)(0x8000 - *(s16 *)obj + *(s16 *)(state + 0x490)),
                    (s16)(*(s16 *)(obj + 2) + *(s16 *)(state + 0x492)),
                    (s16)(*(s16 *)(obj + 4) + *(s16 *)(state + 0x494)),
                    pos[0], pos[1], pos[2], lbl_803E6FF8);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void fn_8022D460(int arwing, f32 val) { *(f32 *)(*(int *)(arwing + 0xb8) + 0x20) = val; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int fn_8022D46C(int arwing) { return (s16) * (int *)(*(int *)(arwing + 0xb8) + 0x358); }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void fn_8022D47C(int arwing, int p2) { *(int *)(*(int *)(arwing + 0xb8) + 0x358) = (s16)p2; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void fn_8022D48C(int out, int arwing)
{
    *(Vec12 *)out = *(Vec12 *)(*(int *)(arwing + 0xb8) + 0x48);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void fn_8022D4AC(int arwing, int in)
{
    int state = *(int *)(arwing + 0xb8);
    *(f32 *)(state + 0x48) = *(f32 *)(in + 0);
    *(f32 *)(state + 0x4c) = *(f32 *)(in + 4);
    *(f32 *)(state + 0x50) = *(f32 *)(in + 8);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void fn_8022D4CC(int arwing, int in)
{
    int v = *(int *)(arwing + 0xb8) + 0x48;
    PSVECAdd(v, in, v);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void fn_8022D4F8(int arwing) { *(int *)(*(int *)(arwing + 0xb8) + 0x438) = 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int arwarwing_getRequiredRingCount(int arwing) { return *(u8 *)(*(int *)(arwing + 0xb8) + 0x471); }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int arwarwing_getCollectedRingCount(int arwing) { return *(u8 *)(*(int *)(arwing + 0xb8) + 0x470); }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void arwarwing_addScore(int arwing, u8 amount)
{
    int state = *(int *)(arwing + 0xb8);
    u16 v;
    *(u16 *)(state + 0x47c) = *(u16 *)(state + 0x47c) + amount;
    v = *(u16 *)(state + 0x47c);
    if (v > 0x270f) {
        v = 0x270f;
    }
    *(u16 *)(state + 0x47c) = v;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int arwarwing_getScore(int arwing)
{
    int state = *(int *)(arwing + 0xb8);
    if (*(u16 *)(state + 0x47c) > 0x270f) {
        *(u16 *)(state + 0x47c) = 0x270f;
    }
    return *(u16 *)(state + 0x47c);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int fn_8022D574(int arwing) { return *(u8 *)(*(int *)(arwing + 0xb8) + 0x44c); }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int arwarwing_getMaxShield(int arwing) { return *(s8 *)(*(int *)(arwing + 0xb8) + 0x469); }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int arwarwing_getShield(int arwing) { return *(s8 *)(*(int *)(arwing + 0xb8) + 0x468); }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int fn_8022D5A0(int arwing) { return (*(u8 *)(*(int *)(arwing + 0xb8) + 0x475))++; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int fn_8022D5B4(int arwing) { return (*(u8 *)(*(int *)(arwing + 0xb8) + 0x474))++; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int fn_8022D5C8(int arwing) { return (*(u8 *)(*(int *)(arwing + 0xb8) + 0x473))++; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int fn_8022D5DC(int arwing) { return (*(u8 *)(*(int *)(arwing + 0xb8) + 0x472))++; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int fn_8022D5F0(int arwing)
{
    int state = *(int *)(arwing + 0xb8);
    if (*(u8 *)(state + 0x470) == 9) {
        *(u16 *)(state + 0x47c) = *(u16 *)(state + 0x47c) + 0x64;
        if (*(u16 *)(state + 0x47c) > 0x270f) {
            *(u16 *)(state + 0x47c) = 0x270f;
        }
    }
    return (*(u8 *)(state + 0x470))++;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwarwing_addMaxShield(int arwing, int p2)
{
    int state = *(int *)(arwing + 0xb8);
    *(s8 *)(state + 0x469) = *(u8 *)(state + 0x469) + p2;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void arwarwing_addShield(int arwing, int p2)
{
    int state = *(int *)(arwing + 0xb8);
    s8 v;

    *(s8 *)(state + 0x468) = *(u8 *)(state + 0x468) + p2;
    v = *(s8 *)(state + 0x468);
    if (v < 0) {
        v = 0;
    } else if (v > *(s8 *)(state + 0x469)) {
        v = *(s8 *)(state + 0x469);
    }
    *(s8 *)(state + 0x468) = v;
    if (*(s8 *)(state + 0x468) > 3) {
        Sfx_StopObjectChannel(arwing, 4);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void fn_8022BCD0(int p, int q) {
    u8 flag;
    struct {
        u8 pad[6];
        s16 type;
        f32 a;
        f32 b;
        f32 c;
        f32 d;
    } emit;
    flag = 0;
    if ((s8) * (u8 *)(q + 0x468) <= 4) {
        if ((*(u8 *)(q + 0x476))++ % 2 != 0) {
            emit.a = lbl_803E6F08;
            emit.b = lbl_803E6F0C;
            emit.c = lbl_803E6F10;
            emit.d = lbl_803E6F14;
            if ((s8) * (u8 *)(q + 0x468) <= 2)
                emit.type = 0x61a8;
            else
                emit.type = -0x63c0;
            (*(void (**)(int, int, void *, int, int, u8 *))(*gPartfxInterface + 0x8))(
                p, 0x7d0, &emit.pad, 4, -1, &flag);
        }
    }
    if ((s8) * (u8 *)(q + 0x468) <= 2) {
        emit.a = lbl_803E6F18;
        emit.type = 0xc0a;
        emit.b = lbl_803E6ECC;
        emit.c = lbl_803E6F1C;
        emit.d = lbl_803E6F20;
        (*(void (**)(int, int, void *, int, int, u8 *))(*gPartfxInterface + 0x8))(
            p, 0x7d1, &emit.pad, 4, -1, &flag);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void fn_8022C680(int obj) {
    switch ((s8) * (u8 *)(obj + 0xac)) {
    case 0x3a:
        if ((u32)GameBit_Get(0xc85) != 0) {
            GameBit_Set(0x405, 0);
            ((MapEventInterface *)*gMapEventInterface)->setMode(0xb, 5);
            ((MapEventInterface *)*gMapEventInterface)->setAnimEvent(0xb, 0xa, 1);
            ((MapEventInterface *)*gMapEventInterface)->setAnimEvent(0xb, 0xb, 1);
            warpToMap(0x22, 0);
        } else {
            warpToMap(0x6c, 0);
        }
        break;
    case 0x3b:
        warpToMap(0x77, 0);
        break;
    case 0x3d:
        warpToMap(0x78, 0);
        break;
    case 0x3c:
        warpToMap(0x63, 0);
        break;
    case 0x3e:
        warpToMap(0x79, 0);
        break;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwarwing_updateWeaponFire(int obj, int state) {
    int fire;
    fn_8022A9C8(obj, state);
    {
        f32 t = *(f32 *)(state + 0x408);
        if (t > lbl_803E6ECC) {
            *(f32 *)(state + 0x408) = t - timeDelta;
            if (*(f32 *)(state + 0x408) >= lbl_803E6ECC)
                return;
            *(f32 *)(state + 0x408) = lbl_803E6ECC;
        }
    }
    fire = 0;
    if (*(u16 *)(state + 0x3f8) & 0x100) {
        *(f32 *)(state + 0x414) -= timeDelta;
        if (*(f32 *)(state + 0x414) <= lbl_803E6ECC)
            fire = 1;
    }
    if ((*(u16 *)(state + 0x3f4) & 0x100) == 0 && fire == 0)
        return;
    *(f32 *)(state + 0x414) = lbl_803E6F04;
    switch ((s8) * (u8 *)(state + 0x404)) {
    case 2:
        arwarwing_spawnLaserShot(obj, state, 0, 2, 1);
        arwarwing_spawnLaserShot(obj, state, 1, 2, 0);
        break;
    case 1:
        arwarwing_spawnLaserShot(obj, state, 0, 1, 1);
        arwarwing_spawnLaserShot(obj, state, 1, 1, 0);
        break;
    default:
        arwarwing_spawnLaserShot(obj, state, *(u8 *)(state + 0x405), 0, 1);
        *(u8 *)(state + 0x405) = (*(u8 *)(state + 0x405) ^ 1) & 0xff;
        break;
    }
    *(f32 *)(state + 0x408) = (f32)(u32) * (u16 *)(state + 0x40c);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void arwarwing_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    f32 camPos[2];
    s16 camRot[3];
    u8 mode;
    int p;
    f32 t;
    f32 throttle;

    if ((*(u8 *)(state + 0x477) & 1) == 0) {
        fn_8022CDEC(obj, state);
        return;
    }
    mode = *(u8 *)(state + 0x478);
    if (mode == 5) {
        t = *(f32 *)(state + 0x46c) - timeDelta;
        *(f32 *)(state + 0x46c) = t;
        if (t <= lbl_803E6ECC) {
            *(u8 *)(state + 0x478) = 6;
            (*(void (**)(int, int))(*gScreenTransitionInterface + 8))(0x14, 1);
            *(f32 *)(state + 0x46c) = lbl_803E6F34;
        }
        return;
    }
    if (mode == 6) {
        t = *(f32 *)(state + 0x46c) - timeDelta;
        *(f32 *)(state + 0x46c) = t;
        if (t <= lbl_803E6ECC) {
            if (*(s8 *)(obj + 0xac) == 0x26) {
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(0x26), 0);
                lockLevel(mapGetDirIdx(0xb), 1);
                warpToMap(0x32, 0);
            } else {
                warpToMap(0x60, 0);
            }
        }
        return;
    }
    if (mode == 4) {
        t = *(f32 *)(state + 0x46c) - timeDelta;
        *(f32 *)(state + 0x46c) = t;
        if (t <= lbl_803E6ECC) {
            *(u8 *)(state + 0x478) = 5;
            *(f32 *)(state + 0x46c) = lbl_803E6F24;
            *(s16 *)(obj + 6) = (s16)(*(s16 *)(obj + 6) | 0x4000);
            spawnExplosion(obj, lbl_803E6F28, 1, 0, 1, 1, 0, 1, 0);
        }
        *(int *)(state + 0x36c) =
            (int)(lbl_803E6F6C * timeDelta + (f32) * (int *)(state + 0x36c));
        *(s16 *)(obj + 4) = (s16) * (int *)(state + 0x36c);
        *(f32 *)(state + 0x4c) = *(f32 *)(state + 0x4c) - lbl_803E6EF8 * timeDelta;
        objMove(obj, *(f32 *)(state + 0x48) * timeDelta, *(f32 *)(state + 0x4c) * timeDelta,
                *(f32 *)(state + 0x50) * timeDelta);
        fn_8022AE1C(obj, state);
        p = *(int *)(state + 0x418);
        *(s16 *)(p + 6) = (s16)(*(s16 *)(p + 6) | 0x4000);
        p = *(int *)(state + 0x41c);
        *(s16 *)(p + 6) = (s16)(*(s16 *)(p + 6) | 0x4000);
    } else {
        fn_8022A670(obj, state);
        if ((*(s16 *)(obj + 6) & 0x4000) != 0) {
            *(s16 *)(state + 0x3f8) = 0;
            *(s16 *)(state + 0x3f4) = 0;
            p = *(int *)(state + 0x418);
            *(s16 *)(p + 6) = (s16)(*(s16 *)(p + 6) | 0x4000);
            p = *(int *)(state + 0x41c);
            *(s16 *)(p + 6) = (s16)(*(s16 *)(p + 6) | 0x4000);
        } else {
            p = *(int *)(state + 0x418);
            *(s16 *)(p + 6) = (s16)(*(s16 *)(p + 6) & ~0x4000);
            throttle = lbl_803E6FFC * timeDelta +
                       (f32)(u32) * (u8 *)(*(int *)(state + 0x418) + 0x36);
            if (throttle > lbl_803E7000) throttle = lbl_803E7000;
            *(u8 *)(*(int *)(state + 0x418) + 0x36) = (u8)(int)throttle;
            p = *(int *)(state + 0x41c);
            *(s16 *)(p + 6) = (s16)(*(s16 *)(p + 6) & ~0x4000);
            *(u8 *)(*(int *)(state + 0x41c) + 0x36) = (u8)(int)throttle;
        }
        *(f32 *)(state + 0x3c) = -*(f32 *)(state + 0x3e4) * *(f32 *)(state + 0x54);
        *(f32 *)(state + 0x40) = -*(f32 *)(state + 0x3e8) * *(f32 *)(state + 0x58);
        *(f32 *)(state + 0x44) = *(f32 *)(state + 0x5c) * *(f32 *)(state + 0x6c);
        *(int *)(state + 0x340) =
            (int)(-*(f32 *)(state + 0x3e4) * *(f32 *)(state + 0x348));
        *(int *)(state + 0x354) = (int)(*(f32 *)(state + 0x3e8) * *(f32 *)(state + 0x35c));
        *(int *)(state + 0x368) = (int)(*(f32 *)(state + 0x3e4) * *(f32 *)(state + 0x370));
        *(int *)(state + 0x37c) =
            (int)(*(f32 *)(state + 0x384) *
                  (*(f32 *)(state + 0x3f0) + *(f32 *)(state + 0x3ec)));
        fn_8022AECC(obj, state);
        arwarwing_updateWeaponFire(obj, state);
        fn_8022B8A0(obj, state);

        *(s16 *)(*(int *)(state + 0x454) + 0) =
            (int)((f32)(-*(int *)(state + 0x36c)) * *(f32 *)(state + 0x464));
        *(s16 *)(*(int *)(state + 0x454) + 4) =
            (int)((f32) * (int *)(state + 0x36c) * *(f32 *)(state + 0x464));
        *(s16 *)(*(int *)(state + 0x458) + 0) =
            (int)((f32)(-*(int *)(state + 0x36c)) * *(f32 *)(state + 0x464));
        *(s16 *)(*(int *)(state + 0x458) + 4) =
            (int)((f32) * (int *)(state + 0x36c) * *(f32 *)(state + 0x464));
        p = (int)((f32) * (int *)(state + 0x36c) * *(f32 *)(state + 0x464));
        *(s16 *)(*(int *)(state + 0x45c) + 4) = p;
        *(s16 *)(*(int *)(state + 0x45c) + 0) = p;
        p = (int)((f32) * (int *)(state + 0x36c) * *(f32 *)(state + 0x464));
        *(s16 *)(*(int *)(state + 0x460) + 4) = p;
        *(s16 *)(*(int *)(state + 0x460) + 0) = p;

        *(s16 *)(*(int *)(state + 0x454) + 0) =
            (int)((f32)(-*(int *)(state + 0x358)) * *(f32 *)(state + 0x464) +
                  (f32) * (s16 *)(*(int *)(state + 0x454) + 0));
        *(s16 *)(*(int *)(state + 0x454) + 4) =
            (int)((f32) * (int *)(state + 0x358) * *(f32 *)(state + 0x464) +
                  (f32) * (s16 *)(*(int *)(state + 0x454) + 4));
        *(s16 *)(*(int *)(state + 0x458) + 0) =
            (int)((f32)(-*(int *)(state + 0x358)) * *(f32 *)(state + 0x464) +
                  (f32) * (s16 *)(*(int *)(state + 0x458) + 0));
        *(s16 *)(*(int *)(state + 0x458) + 4) =
            (int)((f32) * (int *)(state + 0x358) * *(f32 *)(state + 0x464) +
                  (f32) * (s16 *)(*(int *)(state + 0x458) + 4));
        *(s16 *)(*(int *)(state + 0x45c) + 0) =
            (int)((f32)(-*(int *)(state + 0x358)) * *(f32 *)(state + 0x464) +
                  (f32) * (s16 *)(*(int *)(state + 0x45c) + 0));
        *(s16 *)(*(int *)(state + 0x45c) + 4) =
            (int)((f32)(-*(int *)(state + 0x358)) * *(f32 *)(state + 0x464) +
                  (f32) * (s16 *)(*(int *)(state + 0x45c) + 4));
        *(s16 *)(*(int *)(state + 0x460) + 0) =
            (int)((f32)(-*(int *)(state + 0x358)) * *(f32 *)(state + 0x464) +
                  (f32) * (s16 *)(*(int *)(state + 0x460) + 0));
        *(s16 *)(*(int *)(state + 0x460) + 4) =
            (int)((f32)(-*(int *)(state + 0x358)) * *(f32 *)(state + 0x464) +
                  (f32) * (s16 *)(*(int *)(state + 0x460) + 4));
    }

    fn_8022C30C(obj, state);
    (*(void (**)(void *, int))(*gCameraInterface + 0x60))((void *)(state + 0x2c), 0xc);
    camRot[0] = *(s16 *)(obj + 0);
    camRot[1] = *(s16 *)(obj + 2);
    camRot[2] = (s16) * (int *)(state + 0x36c);
    (*(void (**)(void *, int))(*gCameraInterface + 0x60))(camRot, 6);
    camPos[0] = *(f32 *)(state + 0x5c);
    camPos[1] = *(f32 *)(state + 0x50);
    (*(void (**)(void *, int))(*gCameraInterface + 0x60))(camPos, 8);
    fn_8022BE14(obj, state);
    fn_8022C0D0(obj, state);
    fn_8022BCD0(obj, state);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwarwing_spawnLaserShot(int obj, int state, int side, int level, int linkEffect) {
    f32 pz, py, px;
    int proj;
    if (Obj_IsLoadingLocked() == 0)
        return;
    if (side == 0) {
        ObjPath_GetPointWorldPosition(obj, 3, &px, &py, &pz, 0);
        arwarwinggu_setActiveVisible(*(int *)(state + 8), 1, level == 2);
    } else {
        ObjPath_GetPointWorldPosition(obj, 4, &px, &py, &pz, 0);
        arwarwinggu_setActiveVisible(*(int *)(state + 0xc), 1, level == 2);
    }
    {
        int setup = Obj_AllocObjectSetup(0x20, 0x604);
        *(f32 *)(setup + 8) = px;
        *(f32 *)(setup + 0xc) = py;
        *(f32 *)(setup + 0x10) = pz;
        *(u8 *)(setup + 0x1a) = *(s16 *)obj >> 8;
        *(u8 *)(setup + 0x19) = *(s16 *)(obj + 2) >> 8;
        *(u8 *)(setup + 0x18) = 0;
        *(u8 *)(setup + 4) = 1;
        *(u8 *)(setup + 5) = 1;
    }
    proj = loadObjectAtObject(obj);
    if (proj == 0)
        return;
    if (level == 0) {
        Sfx_PlayFromObject(proj, SFXbaddie_rach_call1);
    } else if (level == 1) {
        Sfx_PlayFromObject(proj, SFXbaddie_rach_call2);
    } else {
        Sfx_PlayFromObject(proj, SFXbaddie_eba_bigswipe);
        Obj_SetActiveModelIndex(proj, 1);
    }
    if (linkEffect != 0)
        arwprojectile_createLinkedEffect(proj, 1);
    arwprojectile_setLifetime(proj, *(u16 *)(state + 0x40e));
    arwprojectile_placeForward(proj, *(f32 *)(state + 0x410));
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void fn_8022D6D0(int arwing)
{
    int state = *(int *)(arwing + 0xb8);
    if (*(u8 *)(state + 0x44c) < *(u8 *)(state + 0x44d)) {
        (*(u8 *)(state + 0x44c))++;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void fn_8022D6F0(int arwing)
{
    int state = *(int *)(arwing + 0xb8);
    if ((s8) * (u8 *)(state + 0x404) < 2) {
        (*(u8 *)(state + 0x404))++;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int fn_8022D710(int arwing)
{
    int result = 0;
    u32 v = *(u8 *)(*(int *)(arwing + 0xb8) + 0x478);
    if (v == 5 || v == 6) {
        result = 1;
    }
    return result;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int fn_8022D738(int arwing) { return *(u8 *)(*(int *)(arwing + 0xb8) + 0x478) == 1; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int fn_8022D750(int arwing) { return *(u8 *)(*(int *)(arwing + 0xb8) + 0x478) == 4; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void fn_8022C30C(int obj, int state)
{
    int vec;
    f32 vol;

    vec = objModelGetVecFn_800395d8(*(int *)(state + 0x4), 0x14);

    if (*(u8 *)(state + 0x478) < 4 && (u32)GameBit_Get(0x9d6) == 0 && (u32)GameBit_Get(0x9d8) == 0) {
        vol = (f32)((lbl_803E6F48 + fn_802945E0(*(f32 *)(state + 0x50) / *(f32 *)(state + 0x5c))) *
                    lbl_803E6F50);
        Sfx_KeepAliveLoopedObjectSound(obj, 0x29f);
        Sfx_SetObjectChannelVolume(obj, 0x40, 0xfe, vol);
    }

    fn_8022F270(*(int *)(state + 0x4), *(u16 *)(state + 0x44e));

    if (*(f32 *)(state + 0xb4) <= lbl_803E6ECC) {
        if ((*(u8 *)(state + 0x477) & 0x2) == 0) {
            if ((*(u16 *)(state + 0x3f4) & 0x800) != 0) {
                *(u8 *)(state + 0x477) &= ~0x4;
                *(u8 *)(state + 0x477) |= 0x2;
                *(f32 *)(state + 0xb0) = lbl_803E6F58;
                Sfx_PlayFromObjectLimited(obj, 0x2b6, 3);
            }
        } else {
            *(f32 *)(state + 0x6c) = *(f32 *)(state + 0x88);
            *(f32 *)(state + 0x68) = *(f32 *)(state + 0x90);
            if ((*(u16 *)(state + 0x3f6) & 0x800) != 0) {
                *(u8 *)(state + 0x477) &= ~0x2;
                *(f32 *)(state + 0xb0) = lbl_803E6F5C;
            }
        }
        if ((*(u8 *)(state + 0x477) & 0x4) == 0) {
            if ((*(u16 *)(state + 0x3f4) & 0x400) != 0) {
                *(u8 *)(state + 0x477) &= ~0x2;
                *(u8 *)(state + 0x477) |= 0x4;
                *(f32 *)(state + 0xb0) = lbl_803E6F60;
                Sfx_PlayFromObjectLimited(obj, 0x2b7, 3);
            }
        } else {
            *(f32 *)(state + 0x6c) = *(f32 *)(state + 0x8c);
            *(f32 *)(state + 0x68) = *(f32 *)(state + 0x94);
            if ((*(u16 *)(state + 0x3f6) & 0x400) != 0) {
                *(u8 *)(state + 0x477) &= ~0x4;
                *(f32 *)(state + 0xb0) = lbl_803E6F5C;
            }
        }
    } else {
        if ((*(u16 *)(state + 0x3f4) & 0xc00) != 0) {
            Sfx_PlayFromObject(obj, 0x381);
        }
        *(f32 *)(state + 0xb4) -= timeDelta;
        if (*(f32 *)(state + 0xb4) <= lbl_803E6ECC) {
            *(f32 *)(state + 0xb0) = lbl_803E6F5C;
        }
    }

    if ((*(u8 *)(state + 0x477) & 0x6) == 0) {
        *(f32 *)(state + 0x6c) = lbl_803E6ED0;
        *(f32 *)(state + 0x68) = *(f32 *)(state + 0x98);
        if (*(f32 *)(state + 0xbc) <= lbl_803E6ECC) {
            *(f32 *)(state + 0x9c) = lbl_803E6F64 * timeDelta + *(f32 *)(state + 0x9c);
        } else {
            *(f32 *)(state + 0xbc) -= timeDelta;
        }
    } else {
        *(f32 *)(state + 0x9c) -= timeDelta;
        *(f32 *)(state + 0xbc) = lbl_803E6F38;
    }

    *(f32 *)(state + 0x9c) = *(f32 *)(state + 0x9c) < lbl_803E6ECC
                                 ? lbl_803E6ECC
                                 : *(f32 *)(state + 0x9c) > *(f32 *)(state + 0xa0)
                                       ? *(f32 *)(state + 0xa0)
                                       : *(f32 *)(state + 0x9c);

    if (*(f32 *)(state + 0x9c) <= lbl_803E6ECC) {
        *(u8 *)(state + 0x477) &= ~0x6;
        *(f32 *)(state + 0xb4) = *(f32 *)(state + 0xb8);
        *(f32 *)(state + 0x9c) = *(f32 *)(state + 0xa0);
        *(f32 *)(state + 0xb0) = lbl_803E6F68;
        *(f32 *)(state + 0xbc) = lbl_803E6ECC;
    }

    if ((u32)vec != 0) {
        int n;
        *(f32 *)(state + 0xac) =
            lbl_803E6EF8 * (*(f32 *)(state + 0xb0) - *(f32 *)(state + 0xac)) + *(f32 *)(state + 0xac);
        n = (int)*(f32 *)(state + 0xac);
        *(s16 *)(vec + 0xa) = n;
        *(s16 *)(vec + 0x8) = n;
        *(s16 *)(vec + 0x6) = n;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void fn_8022C7A4(int obj) { *(u8 *)(*(int *)(obj + 0xb8) + 0x47f) = 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void fn_8022CDEC(int obj, int state)
{
    int found;
    int mev;
    f32 radius;

    radius = lbl_803E6FC0;
    mev = (*(int (**)(int))(*gMapEventInterface + 0x8c))(*gMapEventInterface);

    if (*(void **)(state + 0x4) == 0) {
        *(int *)(state + 0x4) = ObjList_FindNearestObjectByDefNo(obj, 0x606, &radius);
        if (*(void **)(state + 0x4) != 0) {
            ObjLink_AttachChild(obj, *(int *)(state + 0x4), 0);
        }
    }

    if (*(u8 *)(state + 0x480) != 0) {
        if (*(void **)(state + 0x10) == 0) {
            *(int *)(state + 0x10) = ObjList_FindNearestObjectByDefNo(obj, 0x611, &radius);
            if (*(void **)(state + 0x10) != 0) {
                ObjLink_AttachChild(obj, *(int *)(state + 0x10), 0);
            }
        }
        if (*(void **)(state + 0x8) == 0) {
            *(int *)(state + 0x8) = ObjList_FindNearestObjectByDefNo(obj, 0x610, &radius);
            if (*(void **)(state + 0x8) != 0) {
                ObjLink_AttachChild(obj, *(int *)(state + 0x8), 0);
            }
        }
        if (*(void **)(state + 0xc) == 0) {
            *(int *)(state + 0xc) = ObjList_FindNearestObjectByDefNo(obj, 0x615, &radius);
            if (*(void **)(state + 0xc) != 0) {
                ObjLink_AttachChild(obj, *(int *)(state + 0xc), 0);
            }
        }
    }

    if (*(void **)(state + 0x418) == 0 && *(void **)(state + 0x41c) == 0) {
        int setup;
        setup = Obj_AllocObjectSetup(0x20, 0x6de);
        *(u8 *)(setup + 0x4) = 1;
        *(u8 *)(setup + 0x5) = 1;
        *(int *)(state + 0x418) = ((int (*)(int, int))loadObjectAtObject)(obj, setup);
        setup = Obj_AllocObjectSetup(0x20, 0x6de);
        *(u8 *)(setup + 0x4) = 1;
        *(u8 *)(setup + 0x5) = 1;
        *(int *)(state + 0x41c) = ((int (*)(int, int))loadObjectAtObject)(obj, setup);
    }

    found = 0;
    if (*(u8 *)(state + 0x480) != 0) {
        if (*(void **)(state + 0x450) == 0) {
            *(int *)(state + 0x450) = (int)objCreateLight(obj, 1);
            if (*(void **)(state + 0x450) != 0) {
                modelLightStruct_setField50(*(void **)(state + 0x450), 2);
                lightVecFn_8001dd88(*(void **)(state + 0x450), lbl_803E6ECC, lbl_803E6FC4, lbl_803E6FC8);
                lightSetFieldBC_8001db14(*(void **)(state + 0x450), 1);
                modelLightStruct_setColorsA8AC(*(void **)(state + 0x450), 0x28, 0x7d, 0xff, 0);
                lightDistAttenFn_8001dc38(*(void **)(state + 0x450), lbl_803E6FCC, lbl_803E6FD0);
                lightFn_8001d620(*(void **)(state + 0x450), 1, 1);
                lightSetFieldB0(*(void **)(state + 0x450), 0x14, 0x64, 0xc8, 0);
            }
        }
        if (*(void **)(state + 0x4) != 0 && *(void **)(state + 0x10) != 0 && *(void **)(state + 0x8) != 0 &&
            *(void **)(state + 0xc) != 0) {
            found = 1;
        }
    } else {
        if (*(void **)(state + 0x4) != 0) {
            found = 1;
        }
    }

    if (found != 0) {
        (*(void (**)(int, int))(*gCameraInterface + 0x28))(obj, 0);
        *(u8 *)(state + 0x477) |= 1;
        *(f32 *)(state + 0x54) = lbl_803E6F70;
        *(f32 *)(state + 0x60) = lbl_803E6F74;
        *(f32 *)(state + 0x58) = lbl_803E6F78;
        *(f32 *)(state + 0x64) = lbl_803E6F7C;
        *(f32 *)(state + 0x5c) = lbl_803E6F78;
        *(f32 *)(state + 0x68) = lbl_803E6F7C;
        *(f32 *)(state + 0x78) = lbl_803E6F80;
        *(f32 *)(state + 0x84) = lbl_803E6F84;
        *(f32 *)(state + 0x6c) = lbl_803E6ED0;
        *(f32 *)(state + 0x348) = lbl_803E6F88;
        *(f32 *)(state + 0x34c) = lbl_803E6F74;
        *(f32 *)(state + 0x35c) = lbl_803E6F8C;
        *(f32 *)(state + 0x360) = lbl_803E6F7C;
        *(f32 *)(state + 0x370) = lbl_803E6F90;
        *(f32 *)(state + 0x374) = lbl_803E6F94;
        *(f32 *)(state + 0x384) = lbl_803E6F98;
        *(f32 *)(state + 0x388) = lbl_803E6F9C;
        *(f32 *)(state + 0x394) = lbl_803E6FA0;
        *(f32 *)(state + 0x390) = lbl_803E6FA4;
        *(f32 *)(state + 0x39c) = lbl_803E6FA8;
        *(u8 *)(state + 0x3fa) = 0x19;
        *(f32 *)(state + 0x3a4) = lbl_803E6FAC;
        *(f32 *)(state + 0x38) = lbl_803E6FB0;
        *(f32 *)(obj + 0x8) = lbl_803E6FB0;
        *(f32 *)(state + 0x3ac) = lbl_803E6FB4;
        *(f32 *)(state + 0x3b0) = lbl_803E6FB8;
        *(f32 *)(state + 0x88) = lbl_803E6FBC;
        *(f32 *)(state + 0x8c) = lbl_803E6F64;
        *(f32 *)(state + 0x90) = lbl_803E6FD4;
        *(f32 *)(state + 0x94) = lbl_803E6F74;
        *(f32 *)(state + 0x98) = lbl_803E6FD8;
        *(f32 *)(state + 0xb8) = lbl_803E6FDC;
        *(f32 *)(state + 0xa0) = lbl_803E6FE0;
        *(f32 *)(state + 0xa8) = lbl_803E6F2C;
        *(f32 *)(state + 0x9c) = *(f32 *)(state + 0xa0);
        *(f32 *)(state + 0xa4) = *(f32 *)(state + 0xa8);
        *(f32 *)(state + 0xac) = lbl_803E6F5C;
        *(f32 *)(state + 0xb0) = lbl_803E6F5C;
        if (*(s8 *)(obj + 0xac) == 0x26) {
            *(f32 *)(state + 0x50) = lbl_803E6ECC;
        } else {
            *(f32 *)(state + 0x50) = lbl_803E6F78;
        }
        *(s16 *)(state + 0x40e) = 0x28;
        *(f32 *)(state + 0x410) = lbl_803E6FE0;
        *(s16 *)(state + 0x40c) = 0x6;
        *(s16 *)(state + 0x446) = 0x5a;
        *(f32 *)(state + 0x448) = lbl_803E6F34;
        *(s16 *)(state + 0x444) = 0xc;
        *(u8 *)(state + 0x44d) = 0x3;
        *(int *)(state + 0x454) = objModelGetVecFn_800395d8(obj, 0);
        *(int *)(state + 0x458) = objModelGetVecFn_800395d8(obj, 1);
        *(int *)(state + 0x45c) = objModelGetVecFn_800395d8(obj, 2);
        *(int *)(state + 0x460) = objModelGetVecFn_800395d8(obj, 3);
        *(f32 *)(state + 0x464) = lbl_803E6F64;
        *(s16 *)(state + 0x44e) = 0xaf;
        *(u8 *)(state + 0x469) = *(u8 *)(mev + 0x1);
        *(u8 *)(state + 0x468) = *(u8 *)(state + 0x469);
        *(f32 *)(state + 0x3b4) = lbl_803E6EF8;
        *(f32 *)(state + 0x3b8) = lbl_803E6EF0;
        *(f32 *)(state + 0x3bc) = lbl_803E6FE4;
        *(f32 *)(state + 0x3c4) = lbl_803E6EF4;
        *(f32 *)(state + 0x3c8) = lbl_803E6FD4;
        *(f32 *)(state + 0x3d0) = lbl_803E6FE8;
        *(f32 *)(state + 0x3d4) = lbl_803E6F80;
        *(f32 *)(state + 0x3e0) = lbl_803E6FA4;
        *(f32 *)(state + 0x14) = *(f32 *)(obj + 0xc);
        *(f32 *)(state + 0x18) = *(f32 *)(obj + 0x10);
        *(f32 *)(state + 0x1c) = *(f32 *)(obj + 0x14);
        *(f32 *)(state + 0x20) = lbl_803E6FEC;
        *(f32 *)(state + 0x28) = lbl_803E6FF0;
        *(f32 *)(state + 0x24) = lbl_803E6EF0;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void fn_8022D308(int obj)
{
    int state = *(int *)(obj + 0xb8);
    f32 v7c = lbl_803E6F7C;
    f32 v74 = lbl_803E6F74;

    *(f32 *)(state + 0x54) = lbl_803E6F70;
    *(f32 *)(state + 0x60) = v74;
    *(f32 *)(state + 0x58) = lbl_803E6F78;
    *(f32 *)(state + 0x64) = v7c;
    *(f32 *)(state + 0x5c) = lbl_803E6F78;
    *(f32 *)(state + 0x68) = v7c;
    *(f32 *)(state + 0x78) = lbl_803E6F80;
    *(f32 *)(state + 0x84) = lbl_803E6F84;
    *(f32 *)(state + 0x6c) = lbl_803E6ED0;
    *(f32 *)(state + 0x348) = lbl_803E6F88;
    *(f32 *)(state + 0x34c) = v74;
    *(f32 *)(state + 0x35c) = lbl_803E6F8C;
    *(f32 *)(state + 0x360) = v7c;
    *(f32 *)(state + 0x370) = lbl_803E6F90;
    *(f32 *)(state + 0x374) = lbl_803E6F94;
    *(f32 *)(state + 0x384) = lbl_803E6F98;
    *(f32 *)(state + 0x388) = lbl_803E6F9C;
    *(f32 *)(state + 0x394) = lbl_803E6FA0;
    *(f32 *)(state + 0x390) = lbl_803E6FA4;
    *(f32 *)(state + 0x39c) = lbl_803E6FA8;
    *(u8 *)(state + 0x3fa) = 0x19;
    *(f32 *)(state + 0x3a4) = lbl_803E6FAC;
    *(f32 *)(state + 0x38) = lbl_803E6FB0;
    *(f32 *)(state + 0x3ac) = lbl_803E6FB4;
    *(f32 *)(state + 0x3b0) = lbl_803E6FB8;
    *(f32 *)(state + 0x88) = lbl_803E6FBC;
    *(f32 *)(state + 0x8c) = lbl_803E6F64;
    *(f32 *)(state + 0x9c) = *(f32 *)(state + 0xa0);
    *(f32 *)(state + 0xa4) = *(f32 *)(state + 0xa8);
    *(f32 *)(state + 0xac) = lbl_803E6F5C;
    *(f32 *)(state + 0xb0) = lbl_803E6F5C;
    *(f32 *)(state + 0x48) = lbl_803E6ECC;
    *(f32 *)(state + 0x4c) = lbl_803E6ECC;
    *(f32 *)(state + 0x50) = lbl_803E6ECC;
    *(u8 *)(state + 0x404) = 0;
    *(f32 *)(obj + 0xc) = *(f32 *)(state + 0x14);
    *(f32 *)(obj + 0x10) = *(f32 *)(state + 0x18);
    *(f32 *)(obj + 0x14) = *(f32 *)(state + 0x1c);
    *(int *)(state + 0x358) = 0;
    *(int *)(state + 0x36c) = 0;
    *(s16 *)(obj + 0) = 0;
    *(s16 *)(obj + 2) = 0;
    *(s16 *)(obj + 4) = 0;
    arwarwingbo_setActiveVisible(*(int *)(state + 0x10), 0, 0);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void fn_8022BE14(int obj, int state)
{
    int sub = state + 0xc0;
    int dmg;

    (*(void (**)(int, int, f32))(*gPathControlInterface + 0x10))(obj, sub, timeDelta);
    (*(void (**)(int, int))(*gPathControlInterface + 0x14))(obj, sub);
    (*(void (**)(int, int, f32))(*gPathControlInterface + 0x18))(obj, sub, timeDelta);

    if (*(u8 *)(state + 0x338) == 0 || *(u8 *)(state + 0x478) == 4) {
        dmg = (s8)*(u8 *)(sub + 0x260);
        if (dmg == 0)
            return;
        if (*(u8 *)(state + 0x478) == 4) {
            *(u8 *)(state + 0x478) = 5;
            *(f32 *)(state + 0x46c) = lbl_803E6F24;
            *(s16 *)(obj + 6) |= 0x4000;
            spawnExplosion(obj, lbl_803E6F28, 1, 0, 1, 1, 0, 1, 0);
            return;
        }
        if ((dmg & 1) && (s8)*(u8 *)(sub + 0xb8) == 8)
            *(u8 *)(state + 0x468) = 0;
        else
            *(u8 *)(state + 0x468) = *(u8 *)(state + 0x468) - 1;
        doRumble(lbl_803E6F2C);
        if ((s8)*(u8 *)(state + 0x468) <= 0) {
            arwarwingbo_setActiveVisible(*(int *)(state + 0x10), 0, 0);
            if ((s8)*(u8 *)(obj + 0xac) == 0x26)
                GameBit_Set(0xe74, 1);
            else
                *(u8 *)(state + 0x478) = 4;
            *(f32 *)(state + 0x46c) = lbl_803E6F30;
            Sfx_PlayFromObject(obj, 0x380);
            Music_Trigger(0xd6, 1);
        } else if ((s8)*(u8 *)(*(int *)(obj + 0xb8) + 0x468) <= 3) {
            Sfx_KeepAliveLoopedObjectSound(obj, 0x37f);
        }
        Sfx_PlayFromObject(obj, SFXbaddie_rach_bite);
        *(u8 *)(state + 0x339) |= 0x80;
        Obj_SetModelColorFadeRecursive(obj, 0x4b, 0xc8, 0, 0, 1);
        *(f32 *)(state + 0x328) = lbl_803E6F34;
        *(u8 *)(state + 0x338) = 1;
        *(s16 *)(state + 0x33a) = 0;
        *(s16 *)(state + 0x33c) = 0;
        *(f32 *)(state + 0x32c) = *(f32 *)(sub + 0x1a0);
        *(f32 *)(state + 0x330) = *(f32 *)(sub + 0x1a4);
        Camera_EnableViewYOffset();
        CameraShake_SetAllMagnitudes(lbl_803E6F38);
    } else {
        *(s16 *)(state + 0x33a) = lbl_803E6F3C * timeDelta + (f32)*(u16 *)(state + 0x33a);
        *(s16 *)(state + 0x33c) = lbl_803E6F40 * timeDelta + (f32)*(u16 *)(state + 0x33c);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void fn_8022C0D0(int obj, int state)
{
    int hitVol;
    int hitObj;

    if (objGetFlagsE5_2(obj) != 0)
        return;
    if (ObjHits_GetPriorityHit(obj, &hitObj, 0, &hitVol) != 0 && hitVol != 0) {
        if (*(u8 *)(state + 0x478) == 4) {
            *(u8 *)(state + 0x478) = 5;
            *(f32 *)(state + 0x46c) = lbl_803E6F24;
            *(s16 *)(obj + 6) |= 0x4000;
            spawnExplosion(obj, lbl_803E6F28, 1, 0, 1, 1, 0, 1, 0);
        } else {
            if (*(s16 *)(hitObj + 0x46) == 0x6ae && *(u8 *)(state + 0x478) == 1) {
                Sfx_PlayFromObject(obj, SFXbaddie_eggsnatch_movelp);
                return;
            }
            doRumble(lbl_803E6F2C);
            *(u8 *)(state + 0x468) = *(u8 *)(state + 0x468) - hitVol;
            Sfx_PlayFromObject(obj, SFXbaddie_vambat_death);
            *(u8 *)(state + 0x339) |= 0x80;
            Obj_SetModelColorFadeRecursive(obj, 0x4b, 0xc8, 0, 0, 1);
            *(f32 *)(state + 0x328) = lbl_803E6F34;
            *(u8 *)(state + 0x338) = 1;
            *(s16 *)(state + 0x33a) = 0;
            *(s16 *)(state + 0x33c) = 0;
            *(f32 *)(state + 0x32c) = lbl_803E6ECC;
            *(f32 *)(state + 0x330) = lbl_803E6ECC;
            Camera_EnableViewYOffset();
            CameraShake_SetAllMagnitudes(lbl_803E6F2C);
        }
    }
    if (*(u8 *)(state + 0x478) != 4 && *(u8 *)(state + 0x478) != 5 &&
        *(u8 *)(state + 0x478) != 6 && (s8)*(u8 *)(state + 0x468) <= 0) {
        arwarwingbo_setActiveVisible(*(int *)(state + 0x10), 0, 0);
        if ((s8)*(u8 *)(obj + 0xac) == 0x26)
            GameBit_Set(0xe74, 1);
        *(u8 *)(state + 0x478) = 4;
        *(f32 *)(state + 0x46c) = lbl_803E6F30;
        Sfx_PlayFromObject(obj, 0x380);
        Music_Trigger(0xd6, 1);
        unlockLevel(0, 0, 1);
        loadMapAndParent(0x29);
        lockLevel(mapGetDirIdx(0x29), 0);
    } else if ((s8)*(u8 *)(*(int *)(obj + 0xb8) + 0x468) <= 3) {
        Sfx_KeepAliveLoopedObjectSound(obj, 0x37f);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int fn_8022C7B4(int obj, int p2, int script)
{
    int state = *(int *)(obj + 0xb8);
    int i;

    Camera_GetCurrentViewSlot();
    *(int *)(script + 0xe8) = (int)fn_8022C7A4;
    if ((*(u8 *)(state + 0x477) & 1) == 0) {
        fn_8022CDEC(obj, state);
        return 0;
    }
    fn_8022C30C(obj, state);
    fn_8022A9C8(obj, state);
    if (*(int *)(state + 0x10) != 0)
        arwarwingbo_setActiveVisible(*(int *)(state + 0x10), 0, 0);
    *(s16 *)(*(int *)(state + 0x418) + 6) |= 0x4000;
    *(u8 *)(*(int *)(state + 0x418) + 0x36) = 0;
    *(s16 *)(*(int *)(state + 0x41c) + 6) |= 0x4000;
    *(u8 *)(*(int *)(state + 0x41c) + 0x36) = 0;
    *(s16 *)(obj + 6) &= ~0x4000;

    for (i = 0; i < *(u8 *)(script + 0x8b); i++) {
        switch (*(u8 *)(script + i + 0x81)) {
        case 8: {
            int cam = Camera_GetCurrentViewSlot();
            *(f32 *)(state + 0x484) = *(f32 *)(cam + 0xc) - *(f32 *)(obj + 0xc);
            *(f32 *)(state + 0x488) = *(f32 *)(cam + 0x10) - *(f32 *)(obj + 0x10);
            *(f32 *)(state + 0x48c) = *(f32 *)(cam + 0x14) - *(f32 *)(obj + 0x14);
            *(s16 *)(state + 0x490) = *(s16 *)(obj + 0) - (u16)*(s16 *)(cam + 0);
            if (*(s16 *)(state + 0x490) > 32768)
                *(s16 *)(state + 0x490) -= 65535;
            if (*(s16 *)(state + 0x490) < -32768)
                *(s16 *)(state + 0x490) += 65535;
            *(s16 *)(state + 0x492) = *(s16 *)(obj + 2) - (u16)*(s16 *)(cam + 2);
            if (*(s16 *)(state + 0x492) > 32768)
                *(s16 *)(state + 0x492) -= 65535;
            if (*(s16 *)(state + 0x492) < -32768)
                *(s16 *)(state + 0x492) += 65535;
            *(s16 *)(state + 0x494) = *(s16 *)(cam + 4) - *(s16 *)(obj + 4);
            *(u8 *)(state + 0x47f) = 1;
            break;
        }
        case 9:
            *(u8 *)(state + 0x47f) = 0;
            break;
        case 1:
            clearLoadedFileFlags_blocks1();
            warpToMap(0x60, 0);
            break;
        case 2:
            clearLoadedFileFlags_blocks1();
            fn_8022C680(obj);
            break;
        case 0xa:
            if (Obj_IsLoadingLocked()) {
                int setup = Obj_AllocObjectSetup(0x24, 0x608);
                int o;
                *(f32 *)(setup + 8) = *(f32 *)(obj + 0xc);
                *(f32 *)(setup + 0xc) = *(f32 *)(obj + 0x10);
                *(f32 *)(setup + 0x10) = *(f32 *)(obj + 0x14);
                *(u8 *)(setup + 4) = 1;
                *(u8 *)(setup + 5) = 1;
                o = loadObjectAtObject(obj);
                if (o != 0)
                    fn_8022F558(o, 0x12c);
            }
            break;
        case 0xb:
            *(u8 *)(state + 0x44c) = 1;
            fn_8022B764(obj, state, *(u8 *)(state + 0x43d));
            *(u8 *)(state + 0x43d) ^= 1;
            break;
        case 0xc:
            arwarwing_spawnLaserShot(obj, state, 0, 1, 1);
            arwarwing_spawnLaserShot(obj, state, 1, 1, 0);
            break;
        case 4:
            unlockLevel(0, 0, 1);
            mapUnload(0, 0x80000000);
            setLoadedFileFlags_blocks1();
            break;
        case 5:
            if (*(u8 *)(state + 0x47b) == 0 && GameBit_Get(0xc85)) {
                loadMapAndParent(0xb);
                lockLevel(mapGetDirIdx(0xb), 0);
            } else {
                loadMapAndParent(lbl_803DC3C8[*(u8 *)(state + 0x47b)]);
                lockLevel(mapGetDirIdx(lbl_803DC3C8[*(u8 *)(state + 0x47b)]), 0);
            }
            switch ((s8)*(u8 *)(obj + 0xac)) {
            case 0x3b:
                ((MapEventInterface *)*gMapEventInterface)->setAnimEvent(0x13, 0, 1);
                ((MapEventInterface *)*gMapEventInterface)->setAnimEvent(0x13, 0x16, 1);
                break;
            case 0x3d:
                GameBit_Set(0x36a, 0);
                ((MapEventInterface *)*gMapEventInterface)->setAnimEvent(0xd, 0, 1);
                ((MapEventInterface *)*gMapEventInterface)->setAnimEvent(0xd, 1, 1);
                ((MapEventInterface *)*gMapEventInterface)->setAnimEvent(0xd, 5, 1);
                ((MapEventInterface *)*gMapEventInterface)->setAnimEvent(0xd, 0xa, 1);
                ((MapEventInterface *)*gMapEventInterface)->setAnimEvent(0xd, 0xb, 1);
                GameBit_Set(0xe05, 0);
                break;
            case 0x3c:
                GameBit_Set(0x458, 0);
                GameBit_Set(0x47c, 0);
                GameBit_Set(0x4a3, 0);
                ((MapEventInterface *)*gMapEventInterface)->setAnimEvent(0xc, 0, 1);
                GameBit_Set(0xd73, 0);
                break;
            case 0x3e:
                GameBit_Set(0x5db, 0);
                ((MapEventInterface *)*gMapEventInterface)->setAnimEvent(2, 0xf, 1);
                ((MapEventInterface *)*gMapEventInterface)->setAnimEvent(2, 0x10, 1);
                GameBit_Set(0xe7b, 0);
                GameBit_Set(0x9e9, 0);
                break;
            }
            break;
        case 6:
            unlockLevel(0, 0, 1);
            loadMapAndParent(0x29);
            lockLevel(mapGetDirIdx(0x29), 0);
            break;
        case 7:
            if (!((Arw339Flags *)(state + 0x339))->scoreFlag) {
                int s2 = *(int *)(obj + 0xb8);
                *(u16 *)(s2 + 0x47c) = *(u16 *)(s2 + 0x47c) + 0xc8;
                if (*(u16 *)(s2 + 0x47c) > 0x270f)
                    *(u16 *)(s2 + 0x47c) = 0x270f;
            }
            registerNewScore((s8)*(u8 *)(state + 0x47e), *(u16 *)(state + 0x47c),
                             *(u8 *)(state + 0x470), 2);
            break;
        case 0xd:
            gameTextFn_80125ba4(0x13);
            break;
        case 0xe:
            gameTextFn_80125ba4(0x14);
            break;
        }
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwarwing_init(int obj)
{
    int state;
    int sub;
    ArwInitCfg cfg;

    cfg.a = lbl_802C25E8.a;
    cfg.b = lbl_802C25E8.b;
    cfg.c = lbl_802C25E8.c;
    state = *(int *)(obj + 0xb8);
    sub = state + 0xc0;
    *(int *)(obj + 0xbc) = (int)fn_8022C7B4;
    (*(void (**)(int, int, int, int))(*gPathControlInterface + 4))(sub, 4, 0x1040006, 1);
    (*(void (**)(int, int, void *, void *, void *))(*gPathControlInterface + 0xc))(sub, 3, lbl_8032B408, lbl_8032B480, &cfg);
    (*(void (**)(int, int))(*gPathControlInterface + 0x20))(obj, sub);
    ObjGroup_AddObject(obj, 0x26);
    lbl_803DDD88 = obj;
    ObjHits_SetTargetMask(obj, 1);
    *(u8 *)(state + 0x480) = 1;
    switch ((s8)*(u8 *)(obj + 0xac) - 0x26) {
    case 27:
    default:
        *(u8 *)(state + 0x480) = 0;
        break;
    case 20:
        *(u8 *)(state + 0x47b) = 0;
        *(u8 *)(state + 0x471) = 1;
        *(u8 *)(state + 0x47e) = 0;
        break;
    case 21:
        *(u8 *)(state + 0x47b) = 1;
        *(u8 *)(state + 0x471) = 3;
        *(u8 *)(state + 0x47e) = 1;
        break;
    case 23:
        *(u8 *)(state + 0x47b) = 2;
        *(u8 *)(state + 0x471) = 7;
        *(u8 *)(state + 0x47e) = 3;
        break;
    case 22:
        *(u8 *)(state + 0x47b) = 3;
        *(u8 *)(state + 0x471) = 5;
        *(u8 *)(state + 0x47e) = 2;
        break;
    case 24:
        *(u8 *)(state + 0x47b) = 4;
        *(u8 *)(state + 0x471) = 0xa;
        *(u8 *)(state + 0x47e) = 4;
        break;
    case 0:
        break;
    }
}
#pragma scheduling reset
#pragma peephole reset
