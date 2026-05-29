#include "main/dll/dll_80220608_shared.h"

#pragma peephole off
#pragma scheduling off
void wclevelcont_func16(s16 value, s16 *outRow, s16 *outCol)
{
    int i, j;

    for (i = 0; i < 8; i++) {
        for (j = 0; j < 8; j++) {
            if (value == lbl_8032B0C8[i][j]) {
                *outRow = (s16)i;
                *outCol = (s16)j;
                return;
            }
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wclevelcont_func15(s16 value, s16 *outRow, s16 *outCol)
{
    int i, j;

    for (i = 0; i < 8; i++) {
        for (j = 0; j < 8; j++) {
            if (value == lbl_8032B088[i][j]) {
                *outRow = (s16)i;
                *outCol = (s16)j;
                return;
            }
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int wclevelcont_func14(s16 i, s16 j)
{
    if (i < 0 || i > 7 || j < 0 || j > 7) {
        return 0;
    }
    return lbl_803AD298[i][j];
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wclevelcont_func13(int value, s16 i, s16 j)
{
    if (i < 0 || i > 7 || j < 0 || j > 7) {
        return;
    }
    lbl_803AD298[i][j] = (u8)value;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wclevelcont_func12(int obj, s16 *outRow, s16 *outCol, f32 px, f32 pz)
{
    f32 outX, outZ;

    fn_8005B0A8(&outX, &outZ, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
    *outRow = (s16)((s16)(px - outX - lbl_803E6DB8) / 48);
    *outCol = (s16)((s16)(pz - outZ - lbl_803E6DC0) / 48);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wclevelcont_func11(int obj, s16 col, s16 row, f32 *outXp, f32 *outZp)
{
    f32 outX, outZ;

    fn_8005B0A8(&outX, &outZ, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
    *outXp = lbl_803E6DB4 + (lbl_803E6DB8 + outX + (f32)(col * 48));
    *outZp = lbl_803E6DB4 + (lbl_803E6DC0 + outZ + (f32)(row * 48));
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wclevelcont_func0F(s16 value, s16 *outRow, s16 *outCol)
{
    int i, j;

    for (i = 0; i < 8; i++) {
        for (j = 0; j < 8; j++) {
            if (value == lbl_8032B048[i][j]) {
                *outRow = (s16)i;
                *outCol = (s16)j;
                return;
            }
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wclevelcont_func0E(s16 value, s16 *outRow, s16 *outCol)
{
    int i, j;

    for (i = 0; i < 8; i++) {
        for (j = 0; j < 8; j++) {
            if (value == lbl_8032B008[i][j]) {
                *outRow = (s16)i;
                *outCol = (s16)j;
                return;
            }
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int wclevelcont_render2(s16 i, s16 j)
{
    if (i < 0 || i > 7 || j < 0 || j > 7) {
        return 0;
    }
    return lbl_803AD2D8[i][j];
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wclevelcont_modelMtxFn(int value, s16 i, s16 j)
{
    if (i < 0 || i > 7 || j < 0 || j > 7) {
        return;
    }
    lbl_803AD2D8[i][j] = (u8)value;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wclevelcont_func0B(int obj, s16 *outRow, s16 *outCol, f32 px, f32 pz)
{
    f32 outX, outZ;

    fn_8005B0A8(&outX, &outZ, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
    *outRow = (s16)((s16)(px - outX - lbl_803E6DD0) / 48);
    *outCol = (s16)((s16)(pz - outZ - lbl_803E6DD4) / 48);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wclevelcont_setScale(int obj, s16 col, s16 row, f32 *outXp, f32 *outZp)
{
    f32 outX, outZ;

    fn_8005B0A8(&outX, &outZ, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
    *outXp = lbl_803E6DB4 + (lbl_803E6DD0 + outX + (f32)(col * 48));
    *outZp = lbl_803E6DB4 + (lbl_803E6DD4 + outZ + (f32)(row * 48));
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int wclevelcont_getExtraSize(void) { return 0x1c; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int wclevelcont_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void wclevelcont_free(int obj)
{
    int state = *(int *)(obj + 0xb8);
    u8 mode;

    ObjGroup_RemoveObject(obj, 9);
    mode = *(u8 *)(state + 0xc);
    if (mode == 1) {
        GameBit_Set(0x7ef, 0);
        GameBit_Set(0x7ed, 0);
        GameBit_Set(0xba6, 0);
        GameBit_Set(0xedd, 0);
    } else if (mode == 2) {
        GameBit_Set(0x7f0, 0);
        GameBit_Set(0x7ee, 0);
        GameBit_Set(0xba6, 0);
        GameBit_Set(0xedc, 0);
    }
    gameTimerStop();
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling on
void wclevelcont_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6DD8);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wclevelcont_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wclevelcont_syncProgressBits(int obj)
{
    int flag;

    if ((*(int (**)(int))(*gSHthorntailAnimationInterface + 0x24))(0)) {
        if (*(u16 *)(obj + 0x16) != 0x2d) {
            *(u16 *)(obj + 0x16) = 0x2d;
            Music_Trigger(0x2d, 1);
        }
        if (*(u16 *)(obj + 0x18) != -1) {
            *(u16 *)(obj + 0x18) = 0xffff;
            Music_Trigger(0x22, 0);
        }
    } else {
        if (*(u16 *)(obj + 0x16) != 0x39) {
            *(u16 *)(obj + 0x16) = 0x39;
            Music_Trigger(0x39, 1);
        }
        if (*(u16 *)(obj + 0x18) != 0x22) {
            *(u16 *)(obj + 0x18) = 0x22;
            Music_Trigger(0x22, 1);
        }
    }
    SCGameBitLatch_Update(obj + 0x10, 0x8, -1, -1, 0xba6, 0xd2);
    SCGameBitLatch_Update(obj + 0x10, 0x4, -1, -1, 0xcce, 0x36);
    SCGameBitLatch_Update(obj + 0x10, 0x10, -1, -1, 0xcd0, 0xd4);
    SCGameBitLatch_Update(obj + 0x10, 0x40, -1, -1, 0xcbb, 0xc4);
    flag = 0;
    if ((u32)GameBit_Get(0xba6) == 0 && ((u32)GameBit_Get(0xda9) != 0 || gameTimerIsRunning() != 0)) {
        flag = 1;
    }
    GameBit_Set(0xf31, flag);
    SCGameBitLatch_Update(obj + 0x10, 0x80, -1, -1, 0xf31, 0xaf);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wclevelcont_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int hitOut;

    if (*(int *)(obj + 0xf4) == 0) {
        if ((u32)GameBit_Get(0xe05) == 0) {
            getEnvfxActImmediately(obj, obj, 0x1fb, 0);
            getEnvfxActImmediately(obj, obj, 0x1ff, 0);
            getEnvfxActImmediately(obj, obj, 0x1fc, 0);
            getEnvfxActImmediately(obj, obj, 0x1fd, 0);
            skyFn_80088e54(0, lbl_803E6DA8);
            GameBit_Set(0xe05, 1);
        }
        *(int *)(obj + 0xf4) = 1;
    }
    switch ((*(u8 (**)(int))(*gMapEventInterface + 0x40))(*(s8 *)(obj + 0xac))) {
    case 1:
    default:
        wcpushblock_updateLevelControlState(obj, state);
        break;
    case 2:
        fn_802251B4(obj, state);
        break;
    }
    wclevelcont_syncProgressBits(state);
    if ((*(int (**)(int *))(*gSHthorntailAnimationInterface + 0x24))(&hitOut)) {
        GameBit_Set(0x7f3, 1);
        GameBit_Set(0x7f1, 0);
    } else {
        GameBit_Set(0x7f3, 0);
        GameBit_Set(0x7f1, 1);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int wclevelcont_func10(int obj, s16 a, s16 b, f32 *outX, f32 *outZ, int dx, int dy)
{
    int i;
    int limit;

    if (dx != 0) {
        int bi = b;
        if (dx == -1) {
            f32 pz, px;
            fn_8005B0A8(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
            *outX = lbl_803E6DB4 + (lbl_803E6DD0 + px + lbl_803E6DBC);
            *outZ = lbl_803E6DB4 + (lbl_803E6DD4 + pz + (f32)(bi * 48));
            a += 1;
            limit = 8;
        } else {
            f32 pz, px;
            fn_8005B0A8(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
            *outX = lbl_803E6DB4 + (lbl_803E6DD0 + px + lbl_803E6DA8);
            *outZ = lbl_803E6DB4 + (lbl_803E6DD4 + pz + (f32)(bi * 48));
            a -= 1;
            limit = -1;
        }
        for (i = a; i != limit; i -= dx) {
            if (lbl_803AD2D8[i][b] != 0) {
                if (lbl_803AD2D8[i][b] <= 4) {
                    f32 pz, px;
                    i += dx;
                    fn_8005B0A8(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
                    *outX = lbl_803E6DB4 + (lbl_803E6DD0 + px + (f32)((s16)i * 48));
                    return 1;
                }
                {
                    f32 pz, px;
                    fn_8005B0A8(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
                    *outX = lbl_803E6DB4 + (lbl_803E6DD0 + px + (f32)((s16)i * 48));
                    return 2;
                }
            }
        }
        return 4;
    } else {
        int ai = a;
        if (dy == -1) {
            f32 pz, px;
            fn_8005B0A8(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
            *outX = lbl_803E6DB4 + (lbl_803E6DD0 + px + (f32)(ai * 48));
            *outZ = lbl_803E6DB4 + (lbl_803E6DD4 + pz + lbl_803E6DBC);
            b += 1;
            limit = 8;
        } else {
            f32 pz, px;
            fn_8005B0A8(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
            *outX = lbl_803E6DB4 + (lbl_803E6DD0 + px + (f32)(ai * 48));
            *outZ = lbl_803E6DB4 + (lbl_803E6DD4 + pz + lbl_803E6DA8);
            b -= 1;
            limit = -1;
        }
        for (i = b; i != limit; i -= dy) {
            if (lbl_803AD2D8[a][i] != 0) {
                if (lbl_803AD2D8[a][i] <= 4) {
                    f32 pz, px;
                    i += dy;
                    fn_8005B0A8(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
                    *outZ = lbl_803E6DB4 + (lbl_803E6DD4 + pz + (f32)((s16)i * 48));
                    return 1;
                }
                {
                    f32 pz, px;
                    fn_8005B0A8(&px, &pz, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14));
                    *outZ = lbl_803E6DB4 + (lbl_803E6DD4 + pz + (f32)((s16)i * 48));
                    return 2;
                }
            }
        }
        return 4;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wclevelcont_init(int obj)
{
    int state = *(int *)(obj + 0xb8);
    u16 flags;

    *(void **)(obj + 0xbc) = (void *)wcpushblock_levelControlTriggerCallback;
    GameBit_Set(0x810, 0);
    memcpy(lbl_803AD2D8, lbl_8032B008, 0x40);
    GameBit_Set(0x811, 0);
    memcpy(lbl_803AD298, lbl_8032B088, 0x40);
    if ((u32)GameBit_Get(0x7fa) != 0) *(u16 *)(state + 0x1a) |= 0x8;
    if ((u32)GameBit_Get(0x7f9) != 0) *(u16 *)(state + 0x1a) |= 0x4;
    if ((u32)GameBit_Get(0x813) != 0) *(u16 *)(state + 0x1a) |= 0x20;
    if ((u32)GameBit_Get(0x812) != 0) *(u16 *)(state + 0x1a) |= 0x10;
    if ((u32)GameBit_Get(0x2a5) != 0) *(u16 *)(state + 0x1a) |= 0x40;
    if ((u32)GameBit_Get(0x205) != 0) *(u16 *)(state + 0x1a) |= 0x80;
    if ((u32)GameBit_Get(0xbcf) != 0) *(u16 *)(state + 0x1a) |= 0x100;
    if ((u32)GameBit_Get(0xcac) != 0) *(u16 *)(state + 0x1a) |= 0x200;
    flags = *(u16 *)(state + 0x1a);
    if (flags & 0x200) {
        *(u8 *)(state + 0xc) = 7;
    } else if ((flags & 0x4) && (flags & 0x8)) {
        *(u8 *)(state + 0xc) = 3;
    }
    ObjGroup_AddObject(obj, 9);
    GameBit_Set(0x226, 1);
    GameBit_Set(0x2a6, 1);
    GameBit_Set(0x206, 1);
    GameBit_Set(0x25f, 1);
    (*(void (**)(int))(*gMapEventInterface + 0x40))(*(s8 *)(obj + 0xac));
    ((WclevelcontFlags *)(state + 0x14))->b40 = GameBit_Get(0xc58);
    ((WclevelcontFlags *)(state + 0x14))->b20 = GameBit_Get(0xc59);
    ((WclevelcontFlags *)(state + 0x14))->b18 = GameBit_Get(0xc5a);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wclevelcont_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wclevelcont_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset
