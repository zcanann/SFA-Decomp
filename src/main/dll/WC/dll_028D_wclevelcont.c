/*
 * wclevelcont (DLL 0x28D) - the master level controller for the Walled
 * City (WC) push-block puzzle. One instance owns the level's global
 * progress: it drives the day/night sky and music state, latches a set of
 * game bits through a SCGameBitLatch, and dispatches the tile puzzle by the
 * object's map-event act (act 1 -> wcpushblock_updateLevelControlState,
 * act 2 -> fn_802251B4). state->mode is seeded at init from completion
 * game bits.
 *
 * The puzzle runs on two 8x8 u8 grids (lbl_803AD2D8 / lbl_803AD298), copied
 * at init from the ROM templates lbl_8032B008 / lbl_8032B088. The
 * func0E/func0F/func15/func16 helpers scan an 8x8 ROM table for a value and
 * return its (row,col); render2/func14 read a working-grid cell with bounds
 * checks and modelMtxFn/func13 write one; func0B/func12 map a world XZ to a
 * cell and setScale/func11 map a cell back to world XZ (via
 * mapGetBlockOriginForPos); func10 ray-walks a row or column from a start
 * cell in a +/-1 step direction, returning a hit classification (1/2/4) and
 * the world position of the blocking cell. The func* names are the retail
 * symbol names, not semantic.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

/* find `value` in ROM grid lbl_8032B0C8 -> (row, col) */
void wclevelcont_func16(s16 value, s16* outRow, s16* outCol)
{
    int i, j;

    for (i = 0; i < 8; i++)
    {
        for (j = 0; j < 8; j++)
        {
            if (value == lbl_8032B0C8[i][j])
            {
                *outRow = (s16)i;
                *outCol = (s16)j;
                return;
            }
        }
    }
}

/* find `value` in ROM grid lbl_8032B088 -> (row, col) */
void wclevelcont_func15(s16 value, s16* outRow, s16* outCol)
{
    int i, j;

    for (i = 0; i < 8; i++)
    {
        for (j = 0; j < 8; j++)
        {
            if (value == lbl_8032B088[i][j])
            {
                *outRow = (s16)i;
                *outCol = (s16)j;
                return;
            }
        }
    }
}

/* read working grid lbl_803AD298 cell, 0 when (i,j) out of range */
int wclevelcont_func14(s16 i, s16 j)
{
    if (i < 0 || i > 7 || j < 0 || j > 7)
    {
        return 0;
    }
    return lbl_803AD298[i][j];
}

/* write working grid lbl_803AD298 cell, bounds-checked */
void wclevelcont_func13(int value, s16 i, s16 j)
{
    if (i < 0 || i > 7 || j < 0 || j > 7)
    {
        return;
    }
    lbl_803AD298[i][j] = (u8)value;
}

/* world XZ -> grid (row, col) for the lbl_803AD298 grid */
void wclevelcont_func12(int obj, f32 px, f32 pz, s16* outRow, s16* outCol)
{
    f32 outX, outZ;

    ((void (*)(f32, f32, f32, f32*, f32*))mapGetBlockOriginForPos)(
        ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
        ((GameObject*)obj)->anim.localPosZ, &outX, &outZ);
    *outRow = (s16)((s16)(px - outX - lbl_803E6DB8) / 48);
    *outCol = (s16)((s16)(pz - outZ - lbl_803E6DC0) / 48);
}

/* grid (col, row) -> world XZ for the lbl_803AD298 grid */
void wclevelcont_func11(int obj, s16 col, s16 row, f32* outXp, f32* outZp)
{
    f32 outX, outZ;
    f32 base;

    ((void (*)(f32, f32, f32, f32*, f32*))mapGetBlockOriginForPos)(
        ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
        ((GameObject*)obj)->anim.localPosZ, &outX, &outZ);
    base = lbl_803E6DB4;
    *outXp = base + (lbl_803E6DB8 + outX + (f32)(col * 48));
    *outZp = base + (lbl_803E6DC0 + outZ + (f32)(row * 48));
}

/* find `value` in ROM grid lbl_8032B048 -> (row, col) */
void wclevelcont_func0F(s16 value, s16* outRow, s16* outCol)
{
    int i, j;

    for (i = 0; i < 8; i++)
    {
        for (j = 0; j < 8; j++)
        {
            if (value == lbl_8032B048[i][j])
            {
                *outRow = (s16)i;
                *outCol = (s16)j;
                return;
            }
        }
    }
}

/* find `value` in ROM grid lbl_8032B008 -> (row, col) */
void wclevelcont_func0E(s16 value, s16* outRow, s16* outCol)
{
    int i, j;

    for (i = 0; i < 8; i++)
    {
        for (j = 0; j < 8; j++)
        {
            if (value == lbl_8032B008[i][j])
            {
                *outRow = (s16)i;
                *outCol = (s16)j;
                return;
            }
        }
    }
}

/* read working grid lbl_803AD2D8 cell, 0 when (i,j) out of range */
int wclevelcont_render2(s16 i, s16 j)
{
    if (i < 0 || i > 7 || j < 0 || j > 7)
    {
        return 0;
    }
    return lbl_803AD2D8[i][j];
}

/* write working grid lbl_803AD2D8 cell, bounds-checked */
void wclevelcont_modelMtxFn(int value, s16 i, s16 j)
{
    if (i < 0 || i > 7 || j < 0 || j > 7)
    {
        return;
    }
    lbl_803AD2D8[i][j] = (u8)value;
}

/* world XZ -> grid (row, col) for the lbl_803AD2D8 grid */
void wclevelcont_func0B(int obj, f32 px, f32 pz, s16* outRow, s16* outCol)
{
    f32 outX, outZ;

    ((void (*)(f32, f32, f32, f32*, f32*))mapGetBlockOriginForPos)(
        ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
        ((GameObject*)obj)->anim.localPosZ, &outX, &outZ);
    *outRow = (s16)((s16)(px - outX - lbl_803E6DD0) / 48);
    *outCol = (s16)((s16)(pz - outZ - lbl_803E6DD4) / 48);
}

/* grid (col, row) -> world XZ for the lbl_803AD2D8 grid */
void wclevelcont_setScale(int obj, s16 col, s16 row, f32* outXp, f32* outZp)
{
    f32 outX, outZ;
    f32 base;

    ((void (*)(f32, f32, f32, f32*, f32*))mapGetBlockOriginForPos)(
        ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
        ((GameObject*)obj)->anim.localPosZ, &outX, &outZ);
    base = lbl_803E6DB4;
    *outXp = base + (lbl_803E6DD0 + outX + (f32)(col * 48));
    *outZp = base + (lbl_803E6DD4 + outZ + (f32)(row * 48));
}

int wclevelcont_getExtraSize(void) { return 0x1c; }

int wclevelcont_getObjectTypeId(void) { return 0; }

void wclevelcont_free(int obj)
{
    WcLevelControlState* state = ((GameObject*)obj)->extra;
    u8 mode;

    ObjGroup_RemoveObject(obj, 9);
    mode = state->mode;
    if (mode == 1)
    {
        GameBit_Set(0x7ef, 0);
        GameBit_Set(0x7ed, 0);
        GameBit_Set(0xba6, 0);
        GameBit_Set(0xedd, 0);
    }
    else if (mode == 2)
    {
        GameBit_Set(0x7f0, 0);
        GameBit_Set(0x7ee, 0);
        GameBit_Set(0xba6, 0);
        GameBit_Set(0xedc, 0);
    }
    gameTimerStop();
}

void wclevelcont_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6DD8);
    }
}

void wclevelcont_hitDetect(void)
{
}

#pragma opt_common_subs off
void wclevelcont_syncProgressBits(int stateArg)
{
    WcLevelControlState* state = (WcLevelControlState*)stateArg;
    int flag;

    if ((*gSkyInterface)->getSunPosition(0))
    {
        if (state->thorntailMusicId != 0x2d)
        {
            state->thorntailMusicId = 0x2d;
            Music_Trigger(0x2d, 1);
        }
        if (state->ambientMusicId != -1)
        {
            state->ambientMusicId = 0xffff;
            Music_Trigger(0x22, 0);
        }
    }
    else
    {
        if (state->thorntailMusicId != 0x39)
        {
            state->thorntailMusicId = 0x39;
            Music_Trigger(0x39, 1);
        }
        if (state->ambientMusicId != 0x22)
        {
            state->ambientMusicId = 0x22;
            Music_Trigger(0x22, 1);
        }
    }
    SCGameBitLatch_Update((int)&state->gameBitLatch, 0x8, -1, -1, 0xba6, 0xd2);
    SCGameBitLatch_Update((int)&state->gameBitLatch, 0x4, -1, -1, 0xcce, 0x36);
    SCGameBitLatch_Update((int)&state->gameBitLatch, 0x10, -1, -1, 0xcd0, 0xd4);
    SCGameBitLatch_Update((int)&state->gameBitLatch, 0x40, -1, -1, 0xcbb, 0xc4);
    flag = 0;
    if ((u32)GameBit_Get(0xba6) == 0 && ((u32)GameBit_Get(0xda9) != 0 || gameTimerIsRunning() != 0))
    {
        flag = 1;
    }
    GameBit_Set(0xf31, flag);
    SCGameBitLatch_Update((int)&state->gameBitLatch, 0x80, -1, -1, 0xf31, 0xaf);
}
#pragma opt_common_subs reset

void wclevelcont_update(int obj)
{
    WcLevelControlState* state = ((GameObject*)obj)->extra;
    f32 sunTime;

    if (((GameObject*)obj)->unkF4 == 0)
    {
        if ((u32)GameBit_Get(0xe05) == 0)
        {
            getEnvfxActImmediately(obj, obj, 0x1fb, 0);
            getEnvfxActImmediately(obj, obj, 0x1ff, 0);
            getEnvfxActImmediately(obj, obj, 0x1fc, 0);
            getEnvfxActImmediately(obj, obj, 0x1fd, 0);
            skyFn_80088e54(0, lbl_803E6DA8);
            GameBit_Set(0xe05, 1);
        }
        ((GameObject*)obj)->unkF4 = 1;
    }
    switch ((*gMapEventInterface)->getMapAct(((GameObject*)obj)->anim.mapEventSlot))
    {
    case 1:
    default:
        wcpushblock_updateLevelControlState(obj, state);
        break;
    case 2:
        fn_802251B4(obj, state);
        break;
    }
    wclevelcont_syncProgressBits((int)state);
    if ((*gSkyInterface)->getSunPosition(&sunTime))
    {
        GameBit_Set(0x7f3, 1);
        GameBit_Set(0x7f1, 0);
    }
    else
    {
        GameBit_Set(0x7f3, 0);
        GameBit_Set(0x7f1, 1);
    }
}

#pragma scheduling off
int wclevelcont_func10(int obj, s16 a, s16 b, f32* outX, f32* outZ, int dx, int dy)
{
    int i;
    int limit;

    if (dx != 0)
    {
        int bi = b;
        if (dx == -1)
        {
            f32 pz, px;
            ((void (*)(f32*, f32*, f32, f32, f32))mapGetBlockOriginForPos)(&px, &pz, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                    ((GameObject*)obj)->anim.localPosZ);
            {
                f32 base = lbl_803E6DB4;
                f32 tx = lbl_803E6DD0 + px;
                tx = tx + lbl_803E6DBC;
                *outX = base + tx;
                *outZ = base + (lbl_803E6DD4 + pz + (f32)(bi * 48));
            }
            a += 1;
            limit = 8;
        }
        else
        {
            f32 pz, px;
            ((void (*)(f32*, f32*, f32, f32, f32))mapGetBlockOriginForPos)(&px, &pz, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                    ((GameObject*)obj)->anim.localPosZ);
            {
                f32 base = lbl_803E6DB4;
                *outX = base + (lbl_803E6DD0 + px + lbl_803E6DA8);
                *outZ = base + (lbl_803E6DD4 + pz + (f32)(bi * 48));
            }
            a -= 1;
            limit = -1;
        }
        for (i = a; i != limit; i -= dx)
        {
            if (lbl_803AD2D8[i][b] != 0)
            {
                if (lbl_803AD2D8[i][b] <= 4)
                {
                    f32 pz, px;
                    i += dx;
                    ((void (*)(f32*, f32*, f32, f32, f32))mapGetBlockOriginForPos)(&px, &pz, ((GameObject*)obj)->anim.localPosX,
                                            ((GameObject*)obj)->anim.localPosY, ((GameObject*)obj)->anim.localPosZ);
                    *outX = lbl_803E6DB4 + (lbl_803E6DD0 + px + (f32)((s16)i * 48));
                    return 1;
                }
                {
                    f32 pz, px;
                    ((void (*)(f32*, f32*, f32, f32, f32))mapGetBlockOriginForPos)(&px, &pz, ((GameObject*)obj)->anim.localPosX,
                                            ((GameObject*)obj)->anim.localPosY, ((GameObject*)obj)->anim.localPosZ);
                    *outX = lbl_803E6DB4 + (lbl_803E6DD0 + px + (f32)((s16)i * 48));
                    return 2;
                }
            }
        }
        return 4;
    }
    else
    {
        int ai = a;
        if (dy == -1)
        {
            f32 pz, px;
            ((void (*)(f32*, f32*, f32, f32, f32))mapGetBlockOriginForPos)(&px, &pz, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                    ((GameObject*)obj)->anim.localPosZ);
            {
                f32 base = lbl_803E6DB4;
                f32 tz;
                *outX = base + (lbl_803E6DD0 + px + (f32)(ai * 48));
                tz = lbl_803E6DD4 + pz;
                tz = tz + lbl_803E6DBC;
                *outZ = base + tz;
            }
            b += 1;
            limit = 8;
        }
        else
        {
            f32 pz, px;
            ((void (*)(f32*, f32*, f32, f32, f32))mapGetBlockOriginForPos)(&px, &pz, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                    ((GameObject*)obj)->anim.localPosZ);
            {
                f32 base = lbl_803E6DB4;
                f32 tz;
                *outX = base + (lbl_803E6DD0 + px + (f32)(ai * 48));
                tz = lbl_803E6DD4 + pz;
                tz = tz + lbl_803E6DA8;
                *outZ = base + tz;
            }
            b -= 1;
            limit = -1;
        }
        for (i = b; i != limit; i -= dy)
        {
            if (lbl_803AD2D8[a][i] != 0)
            {
                if (lbl_803AD2D8[a][i] <= 4)
                {
                    f32 pz, px;
                    i += dy;
                    ((void (*)(f32*, f32*, f32, f32, f32))mapGetBlockOriginForPos)(&px, &pz, ((GameObject*)obj)->anim.localPosX,
                                            ((GameObject*)obj)->anim.localPosY, ((GameObject*)obj)->anim.localPosZ);
                    *outZ = lbl_803E6DB4 + (lbl_803E6DD4 + pz + (f32)((s16)i * 48));
                    return 1;
                }
                {
                    f32 pz, px;
                    ((void (*)(f32*, f32*, f32, f32, f32))mapGetBlockOriginForPos)(&px, &pz, ((GameObject*)obj)->anim.localPosX,
                                            ((GameObject*)obj)->anim.localPosY, ((GameObject*)obj)->anim.localPosZ);
                    *outZ = lbl_803E6DB4 + (lbl_803E6DD4 + pz + (f32)((s16)i * 48));
                    return 2;
                }
            }
        }
        return 4;
    }
}

#pragma scheduling off
void wclevelcont_init(int obj)
{
    WcLevelControlState* state = ((GameObject*)obj)->extra;
    u16 flags;

    ((GameObject*)obj)->animEventCallback = (void*)wcpushblock_levelControlTriggerCallback;
    GameBit_Set(0x810, 0);
    memcpy(lbl_803AD2D8, lbl_8032B008, 0x40);
    GameBit_Set(0x811, 0);
    memcpy(lbl_803AD298, lbl_8032B088, 0x40);
    if ((u32)GameBit_Get(0x7fa) != 0) state->completionFlags |= 0x8;
    if ((u32)GameBit_Get(0x7f9) != 0) state->completionFlags |= 0x4;
    if ((u32)GameBit_Get(0x813) != 0) state->completionFlags |= 0x20;
    if ((u32)GameBit_Get(0x812) != 0) state->completionFlags |= 0x10;
    if ((u32)GameBit_Get(0x2a5) != 0) state->completionFlags |= 0x40;
    if ((u32)GameBit_Get(0x205) != 0) state->completionFlags |= 0x80;
    if ((u32)GameBit_Get(0xbcf) != 0) state->completionFlags |= 0x100;
    if ((u32)GameBit_Get(0xcac) != 0) state->completionFlags |= 0x200;
    flags = state->completionFlags;
    if (flags & 0x200)
    {
        state->mode = 7;
    }
    else if ((flags & 0x4) && (flags & 0x8))
    {
        state->mode = 3;
    }
    ObjGroup_AddObject(obj, 9);
    GameBit_Set(0x226, 1);
    GameBit_Set(0x2a6, 1);
    GameBit_Set(0x206, 1);
    GameBit_Set(0x25f, 1);
    (*gMapEventInterface)->getMapAct(((GameObject*)obj)->anim.mapEventSlot);
    state->dialogueFlags.b40 = GameBit_Get(0xc58);
    state->dialogueFlags.b20 = GameBit_Get(0xc59);
    state->dialogueFlags.b18 = GameBit_Get(0xc5a);
}
#pragma scheduling reset

void wclevelcont_release(void)
{
}

void wclevelcont_initialise(void)
{
}
