#include "main/audio/music_api.h"
#include "main/game_timer.h"
#include "main/gamebits.h"
#include "main/obj_group.h"
#include "main/dll/SH/dll_01AE_shlevelcontrol.h"
#include "main/mapEventTypes.h"
#include "main/sky_interface.h"
#include "main/dll/WC/dll_0290_wcpushblock.h"
#include "string.h"
#include "main/lightmap_api.h"
#include "main/dll/WC/dll_028D_wclevelcont.h"
#include "main/render_envfx_api.h"
#include "main/game_object.h"
#include "main/sky_api.h"
#include "main/audio/music_trigger_ids.h"
#include "main/gamebit_ids.h"
#include "main/object_render_legacy.h"
#include "main/object_descriptor.h"
#include "main/frame_timing.h"
#include "main/objseq.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"

#define WCLEVELCONT_OBJGROUP 0x9

/* env effects co-activated once on first update (gated by gamebit 0xe05) alongside the sky preset; opaque distinct roles */
#define WCLEVELCONT_ENVFX_A 0x1fb
#define WCLEVELCONT_ENVFX_B 0x1ff
#define WCLEVELCONT_ENVFX_C 0x1fc
#define WCLEVELCONT_ENVFX_D 0x1fd

#define WCPUSHBLOCK_GAMEBIT_A_SOLVED 0x812
#define WCPUSHBLOCK_GAMEBIT_A_FADE   0x808
#define WCPUSHBLOCK_GAMEBIT_A_COUNT  0x810
#define WCPUSHBLOCK_GAMEBIT_B_SOLVED 0x813
#define WCPUSHBLOCK_GAMEBIT_B_FADE   0x809
#define WCPUSHBLOCK_GAMEBIT_B_COUNT  0x811

#pragma dont_inline on
void fn_802251B4(GameObject* obj, WcLevelControlState* state)
{
    f32 sunTime;

    (*gSkyInterface)->getSunPosition(&sunTime);
    switch (state->mode)
    {
    case WCLEVELCTL_MODE_TREX_INIT:
        gameTimerInit(0x1d, 0x50);
        timerSetToCountUp();
        state->mode = WCLEVELCTL_MODE_TREX_ACTIVE;
        break;
    case WCLEVELCTL_MODE_TREX_ACTIVE:
        if ((u32)mainGetBit(0x2a5) != 0)
        {
            GameObject* player;
            mainSetBits(0x274, 1);
            mainSetBits(0xef1, 0);
            player = (GameObject*)Obj_GetPlayerObject();
            (*gMapEventInterface)->savePoint((int)&player->anim.localPosX, player->anim.rotX, 1, 0);
            state->completionFlags |= WCLEVELCTL_FLAG_TREX;
            state->mode = WCLEVELCTL_MODE_IDLE;
            Sfx_PlayFromObject(0, SFXTRIG_mpick1_b);
            gameTimerStop();
        }
        else if (isGameTimerDisabled() != 0)
        {
            mainSetBits(0x274, 0);
            mainSetBits(0xef1, 0);
            if ((u32)mainGetBit(0x34d) == 0)
            {
                mainSetBits(0x2b1, 0);
                mainSetBits(0x226, 1);
                mainSetBits(0x2a6, 1);
                mainSetBits(0x206, 1);
                mainSetBits(0x25f, 1);
                state->mode = WCLEVELCTL_MODE_IDLE;
            }
        }
        break;
    default:
        if (!(state->completionFlags & WCLEVELCTL_FLAG_TREX) && mainGetBit(0x2b1) != 0)
        {
            mainSetBits(0xef1, 1);
            mainSetBits(0xe6d, 0);
            if ((u32)mainGetBit(0x204) != 0)
            {
                mainSetBits(0x226, 0);
                mainSetBits(0x2a6, 0);
                mainSetBits(0x206, 0);
                mainSetBits(0x25f, 0);
                mainSetBits(0x274, 1);
                state->mode = WCLEVELCTL_MODE_TREX_INIT;
            }
        }
        break;
    }

    if (!(state->completionFlags & WCLEVELCTL_FLAG_TILE_A))
    {
        if ((u8)mainGetBit(WCPUSHBLOCK_GAMEBIT_A_COUNT) == 4)
        {
            mainSetBits(WCPUSHBLOCK_GAMEBIT_A_SOLVED, 1);
            Sfx_PlayFromObject(0, SFXTRIG_mpick1_b);
            state->completionFlags |= WCLEVELCTL_FLAG_TILE_A;
        }
        else if ((u32)mainGetBit(WCPUSHBLOCK_GAMEBIT_A_FADE) != 0)
        {
            if (state->tileAResetTimer <= lbl_803E6DA8)
            {
                mainSetBits(WCPUSHBLOCK_GAMEBIT_A_COUNT, 0);
                memcpy(lbl_803AD2D8, lbl_8032B008.g, 0x40);
                state->tileAResetTimer = gWcPushBlockTileResetTime;
            }
        }
        if (state->tileAResetTimer > lbl_803E6DA8)
        {
            state->tileAResetTimer -= timeDelta;
            if (state->tileAResetTimer <= lbl_803E6DA8)
                mainSetBits(WCPUSHBLOCK_GAMEBIT_A_FADE, 0);
        }
    }

    if (!(state->completionFlags & WCLEVELCTL_FLAG_TILE_B))
    {
        if ((u8)mainGetBit(WCPUSHBLOCK_GAMEBIT_B_COUNT) == 4)
        {
            mainSetBits(WCPUSHBLOCK_GAMEBIT_B_SOLVED, 1);
            Sfx_PlayFromObject(0, SFXTRIG_mpick1_b);
            state->completionFlags |= WCLEVELCTL_FLAG_TILE_B;
        }
        else if ((u32)mainGetBit(WCPUSHBLOCK_GAMEBIT_B_FADE) != 0)
        {
            if (state->tileBResetTimer <= lbl_803E6DA8)
            {
                mainSetBits(WCPUSHBLOCK_GAMEBIT_B_COUNT, 0);
                memcpy(lbl_803AD298, lbl_8032B088.g, 0x40);
                state->tileBResetTimer = gWcPushBlockTileResetTime;
            }
        }
        if (state->tileBResetTimer > lbl_803E6DA8)
        {
            state->tileBResetTimer -= timeDelta;
            if (state->tileBResetTimer <= lbl_803E6DA8)
                mainSetBits(WCPUSHBLOCK_GAMEBIT_B_FADE, 0);
        }
    }

    if (!(state->completionFlags & WCLEVELCTL_FLAG_SWITCHES))
    {
        if ((u32)mainGetBit(0xc58) != 0 && mainGetBit(0xc59) != 0 && mainGetBit(0xc5a) != 0)
        {
            mainSetBits(0x205, 1);
            Sfx_PlayFromObject(0, SFXTRIG_mpick1_b);
            state->completionFlags |= WCLEVELCTL_FLAG_SWITCHES;
        }
        else if (!state->dialogueFlags.b40 && mainGetBit(0xc58) != 0)
        {
            Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
            state->dialogueFlags.b40 = 1;
        }
        else if (!state->dialogueFlags.b20 && mainGetBit(0xc59) != 0)
        {
            Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
            state->dialogueFlags.b20 = 1;
        }
        else if (!state->dialogueFlags.b18 && mainGetBit(0xc5a) != 0)
        {
            Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
            state->dialogueFlags.b18 = 1;
        }
    }

    if (!(state->completionFlags & WCLEVELCTL_FLAG_FINAL))
    {
        if ((u32)mainGetBit(0xbcf) != 0)
        {
            GameObject* player;
            mainSetBits(0xbc8, 0);
            mainSetBits(0x2f0, 1);
            mainSetBits(0xeec, 0);
            mainSetBits(0xbd0, 0);
            player = (GameObject*)Obj_GetPlayerObject();
            (*gMapEventInterface)->savePoint((int)&player->anim.localPosX, player->anim.rotX, 1, 0);
            Sfx_PlayFromObject(0, SFXTRIG_mpick1_b);
            state->completionFlags |= WCLEVELCTL_FLAG_FINAL;
        }
    }

    state->completionFlags &= ~WCLEVELCTL_FLAG_TRIGGERED;
    if ((u32)mainGetBit(GAMEBIT_Tricky_SaidGoodBye) != 0)
    {
        mainSetBits(GAMEBIT_Tricky_Usable, 0);
        mainSetBits(GAMEBIT_IM_DoneRace, 0);
        if ((u32)mainGetBit(GAMEBIT_TrickyTalk) == 0xff)
            mainSetBits(GAMEBIT_TrickyTalk, randomGetRange(6, 7));
    }
}
#pragma dont_inline reset

#pragma dont_inline on
void wcpushblock_updateLevelControlState(GameObject* obj, WcLevelControlState* state)
{
    if (state->completionFlags & WCLEVELCTL_FLAG_EVENT_ACTIVE)
        return;
    state->previousMode = state->mode;
    switch (state->mode)
    {
    case WCLEVELCTL_MODE_PUZZLE_A:
        if (state->completionFlags & WCLEVELCTL_FLAG_TRIGGERED)
        {
            gameTimerInit(0x1d, 0x3c);
            timerSetToCountUp();
            mainSetBits(GAMEBIT_WC_PushBlockTimerActive, 1);
            mainSetBits(0xedd, 1);
        }
        else if ((u32)mainGetBit(0x7f9) != 0)
        {
            state->completionFlags |= WCLEVELCTL_FLAG_PUZZLE_A;
            gameTimerStop();
            if ((u32)mainGetBit(0x7fa) != 0)
                Sfx_PlayFromObject(0, SFXTRIG_mpick1_b);
            else
                Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
            mainSetBits(GAMEBIT_WC_PushBlockTimerActive, 0);
            mainSetBits(0xedd, 0);
            if ((u32)mainGetBit(0x7fa) != 0)
            {
                (*gObjectTriggerInterface)->runSequence(0, obj, -1);
                state->mode = WCLEVELCTL_MODE_SEQUENCE;
            }
            else
            {
                (*gObjectTriggerInterface)->runSequence(1, obj, -1);
                state->mode = WCLEVELCTL_MODE_IDLE;
            }
            state->completionFlags |= WCLEVELCTL_FLAG_EVENT_ACTIVE;
        }
        else if (isGameTimerDisabled() != 0)
        {
            mainSetBits(0x7ef, 0);
            mainSetBits(0x7ed, 0);
            mainSetBits(GAMEBIT_WC_PushBlockTimerActive, 0);
            mainSetBits(0xedd, 0);
            state->mode = WCLEVELCTL_MODE_IDLE;
        }
        break;
    case WCLEVELCTL_MODE_PUZZLE_B:
        if (state->completionFlags & WCLEVELCTL_FLAG_TRIGGERED)
        {
            gameTimerInit(0x1d, 0x50);
            timerSetToCountUp();
            mainSetBits(GAMEBIT_WC_PushBlockTimerActive, 1);
            mainSetBits(0xedc, 1);
        }
        else if ((u32)mainGetBit(0x7fa) != 0)
        {
            state->completionFlags |= WCLEVELCTL_FLAG_PUZZLE_B;
            gameTimerStop();
            if ((u32)mainGetBit(0x7f9) != 0)
                Sfx_PlayFromObject(0, SFXTRIG_mpick1_b);
            else
                Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
            mainSetBits(GAMEBIT_WC_PushBlockTimerActive, 0);
            mainSetBits(0xedc, 0);
            if ((u32)mainGetBit(0x7f9) != 0)
            {
                (*gObjectTriggerInterface)->runSequence(0, obj, -1);
                state->mode = WCLEVELCTL_MODE_SEQUENCE;
            }
            else
            {
                (*gObjectTriggerInterface)->runSequence(1, obj, -1);
                state->mode = WCLEVELCTL_MODE_IDLE;
            }
            state->completionFlags |= WCLEVELCTL_FLAG_EVENT_ACTIVE;
        }
        else if (isGameTimerDisabled() != 0)
        {
            mainSetBits(0x7f0, 0);
            mainSetBits(0x7ee, 0);
            mainSetBits(GAMEBIT_WC_PushBlockTimerActive, 0);
            mainSetBits(0xedc, 0);
            state->mode = WCLEVELCTL_MODE_IDLE;
        }
        break;
    case WCLEVELCTL_MODE_SEQUENCE:
        if ((u32)mainGetBit(0xcac) != 0)
        {
            GameObject* player;
            mainSetBits(0xda9, 0);
            mainSetBits(0xc37, 1);
            player = (GameObject*)Obj_GetPlayerObject();
            (*gMapEventInterface)->savePoint((int)&player->anim.localPosX, player->anim.rotX, 1, 0);
            state->mode = WCLEVELCTL_MODE_DONE;
        }
        break;
    case WCLEVELCTL_MODE_DONE:
        break;
    default:
        if (!(state->completionFlags & WCLEVELCTL_FLAG_PUZZLE_A) && mainGetBit(0x7ed) != 0)
        {
            mainSetBits(0x7ef, 1);
            state->eventTimer = lbl_803E6DB0;
            state->mode = WCLEVELCTL_MODE_PUZZLE_A;
            state->completionFlags |= WCLEVELCTL_FLAG_EVENT_ACTIVE;
            break;
        }
        if (!(state->completionFlags & WCLEVELCTL_FLAG_PUZZLE_B) && mainGetBit(0x7ee) != 0)
        {
            mainSetBits(0x7f0, 1);
            state->eventTimer = lbl_803E6DB0;
            state->mode = WCLEVELCTL_MODE_PUZZLE_B;
            state->completionFlags |= WCLEVELCTL_FLAG_EVENT_ACTIVE;
        }
        break;
    }
    state->completionFlags &= ~WCLEVELCTL_FLAG_TRIGGERED;
}
#pragma dont_inline reset

#pragma dont_inline on
int wclevelcont_seqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    WcLevelControlState* state = obj->extra;
    int i;

    state->completionFlags |= WCLEVELCTL_FLAG_TRIGGERED;
    state->completionFlags &= ~WCLEVELCTL_FLAG_EVENT_ACTIVE;
    if (state->previousMode == WCLEVELCTL_MODE_PUZZLE_A)
    {
        f32 t = state->eventTimer - timeDelta;
        state->eventTimer = t;
        if (t <= lbl_803E6DA8)
        {
            GameObject* player;
            mainSetBits(0x7f7, 1);
            player = (GameObject*)Obj_GetPlayerObject();
            (*gMapEventInterface)->savePoint((int)&player->anim.localPosX, player->anim.rotX, 1, 0);
        }
    }
    else if (state->previousMode == WCLEVELCTL_MODE_PUZZLE_B)
    {
        f32 t = state->eventTimer - timeDelta;
        state->eventTimer = t;
        if (t <= lbl_803E6DA8)
        {
            GameObject* player;
            mainSetBits(0x802, 1);
            player = (GameObject*)Obj_GetPlayerObject();
            (*gMapEventInterface)->savePoint((int)&player->anim.localPosX, player->anim.rotX, 1, 0);
        }
    }
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case 1:
            state->mode = WCLEVELCTL_MODE_TREX_INIT;
            break;
        }
    }
    return 0;
}
#pragma dont_inline reset

#pragma dont_inline on
int wclevelcont_traceMoveB(GameObject* obj, s16 a, s16 b, f32* outX, f32* outZ, int dx, int dy)
{
    int i;
    int limit;
    f32 k6db4;
    f32 kc;

    if (dx != 0)
    {
        int bi = b;
        if (dx == -1)
        {
            f32 pz, px;
            mapGetBlockOriginForPos(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &px, &pz);
            *outX = (k6db4 = lbl_803E6DB4) + (lbl_803E6DB8 + px + (kc = lbl_803E6DBC));
            *outZ = k6db4 + (lbl_803E6DC0 + pz + (f32)(bi * 48));
            a += 1;
            limit = 8;
        }
        else
        {
            f32 pz, px;
            mapGetBlockOriginForPos(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &px, &pz);
            *outX = (k6db4 = lbl_803E6DB4) + (lbl_803E6DB8 + px + (kc = lbl_803E6DA8));
            *outZ = k6db4 + (lbl_803E6DC0 + pz + (f32)(bi * 48));
            a -= 1;
            limit = -1;
        }
        for (i = a; i != limit; i -= dx)
        {
            if (lbl_803AD298[i][b] != 0)
            {
                if (lbl_803AD298[i][b] <= 4)
                {
                    f32 pz, px;
                    i += dx;
                    mapGetBlockOriginForPos(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &px, &pz);
                    *outX = lbl_803E6DB4 + (lbl_803E6DB8 + px + (f32)((s16)i * 48));
                    return 1;
                }
                {
                    f32 pz, px;
                    mapGetBlockOriginForPos(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &px, &pz);
                    *outX = lbl_803E6DB4 + (lbl_803E6DB8 + px + (f32)((s16)i * 48));
                    return 2;
                }
            }
        }
    }
    else
    {
        int ai = a;
        if (dy == -1)
        {
            f32 pz, px;
            mapGetBlockOriginForPos(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &px, &pz);
            *outX = (k6db4 = lbl_803E6DB4) + (lbl_803E6DB8 + px + (f32)(ai * 48));
            *outZ = k6db4 + (lbl_803E6DC0 + pz + (kc = lbl_803E6DBC));
            b += 1;
            limit = 8;
        }
        else
        {
            f32 pz, px;
            mapGetBlockOriginForPos(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &px, &pz);
            *outX = (k6db4 = lbl_803E6DB4) + (lbl_803E6DB8 + px + (f32)(ai * 48));
            *outZ = k6db4 + (lbl_803E6DC0 + pz + (kc = lbl_803E6DA8));
            b -= 1;
            limit = -1;
        }
        for (i = b; i != limit; i -= dy)
        {
            if (lbl_803AD298[a][i] != 0)
            {
                if (lbl_803AD298[a][i] <= 4)
                {
                    f32 pz, px;
                    i += dy;
                    mapGetBlockOriginForPos(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &px, &pz);
                    *outZ = lbl_803E6DB4 + (lbl_803E6DC0 + pz + (f32)((s16)i * 48));
                    return 1;
                }
                {
                    f32 pz, px;
                    mapGetBlockOriginForPos(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &px, &pz);
                    *outZ = lbl_803E6DB4 + (lbl_803E6DC0 + pz + (f32)((s16)i * 48));
                    return 2;
                }
            }
        }
    }
    return 4;
}
#pragma dont_inline reset

void wclevelcont_getSolvedTileXYB(s16 value, s16* outRow, s16* outCol)
{
    int i, j;

    for (i = 0; i < 8; i++)
    {
        for (j = 0; j < 8; j++)
        {
            if (value == lbl_8032B0C8.g[i][j])
            {
                *outRow = i;
                *outCol = j;
                return;
            }
        }
    }
}

void wclevelcont_getInitialTileXYB(s16 value, s16* outRow, s16* outCol)
{
    int i, j;

    for (i = 0; i < 8; i++)
    {
        for (j = 0; j < 8; j++)
        {
            if (value == lbl_8032B088.g[i][j])
            {
                *outRow = i;
                *outCol = j;
                return;
            }
        }
    }
}

int wclevelcont_getTileB(s16 i, s16 j)
{
    if (i < 0 || i > 7 || j < 0 || j > 7)
    {
        return 0;
    }
    return lbl_803AD298[i][j];
}

void wclevelcont_setTileB(int value, s16 i, s16 j)
{
    if (i < 0 || i > 7 || j < 0 || j > 7)
    {
        return;
    }
    lbl_803AD298[i][j] = value;
}

void wclevelcont_worldPosToTileB(GameObject* obj, f32 px, f32 pz, s16* outRow, s16* outCol)
{
    f32 outX, outZ;

    ((void (*)(f32, f32, f32, f32*, f32*))mapGetBlockOriginForPos)(obj->anim.localPosX, obj->anim.localPosY,
                                                                   obj->anim.localPosZ, &outX, &outZ);
    *outRow = (s16)((s16)(px - outX - lbl_803E6DB8) / 48);
    *outCol = (s16)((s16)(pz - outZ - lbl_803E6DC0) / 48);
}

void wclevelcont_tileBToWorldPos(GameObject* obj, s16 col, s16 row, f32* outXp, f32* outZp)
{
    f32 outX, outZ;

    ((void (*)(f32, f32, f32, f32*, f32*))mapGetBlockOriginForPos)(obj->anim.localPosX, obj->anim.localPosY,
                                                                   obj->anim.localPosZ, &outX, &outZ);
    {
        f32 base = lbl_803E6DB4;
        *outXp = base + (lbl_803E6DB8 + outX + (f32)(col * 48));
        *outZp = base + (lbl_803E6DC0 + outZ + (f32)(row * 48));
    }
}

int wclevelcont_traceMoveA(GameObject* obj, s16 a, s16 b, f32* outX, f32* outZ, int dx, int dy)
{
    int i;
    int limit;

    if (dx != 0)
    {
        int bi = b;
        if (dx == -1)
        {
            f32 pz, px;
            ((void (*)(f32, f32, f32, f32*, f32*))mapGetBlockOriginForPos)(obj->anim.localPosX, obj->anim.localPosY,
                                                                           obj->anim.localPosZ, &px, &pz);
            {
                f32 base = lbl_803E6DB4;
                f32 tx = lbl_803E6DD0 + px;
                *outX = base + (tx + lbl_803E6DBC);
                *outZ = (lbl_803E6DD4 + pz + (f32)(bi * 48)) + base;
            }
            a += 1;
            limit = 8;
        }
        else
        {
            f32 pz, px;
            ((void (*)(f32, f32, f32, f32*, f32*))mapGetBlockOriginForPos)(obj->anim.localPosX, obj->anim.localPosY,
                                                                           obj->anim.localPosZ, &px, &pz);
            {
                f32 base = lbl_803E6DB4;
                f32 tx = lbl_803E6DD0 + px;
                *outX = base + (tx + lbl_803E6DA8);
                *outZ = (lbl_803E6DD4 + pz + (f32)(bi * 48)) + base;
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
                    ((void (*)(f32, f32, f32, f32*, f32*))mapGetBlockOriginForPos)(
                        obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &px, &pz);
                    *outX = (lbl_803E6DD0 + px + (f32)((s16)i * 48)) + lbl_803E6DB4;
                    return 1;
                }
                {
                    f32 pz, px;
                    ((void (*)(f32, f32, f32, f32*, f32*))mapGetBlockOriginForPos)(
                        obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &px, &pz);
                    *outX = (lbl_803E6DD0 + px + (f32)((s16)i * 48)) + lbl_803E6DB4;
                    return 2;
                }
            }
        }
    }
    else
    {
        int ai = a;
        if (dy == -1)
        {
            f32 pz, px;
            ((void (*)(f32, f32, f32, f32*, f32*))mapGetBlockOriginForPos)(obj->anim.localPosX, obj->anim.localPosY,
                                                                           obj->anim.localPosZ, &px, &pz);
            {
                f32 base = lbl_803E6DB4;
                f32 tz;
                *outX = (lbl_803E6DD0 + px + (f32)(ai * 48)) + base;
                tz = lbl_803E6DD4 + pz;
                *outZ = base + (tz + lbl_803E6DBC);
            }
            b += 1;
            limit = 8;
        }
        else
        {
            f32 pz, px;
            ((void (*)(f32, f32, f32, f32*, f32*))mapGetBlockOriginForPos)(obj->anim.localPosX, obj->anim.localPosY,
                                                                           obj->anim.localPosZ, &px, &pz);
            {
                f32 base = lbl_803E6DB4;
                f32 tz;
                *outX = (lbl_803E6DD0 + px + (f32)(ai * 48)) + base;
                tz = lbl_803E6DD4 + pz;
                *outZ = base + (tz + lbl_803E6DA8);
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
                    ((void (*)(f32, f32, f32, f32*, f32*))mapGetBlockOriginForPos)(
                        obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &px, &pz);
                    *outZ = (lbl_803E6DD4 + pz + (f32)((s16)i * 48)) + lbl_803E6DB4;
                    return 1;
                }
                {
                    f32 pz, px;
                    ((void (*)(f32, f32, f32, f32*, f32*))mapGetBlockOriginForPos)(
                        obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &px, &pz);
                    *outZ = (lbl_803E6DD4 + pz + (f32)((s16)i * 48)) + lbl_803E6DB4;
                    return 2;
                }
            }
        }
    }
    return 4;
}

void wclevelcont_getSolvedTileXYA(s16 value, s16* outRow, s16* outCol)
{
    int i, j;

    for (i = 0; i < 8; i++)
    {
        for (j = 0; j < 8; j++)
        {
            if (value == lbl_8032B048.g[i][j])
            {
                *outRow = i;
                *outCol = j;
                return;
            }
        }
    }
}

void wclevelcont_getInitialTileXYA(s16 value, s16* outRow, s16* outCol)
{
    int i, j;

    for (i = 0; i < 8; i++)
    {
        for (j = 0; j < 8; j++)
        {
            if (value == lbl_8032B008.g[i][j])
            {
                *outRow = i;
                *outCol = j;
                return;
            }
        }
    }
}

int wclevelcont_getTileA(s16 i, s16 j)
{
    if (i < 0 || i > 7 || j < 0 || j > 7)
    {
        return 0;
    }
    return lbl_803AD2D8[i][j];
}

void wclevelcont_setTileA(int value, s16 i, s16 j)
{
    if (i < 0 || i > 7 || j < 0 || j > 7)
    {
        return;
    }
    lbl_803AD2D8[i][j] = value;
}

void wclevelcont_worldPosToTileA(GameObject* obj, f32 px, f32 pz, s16* outRow, s16* outCol)
{
    f32 outX, outZ;

    ((void (*)(f32, f32, f32, f32*, f32*))mapGetBlockOriginForPos)(obj->anim.localPosX, obj->anim.localPosY,
                                                                   obj->anim.localPosZ, &outX, &outZ);
    *outRow = (s16)((s16)(px - outX - lbl_803E6DD0) / 48);
    *outCol = (s16)((s16)(pz - outZ - lbl_803E6DD4) / 48);
}

void wclevelcont_tileAToWorldPos(GameObject* obj, s16 col, s16 row, f32* outXp, f32* outZp)
{
    f32 outX, outZ;

    ((void (*)(f32, f32, f32, f32*, f32*))mapGetBlockOriginForPos)(obj->anim.localPosX, obj->anim.localPosY,
                                                                   obj->anim.localPosZ, &outX, &outZ);
    {
        f32 base = lbl_803E6DB4;
        *outXp = base + (lbl_803E6DD0 + outX + (f32)(col * 48));
        *outZp = base + (lbl_803E6DD4 + outZ + (f32)(row * 48));
    }
}

int wclevelcont_getExtraSize(void)
{
    return 0x1c;
}

int wclevelcont_getObjectTypeId(void)
{
    return 0;
}

void wclevelcont_free(GameObject* obj)
{
    WcLevelControlState* state = obj->extra;
    u8 mode;

    ObjGroup_RemoveObject((int)obj, WCLEVELCONT_OBJGROUP);
    mode = state->mode;
    if (mode == 1)
    {
        mainSetBits(0x7ef, 0);
        mainSetBits(0x7ed, 0);
        mainSetBits(GAMEBIT_WC_PushBlockTimerActive, 0);
        mainSetBits(0xedd, 0);
    }
    else if (mode == 2)
    {
        mainSetBits(0x7f0, 0);
        mainSetBits(0x7ee, 0);
        mainSetBits(GAMEBIT_WC_PushBlockTimerActive, 0);
        mainSetBits(0xedc, 0);
    }
    gameTimerStop();
}

void wclevelcont_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes((int)obj, p2, p3, p4, p5, lbl_803E6DD8);
    }
}

void wclevelcont_hitDetect(void)
{
}

#pragma opt_common_subs off
void wclevelcont_syncProgressBits(WcLevelControlState* state)
{
    int flag;

    if ((*gSkyInterface)->getSunPosition(0))
    {
        if (state->thorntailMusicId != 0x2d)
        {
            state->thorntailMusicId = 0x2d;
            Music_Trigger(MUSICTRIG_PU1_Mysterious, 1);
        }
        if (state->ambientMusicId != -1)
        {
            state->ambientMusicId = 0xffff;
            Music_Trigger(MUSICTRIG_fox_arwing, 0);
        }
    }
    else
    {
        if (state->thorntailMusicId != 0x39)
        {
            state->thorntailMusicId = 0x39;
            Music_Trigger(MUSICTRIG_nightjungle, 1);
        }
        if (state->ambientMusicId != 0x22)
        {
            state->ambientMusicId = 0x22;
            Music_Trigger(MUSICTRIG_fox_arwing, 1);
        }
    }
    SCGameBitLatch_Update(&state->gameBitLatch, 0x8, -1, -1, 0xba6, 0xd2);
    SCGameBitLatch_Update(&state->gameBitLatch, 0x4, -1, -1, 0xcce, 0x36);
    SCGameBitLatch_Update(&state->gameBitLatch, 0x10, -1, -1, 0xcd0, 0xd4);
    SCGameBitLatch_Update(&state->gameBitLatch, 0x40, -1, -1, 0xcbb, 0xc4);
    flag = 0;
    if ((u32)mainGetBit(GAMEBIT_WC_PushBlockTimerActive) == 0 &&
        ((u32)mainGetBit(0xda9) != 0 || gameTimerIsRunning() != 0))
    {
        flag = 1;
    }
    mainSetBits(0xf31, flag);
    SCGameBitLatch_Update(&state->gameBitLatch, 0x80, -1, -1, 0xf31, 0xaf);
}
#pragma opt_common_subs reset

#pragma dont_inline on
void wclevelcont_update(GameObject* obj)
{
    WcLevelControlState* state = obj->extra;
    f32 sunTime;

    if (obj->unkF4 == 0)
    {
        if ((u32)mainGetBit(GAMEBIT_WC_MagicCaveRelated0E05) == 0)
        {
            getEnvfxActImmediatelyVoid((int)obj, (int)obj, WCLEVELCONT_ENVFX_A, 0);
            getEnvfxActImmediatelyVoid((int)obj, (int)obj, WCLEVELCONT_ENVFX_B, 0);
            getEnvfxActImmediatelyVoid((int)obj, (int)obj, WCLEVELCONT_ENVFX_C, 0);
            getEnvfxActImmediatelyVoid((int)obj, (int)obj, WCLEVELCONT_ENVFX_D, 0);
            skyFn_80088e54(0, lbl_803E6DA8);
            mainSetBits(GAMEBIT_WC_MagicCaveRelated0E05, 1);
        }
        obj->unkF4 = 1;
    }
    switch ((*gMapEventInterface)->getMapAct(obj->anim.mapEventSlot))
    {
    case 1:
    default:
        wcpushblock_updateLevelControlState(obj, state);
        break;
    case 2:
        fn_802251B4(obj, state);
        break;
    }
    wclevelcont_syncProgressBits(state);
    if ((*gSkyInterface)->getSunPosition(&sunTime))
    {
        mainSetBits(0x7f3, 1);
        mainSetBits(0x7f1, 0);
    }
    else
    {
        mainSetBits(0x7f3, 0);
        mainSetBits(0x7f1, 1);
    }
}
#pragma dont_inline off

void wclevelcont_init(GameObject* obj)
{
    WcLevelControlState* state = obj->extra;
    u16 flags;

    obj->animEventCallback = wclevelcont_seqFn;
    mainSetBits(0x810, 0);
    memcpy(lbl_803AD2D8, lbl_8032B008.g, 0x40);
    mainSetBits(0x811, 0);
    memcpy(lbl_803AD298, lbl_8032B088.g, 0x40);
    if ((u32)mainGetBit(0x7fa) != 0)
        state->completionFlags |= WCLEVELCTL_FLAG_PUZZLE_B;
    if ((u32)mainGetBit(0x7f9) != 0)
        state->completionFlags |= WCLEVELCTL_FLAG_PUZZLE_A;
    if ((u32)mainGetBit(0x813) != 0)
        state->completionFlags |= WCLEVELCTL_FLAG_TILE_B;
    if ((u32)mainGetBit(0x812) != 0)
        state->completionFlags |= WCLEVELCTL_FLAG_TILE_A;
    if ((u32)mainGetBit(0x2a5) != 0)
        state->completionFlags |= WCLEVELCTL_FLAG_TREX;
    if ((u32)mainGetBit(0x205) != 0)
        state->completionFlags |= WCLEVELCTL_FLAG_SWITCHES;
    if ((u32)mainGetBit(0xbcf) != 0)
        state->completionFlags |= WCLEVELCTL_FLAG_FINAL;
    if ((u32)mainGetBit(0xcac) != 0)
        state->completionFlags |= WCLEVELCTL_FLAG_EXTRA;
    flags = state->completionFlags;
    if (flags & 0x200)
    {
        state->mode = 7;
    }
    else if ((flags & 0x4) && (flags & 0x8))
    {
        state->mode = 3;
    }
    ObjGroup_AddObject((int)obj, WCLEVELCONT_OBJGROUP);
    mainSetBits(0x226, 1);
    mainSetBits(0x2a6, 1);
    mainSetBits(0x206, 1);
    mainSetBits(0x25f, 1);
    (*gMapEventInterface)->getMapAct(obj->anim.mapEventSlot);
    state->dialogueFlags.b40 = mainGetBit(0xc58);
    state->dialogueFlags.b20 = mainGetBit(0xc59);
    state->dialogueFlags.b18 = mainGetBit(0xc5a);
}

void wclevelcont_release(void)
{
}

void wclevelcont_initialise(void)
{
}

ObjectDescriptor24 gWCLevelContObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_24_SLOTS,
    (ObjectDescriptorCallback)wclevelcont_initialise,
    (ObjectDescriptorCallback)wclevelcont_release,
    0,
    (ObjectDescriptorCallback)wclevelcont_init,
    (ObjectDescriptorCallback)wclevelcont_update,
    (ObjectDescriptorCallback)wclevelcont_hitDetect,
    (ObjectDescriptorCallback)wclevelcont_render,
    (ObjectDescriptorCallback)wclevelcont_free,
    (ObjectDescriptorCallback)wclevelcont_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)wclevelcont_getExtraSize,
    (ObjectDescriptorCallback)wclevelcont_tileAToWorldPos,
    (ObjectDescriptorCallback)wclevelcont_worldPosToTileA,
    (ObjectDescriptorCallback)wclevelcont_setTileA,
    (ObjectDescriptorCallback)wclevelcont_getTileA,
    (ObjectDescriptorCallback)wclevelcont_getInitialTileXYA,
    (ObjectDescriptorCallback)wclevelcont_getSolvedTileXYA,
    (ObjectDescriptorCallback)wclevelcont_traceMoveA,
    (ObjectDescriptorCallback)wclevelcont_tileBToWorldPos,
    (ObjectDescriptorCallback)wclevelcont_worldPosToTileB,
    (ObjectDescriptorCallback)wclevelcont_setTileB,
    (ObjectDescriptorCallback)wclevelcont_getTileB,
    (ObjectDescriptorCallback)wclevelcont_getInitialTileXYB,
    (ObjectDescriptorCallback)wclevelcont_getSolvedTileXYB,
    (ObjectDescriptorCallback)wclevelcont_traceMoveB,
};
