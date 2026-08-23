/* WCLevelCont (DLL 653) */
#include "main/audio/music_api.h"
#include "main/game_timer.h"
#include "main/gamebits.h"
#include "main/lightmap_api.h"
#include "main/mapEventTypes.h"
#include "main/objtype.h"
#include "main/sky_interface.h"
#include "main/dll/WC/dll_0290_wcpushblock.h"
#include "main/dll/WC/dll_028D_wclevelcont.h"
#include "main/render_envfx_api.h"
#include "main/sky_api.h"
#include "main/audio/music_trigger_ids.h"
#include "main/gamebit_ids.h"
#include "main/object_render.h"
#include "dlls/object_descriptor.h"
#include "main/frame_timing.h"
#include "main/objseq.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/sfx_play_legacy_api.h"
#include "main/vecmath.h"
#include "string.h"
#include "sys/objects.h"
#include "main/game_timer_control_api.h"

#define WCLEVELCONT_OBJGROUP 0x9

/* env effects co-activated once on first update (gated by gamebit 0xe05) alongside the sky preset; opaque distinct roles */
#define WCLEVELCONT_ENVFX_A 0x1fb
#define WCLEVELCONT_ENVFX_B 0x1ff
#define WCLEVELCONT_ENVFX_C 0x1fc
#define WCLEVELCONT_ENVFX_D 0x1fd

u8 gWcTileGridB[8][8];

const f32 gWcLevelContZero[1] = {0.0f};
const f32 gWcPushBlockTileResetTime[1] = {20.0f};

void wclevelcont_updateAct2State(GameObject* obj, WcLevelControlState* state)
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
        if (mainGetBit(0x2a5) != 0)
        {
            GameObject* player;
            mainSetBits(0x274, 1);
            mainSetBits(0xef1, 0);
            player = (GameObject*)Obj_GetPlayerObject();
            (*gMapEventInterface)->savePoint(&player->anim.localPosX, player->anim.rotX, 1, 0);
            state->completionFlags |= WCLEVELCTL_FLAG_TREX;
            state->mode = WCLEVELCTL_MODE_IDLE;
            Sfx_PlayFromObject(0, SFXTRIG_mpick1_b);
            gameTimerStop();
        }
        else if (isGameTimerDisabled() != 0)
        {
            mainSetBits(0x274, 0);
            mainSetBits(0xef1, 0);
            if (mainGetBit(0x34d) == 0)
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
            if (mainGetBit(0x204) != 0)
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
        else if (mainGetBit(WCPUSHBLOCK_GAMEBIT_A_FADE) != 0)
        {
            if (state->tileAResetTimer <= gWcLevelContZero[0])
            {
                mainSetBits(WCPUSHBLOCK_GAMEBIT_A_COUNT, 0);
                memcpy(gWcTileGridA, gWcTileGridAInitial.g, 0x40);
                state->tileAResetTimer = gWcPushBlockTileResetTime[0];
            }
        }
        if (state->tileAResetTimer > gWcLevelContZero[0])
        {
            state->tileAResetTimer -= timeDelta;
            if (state->tileAResetTimer <= gWcLevelContZero[0])
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
        else if (mainGetBit(WCPUSHBLOCK_GAMEBIT_B_FADE) != 0)
        {
            if (state->tileBResetTimer <= gWcLevelContZero[0])
            {
                mainSetBits(WCPUSHBLOCK_GAMEBIT_B_COUNT, 0);
                memcpy(gWcTileGridB, gWcTileGridBInitial.g, 0x40);
                state->tileBResetTimer = gWcPushBlockTileResetTime[0];
            }
        }
        if (state->tileBResetTimer > gWcLevelContZero[0])
        {
            state->tileBResetTimer -= timeDelta;
            if (state->tileBResetTimer <= gWcLevelContZero[0])
                mainSetBits(WCPUSHBLOCK_GAMEBIT_B_FADE, 0);
        }
    }

    if (!(state->completionFlags & WCLEVELCTL_FLAG_SWITCHES))
    {
        if (mainGetBit(0xc58) != 0 && mainGetBit(0xc59) != 0 && mainGetBit(0xc5a) != 0)
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
        if (mainGetBit(0xbcf) != 0)
        {
            GameObject* player;
            mainSetBits(0xbc8, 0);
            mainSetBits(0x2f0, 1);
            mainSetBits(0xeec, 0);
            mainSetBits(0xbd0, 0);
            player = (GameObject*)Obj_GetPlayerObject();
            (*gMapEventInterface)->savePoint(&player->anim.localPosX, player->anim.rotX, 1, 0);
            Sfx_PlayFromObject(0, SFXTRIG_mpick1_b);
            state->completionFlags |= WCLEVELCTL_FLAG_FINAL;
        }
    }

    state->completionFlags &= ~WCLEVELCTL_FLAG_TRIGGERED;
    if (mainGetBit(GAMEBIT_Tricky_SaidGoodBye) != 0)
    {
        mainSetBits(GAMEBIT_Tricky_Unlocked_Sidekick_Commands, 0);
        mainSetBits(GAMEBIT_TrickyWarpEnabled, 0);
        if (mainGetBit(GAMEBIT_TrickyTalk) == 0xff)
            mainSetBits(GAMEBIT_TrickyTalk, randomGetRange(6, 7));
    }
}

u8 gWcTileGridA[9][8];

void wclevelcont_updateAct1State(GameObject* obj, WcLevelControlState* state)
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
        else if (mainGetBit(0x7f9) != 0)
        {
            state->completionFlags |= WCLEVELCTL_FLAG_PUZZLE_A;
            gameTimerStop();
            if (mainGetBit(0x7fa) != 0)
                Sfx_PlayFromObject(0, SFXTRIG_mpick1_b);
            else
                Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
            mainSetBits(GAMEBIT_WC_PushBlockTimerActive, 0);
            mainSetBits(0xedd, 0);
            if (mainGetBit(0x7fa) != 0)
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
        else if (mainGetBit(0x7fa) != 0)
        {
            state->completionFlags |= WCLEVELCTL_FLAG_PUZZLE_B;
            gameTimerStop();
            if (mainGetBit(0x7f9) != 0)
                Sfx_PlayFromObject(0, SFXTRIG_mpick1_b);
            else
                Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
            mainSetBits(GAMEBIT_WC_PushBlockTimerActive, 0);
            mainSetBits(0xedc, 0);
            if (mainGetBit(0x7f9) != 0)
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
        if (mainGetBit(0xcac) != 0)
        {
            GameObject* player;
            mainSetBits(0xda9, 0);
            mainSetBits(0xc37, 1);
            player = (GameObject*)Obj_GetPlayerObject();
            (*gMapEventInterface)->savePoint(&player->anim.localPosX, player->anim.rotX, 1, 0);
            state->mode = WCLEVELCTL_MODE_DONE;
        }
        break;
    case WCLEVELCTL_MODE_DONE:
        break;
    default:
        if (!(state->completionFlags & WCLEVELCTL_FLAG_PUZZLE_A) && mainGetBit(0x7ed) != 0)
        {
            mainSetBits(0x7ef, 1);
            state->eventTimer = 70.0f;
            state->mode = WCLEVELCTL_MODE_PUZZLE_A;
            state->completionFlags |= WCLEVELCTL_FLAG_EVENT_ACTIVE;
            break;
        }
        if (!(state->completionFlags & WCLEVELCTL_FLAG_PUZZLE_B) && mainGetBit(0x7ee) != 0)
        {
            mainSetBits(0x7f0, 1);
            state->eventTimer = 70.0f;
            state->mode = WCLEVELCTL_MODE_PUZZLE_B;
            state->completionFlags |= WCLEVELCTL_FLAG_EVENT_ACTIVE;
        }
        break;
    }
    state->completionFlags &= ~WCLEVELCTL_FLAG_TRIGGERED;
}

int wclevelcont_seqFn(GameObject* obj, int unused, ObjSeqState* animUpdate)
{
    WcLevelControlState* state = obj->extra;
    int i;

    state->completionFlags |= WCLEVELCTL_FLAG_TRIGGERED;
    state->completionFlags &= ~WCLEVELCTL_FLAG_EVENT_ACTIVE;
    if (state->previousMode == WCLEVELCTL_MODE_PUZZLE_A)
    {
        f32 t = state->eventTimer - timeDelta;
        state->eventTimer = t;
        if (t <= gWcLevelContZero[0])
        {
            GameObject* player;
            mainSetBits(0x7f7, 1);
            player = (GameObject*)Obj_GetPlayerObject();
            (*gMapEventInterface)->savePoint(&player->anim.localPosX, player->anim.rotX, 1, 0);
        }
    }
    else if (state->previousMode == WCLEVELCTL_MODE_PUZZLE_B)
    {
        f32 t = state->eventTimer - timeDelta;
        state->eventTimer = t;
        if (t <= gWcLevelContZero[0])
        {
            GameObject* player;
            mainSetBits(0x802, 1);
            player = (GameObject*)Obj_GetPlayerObject();
            (*gMapEventInterface)->savePoint(&player->anim.localPosX, player->anim.rotX, 1, 0);
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

int wclevelcont_traceMoveB(GameObject* obj, s16 a, s16 b, f32* outX, f32* outZ, int dx, int dy)
{
    int i;
    int limit;

    if (dx != 0)
    {
        int bi = b;
        if (dx == -1)
        {
            f32 pz, px;
            mapGetBlockOriginForPos(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &px, &pz);
            {
                f32 base = 24.0f;
                f32 ofs = 336.0f;
                *outX = base + (224.0f + px + ofs);
                *outZ = base + (128.0f + pz + (f32)(bi * 48));
            }
            a += 1;
            limit = 8;
        }
        else
        {
            f32 pz, px;
            mapGetBlockOriginForPos(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &px, &pz);
            {
                f32 base = 24.0f;
                *outX = base + (224.0f + px + gWcLevelContZero[0]);
                *outZ = base + (128.0f + pz + (f32)(bi * 48));
            }
            a -= 1;
            limit = -1;
        }
        for (i = a; i != limit; i -= dx)
        {
            if (gWcTileGridB[i][b] != 0)
            {
                if (gWcTileGridB[i][b] <= 4)
                {
                    f32 pz, px;
                    i += dx;
                    mapGetBlockOriginForPos(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &px, &pz);
                    *outX = 24.0f + (224.0f + px + (f32)((s16)i * 48));
                    return 1;
                }
                {
                    f32 pz, px;
                    mapGetBlockOriginForPos(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &px, &pz);
                    *outX = 24.0f + (224.0f + px + (f32)((s16)i * 48));
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
            {
                f32 base = 24.0f;
                f32 ofs = 336.0f;
                *outX = base + (224.0f + px + (f32)(ai * 48));
                *outZ = base + (128.0f + pz + ofs);
            }
            b += 1;
            limit = 8;
        }
        else
        {
            f32 pz, px;
            mapGetBlockOriginForPos(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &px, &pz);
            {
                f32 base = 24.0f;
                *outX = base + (224.0f + px + (f32)(ai * 48));
                *outZ = base + (128.0f + pz + gWcLevelContZero[0]);
            }
            b -= 1;
            limit = -1;
        }
        for (i = b; i != limit; i -= dy)
        {
            if (gWcTileGridB[a][i] != 0)
            {
                if (gWcTileGridB[a][i] <= 4)
                {
                    f32 pz, px;
                    i += dy;
                    mapGetBlockOriginForPos(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &px, &pz);
                    *outZ = 24.0f + (128.0f + pz + (f32)((s16)i * 48));
                    return 1;
                }
                {
                    f32 pz, px;
                    mapGetBlockOriginForPos(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &px, &pz);
                    *outZ = 24.0f + (128.0f + pz + (f32)((s16)i * 48));
                    return 2;
                }
            }
        }
    }
    return 4;
}

void wclevelcont_getSolvedTileXYB(s16 value, s16* outTileX, s16* outTileY)
{
    int i, j;

    for (i = 0; i < 8; i++)
    {
        for (j = 0; j < 8; j++)
        {
            if (value == gWcTileGridBSolved.g[i][j])
            {
                *outTileX = i;
                *outTileY = j;
                return;
            }
        }
    }
}

void wclevelcont_getInitialTileXYB(s16 value, s16* outTileX, s16* outTileY)
{
    int i, j;

    for (i = 0; i < 8; i++)
    {
        for (j = 0; j < 8; j++)
        {
            if (value == gWcTileGridBInitial.g[i][j])
            {
                *outTileX = i;
                *outTileY = j;
                return;
            }
        }
    }
}

int wclevelcont_getTileB(s16 tileX, s16 tileY)
{
    if (tileX < 0 || tileX > 7 || tileY < 0 || tileY > 7)
    {
        return 0;
    }
    return gWcTileGridB[tileX][tileY];
}

void wclevelcont_setTileB(int value, s16 tileX, s16 tileY)
{
    if (tileX < 0 || tileX > 7 || tileY < 0 || tileY > 7)
    {
        return;
    }
    gWcTileGridB[tileX][tileY] = value;
}

void wclevelcont_worldPosToTileB(GameObject* obj, f32 px, f32 pz, s16* outTileX, s16* outTileY)
{
    f32 outX, outZ;

    mapGetBlockOriginForPos(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &outX, &outZ);
    *outTileX = (s16)((s16)(px - outX - 224.0f) / 48);
    *outTileY = (s16)((s16)(pz - outZ - 128.0f) / 48);
}

void wclevelcont_tileBToWorldPos(GameObject* obj, s16 tileX, s16 tileY, f32* outXp, f32* outZp)
{
    f32 outX, outZ;

    mapGetBlockOriginForPos(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &outX, &outZ);
    {
        f32 base = 24.0f;
        *outXp = base + (224.0f + outX + (f32)(tileX * 48));
        *outZp = base + (128.0f + outZ + (f32)(tileY * 48));
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
            mapGetBlockOriginForPos(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &px, &pz);
            {
                f32 base = 24.0f;
                f32 tx = 32.0f + px;
                f32 ofs = 336.0f;
                *outX = base + (tx + ofs);
                *outZ = (129.0f + pz + (f32)(bi * 48)) + base;
            }
            a += 1;
            limit = 8;
        }
        else
        {
            f32 pz, px;
            mapGetBlockOriginForPos(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &px, &pz);
            {
                f32 base = 24.0f;
                f32 tx = 32.0f + px;
                *outX = base + (tx + gWcLevelContZero[0]);
                *outZ = (129.0f + pz + (f32)(bi * 48)) + base;
            }
            a -= 1;
            limit = -1;
        }
        for (i = a; i != limit; i -= dx)
        {
            if (gWcTileGridA[i][b] != 0)
            {
                if (gWcTileGridA[i][b] <= 4)
                {
                    f32 pz, px;
                    i += dx;
                    mapGetBlockOriginForPos(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &px,
                                            &pz);
                    *outX = (32.0f + px + (f32)((s16)i * 48)) + 24.0f;
                    return 1;
                }
                {
                    f32 pz, px;
                    mapGetBlockOriginForPos(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &px,
                                            &pz);
                    *outX = (32.0f + px + (f32)((s16)i * 48)) + 24.0f;
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
            {
                f32 base = 24.0f;
                f32 tz;
                f32 ofs = 336.0f;
                *outX = (32.0f + px + (f32)(ai * 48)) + base;
                tz = 129.0f + pz;
                *outZ = base + (tz + ofs);
            }
            b += 1;
            limit = 8;
        }
        else
        {
            f32 pz, px;
            mapGetBlockOriginForPos(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &px, &pz);
            {
                f32 base = 24.0f;
                f32 tz;
                *outX = (32.0f + px + (f32)(ai * 48)) + base;
                tz = 129.0f + pz;
                *outZ = base + (tz + gWcLevelContZero[0]);
            }
            b -= 1;
            limit = -1;
        }
        for (i = b; i != limit; i -= dy)
        {
            if (gWcTileGridA[a][i] != 0)
            {
                if (gWcTileGridA[a][i] <= 4)
                {
                    f32 pz, px;
                    i += dy;
                    mapGetBlockOriginForPos(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &px,
                                            &pz);
                    *outZ = (129.0f + pz + (f32)((s16)i * 48)) + 24.0f;
                    return 1;
                }
                {
                    f32 pz, px;
                    mapGetBlockOriginForPos(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &px,
                                            &pz);
                    *outZ = (129.0f + pz + (f32)((s16)i * 48)) + 24.0f;
                    return 2;
                }
            }
        }
    }
    return 4;
}

void wclevelcont_getSolvedTileXYA(s16 value, s16* outTileX, s16* outTileY)
{
    int i, j;

    for (i = 0; i < 8; i++)
    {
        for (j = 0; j < 8; j++)
        {
            if (value == gWcTileGridASolved.g[i][j])
            {
                *outTileX = i;
                *outTileY = j;
                return;
            }
        }
    }
}

void wclevelcont_getInitialTileXYA(s16 value, s16* outTileX, s16* outTileY)
{
    int i, j;

    for (i = 0; i < 8; i++)
    {
        for (j = 0; j < 8; j++)
        {
            if (value == gWcTileGridAInitial.g[i][j])
            {
                *outTileX = i;
                *outTileY = j;
                return;
            }
        }
    }
}

int wclevelcont_getTileA(s16 tileX, s16 tileY)
{
    if (tileX < 0 || tileX > 7 || tileY < 0 || tileY > 7)
    {
        return 0;
    }
    return gWcTileGridA[tileX][tileY];
}

void wclevelcont_setTileA(int value, s16 tileX, s16 tileY)
{
    if (tileX < 0 || tileX > 7 || tileY < 0 || tileY > 7)
    {
        return;
    }
    gWcTileGridA[tileX][tileY] = value;
}

void wclevelcont_worldPosToTileA(GameObject* obj, f32 px, f32 pz, s16* outTileX, s16* outTileY)
{
    f32 outX, outZ;

    mapGetBlockOriginForPos(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &outX, &outZ);
    *outTileX = (s16)((s16)(px - outX - 32.0f) / 48);
    *outTileY = (s16)((s16)(pz - outZ - 129.0f) / 48);
}

void wclevelcont_tileAToWorldPos(GameObject* obj, s16 tileX, s16 tileY, f32* outXp, f32* outZp)
{
    f32 outX, outZ;

    mapGetBlockOriginForPos(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &outX, &outZ);
    {
        f32 base = 24.0f;
        *outXp = base + (32.0f + outX + (f32)(tileX * 48));
        *outZp = base + (129.0f + outZ + (f32)(tileY * 48));
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

    objFreeObjectType(obj, WCLEVELCONT_OBJGROUP);
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
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
    }
}

void wclevelcont_hitDetect(void)
{
}

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
    GameBitLatch_Update(&state->gameBitLatch, 0x8, -1, -1, 0xba6, 0xd2);
    GameBitLatch_Update(&state->gameBitLatch, 0x4, -1, -1, 0xcce, 0x36);
    GameBitLatch_Update(&state->gameBitLatch, 0x10, -1, -1, 0xcd0, 0xd4);
    GameBitLatch_Update(&state->gameBitLatch, 0x40, -1, -1, GAMEBIT_SHRINE_MUSIC_LOCK,
                        MUSICTRIG_PU3_Adventure_c4);
    flag = 0;
    if (mainGetBit(GAMEBIT_WC_PushBlockTimerActive) == 0 &&
        (mainGetBit(0xda9) != 0 || gameTimerIsRunning() != 0))
    {
        flag = 1;
    }
    mainSetBits(0xf31, flag);
    GameBitLatch_Update(&state->gameBitLatch, 0x80, -1, -1, 0xf31, 0xaf);
}

void wclevelcont_update(GameObject* obj)
{
    WcLevelControlState* state = obj->extra;
    f32 sunTime;

    if (obj->userData1 == 0)
    {
        if (mainGetBit(GAMEBIT_WC_MagicCaveRelated0E05) == 0)
        {
            getEnvfxActImmediately(obj, obj, WCLEVELCONT_ENVFX_A, 0);
            getEnvfxActImmediately(obj, obj, WCLEVELCONT_ENVFX_B, 0);
            getEnvfxActImmediately(obj, obj, WCLEVELCONT_ENVFX_C, 0);
            getEnvfxActImmediately(obj, obj, WCLEVELCONT_ENVFX_D, 0);
            skySetLightIndex(0, gWcLevelContZero[0]);
            mainSetBits(GAMEBIT_WC_MagicCaveRelated0E05, 1);
        }
        obj->userData1 = 1;
    }
    switch ((*gMapEventInterface)->getMapAct(obj->anim.mapEventSlot))
    {
    case 1:
    default:
        wclevelcont_updateAct1State(obj, state);
        break;
    case 2:
        wclevelcont_updateAct2State(obj, state);
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

void wclevelcont_init(GameObject* obj)
{
    WcLevelControlState* state = obj->extra;
    u16 flags;

    obj->animEventCallback = wclevelcont_seqFn;
    mainSetBits(0x810, 0);
    memcpy(gWcTileGridA, gWcTileGridAInitial.g, 0x40);
    mainSetBits(0x811, 0);
    memcpy(gWcTileGridB, gWcTileGridBInitial.g, 0x40);
    if (mainGetBit(0x7fa) != 0)
        state->completionFlags |= WCLEVELCTL_FLAG_PUZZLE_B;
    if (mainGetBit(0x7f9) != 0)
        state->completionFlags |= WCLEVELCTL_FLAG_PUZZLE_A;
    if (mainGetBit(0x813) != 0)
        state->completionFlags |= WCLEVELCTL_FLAG_TILE_B;
    if (mainGetBit(0x812) != 0)
        state->completionFlags |= WCLEVELCTL_FLAG_TILE_A;
    if (mainGetBit(0x2a5) != 0)
        state->completionFlags |= WCLEVELCTL_FLAG_TREX;
    if (mainGetBit(0x205) != 0)
        state->completionFlags |= WCLEVELCTL_FLAG_SWITCHES;
    if (mainGetBit(0xbcf) != 0)
        state->completionFlags |= WCLEVELCTL_FLAG_FINAL;
    if (mainGetBit(0xcac) != 0)
        state->completionFlags |= WCLEVELCTL_FLAG_EXTRA;
    flags = state->completionFlags;
    if (flags & WCLEVELCTL_FLAG_EXTRA)
    {
        state->mode = WCLEVELCTL_MODE_DONE;
    }
    else if ((flags & WCLEVELCTL_FLAG_PUZZLE_A) && (flags & WCLEVELCTL_FLAG_PUZZLE_B))
    {
        state->mode = WCLEVELCTL_MODE_SEQUENCE;
    }
    objAddObjectType(obj, WCLEVELCONT_OBJGROUP);
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

WcTileGrid gWcTileGridAInitial = {{
    {0, 0, 0, 0, 0, 0, 8, 0},
    {0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 4, 0, 0, 0},
    {0, 2, 0, 0, 0, 0, 3, 0},
    {0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 7},
    {0, 0, 0, 0, 6, 0, 0, 0},
    {0, 5, 0, 0, 1, 0, 0, 0},
}};
WcTileGrid gWcTileGridASolved = {{
    {0, 0, 0, 0, 0, 0, 4, 0},
    {0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 3},
    {0, 0, 0, 0, 2, 0, 0, 0},
    {0, 1, 0, 0, 0, 0, 0, 0},
}};
WcTileGrid gWcTileGridBInitial = {{
    {0, 0, 0, 0, 0, 0, 0, 0},
    {0, 1, 5, 0, 0, 2, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 3},
    {0, 0, 0, 0, 0, 0, 6, 0},
    {0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 7},
    {0, 8, 0, 0, 4, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0},
}};
WcTileGrid gWcTileGridBSolved = {{
    {0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 1, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 2, 0},
    {0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 3},
    {0, 4, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0},
}};

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
