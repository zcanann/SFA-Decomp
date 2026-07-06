/*
 * DLL 0x22C (dll22c) - a vertically-moving placed object (Dll22CState,
 * extraSize 0x10).
 *
 * init seeds the state from the placement record (rotX, two game bits,
 * raise height, an init flag) and sinks the object by 1228.0f.
 * The update state-machine (fn_80204BF8) drives a rise/hold/fall cycle
 * relative to the player:
 *   mode 0  armed - once gameBit is set and the player is within
 *           230.0f, rise by timeDelta to posY+60.0f,
 *           looping SFX 0x116 on object channel 8 -> mode 1.
 *   mode 1  -> mode 2 with a 100-frame hold (pauseTimer).
 *   mode 2  after the hold, pick descend (mode 3) or ascend (mode 4)
 *           by the player's Y vs placement posY (SFX 0x1cb).
 *   mode 3  fall by timeDelta to posY-1228.0f, then hold (mode 2).
 *   mode 4  rise by timeDelta to posY+60.0f, then hold (mode 2).
 *
 * Render (dll_22C_render) draws via objRenderModelAndHitVolumes; hitDetect,
 * release, initialise and the SeqFn are stubs. fn_80204B6C frees the
 * object's expgfx source. The remaining handlers are descriptor
 * callbacks (getExtraSize=0x10, getObjectTypeId=0).
 *
 * The STATIC_ASSERTs below pin sibling-DLL control-record layouts that
 * this family of DLLs shares.
 */
#include "main/dll/dll22cstate_struct.h"
#include "main/dll/dfpobjcreatorstate_struct.h"
#include "main/dll/dbholecontrol1state_struct.h"
#include "main/dll/dfptorchstate_struct.h"
#include "main/dll/dbeggstate_struct.h"
#include "main/dll/drakorenergystate_struct.h"
#include "main/dll/dbstealerwormcontrol_struct.h"
#include "main/dll/blastflags4_types.h"
#include "main/dll/dfp_types.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/anim.h"
#include "main/gameplay_runtime.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"

#define DLL22C_OBJFLAG_HITDETECT_DISABLED 0x2000

/*
 * DbStealerwormControl - the per-family control record hung off
 * GroundBaddieState.control (state+0x40C) for dbstealerworm
 * (extraSize 0x460 = GroundBaddieState 0x410 + a 0x50 private tail;
 * the control record itself is memset(0x50) in dbstealerworm_init).
 */

STATIC_ASSERT(sizeof(DbStealerwormControl) == 0x50);

STATIC_ASSERT(sizeof(DfpLevelControlState) == 0xC);

STATIC_ASSERT(sizeof(DfpObjCreatorState) == 0x1C);

STATIC_ASSERT(sizeof(DfpTorchState) == 0x10);

STATIC_ASSERT(sizeof(Dll22CState) == 0x10);

STATIC_ASSERT(offsetof(DbEggState, mode) == 0x118);

STATIC_ASSERT(sizeof(DfpSeqPointState) == 0x10);

STATIC_ASSERT(sizeof(DrakorEnergyState) == 0xC);

STATIC_ASSERT(sizeof(GCRobotBlastState) == 0x8);

STATIC_ASSERT(sizeof(DbHoleControl1State) == 0xC);

typedef struct Dll22CMapData
{
    ObjPlacement base;
    s8 rotXByte;  /* 0x18: rotX in 1/256 turns */
    s8 unk19;     /* 0x19 */
    s16 raiseHeight; /* 0x1A */
    s16 unk1C;    /* 0x1C: -> state raiseMode */
    s16 gameBit2; /* 0x1E */
    s16 gameBit;  /* 0x20 */
} Dll22CMapData;

STATIC_ASSERT(offsetof(Dll22CMapData, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(Dll22CMapData, raiseHeight) == 0x1A);
STATIC_ASSERT(offsetof(Dll22CMapData, unk1C) == 0x1C);
STATIC_ASSERT(offsetof(Dll22CMapData, gameBit2) == 0x1E);
STATIC_ASSERT(offsetof(Dll22CMapData, gameBit) == 0x20);

extern int getLActions(int a, int b, u16 idx, int p4, int p5, int p6);
extern f32 timeDelta;

/* Dll22CState.mode rise/hold/fall cycle (see file-header comment). */
#define DLL22C_MODE_ARMED   0 /* wait for gameBit + player proximity, then rise -> HOLD_SETUP */
#define DLL22C_MODE_HOLD_SETUP 1 /* one-frame: arm the 100-frame pauseTimer -> HOLD */
#define DLL22C_MODE_HOLD    2 /* hold, then pick DESCEND or ASCEND by player Y */
#define DLL22C_MODE_DESCEND 3 /* fall to posY-1228.0f, then -> HOLD */
#define DLL22C_MODE_ASCEND  4 /* rise to posY+60.0f, then -> HOLD */

int dll_22C_SeqFn(void) { return 0x0; }
int dll_22C_getExtraSize_ret_16(void) { return 0x10; }
int dll_22C_getObjectTypeId(void) { return 0x0; }

void fn_80204B6C(int p1)
{
    (*gExpgfxInterface)->freeSource2((u32)p1);
    getLActions(p1, p1, 0, 0, 0, 0);
}

void dll_22C_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, 1.0f);
}

void dll_22C_hitDetect_nop(void)
{
}

void fn_80204BF8(int obj)
{
    /* block-scope to override the engine_shared.h prototypes' return/param
       types (GameObject* return, signed args) the codegen here depends on. */

    extern f32 Vec_xzDistance(f32* a, f32* b);
    extern int Sfx_IsPlayingFromObjectChannel(int, int);


    GameObject* object = (GameObject*)obj;
    ObjPlacement* placement = object->anim.placement;
    Dll22CState* blob = object->extra;
    GameObject* player;
    int h;
    f32 d;
    f32 k;
    f32 y;

    player = Obj_GetPlayerObject();
    if (player == NULL)
    {
        return;
    }
    switch (blob->mode)
    {
    case DLL22C_MODE_ARMED:
        if (GameBit_Get(blob->gameBit) != 0 && blob->raiseMode != 1 &&
            Vec_xzDistance(&object->anim.worldPosX, &player->anim.worldPosX) < 230.0f)
        {
            if (object->anim.localPosY < 60.0f + placement->posY)
            {
                if (Sfx_IsPlayingFromObjectChannel(obj, 8) == 0)
                {
                    Sfx_PlayFromObject(obj, 0x116);
                    blob->sfxLatch = 1;
                }
                object->anim.localPosY += timeDelta;
                if (object->anim.localPosY >= 60.0f + placement->posY)
                {
                    object->anim.localPosY = 60.0f + placement->posY;
                    blob->mode = DLL22C_MODE_HOLD_SETUP;
                    Sfx_StopObjectChannel(obj, 8);
                }
            }
        }
        else if (blob->raiseMode == 1)
        {
            if (Vec_xzDistance(&object->anim.worldPosX, &player->anim.worldPosX) < 230.0f)
            {
                y = object->anim.localPosY;
                k = 60.0f;
                if (y < k + placement->posY)
                {
                    object->anim.localPosY = y + timeDelta;
                    if (object->anim.localPosY >= k + placement->posY)
                    {
                        object->anim.localPosY = k + placement->posY;
                        blob->mode = DLL22C_MODE_HOLD_SETUP;
                    }
                }
            }
        }
        break;
    case DLL22C_MODE_HOLD_SETUP:
        blob->mode = DLL22C_MODE_HOLD;
        blob->pauseTimer = 0x64;
        break;
    case DLL22C_MODE_HOLD:
        h = blob->pauseTimer;
        if (h != 0)
        {
            blob->pauseTimer -= (s16)timeDelta;
            if (blob->pauseTimer <= 0)
            {
                blob->pauseTimer = 0;
            }
        }
        else
        {
            d = Vec_xzDistance(&object->anim.worldPosX, &player->anim.worldPosX);
            if (d < 50.0f)
            {
                if (object->anim.localPosY == 60.0f + placement->posY)
                {
                    blob->mode = DLL22C_MODE_DESCEND;
                    if (Sfx_IsPlayingFromObjectChannel(obj, 8) == 0)
                    {
                        Sfx_PlayFromObject(obj, SFXTRIG_liftloop);
                        blob->sfxLatch = 1;
                    }
                }
                else if (object->anim.localPosY == placement->posY - 1228.0f)
                {
                    blob->mode = DLL22C_MODE_ASCEND;
                    if (Sfx_IsPlayingFromObjectChannel(obj, 8) == 0)
                    {
                        Sfx_PlayFromObject(obj, SFXTRIG_liftloop);
                        blob->sfxLatch = 1;
                    }
                }
            }
            else
            {
                if (player->anim.localPosY < placement->posY)
                {
                    blob->mode = DLL22C_MODE_DESCEND;
                    if (blob->sfxLatch == 1)
                    {
                        blob->sfxLatch = 0;
                    }
                }
                else if (player->anim.localPosY > placement->posY)
                {
                    blob->mode = DLL22C_MODE_ASCEND;
                    if (blob->sfxLatch == 1)
                    {
                        blob->sfxLatch = 0;
                    }
                }
            }
        }
        break;
    case DLL22C_MODE_DESCEND:
        if (object->anim.localPosY > placement->posY - (k = 1228.0f))
        {
            object->anim.localPosY -= timeDelta;
            if (object->anim.localPosY <= placement->posY - k)
            {
                object->anim.localPosY = placement->posY - k;
                blob->mode = DLL22C_MODE_HOLD;
                Sfx_StopObjectChannel(obj, 8);
                blob->pauseTimer = 0x64;
            }
            Vec_xzDistance(&object->anim.worldPosX, &player->anim.worldPosX);
        }
        else
        {
            Sfx_StopObjectChannel(obj, 8);
            Vec_xzDistance(&object->anim.worldPosX, &player->anim.worldPosX);
            blob->mode = DLL22C_MODE_HOLD;
            blob->pauseTimer = 0x64;
        }
        break;
    case DLL22C_MODE_ASCEND:
        y = object->anim.localPosY;
        k = 60.0f;
        if (y < k + placement->posY)
        {
            object->anim.localPosY = y + timeDelta;
            if (object->anim.localPosY >= k + placement->posY)
            {
                object->anim.localPosY = k + placement->posY;
                blob->mode = DLL22C_MODE_HOLD;
                blob->pauseTimer = 0x64;
                Sfx_StopObjectChannel(obj, 8);
            }
            Vec_xzDistance(&object->anim.worldPosX, &player->anim.worldPosX);
        }
        else
        {
            blob->mode = DLL22C_MODE_HOLD;
            blob->pauseTimer = 0x64;
            Sfx_StopObjectChannel(obj, 8);
            Vec_xzDistance(&object->anim.worldPosX, &player->anim.worldPosX);
        }
        break;
    }
}

void dll_22C_init(int obj, char* p)
{
    Dll22CState* state;
    Dll22CMapData* md = (Dll22CMapData*)p;

    state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = dll_22C_SeqFn;
    ((GameObject*)obj)->anim.rotX = (s16)(md->rotXByte << 8);
    state->mode = DLL22C_MODE_ARMED;
    state->gameBit = md->gameBit;
    state->gameBit2 = md->gameBit2;
    state->raiseHeight = md->raiseHeight;
    state->raiseMode = md->unk1C;
    ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY - 1228.0f;
    ((GameObject*)obj)->objectFlags = ((GameObject*)obj)->objectFlags | DLL22C_OBJFLAG_HITDETECT_DISABLED;
}

void dll_22C_release_nop(void)
{
}

void dll_22C_initialise_nop(void)
{
}
