/*
 * tesla / "Tricky curve" trigger object.
 *
 * A box-shaped trigger volume centred on the object that watches the
 * player's offset from the object on each axis. When the player is inside
 * the half-extents on all three axes (insideAxes == 3) the object reacts:
 *  - fn_80206968 is the cooldown variant: throttled by state->cooldown
 *    (decremented by timeDelta, reset to TRICKY_CURVE_COOLDOWN_TICKS after
 *    a hit). A sliding player (player anim state ==
 *    TRICKY_CURVE_PLAYER_ANIM_SLIDE) sets the hit game bit and spawns the
 *    cooldown partfx; otherwise the player takes a recorded hit. Either
 *    way a sfx plays.
 *  - fn_80206C18 is the burst variant: spawns a directional burst partfx
 *    (TrickyCurveBurstPartfxArgs carries the player-relative deltas and an
 *    x-rotation flip when the player crosses the x midline) and, off the
 *    slide path, messages the player and plays the burst sfx. The
 *    gTrickyCurveBurstCounter gates the bit/sfx to once every
 *    TRICKY_CURVE_BURST_LIMIT ticks while sliding.
 *
 * Both variants cache the entry side per axis (xSide/ySide/zSide) in the
 * trigger state so the burst variant can detect a midline crossing.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/gameplay_runtime.h"
#include "main/objlib.h"

#define TRICKY_CURVE_GAMEBIT_HIT 0x468
#define TRICKY_CURVE_PLAYER_ANIM_SLIDE 0x1d7
#define TRICKY_CURVE_COOLDOWN_TICKS 200
#define TRICKY_CURVE_BURST_LIMIT 0x14
#define TRICKY_CURVE_HIT_PRIORITY 0x14
#define TRICKY_CURVE_MESSAGE_BURST 0x60004
#define TRICKY_CURVE_PARTFX_COOLDOWN 0x397
#define TRICKY_CURVE_PARTFX_BURST 0x399
#define TRICKY_CURVE_SFX_BURST 0x1c9
#define TRICKY_CURVE_SFX_COOLDOWN 0x1ca

typedef struct TrickyCurveObject
{
    u8 unk0[0xc];
    f32 x;                              /* 0x0C: localPosX (GameObject anim) */
    f32 y;                              /* 0x10: localPosY */
    f32 z;                              /* 0x14: localPosZ */
    u8 unk18[0xa0];
    struct TrickyCurveTriggerState* state; /* 0xB8: GameObject extra block */
} TrickyCurveObject;

typedef struct TrickyCurveTriggerState
{
    s16 xExtent;    /* 0x00: half-extent of the trigger box on each axis */
    s16 zExtent;    /* 0x02 */
    s16 yExtent;    /* 0x04 */
    s16 cooldown;   /* 0x06: ticks until the cooldown variant can hit again */
    u8 unk8[8];     /* 0x08: unknown */
    u8 xSide;       /* 0x10: which side of the midline the player entered on */
    u8 ySide;       /* 0x11 */
    u8 zSide;       /* 0x12 */
} TrickyCurveTriggerState;

typedef struct TrickyCurveBurstPartfxArgs
{
    s16 xRot;
    s16 yRot;
    s16 zRot;
    f32 scale;
    f32 xDelta;
    f32 yDelta;
    f32 zDelta;
} TrickyCurveBurstPartfxArgs;

STATIC_ASSERT(offsetof(TrickyCurveTriggerState, cooldown) == 0x06);
STATIC_ASSERT(offsetof(TrickyCurveTriggerState, xSide) == 0x10);
STATIC_ASSERT(sizeof(TrickyCurveTriggerState) == 0x14);
STATIC_ASSERT(offsetof(TrickyCurveBurstPartfxArgs, scale) == 0x08);
STATIC_ASSERT(offsetof(TrickyCurveBurstPartfxArgs, xDelta) == 0x0C);

extern int objGetAnimState80A(int obj);

extern u8 gTrickyCurveBurstCounter; /* inter-frame burst-fire counter; reset to 0 after TRICKY_CURVE_BURST_LIMIT ticks */
extern f32 timeDelta;                   /* engine frame-step seconds */
extern f32 lbl_803E6448;                /* burst partfx scale constant */

#define PARTFX_SPAWN(obj, effectId, args, mode, arg5, arg6) \
    (*gPartfxInterface)->spawnObject((void *)(obj), (effectId), (args), (mode), (arg5), (arg6))

void fn_80206968(TrickyCurveObject* obj)
{
    u8 insideAxes;
    TrickyCurveTriggerState* state;
    GameObject* player;
    u8 xSide;
    u8 ySide;
    u8 zSide;
    f32 xDelta;
    f32 zDelta;
    f32 yDelta;

    state = obj->state;
    player = (GameObject *)Obj_GetPlayerObject();
    insideAxes = 0;
    xSide = 0;
    ySide = 0;
    zSide = 0;

    xDelta = player->anim.localPosX - obj->x;
    yDelta = player->anim.localPosY - obj->y;
    zDelta = player->anim.localPosZ - obj->z;

    if (xDelta <= 0.0f)
    {
        if (xDelta > -(f32)state->xExtent)
        {
            insideAxes = 1;
            xSide = 1;
        }
    }
    if (xDelta > 0.0f)
    {
        if (xDelta < (f32)state->xExtent)
        {
            insideAxes++;
            xSide--;
        }
    }
    if (zDelta <= 0.0f)
    {
        if (zDelta > -(f32)state->zExtent)
        {
            insideAxes++;
            zSide = 1;
        }
    }
    if (zDelta > 0.0f)
    {
        if (zDelta < (f32)state->zExtent)
        {
            insideAxes++;
            zSide--;
        }
    }
    if (yDelta <= 0.0f)
    {
        if (yDelta > -(f32)state->yExtent)
        {
            insideAxes++;
            ySide = 1;
        }
    }
    if (yDelta > 0.0f)
    {
        if (yDelta < (f32)state->yExtent)
        {
            insideAxes++;
            ySide--;
        }
    }

    if (state->cooldown >= 0)
    {
        state->cooldown -= (s16)timeDelta;
    }
    if (insideAxes == 3 && state->cooldown <= 0)
    {
        if (objGetAnimState80A((int)player) == TRICKY_CURVE_PLAYER_ANIM_SLIDE)
        {
            GameBit_Set(TRICKY_CURVE_GAMEBIT_HIT, 1);
            PARTFX_SPAWN(player, TRICKY_CURVE_PARTFX_COOLDOWN, 0, 2, -1, 0);
        }
        else
        {
            ObjHits_RecordObjectHit((int)player, 0, TRICKY_CURVE_HIT_PRIORITY, 2, 0);
        }
        Sfx_PlayFromObject((u32)player, TRICKY_CURVE_SFX_COOLDOWN);
        state->cooldown = TRICKY_CURVE_COOLDOWN_TICKS;
    }

    state->xSide = xSide;
    state->ySide = ySide;
    state->zSide = zSide;
}

void fn_80206C18(TrickyCurveObject* obj)
{
    u8 insideAxes;
    TrickyCurveTriggerState* state;
    GameObject* player;
    u8 xSide;
    u8 ySide;
    u8 zSide;
    f32 xDelta;
    f32 zDelta;
    f32 yDelta;
    TrickyCurveBurstPartfxArgs partfxArgs;

    state = obj->state;
    player = (GameObject *)Obj_GetPlayerObject();
    insideAxes = 0;
    xSide = 0;
    ySide = 0;
    zSide = 0;

    xDelta = player->anim.localPosX - obj->x;
    yDelta = player->anim.localPosY - obj->y;
    zDelta = player->anim.localPosZ - obj->z;
    gTrickyCurveBurstCounter++;

    if (xDelta <= 0.0f)
    {
        if (xDelta > -(f32)state->xExtent)
        {
            insideAxes = 1;
            xSide = 1;
        }
    }
    if (xDelta > 0.0f)
    {
        if (xDelta < (f32)state->xExtent)
        {
            insideAxes++;
            xSide--;
        }
    }
    if (zDelta <= 0.0f)
    {
        if (zDelta > -(f32)state->zExtent)
        {
            insideAxes++;
            zSide = 1;
        }
    }
    if (zDelta > 0.0f)
    {
        if (zDelta < (f32)state->zExtent)
        {
            insideAxes++;
            zSide--;
        }
    }
    if (yDelta <= 0.0f)
    {
        if (yDelta > -(f32)state->yExtent)
        {
            insideAxes++;
            ySide = 1;
        }
    }
    if (yDelta > 0.0f)
    {
        if (yDelta < (f32)state->yExtent)
        {
            insideAxes++;
            ySide--;
        }
    }

    if (insideAxes == 3)
    {
        partfxArgs.xDelta = xDelta;
        partfxArgs.yDelta = yDelta;
        partfxArgs.zDelta = zDelta;
        partfxArgs.scale = lbl_803E6448;
        partfxArgs.zRot = 0;
        partfxArgs.yRot = 0;
        partfxArgs.xRot = 0;
        if (xSide != state->xSide)
        {
            partfxArgs.xRot = 0x3fff;
        }

        if (objGetAnimState80A((int)player) == TRICKY_CURVE_PLAYER_ANIM_SLIDE)
        {
            if (gTrickyCurveBurstCounter > TRICKY_CURVE_BURST_LIMIT)
            {
                gTrickyCurveBurstCounter = 0;
                GameBit_Set(TRICKY_CURVE_GAMEBIT_HIT, 1);
                Sfx_PlayFromObject((u32)obj, TRICKY_CURVE_SFX_BURST);
            }
            PARTFX_SPAWN(player, TRICKY_CURVE_PARTFX_COOLDOWN, 0, 2, -1, 0);
        }
        else
        {
            GameBit_Set(TRICKY_CURVE_GAMEBIT_HIT, 1);
            ObjMsg_SendToObject(player, TRICKY_CURVE_MESSAGE_BURST, obj, 2);
            PARTFX_SPAWN((int)obj, TRICKY_CURVE_PARTFX_BURST, &partfxArgs, 2, -1, 0);
            Sfx_PlayFromObject((u32)obj, TRICKY_CURVE_SFX_BURST);
        }
    }

    state->xSide = xSide;
    state->ySide = ySide;
    state->zSide = zSide;
}
