#include "ghidra_import.h"
#include "main/dll/tesla.h"

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

typedef struct TrickyCurveObject {
    u8 unk0[0xc];
    f32 x;
    f32 y;
    f32 z;
    u8 unk18[0xa0];
    struct TrickyCurveTriggerState *state;
} TrickyCurveObject;

typedef struct TrickyCurveTriggerState {
    s16 xExtent;
    s16 zExtent;
    s16 yExtent;
    s16 cooldown;
    u8 unk8[8];
    u8 xSide;
    u8 ySide;
    u8 zSide;
} TrickyCurveTriggerState;

typedef struct TrickyCurveBurstPartfxArgs {
    s16 xRot;
    s16 yRot;
    s16 zRot;
    f32 scale;
    f32 xDelta;
    f32 yDelta;
    f32 zDelta;
} TrickyCurveBurstPartfxArgs;

typedef void (*PartfxSpawnFn)(int obj, int effectId, void *args, int mode, int arg5, int arg6);

extern u32 GameBit_Set(u32 id, u32 value);
extern int Obj_GetPlayerObject(void);
extern void ObjHits_RecordObjectHit(int obj, int hitObj, int priority, int hitVolume, int sphereIndex);
extern void ObjMsg_SendToObject(int obj, int message, int sender, int param);
extern int objGetAnimState80A(int obj);
extern void Sfx_PlayFromObject(int obj, int sfxId);

extern int *gPartfxInterface;
extern u8 gTrickyCurveBurstCounter;
extern f32 timeDelta;
extern f64 lbl_803E6440;
extern f32 lbl_803E6448;

#define PARTFX_SPAWN(obj, effectId, args, mode, arg5, arg6) \
    ((PartfxSpawnFn)(*(u32 *)(*gPartfxInterface + 0x8)))((obj), (effectId), (args), (mode), (arg5), (arg6))

/*
 * --INFO--
 *
 * Function: fn_80206968
 * EN v1.0 Address: 0x80206968
 * EN v1.0 Size: 688b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void fn_80206968(TrickyCurveObject *obj)
{
    u8 insideAxes;
    TrickyCurveTriggerState *state;
    int player;
    u8 xSide;
    u8 ySide;
    u8 zSide;
    f32 xDelta;
    f32 zDelta;
    f32 yDelta;

    state = obj->state;
    player = Obj_GetPlayerObject();
    insideAxes = 0;
    xSide = 0;
    ySide = 0;
    zSide = 0;

    xDelta = *(f32 *)(player + 0xc) - obj->x;
    yDelta = *(f32 *)(player + 0x10) - obj->y;
    zDelta = *(f32 *)(player + 0x14) - obj->z;

    if (xDelta <= 0.0f) {
        if (xDelta > -(f32)state->xExtent) {
            insideAxes = 1;
            xSide = 1;
        }
    }
    if (xDelta > 0.0f) {
        if (xDelta < (f32)state->xExtent) {
            insideAxes++;
            xSide--;
        }
    }
    if (zDelta <= 0.0f) {
        if (zDelta > -(f32)state->zExtent) {
            insideAxes++;
            zSide = 1;
        }
    }
    if (zDelta > 0.0f) {
        if (zDelta < (f32)state->zExtent) {
            insideAxes++;
            zSide--;
        }
    }
    if (yDelta <= 0.0f) {
        if (yDelta > -(f32)state->yExtent) {
            insideAxes++;
            ySide = 1;
        }
    }
    if (yDelta > 0.0f) {
        if (yDelta < (f32)state->yExtent) {
            insideAxes++;
            ySide--;
        }
    }

    if (state->cooldown >= 0) {
        state->cooldown -= (int)timeDelta;
    }
    if (insideAxes == 3 && state->cooldown <= 0) {
        if (objGetAnimState80A(player) == TRICKY_CURVE_PLAYER_ANIM_SLIDE) {
            GameBit_Set(TRICKY_CURVE_GAMEBIT_HIT, 1);
            PARTFX_SPAWN(player, TRICKY_CURVE_PARTFX_COOLDOWN, 0, 2, -1, 0);
        } else {
            ObjHits_RecordObjectHit(player, 0, TRICKY_CURVE_HIT_PRIORITY, 2, 0);
        }
        Sfx_PlayFromObject(player, TRICKY_CURVE_SFX_COOLDOWN);
        state->cooldown = TRICKY_CURVE_COOLDOWN_TICKS;
    }

    state->xSide = xSide;
    state->ySide = ySide;
    state->zSide = zSide;
}

/*
 * --INFO--
 *
 * Function: fn_80206C18
 * EN v1.0 Address: 0x80206C18
 * EN v1.0 Size: 792b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void fn_80206C18(TrickyCurveObject *obj)
{
    u8 insideAxes;
    TrickyCurveTriggerState *state;
    int player;
    u8 xSide;
    u8 ySide;
    u8 zSide;
    f32 xDelta;
    f32 zDelta;
    f32 yDelta;
    TrickyCurveBurstPartfxArgs partfxArgs;

    state = obj->state;
    player = Obj_GetPlayerObject();
    insideAxes = 0;
    xSide = 0;
    ySide = 0;
    zSide = 0;

    xDelta = *(f32 *)(player + 0xc) - obj->x;
    yDelta = *(f32 *)(player + 0x10) - obj->y;
    zDelta = *(f32 *)(player + 0x14) - obj->z;
    gTrickyCurveBurstCounter++;

    if (xDelta <= 0.0f) {
        if (xDelta > -(f32)state->xExtent) {
            insideAxes = 1;
            xSide = 1;
        }
    }
    if (xDelta > 0.0f) {
        if (xDelta < (f32)state->xExtent) {
            insideAxes++;
            xSide--;
        }
    }
    if (zDelta <= 0.0f) {
        if (zDelta > -(f32)state->zExtent) {
            insideAxes++;
            zSide = 1;
        }
    }
    if (zDelta > 0.0f) {
        if (zDelta < (f32)state->zExtent) {
            insideAxes++;
            zSide--;
        }
    }
    if (yDelta <= 0.0f) {
        if (yDelta > -(f32)state->yExtent) {
            insideAxes++;
            ySide = 1;
        }
    }
    if (yDelta > 0.0f) {
        if (yDelta < (f32)state->yExtent) {
            insideAxes++;
            ySide--;
        }
    }

    if (insideAxes == 3) {
        partfxArgs.xDelta = xDelta;
        partfxArgs.yDelta = yDelta;
        partfxArgs.zDelta = zDelta;
        partfxArgs.scale = lbl_803E6448;
        partfxArgs.zRot = 0;
        partfxArgs.yRot = 0;
        partfxArgs.xRot = 0;
        if (xSide != state->xSide) {
            partfxArgs.xRot = 0x3fff;
        }

        if (objGetAnimState80A(player) == TRICKY_CURVE_PLAYER_ANIM_SLIDE) {
            if (gTrickyCurveBurstCounter > TRICKY_CURVE_BURST_LIMIT) {
                gTrickyCurveBurstCounter = 0;
                GameBit_Set(TRICKY_CURVE_GAMEBIT_HIT, 1);
                Sfx_PlayFromObject((int)obj, TRICKY_CURVE_SFX_BURST);
            }
            PARTFX_SPAWN(player, TRICKY_CURVE_PARTFX_COOLDOWN, 0, 2, -1, 0);
        } else {
            GameBit_Set(TRICKY_CURVE_GAMEBIT_HIT, 1);
            ObjMsg_SendToObject(player, TRICKY_CURVE_MESSAGE_BURST, (int)obj, 2);
            PARTFX_SPAWN((int)obj, TRICKY_CURVE_PARTFX_BURST, &partfxArgs, 2, -1, 0);
            Sfx_PlayFromObject((int)obj, TRICKY_CURVE_SFX_BURST);
        }
    }

    state->xSide = xSide;
    state->ySide = ySide;
    state->zSide = zSide;
}
