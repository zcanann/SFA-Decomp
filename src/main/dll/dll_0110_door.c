/* DLL 0x0110 — door objects [8017AC2C-8017ADB4) */

#include "main/game_object.h"
#include "main/objseq.h"
#include "main/dll/alphaanim.h"
#include "main/objtexture.h"
#include "main/objhits.h"
#include "main/gamebits.h"
#include "main/audio/sfx_trigger_ids.h"

typedef struct DoorObjectDef
{
    u8 pad0[0x18 - 0x0];
    s16 openGameBit;  /* 0x18 */
    s16 latchGameBit; /* 0x1A */
    u8 unk1C;
    u8 unk1D;
    u8 pad1E[0x20 - 0x1E];
    u8 triggerArg; /* 0x20: low 7 bits passed to preempt sequence (== DoorPlacement.triggerArg) */
    u8 rootMotionScaleInput; /* 0x21 */
    s16 closeGameBit;        /* 0x22 */
    u8 pad24[0x28 - 0x24];
} DoorObjectDef;

typedef struct DoorPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 openGameBit;       /* 0x18 */
    s16 latchGameBit;      /* 0x1A */
    s16 triggerSequenceId; /* 0x1C */
    u8 runSequenceId;      /* 0x1E */
    u8 pad1F[0x20 - 0x1F];
    u8 triggerArg;    /* 0x20: low 7 bits passed to preempt sequence */
    u8 pad21[0x22 - 0x21];
    s16 closeGameBit; /* 0x22 */
    s16 unk24;
    u8 pad26[0x28 - 0x26];
} DoorPlacement;

/* Per-door state block (GameObject->extra, Door_getExtraSize == 0x8). */
typedef struct DoorState
{
    u16 openSfx;     /* 0x0: looping sfx played while opening/closing */
    u16 latchSfx;    /* 0x2: sfx played on latch (== CfGuardianState.sfxId slot) */
    u8 phase;        /* 0x4: 0 idle, 1 latched, 2 opening, 3 closing */
    u8 initPending;  /* 0x5: Door_update one-shot trigger flag */
    u8 flags;        /* 0x6: bit0 open texture, bit1 close texture */
    u8 pad7[0x8 - 0x7];
} DoorState;

extern int Sfx_PlayFromObject(int obj, int sfxId);

__declspec(section ".sdata") extern char lbl_803DBD90[];

extern f32 lbl_803E3780;
extern void objRenderFn_8003b8f4(f32);
extern f32 gDoorRootMotionScaleFactor;
extern f32 lbl_803E3788;
extern int Sfx_IsPlayingFromObject(int obj, int sfxId);
extern int Sfx_StopFromObject(int obj, int sfxId);

int Door_getExtraSize(void) { return 0x8; }
int mmp_bridge_getExtraSize(void);

void Door_render(void) { objRenderFn_8003b8f4(lbl_803E3780); }

int Door_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);

void Door_init(int* obj, u8* def)
{
    DoorState* state = (DoorState*)((GameObject*)obj)->extra;
    state->initPending = 1;
    ((GameObject*)obj)->anim.rotX = (s16)(def[0x1f] << 8);
    ((GameObject*)obj)->animEventCallback = Door_SeqFn;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x2000);
    ((GameObject*)obj)->anim.rootMotionScale = (f32)(u32)((DoorObjectDef*)def)->rootMotionScaleInput * gDoorRootMotionScaleFactor;
    if (((GameObject*)obj)->anim.rootMotionScale == lbl_803E3788)
    {
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803E3780;
    }
    ((GameObject*)obj)->anim.rootMotionScale =
        ((GameObject*)obj)->anim.rootMotionScale * ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
    if (((DoorObjectDef*)def)->latchGameBit != -1)
    {
        state->phase = GameBit_Get(((DoorObjectDef*)def)->latchGameBit);
    }
    else
    {
        state->phase = 0;
    }
    state->flags = 0;
    if (GameBit_Get(((DoorObjectDef*)def)->openGameBit) != 0) state->flags = (u8)(state->flags | 1);
    if (GameBit_Get(((DoorObjectDef*)def)->closeGameBit) != 0) state->flags = (u8)(state->flags | 2);
    {
        s16 model = ((GameObject*)obj)->anim.seqId;
        switch (model)
        {
        case 1101:
            {
                s32 subtype = ((GameObject*)obj)->anim.mapEventSlot;
                if (subtype < 40)
                {
                    if (subtype >= 35)
                        goto close;
                    if (subtype >= 31)
                        goto open;
                    goto close;
                }
                if (subtype >= 43)
                    goto close;
            open:
                state->openSfx = 832;
                state->latchSfx = 833;
                break;
            close:
                state->openSfx = 1154;
                state->latchSfx = 1155;
                break;
            }
        case 358:
            state->openSfx = 275;
            state->latchSfx = 504;
            break;
        }
    }
}

void Door_update(int obj)
{
    DoorState* state;
    DoorPlacement* def;
    int triggerArg;
    int triggerId;

    state = (DoorState*)((GameObject*)obj)->extra;
    def = (DoorPlacement*)((GameObject*)obj)->anim.placementData;
    if (state->initPending != 0)
    {
        triggerId = def->triggerSequenceId;
        if ((triggerId != 0) && (state->phase != 0))
        {
            triggerArg = def->triggerArg & 0x7f;
            (*gObjectTriggerInterface)->preempt(obj, triggerId);
        }
        else
        {
            triggerArg = -1;
        }
        if ((s8)def->runSequenceId != -1)
        {
            (*gObjectTriggerInterface)->runSequence((int)(s8)def->runSequenceId, (void*)obj, triggerArg);
        }
        state->initPending = 0;
    }
}

void mmp_bridge_update(int* obj);

int Door_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int i;
    DoorState* state;
    DoorPlacement* def;
    int opened;
    int closeReady;
    ObjTextureRuntimeSlot* tex;
    int ret;

    state = (DoorState*)((GameObject*)obj)->extra;
    def = (DoorPlacement*)((GameObject*)obj)->anim.placementData;
    if (((GameObject*)obj)->anim.alpha == 0)
    {
        ObjHits_DisableObject(obj);
    }
    if (((GameObject*)obj)->anim.modelInstance->textureSlotCount != 0)
    {
        if ((state->flags & 1) != 0)
        {
            tex = objFindTexture((int*)obj, 0, 0);
            if (tex != NULL)
            {
                tex->textureId = 0x100;
            }
        }
        if ((state->flags & 2) != 0)
        {
            tex = objFindTexture((int*)obj, 1, 0);
            if (tex != NULL)
            {
                tex->textureId = 0x100;
            }
        }
    }
    if (state->phase == 0)
    {
        opened = GameBit_Get(def->openGameBit);
        closeReady = 0;
        if ((def->closeGameBit == -1) || (GameBit_Get(def->closeGameBit) != 0))
        {
            closeReady = 1;
        }
        if ((opened != 0) && ((state->flags & 1) == 0))
        {
            if (((GameObject*)obj)->anim.modelInstance->textureSlotCount != 0)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_littletink22);
            }
            state->flags |= 1;
        }
        if ((closeReady != 0) && ((state->flags & 2) == 0))
        {
            if (((GameObject*)obj)->anim.modelInstance->textureSlotCount != 0)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_littletink22);
            }
            state->flags |= 2;
        }
        if (state->flags == 3)
        {
            state->phase = 2;
            if (state->openSfx != 0)
            {
                Sfx_PlayFromObject(obj, state->openSfx);
            }
        }
    }
    else if (state->phase == 1)
    {
        if (GameBit_Get(def->openGameBit) == 0)
        {
            state->phase = 3;
            if (state->openSfx != 0)
            {
                Sfx_PlayFromObject(obj, state->openSfx);
            }
        }
    }
    if (state->phase == 2)
    {
        for (i = 0; i < animUpdate->eventCount; i++)
        {
            if (animUpdate->eventIds[i] == 2)
            {
                state->phase = 1;
                if (def->latchGameBit != -1)
                {
                    GameBit_Set(def->latchGameBit, 1);
                }
                if ((state->openSfx != 0) && (Sfx_IsPlayingFromObject(obj, state->openSfx) != 0))
                {
                    Sfx_StopFromObject(obj, state->openSfx);
                }
                if (state->latchSfx != 0)
                {
                    Sfx_PlayFromObject(obj, state->latchSfx);
                }
            }
        }
    }
    else if (state->phase == 3)
    {
        for (i = 0; i < animUpdate->eventCount; i++)
        {
            if (animUpdate->eventIds[i] == 1)
            {
                state->phase = 0;
                state->flags = 0;
                if (def->latchGameBit != -1)
                {
                    GameBit_Set(def->latchGameBit, 0);
                }
                if ((state->openSfx != 0) && (Sfx_IsPlayingFromObject(obj, state->openSfx) != 0))
                {
                    Sfx_StopFromObject(obj, state->openSfx);
                }
                if (state->latchSfx != 0)
                {
                    Sfx_PlayFromObject(obj, state->latchSfx);
                }
            }
        }
    }
    ret = 0;
    if ((state->phase != 2) && (state->phase != 3))
    {
        ret = 1;
    }
    return ret;
}

/* immultiseq_SeqFn: seqobj2 advance-state predicate. If obj has a trigger id
 * (-1 sentinel skips), peek at the next state slot in def[0x20+n*2], read
 * its GameBit, compare against the def[0x30] mask bit for that slot, and
 * if the polarity flips (GameBit != mask bit) end the current sequence.
 * Always latches state[1] bit 0 before returning 0. */
