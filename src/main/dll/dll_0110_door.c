/* DLL 0x0110 - door objects [0x8017B5C8-0x8017BB80). */

#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/object_render.h"
#include "main/objanim_update.h"
#include "main/objseq.h"
#include "main/objtexture.h"
#include "main/objhits.h"
#include "main/gamebits.h"
#include "main/audio/sfx_object_query_api.h"
#include "main/audio/sfx_play_legacy_api.h"
#include "main/audio/sfx_stop_object_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/object_descriptor.h"

#define DOOR_OBJFLAG_HITDETECT_DISABLED 0x2000

/* DoorState.phase values, verified against the first Magic Cave iron gate. */
#define DOOR_PHASE_OPEN 0
#define DOOR_PHASE_CLOSED 1
#define DOOR_PHASE_CLOSING 2
#define DOOR_PHASE_OPENING 3

#define DOOR_CLOSE_FLAG_REQUESTED 1
#define DOOR_CLOSE_FLAG_READY 2

typedef struct DoorPlacement
{
    ObjPlacement head; /* 0x00 */
    s16 closeRequestGameBit; /* 0x18: nonzero requests that the door close */
    s16 closedLatchGameBit;  /* 0x1A: set after closing, cleared after opening */
    s16 triggerSequenceId;   /* 0x1C */
    u8 runSequenceId;        /* 0x1E */
    u8 rotXByte;             /* 0x1F: high byte of initial anim.rotX */
    u8 triggerArg;           /* 0x20: low 7 bits passed to preempt sequence */
    u8 rootMotionScaleInput; /* 0x21: scale in 1/64 units */
    s16 closeReadyGameBit;   /* 0x22: closure waits for this bit, or -1 */
    s16 unk24;
    u8 pad26[0x28 - 0x26];
} DoorPlacement;

STATIC_ASSERT(offsetof(DoorPlacement, closeRequestGameBit) == 0x18);
STATIC_ASSERT(offsetof(DoorPlacement, rootMotionScaleInput) == 0x21);
STATIC_ASSERT(sizeof(DoorPlacement) == 0x28);

/* Per-door state block (GameObject->extra, Door_getExtraSize == 0x8). */
typedef struct DoorState
{
    u16 movementSfx; /* 0x0: looping sfx played while opening/closing */
    u16 endpointSfx; /* 0x2: sfx played when fully opened or closed */
    u8 phase;        /* 0x4: DOOR_PHASE_* */
    u8 initPending;  /* 0x5: Door_update one-shot trigger flag */
    u8 closeFlags;   /* 0x6: DOOR_CLOSE_FLAG_* */
    u8 pad7[0x8 - 0x7];
} DoorState;

int Door_animEventCallback(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int i;
    DoorState* state;
    DoorPlacement* def;
    int closeRequested;
    int closeReady;
    ObjTextureRuntimeSlot* tex;
    int ret;

    state = (DoorState*)((GameObject*)obj)->extra;
    def = (DoorPlacement*)((GameObject*)obj)->anim.placementData;
    if (((GameObject*)obj)->anim.alpha == 0)
    {
        ObjHits_DisableObject((GameObject*)obj);
    }
    if (((GameObject*)obj)->anim.modelInstance->textureSlotCount != 0)
    {
        if ((state->closeFlags & DOOR_CLOSE_FLAG_REQUESTED) != 0)
        {
            tex = objFindTexture((GameObject*)obj, 0, 0);
            if (tex != NULL)
            {
                tex->textureId = 0x100;
            }
        }
        if ((state->closeFlags & DOOR_CLOSE_FLAG_READY) != 0)
        {
            tex = objFindTexture((GameObject*)obj, 1, 0);
            if (tex != NULL)
            {
                tex->textureId = 0x100;
            }
        }
    }
    if (state->phase == DOOR_PHASE_OPEN)
    {
        closeRequested = mainGetBit(def->closeRequestGameBit);
        closeReady = 0;
        if ((def->closeReadyGameBit == -1) || (mainGetBit(def->closeReadyGameBit) != 0))
        {
            closeReady = 1;
        }
        if ((closeRequested != 0) && ((state->closeFlags & DOOR_CLOSE_FLAG_REQUESTED) == 0))
        {
            if (((GameObject*)obj)->anim.modelInstance->textureSlotCount != 0)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_littletink22);
            }
            state->closeFlags |= DOOR_CLOSE_FLAG_REQUESTED;
        }
        if ((closeReady != 0) && ((state->closeFlags & DOOR_CLOSE_FLAG_READY) == 0))
        {
            if (((GameObject*)obj)->anim.modelInstance->textureSlotCount != 0)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_littletink22);
            }
            state->closeFlags |= DOOR_CLOSE_FLAG_READY;
        }
        if (state->closeFlags == (DOOR_CLOSE_FLAG_REQUESTED | DOOR_CLOSE_FLAG_READY))
        {
            state->phase = DOOR_PHASE_CLOSING;
            if (state->movementSfx != 0)
            {
                Sfx_PlayFromObject(obj, state->movementSfx);
            }
        }
    }
    else if (state->phase == DOOR_PHASE_CLOSED)
    {
        if (mainGetBit(def->closeRequestGameBit) == 0)
        {
            state->phase = DOOR_PHASE_OPENING;
            if (state->movementSfx != 0)
            {
                Sfx_PlayFromObject(obj, state->movementSfx);
            }
        }
    }
    if (state->phase == DOOR_PHASE_CLOSING)
    {
        for (i = 0; i < animUpdate->eventCount; i++)
        {
            if (animUpdate->eventIds[i] == 2)
            {
                state->phase = DOOR_PHASE_CLOSED;
                if (def->closedLatchGameBit != -1)
                {
                    mainSetBits(def->closedLatchGameBit, 1);
                }
                if ((state->movementSfx != 0) &&
                    (Sfx_IsPlayingFromObject(obj, state->movementSfx) != 0))
                {
                    Sfx_StopFromObject(obj, state->movementSfx);
                }
                if (state->endpointSfx != 0)
                {
                    Sfx_PlayFromObject(obj, state->endpointSfx);
                }
            }
        }
    }
    else if (state->phase == DOOR_PHASE_OPENING)
    {
        for (i = 0; i < animUpdate->eventCount; i++)
        {
            if (animUpdate->eventIds[i] == 1)
            {
                state->phase = DOOR_PHASE_OPEN;
                state->closeFlags = 0;
                if (def->closedLatchGameBit != -1)
                {
                    mainSetBits(def->closedLatchGameBit, 0);
                }
                if ((state->movementSfx != 0) &&
                    (Sfx_IsPlayingFromObject(obj, state->movementSfx) != 0))
                {
                    Sfx_StopFromObject(obj, state->movementSfx);
                }
                if (state->endpointSfx != 0)
                {
                    Sfx_PlayFromObject(obj, state->endpointSfx);
                }
            }
        }
    }
    ret = 0;
    if ((state->phase != DOOR_PHASE_CLOSING) && (state->phase != DOOR_PHASE_OPENING))
    {
        ret = 1;
    }
    return ret;
}

int Door_getExtraSize(void) { return 0x8; }

void Door_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible) { objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f); }

void Door_update(GameObject *obj)
{
    DoorState* state;
    DoorPlacement* def;
    int triggerArg;
    int triggerId;

    state = (DoorState*)(obj)->extra;
    def = (DoorPlacement*)(obj)->anim.placementData;
    if (state->initPending != 0)
    {
        triggerId = def->triggerSequenceId;
        if ((triggerId != 0) && (state->phase != DOOR_PHASE_OPEN))
        {
            triggerArg = def->triggerArg & 0x7f;
            (*gObjectTriggerInterface)->preempt((int)obj, triggerId);
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

void Door_init(GameObject* obj, DoorPlacement* def)
{
    DoorState* state = (DoorState*)obj->extra;
    state->initPending = 1;
    obj->anim.rotX = (s16)(def->rotXByte << 8);
    obj->animEventCallback = Door_animEventCallback;
    obj->objectFlags = (u16)(obj->objectFlags | DOOR_OBJFLAG_HITDETECT_DISABLED);
    obj->anim.rootMotionScale = (f32)(u32)def->rootMotionScaleInput / 64.0f;
    if (!obj->anim.rootMotionScale)
    {
        obj->anim.rootMotionScale = 1.0f;
    }
    obj->anim.rootMotionScale =
        obj->anim.rootMotionScale * obj->anim.modelInstance->rootMotionScaleBase;
    if (def->closedLatchGameBit != -1)
    {
        state->phase = mainGetBit(def->closedLatchGameBit);
    }
    else
    {
        state->phase = DOOR_PHASE_OPEN;
    }
    state->closeFlags = 0;
    if (mainGetBit(def->closeRequestGameBit) != 0)
        state->closeFlags = (u8)(state->closeFlags | DOOR_CLOSE_FLAG_REQUESTED);
    if (mainGetBit(def->closeReadyGameBit) != 0)
        state->closeFlags = (u8)(state->closeFlags | DOOR_CLOSE_FLAG_READY);
    {
        s16 model = obj->anim.seqId;
        switch (model)
        {
        case 1101:
            {
                s32 subtype = obj->anim.mapEventSlot;
                switch (subtype)
                {
                case 31:
                case 32:
                case 33:
                case 34:
                case 40:
                case 41:
                case 42:
                    state->movementSfx = 832;
                    state->endpointSfx = 833;
                    break;
                default:
                    state->movementSfx = 1154;
                    state->endpointSfx = 1155;
                    break;
                }
                break;
            }
        case 358:
            state->movementSfx = 275;
            state->endpointSfx = 504;
            break;
        }
    }
}

ObjectDescriptor gDoorObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0, 0, 0,
    (ObjectDescriptorCallback)Door_init,
    (ObjectDescriptorCallback)Door_update,
    0,
    (ObjectDescriptorCallback)Door_render,
    0, 0,
    Door_getExtraSize,
};
