/*
 * cfdoorlight (DLL 0x131) - door-light texture animator at CF
 * (CloudRunner Fortress). Once the placement's trigger game bit is set,
 * runs the object's texture animation from frame 0 forward by frameStep
 * per tick (frames in 1/256 units). On passing maxFrame it either loops
 * back to resetFrame (doneEvent == -1) or grants the done game bit and
 * parks the frame at maxFrame. init re-checks the done bit so a
 * revisited map keeps an already-finished light lit.
 */
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/objtexture.h"
#include "main/gamebits.h"

#define CFDOORLIGHT_OBJFLAG_HIDDEN 0x4000
#define CFDOORLIGHT_OBJFLAG_HITDETECT_DISABLED 0x2000

typedef struct CfDoorLightFlags
{
    u8 unk80 : 1;
    u8 done : 1;   /* 0x40: done event granted; frame parked at maxFrame */
    u8 active : 1; /* 0x20: texture animation running */
    u8 rest : 5;
} CfDoorLightFlags;

typedef struct CfDoorLightState
{
    s32 textureId;          /* 0x00: texture searched for the frame word (always 0) */
    u8 frameStep;           /* 0x04: frame advance per tick, 1/256 frames */
    u8 pad05[0x8 - 0x5];
    s32 maxFrame;           /* 0x08: last frame, 1/256 frames */
    s32 resetFrame;         /* 0x0C: loop-back frame, 1/256 frames */
    s32 currentFrame;       /* 0x10 */
    CfDoorLightFlags flags; /* 0x14 */
    u8 pad15[0x18 - 0x15];
} CfDoorLightState;

typedef struct CfDoorLightMapData
{
    ObjPlacement base;
    s8 resetFrame;   /* 0x18: loop-back frame in whole frames */
    s8 rotXByte;     /* 0x19: rotX in 1/128 turns */
    s16 maxFrame;    /* 0x1A: last frame in whole frames */
    s16 frameStep;   /* 0x1C: frame advance per tick, 1/256 frames */
    s16 doneEvent;   /* 0x1E: game bit granted at animation end (-1 = loop) */
    s16 triggerEvent;/* 0x20: game bit arming the animation */
} CfDoorLightMapData;

STATIC_ASSERT(offsetof(CfDoorLightState, frameStep) == 0x04);
STATIC_ASSERT(offsetof(CfDoorLightState, maxFrame) == 0x08);
STATIC_ASSERT(offsetof(CfDoorLightState, currentFrame) == 0x10);
STATIC_ASSERT(offsetof(CfDoorLightState, flags) == 0x14);
STATIC_ASSERT(sizeof(CfDoorLightState) == 0x18);
STATIC_ASSERT(offsetof(CfDoorLightMapData, resetFrame) == 0x18);
STATIC_ASSERT(offsetof(CfDoorLightMapData, doneEvent) == 0x1E);
STATIC_ASSERT(offsetof(CfDoorLightMapData, triggerEvent) == 0x20);

int cf_doorlight_getExtraSize(void) { return sizeof(CfDoorLightState); }

int cf_doorlight_getObjectTypeId(void) { return 0x0; }

void cf_doorlight_free(void)
{
}

void cf_doorlight_render(void)
{
}

void cf_doorlight_hitDetect(void)
{
}

/* obj is a word here, not a pointer: target colors it r30 UNDER the state
   copy (r31) = the integral-param pool (CLAUDE.md recipe #126). */
void cf_doorlight_update(int obj)
{
    CfDoorLightState* state;
    CfDoorLightMapData* def;
    ObjTextureRuntimeSlot* textureFrame;

    state = ((GameObject*)obj)->extra;
    def = (CfDoorLightMapData*)((GameObject*)obj)->anim.placement;
    if (state->flags.active == 0 && GameBit_Get(def->triggerEvent) != 0 && state->flags.done == 0)
    {
        state->flags.active = 1;
        state->currentFrame = 0;
    }
    if (state->flags.active != 0)
    {
        textureFrame = objFindTexture((void*)obj, state->textureId, 0);
        if (textureFrame != 0)
        {
            state->currentFrame += state->frameStep;
            if (state->currentFrame < 0)
            {
                state->currentFrame = 0;
            }
            else if (state->currentFrame > state->maxFrame)
            {
                if (def->doneEvent != -1)
                {
                    GameBit_Set(def->doneEvent, 1);
                    state->flags.active = 0;
                    state->flags.done = 1;
                    state->currentFrame = state->maxFrame;
                }
                else
                {
                    state->currentFrame = state->resetFrame;
                }
            }
            textureFrame->textureId = state->currentFrame;
        }
    }
}

void cf_doorlight_init(GameObject* obj, CfDoorLightMapData* mapData)
{
    register CfDoorLightState* state = obj->extra;
    state->textureId = 0;
    obj->anim.rotX = (s16)(mapData->rotXByte << 9);
    state->maxFrame = mapData->maxFrame << 8;
    state->frameStep = mapData->frameStep;
    state->resetFrame = mapData->resetFrame << 8;
    if (state->flags.done = GameBit_Get(mapData->doneEvent))
    {
        state->currentFrame = state->maxFrame;
        state->flags.active = 1;
    }
    obj->objectFlags |= CFDOORLIGHT_OBJFLAG_HITDETECT_DISABLED;
    obj->objectFlags |= CFDOORLIGHT_OBJFLAG_HIDDEN;
}

void cf_doorlight_release(void)
{
}

void cf_doorlight_initialise(void)
{
}
