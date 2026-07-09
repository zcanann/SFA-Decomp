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
#include "main/dll/CF/dll_0131_cfdoorlight.h"

#define CFDOORLIGHT_OBJFLAG_HIDDEN             0x4000
#define CFDOORLIGHT_OBJFLAG_HITDETECT_DISABLED 0x2000

int CF_DoorLight_getExtraSize(void)
{
    return sizeof(CfDoorLightState);
}

int CF_DoorLight_getObjectTypeId(void)
{
    return 0x0;
}

void CF_DoorLight_free(void)
{
}

void CF_DoorLight_render(void)
{
}

void CF_DoorLight_hitDetect(void)
{
}

/* obj is a word here, not a pointer: target colors it r30 UNDER the state
   copy (r31) = the integral-param pool. */
void CF_DoorLight_update(struct GameObject* obj)
{
    CfDoorLightState* state;
    CfDoorLightMapData* def;
    ObjTextureRuntimeSlot* textureFrame;

    state = obj->extra;
    def = (CfDoorLightMapData*)obj->anim.placement;
    if (state->flags.active == 0 && mainGetBit(def->triggerEvent) != 0 && state->flags.done == 0)
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
                    mainSetBits(def->doneEvent, 1);
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

void CF_DoorLight_init(GameObject* obj, CfDoorLightMapData* mapData)
{
    register CfDoorLightState* state = obj->extra;
    state->textureId = 0;
    obj->anim.rotX = (s16)(mapData->rotXByte << 9);
    state->maxFrame = mapData->maxFrame << 8;
    state->frameStep = mapData->frameStep;
    state->resetFrame = mapData->resetFrame << 8;
    if (state->flags.done = mainGetBit(mapData->doneEvent))
    {
        state->currentFrame = state->maxFrame;
        state->flags.active = 1;
    }
    obj->objectFlags |= CFDOORLIGHT_OBJFLAG_HITDETECT_DISABLED;
    obj->objectFlags |= CFDOORLIGHT_OBJFLAG_HIDDEN;
}

void CF_DoorLight_release(void)
{
}

void CF_DoorLight_initialise(void)
{
}
