/*
 * slidingdoor (DLL 0x15D) - a proximity-triggered sliding door object.
 *
 * The 3-bit door state (top bits of state byte 0) is a 4-state machine:
 *   0 closed, 1 open, 2 opening, 3 closing.
 * SlidingDoor_SeqFn (installed as the anim/think callback) opens the door
 * when its openGameBit (gated by gateGameBit) is set AND the player or
 * Tricky is within 130.0f xz-distance, and closes it again when
 * neither is near. The opening/closing transitions complete on the matching
 * trigger command (1=close-done, 2=open-done). SeqFn returns 1 in the steady
 * states and 0 mid-transition.
 *
 * SlidingDoor_update fires once (latched via obj->userData1): it preempts the
 * placement's preemptEvent if the door is already moving and runs the
 * placement's startup sequence (-1 = none).
 */
#include "main/object.h"
#include "main/object_descriptor.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/objseq.h"
#include "main/object_api.h"
#include "main/vecmath_distance_api.h"
#include "main/object_render.h"
#include "main/dll/dll_015D_slidingdoor.h"


int SlidingDoor_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    register int playerNear;
    register int trickyNear;
    register SlidingdoorState* state;
    SlidingdoorPlacement* placement;
    u32 mode;
    int result;
    GameObject* player;
    GameObject* tricky;

    player = Obj_GetPlayerObject();
    tricky = getTrickyObject();

    if (player != NULL)
    {
        playerNear =
            Vec_xzDistance(&obj->anim.worldPosX, &player->anim.worldPosX) < 130.0f;
    }
    else
    {
        playerNear = 0;
    }

    if (tricky != NULL)
    {
        trickyNear = Vec_xzDistance(&obj->anim.worldPosX, &tricky->anim.worldPosX) < 130.0f;
    }
    else
    {
        trickyNear = 0;
    }

    state = obj->extra;
    placement = (SlidingdoorPlacement*)obj->anim.placementData;
    mode = state->mode;

    if (mode == SLIDINGDOOR_MODE_CLOSED)
    {
        if (mainGetBit(placement->openGameBit) != 0 &&
            (placement->gateGameBit == -1 || mainGetBit(placement->gateGameBit) != 0))
        {
            mainSetBits(placement->openedGameBit, 1);
            if (playerNear != 0 || trickyNear != 0)
            {
                state->mode = SLIDINGDOOR_MODE_OPENING;
            }
        }
    }
    else if (mode == SLIDINGDOOR_MODE_OPEN)
    {
        if ((mainGetBit(placement->openGameBit) != 0 ||
             (placement->gateGameBit != -1 && mainGetBit(placement->gateGameBit) != 0)) &&
            playerNear == 0 && trickyNear == 0)
        {
            ((SlidingdoorState*)state)->mode = SLIDINGDOOR_MODE_CLOSING;
        }
    }

    {
        register SlidingdoorState* fl = state;
        if (fl->mode == SLIDINGDOOR_MODE_OPENING)
        {
            if (animUpdate->triggerCommand == 2)
            {
                fl->mode = SLIDINGDOOR_MODE_OPEN;
            }
        }
        else if (fl->mode == SLIDINGDOOR_MODE_CLOSING)
        {
            if (animUpdate->triggerCommand == 1)
            {
                fl->mode = SLIDINGDOOR_MODE_CLOSED;
            }
        }
    }

    result = 0;
    {
        u32 modeAfter = state->mode;
        if (modeAfter != SLIDINGDOOR_MODE_OPENING)
        {
            if (modeAfter != SLIDINGDOOR_MODE_CLOSING)
                result = 1;
        }
    }
    return result;
}

int SlidingDoor_getExtraSize(void)
{
    return sizeof(SlidingdoorState);
}
int SlidingDoor_getObjectTypeId(void)
{
    return 0x0;
}

void SlidingDoor_free(void)
{
}

void SlidingDoor_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void SlidingDoor_hitDetect(void)
{
}

void SlidingDoor_update(GameObject* obj)
{
    SlidingdoorState* state;
    SlidingdoorPlacement* placement;
    if (obj->userData1 != 0)
        return;
    state = obj->extra;
    placement = (SlidingdoorPlacement*)obj->anim.placementData;
    if (placement->preemptEvent != 0)
    {
        u32 mode = state->mode;
        if (mode != SLIDINGDOOR_MODE_CLOSED)
        {
            (*gObjectTriggerInterface)->preempt((int)obj, placement->preemptEvent);
        }
    }
    {
        s8 id = placement->startupSequenceId;
        if (id != -1)
        {
            (*gObjectTriggerInterface)->runSequence(id, obj, -1);
        }
    }
    obj->userData1 = 1;
}

void SlidingDoor_init(GameObject* obj, SlidingdoorPlacement* placement)
{
    SlidingdoorState* state;
    f32 scale;
    u32 doorState = 0;
    obj->userData1 = doorState;
    obj->anim.rotX = (s16)(placement->rotXByte << 8);
    obj->animEventCallback = SlidingDoor_SeqFn;
    scale = (f32)(u32)placement->scaleByte / 64.0f;
    obj->anim.rootMotionScale = scale;
    obj->anim.rootMotionScale =
        obj->anim.rootMotionScale * obj->anim.modelInstance->rootMotionScaleBase;
    state = obj->extra;
    state->mode = doorState;
}

void SlidingDoor_release(void)
{
}

void SlidingDoor_initialise(void)
{
}

ObjectDescriptor gSlidingDoorObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)SlidingDoor_initialise,
    (ObjectDescriptorCallback)SlidingDoor_release,
    0,
    (ObjectDescriptorCallback)SlidingDoor_init,
    (ObjectDescriptorCallback)SlidingDoor_update,
    (ObjectDescriptorCallback)SlidingDoor_hitDetect,
    (ObjectDescriptorCallback)SlidingDoor_render,
    (ObjectDescriptorCallback)SlidingDoor_free,
    (ObjectDescriptorCallback)SlidingDoor_getObjectTypeId,
    SlidingDoor_getExtraSize,
};
