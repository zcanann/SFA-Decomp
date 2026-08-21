/*
 * Ocean Force Point Temple spellstone placement. It remains enabled while its
 * activation GameBit is set; when the placement sequence completes it sets
 * the completion GameBit, clears the activation bit, and disables itself.
 */
#include "main/dll/CF/laser.h"
#include "main/game_ui_interface.h"
#include "main/gamebits_api.h"
#include "main/mapEventTypes.h"
#include "main/objprint_render_api.h"

int DFPSpPl_getExtraSize(void)
{
    return sizeof(LaserState);
}

int DFPSpPl_getObjectTypeId(void)
{
    return 0;
}

void DFPSpPl_free(void)
{
}

void DFPSpPl_render(void)
{
}

void DFPSpPl_hitDetect(void)
{
}

void DFPSpPl_update(GameObject* obj)
{
    LaserState* state;
    u32 activationGameBitSet;
    int eventReady;
    int mode;

    if ((((LaserState*)obj->extra)->completionLatched == '\0') &&
        (activationGameBitSet = mainGetBit((int)((LaserState*)obj->extra)->activationGameBit), activationGameBitSet != 0))
    {
        obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags & ~INTERACT_FLAG_DISABLED;
    }
    else
    {
        obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED;
    }
    objUpdateHitVolumeTransforms(obj);
    if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0)
    {
        mode = (u8)(*gMapEventInterface)->getMapAct((int)obj->anim.mapEventSlot);
        switch (mode)
        {
        case LASEROBJ_MODE_SEQUENCE_A:
            state = obj->extra;
            eventReady = (*gGameUIInterface)->isItemBeingUsed(LASEROBJ_SEQUENCE_A_EVENT);
            if (eventReady != 0)
            {
                mainSetBits((int)state->completionGameBit, 1);
                mainSetBits((int)state->activationGameBit, 0);
                state->completionLatched = 1;
                obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED;
            }
            break;
        case LASEROBJ_MODE_SEQUENCE_B:
            state = obj->extra;
            eventReady = (*gGameUIInterface)->isItemBeingUsed(LASEROBJ_SEQUENCE_B_EVENT);
            if (eventReady != 0)
            {
                mainSetBits((int)state->completionGameBit, 1);
                mainSetBits((int)state->activationGameBit, 0);
                state->completionLatched = 1;
                obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED;
                (*gMapEventInterface)->setMapAct(LASEROBJ_SEQUENCE_B_MODE_MAP_A, LASEROBJ_SEQUENCE_B_MODE_A);
                (*gMapEventInterface)->setMapAct(LASEROBJ_SEQUENCE_B_MODE_MAP_B, LASEROBJ_SEQUENCE_B_MODE_B);
            }
            break;
        }
    }
    return;
}

void DFPSpPl_init(GameObject* obj, LaserObjectMapData* mapData)
{
    LaserState* state;
    u32 completionGameBitSet;

    state = obj->extra;
    state->completionGameBit = mapData->completionGameBit;
    state->activationGameBit = mapData->activationGameBit;
    state->completionLatched = 0;
    obj->anim.rotX = (s16)(mapData->yawByte << LASEROBJ_YAW_BYTE_SHIFT);
    completionGameBitSet = mainGetBit((int)state->completionGameBit);
    if (completionGameBitSet != 0)
    {
        state->completionLatched = 1;
        obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED;
    }
    obj->objectFlags = (u16)(obj->objectFlags | (OBJECT_OBJFLAG_HITDETECT_DISABLED | OBJECT_OBJFLAG_HIDDEN));
    return;
}

void DFPSpPl_release(void)
{
}

void DFPSpPl_initialise(void)
{
}

ObjectDescriptor gLaserObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    DFPSpPl_initialise,
    DFPSpPl_release,
    0,
    (ObjectDescriptorCallback)DFPSpPl_init,
    (ObjectDescriptorCallback)DFPSpPl_update,
    DFPSpPl_hitDetect,
    DFPSpPl_render,
    DFPSpPl_free,
    (ObjectDescriptorCallback)DFPSpPl_getObjectTypeId,
    DFPSpPl_getExtraSize,
};
