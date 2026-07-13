/*
 * DragonRock Palace spellstone placement slot (DLL 0x237; "DFPSpPl").
 * A LaserObject spellplace: enabled while its activationGameBit is set; when
 * the placement sequence event completes it sets completionGameBit, clears the
 * activation bit, and disables itself. Sibling of vfpspellplace (VFP).
 */
#include "main/dll/CF/laser.h"
#include "main/game_object.h"
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

void DFPSpPl_update(LaserObject* obj)
{
    LaserState* state;
    u32 activationGameBitSet;
    int eventReady;
    int mode;

    if ((obj->state->completionLatched == '\0') &&
        (activationGameBitSet = mainGetBit((int)obj->state->activationGameBit), activationGameBitSet != 0))
    {
        obj->statusFlags = (u8)(obj->statusFlags & ~LASER_OBJECT_STATUS_DISABLED);
    }
    else
    {
        obj->statusFlags = (u8)(obj->statusFlags | LASER_OBJECT_STATUS_DISABLED);
    }
    objRenderFn_80041018((GameObject*)obj);
    if ((obj->statusFlags & LASER_OBJECT_STATUS_ACTIVE) != 0)
    {
        mode = (u8)(*gMapEventInterface)->getMapAct((int)obj->mapEventSlot);
        switch (mode)
        {
        case LASEROBJ_MODE_SEQUENCE_A:
            state = obj->state;
            eventReady = (*gGameUIInterface)->isEventReady(LASEROBJ_SEQUENCE_A_EVENT);
            if (eventReady != 0)
            {
                mainSetBits((int)state->completionGameBit, 1);
                mainSetBits((int)state->activationGameBit, 0);
                state->completionLatched = 1;
                obj->statusFlags = (u8)(obj->statusFlags | LASER_OBJECT_STATUS_DISABLED);
            }
            break;
        case LASEROBJ_MODE_SEQUENCE_B:
            state = obj->state;
            eventReady = (*gGameUIInterface)->isEventReady(LASEROBJ_SEQUENCE_B_EVENT);
            if (eventReady != 0)
            {
                mainSetBits((int)state->completionGameBit, 1);
                mainSetBits((int)state->activationGameBit, 0);
                state->completionLatched = 1;
                obj->statusFlags = (u8)(obj->statusFlags | LASER_OBJECT_STATUS_DISABLED);
                (*gMapEventInterface)->setMapAct(LASEROBJ_SEQUENCE_B_MODE_MAP_A, LASEROBJ_SEQUENCE_B_MODE_A);
                (*gMapEventInterface)->setMapAct(LASEROBJ_SEQUENCE_B_MODE_MAP_B, LASEROBJ_SEQUENCE_B_MODE_B);
            }
            break;
        }
    }
    return;
}

void DFPSpPl_init(LaserObject* obj, LaserObjectMapData* mapData)
{
    LaserState* state;
    u32 completionGameBitSet;

    state = obj->state;
    state->completionGameBit = mapData->completionGameBit;
    state->activationGameBit = mapData->activationGameBit;
    state->completionLatched = 0;
    obj->modeWord = (s16)(mapData->mapEventSlot << LASEROBJ_MODE_WORD_SHIFT);
    completionGameBitSet = mainGetBit((int)state->completionGameBit);
    if (completionGameBitSet != 0)
    {
        state->completionLatched = 1;
        obj->statusFlags = (u8)(obj->statusFlags | LASER_OBJECT_STATUS_DISABLED);
    }
    obj->objectFlags = (u16)(obj->objectFlags | LASER_OBJECT_FLAGS_SEQUENCE_CONTROL);
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
