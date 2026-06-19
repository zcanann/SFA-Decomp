/*
 * ccriverflow - Crystal Caves river-flow object (DLL 0x0174). A presence
 * object that joins/leaves render group CCRIVERFLOW_OBJECT_GROUP depending
 * on its placement gameBit: while the bit is clear the flow is shown, once
 * set it is removed. A gameBit of -1 means "always on". init also derives
 * the surface height from the model base height plus a placement offset.
 */
#include "main/objlib.h"
#include "main/game_object.h"
#include "main/dll/DF/DFcradle.h"
#include "main/gamebits.h"



extern f32 lbl_803E4DD0; /* height-offset scale */
extern f32 lbl_803E4DD4; /* minimum surface height */

int ccriverflow_getExtraSize(void)
{
    return sizeof(CCriverflowState);
}

void ccriverflow_free(CCriverflowObject* obj)
{
    if (obj->state->active != 0)
    {
        ObjGroup_RemoveObject((u32)obj, CCRIVERFLOW_OBJECT_GROUP);
    }
}

void ccriverflow_render(void)
{
}

void ccriverflow_update(CCriverflowObject* obj)
{
    u32 isGameBitSet;
    CCriverflowMapData* mapData;
    CCriverflowState* state;

    mapData = obj->mapData;
    if (mapData->gameBit != -1)
    {
        state = obj->state;
        isGameBitSet = GameBit_Get((int)mapData->gameBit);
        if (isGameBitSet != 0)
        {
            if (state->active != 0)
            {
                state->active = 0;
                ObjGroup_RemoveObject((u32)obj, CCRIVERFLOW_OBJECT_GROUP);
            }
        }
        else if (state->active == 0)
        {
            state->active = 1;
            ObjGroup_AddObject((u32)obj, CCRIVERFLOW_OBJECT_GROUP);
        }
    }
}

void ccriverflow_init(CCriverflowObject* obj, CCriverflowMapData* params)
{
    if (params->gameBit == -1)
    {
        ObjGroup_AddObject((u32)obj, CCRIVERFLOW_OBJECT_GROUP);
        obj->state->active = 1;
    }
    obj->angle = params->angleByte << 8;
    obj->height = obj->model->baseHeight;
    obj->height = (f32)(u32)params->heightOffset * lbl_803E4DD0 + obj->height;
    if (obj->height < lbl_803E4DD4)
    {
        obj->height = *(f32*)&lbl_803E4DD4;
    }
    if (params->speedByte == 0)
    {
        params->speedByte = CCRIVERFLOW_DEFAULT_SPEED;
    }
}
