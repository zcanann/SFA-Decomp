#include "main/objlib.h"

/* Trivial 4b 0-arg blr leaves. */

/* 8b "li r3, N; blr" returners. */

/* render-with-objRenderFn_8003b8f4 pattern. */

#include "main/game_object.h"
#include "main/dll/DF/DFcradle.h"

extern uint GameBit_Get(int eventId);

extern f32 lbl_803E4DD0;
extern f32 lbl_803E4DD4;

int ccriverflow_getExtraSize(void)
{
    return 1;
}

void ccriverflow_free(CCriverflowObject* obj)
{
    if (obj->state->active != 0)
    {
        ObjGroup_RemoveObject((u32)obj, CCRIVERFLOW_OBJECT_GROUP);
    }
    return;
}

void ccriverflow_render(void)
{
}

void ccriverflow_update(CCriverflowObject* obj)
{
    uint isGameBitSet;
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
    return;
}

void ccriverflow_init(CCriverflowObject* obj, CCriverflowMapData* params)
{
    if (params->gameBit == -1)
    {
        ObjGroup_AddObject((u32)obj, CCRIVERFLOW_OBJECT_GROUP);
        obj->state->active = 1;
    }
    obj->angle = (u16)params->angleByte << 8;
    obj->height = obj->model->baseHeight;
    obj->height = (f32)(u32)
    params->heightOffset * lbl_803E4DD0 + obj->height;
    if (obj->height < lbl_803E4DD4)
    {
        obj->height = *(f32*)&lbl_803E4DD4;
    }
    if (params->speedByte == 0)
    {
        params->speedByte = CCRIVERFLOW_DEFAULT_SPEED;
    }
    return;
}

void fn_801C0BF8(void* templateData, int angle, float* startNode, float* endNode, short* out);
