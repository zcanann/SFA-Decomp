/*
 * androssligh (DLL 0x2BF) - the lightning beam between Andross's hands in
 * the final boss fight. It locks onto a light-anchor object (0x47dd9),
 * mirroring that object's position each frame, and in its active state
 * (ANDROSSLIGH_ACTIVE) builds a screen-space lightning bolt that arcs
 * across the gap between the two hands. The bolt is rebuilt via
 * lightningCreate the first frame and aged each frame until its phase
 * counter reaches the end, then freed. State is driven externally through
 * androssligh_setState (called by androssbrain on defeat).
 *
 * This DLL has no initialise/release entry points (none exist in the retail
 * symbol table); it is a sub-object whose lifetime is driven externally.
 */
#include "dolphin/mtx.h"
#include "main/camera.h"
#include "main/frame_timing.h"
#include "main/mm.h"
#include "main/object_api.h"
#include "main/newclouds.h"
#include "main/shader_api.h"
#include "main/dll/dll_02BF_androssligh.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"

enum
{
    ANDROSSLIGH_ANCHOR_OBJ_ID = 0x47dd9
};

void androssligh_updateBeam(GameObject* obj, AndrossLighState* state)
{
    Vec start;
    Vec end;
    Vec offset;

    start.x = obj->anim.localPosX - lbl_803DC528;
    start.y = obj->anim.localPosY;
    start.z = obj->anim.localPosZ;
    end.x = obj->anim.localPosX + lbl_803DC528;
    end.y = start.y;
    end.z = start.z;
    offset.x = start.x - playerMapOffsetX;
    offset.y = start.y;
    offset.z = start.x - playerMapOffsetZ;
    PSMTXMultVec((MtxP)Camera_GetViewMatrix(), &offset, &offset);
    offset.x = -offset.x;
    offset.y = -offset.y;
    offset.z = -offset.z;
    PSVECScale(&offset, &offset, lbl_803DC52C);
    PSMTXMultVec((MtxP)Camera_GetInverseViewRotationMatrix(), &offset, &offset);
    PSVECAdd(&start, &offset, &start);
    offset.x = end.x - playerMapOffsetX;
    offset.y = end.y;
    offset.z = end.x - playerMapOffsetZ;
    PSMTXMultVec((MtxP)Camera_GetViewMatrix(), &offset, &offset);
    offset.x = -offset.x;
    offset.y = -offset.y;
    offset.z = -offset.z;
    PSVECScale(&offset, &offset, lbl_803DC52C);
    PSMTXMultVec((MtxP)Camera_GetInverseViewRotationMatrix(), &offset, &offset);
    PSVECAdd(&end, &offset, &end);
    if (state->bolt == NULL)
    {
        state->bolt = lightningCreateU16Promoted((const Vec3f*)&start, (const Vec3f*)&end, lbl_803DC518, lbl_803DC51C,
                                                 lbl_803DC520, lbl_803DC524, 0);
        state->boltAge = 0.0f;
    }
    else
    {
        state->boltAge += timeDelta;
        *(u16*)((int)state->bolt + 0x20) = (int)(0.5f + state->boltAge);
        if (*(u16*)((int)state->bolt + 0x20) >= *(u16*)((int)state->bolt + 0x22))
        {
            mm_free(state->bolt);
            state->bolt = NULL;
        }
    }
}

void androssligh_setState(GameObject* obj, AndrossLighMode newState, u8 force)
{
    AndrossLighState* state;

    if ((void*)obj == NULL)
    {
        return;
    }
    state = (obj)->extra;
    if (state->state == ANDROSSLIGH_DONE)
    {
        if (force == 0)
        {
            return;
        }
    }
    state->state = newState;
}

int androssligh_getExtraSize(void)
{
    return sizeof(AndrossLighState);
}

int androssligh_getObjectTypeId(void)
{
    return 0;
}

void androssligh_free(void)
{
}

void androssligh_render(GameObject* obj)
{
    void* bolt = ((AndrossLighState*)obj->extra)->bolt;

    if (bolt != NULL)
    {
        lightningRender(bolt);
    }
}

void androssligh_hitDetect(void)
{
}

void androssligh_update(GameObject* obj)
{
    AndrossLighState* state = (obj)->extra;

    if (state->anchor == NULL)
    {
        state->anchor = ObjList_FindObjectById(ANDROSSLIGH_ANCHOR_OBJ_ID);
    }
    if (state->anchor != NULL)
    {
        (obj)->anim.localPosX = state->anchor->anim.localPosX;
        (obj)->anim.localPosY = state->anchor->anim.localPosY;
        (obj)->anim.localPosZ = state->anchor->anim.localPosZ;
    }
    state->prevState = state->state;
    switch (state->state)
    {
    case ANDROSSLIGH_IDLE:
        break;
    case ANDROSSLIGH_ACTIVE:
        androssligh_updateBeam(obj, state);
        break;
    case ANDROSSLIGH_DONE:
        break;
    }
}

void androssligh_init(void)
{
}

ObjectDescriptor gAndrossLighObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)androssligh_init,
    (ObjectDescriptorCallback)androssligh_update,
    (ObjectDescriptorCallback)androssligh_hitDetect,
    (ObjectDescriptorCallback)androssligh_render,
    (ObjectDescriptorCallback)androssligh_free,
    (ObjectDescriptorCallback)androssligh_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)androssligh_getExtraSize,
};
