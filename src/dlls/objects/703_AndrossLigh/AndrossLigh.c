/*
 * AndrossLigh (DLL 703 / 0x2BF) - the lightning beam between Andross's hands in
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
#include "main/frame_timing.h"
#include "main/mm.h"
#include "sys/objects.h"
#include "main/newclouds.h"
#include "main/shader_api.h"
#include "main/dll/dll_02BF_androssligh.h"
#include "dolphin/mtx/vec.h"
#include "main/camera.h"

enum
{
    ANDROSSLIGH_ANCHOR_OBJ_ID = 0x47dd9
};

f32 gAndrossLighRadiusX = 0.025f;
f32 gAndrossLighRadiusY = 0.1f;
f32 gAndrossLighLifetime = 10.0f;
f32 gAndrossLighWidth = 100.0f;
f32 gAndrossLighHalfLength = 300.0f;
f32 gAndrossLighViewOffsetScale = 0.05f;

void androssligh_updateBeam(GameObject* obj, AndrossLighState* state)
{
    Vec start;
    Vec end;
    Vec offset;

    start.x = obj->anim.localPosX - gAndrossLighHalfLength;
    start.y = obj->anim.localPosY;
    start.z = obj->anim.localPosZ;
    end.x = obj->anim.localPosX + gAndrossLighHalfLength;
    end.y = start.y;
    end.z = start.z;
    offset.x = start.x - playerMapOffsetX;
    offset.y = start.y;
    offset.z = start.x - playerMapOffsetZ;
    PSMTXMultVec((MtxP)Camera_GetViewMatrix(), &offset, &offset);
    offset.x = -offset.x;
    offset.y = -offset.y;
    offset.z = -offset.z;
    PSVECScale(&offset, &offset, gAndrossLighViewOffsetScale);
    PSMTXMultVec((MtxP)Camera_GetInverseViewRotationMatrix(), &offset, &offset);
    PSVECAdd(&start, &offset, &start);
    offset.x = end.x - playerMapOffsetX;
    offset.y = end.y;
    offset.z = end.x - playerMapOffsetZ;
    PSMTXMultVec((MtxP)Camera_GetViewMatrix(), &offset, &offset);
    offset.x = -offset.x;
    offset.y = -offset.y;
    offset.z = -offset.z;
    PSVECScale(&offset, &offset, gAndrossLighViewOffsetScale);
    PSMTXMultVec((MtxP)Camera_GetInverseViewRotationMatrix(), &offset, &offset);
    PSVECAdd(&end, &offset, &end);
    if (state->bolt == NULL)
    {
        state->bolt = lightningCreate((const Vec3f*)&start, (const Vec3f*)&end, gAndrossLighRadiusX,
                                      gAndrossLighRadiusY, gAndrossLighLifetime, gAndrossLighWidth, 0);
        state->boltAge = 0.0f;
    }
    else
    {
        state->boltAge += timeDelta;
        state->bolt->timer = (int)(0.5f + state->boltAge);
        if (state->bolt->timer >= state->bolt->lifetime)
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
    state = obj->extra;
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
    AndrossLighState* state = obj->extra;

    if (state->anchor == NULL)
    {
        state->anchor = ObjList_FindObjectById(ANDROSSLIGH_ANCHOR_OBJ_ID);
    }
    if (state->anchor != NULL)
    {
        obj->anim.localPosX = state->anchor->anim.localPosX;
        obj->anim.localPosY = state->anchor->anim.localPosY;
        obj->anim.localPosZ = state->anchor->anim.localPosZ;
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
