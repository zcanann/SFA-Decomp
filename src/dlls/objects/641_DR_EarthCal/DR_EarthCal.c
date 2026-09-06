/* DR_EarthCal (DLL 641) */
#include "main/dll/player_api.h"
#include "dlls/objects/common/vehicle.h"
#include "main/dll/DR/dll_0281_drearthcal.h"
#include "main/dll/tricky_api.h"
#include "main/obj_trigger.h"
#include "main/objfx.h"
#include "main/objtype.h"
#include "sys/objects.h"
#include "main/objseq.h"

int drearthcal_func0A(void)
{
    return 1;
}

int drearthcal_getExtraSize(void)
{
    return 1;
}

int drearthcal_getObjectTypeId(void)
{
    return 0;
}

void drearthcal_free(void)
{
}

void drearthcal_render(void)
{
}

void drearthcal_hitDetect(void)
{
}

void drearthcal_update(GameObject* obj)
{
    GameObject* player;
    int i;
    struct
    {
        f32 _pad[3];
        f32 vec[3];
    } part;
    f32 searchDist;

    player = Obj_GetPlayerObject();
    searchDist = 200.0f;
    if (playerGetFocusObject(player) != NULL)
    {
        obj->anim.resetHitboxFlags &= ~(INTERACT_FLAG_PROMPT_SUPPRESSED | INTERACT_FLAG_DISABLED);
        if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0)
        {
            setAButtonIcon(0x15);
        }
        if (ObjTrigger_IsSet(obj) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
        }
    }
    else
    {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        if (obj->anim.hitboxTransformState->contactObjectCount > 0)
            for (i = 0; i < obj->anim.hitboxTransformState->contactObjectCount; i++)
            {
                {
                    GameObject* elem = (GameObject*)obj->anim.hitboxTransformState->contactObjects[i];
                    if (elem == player)
                    {
                        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
                    }
                }
            }
        if ((u32)objGetNearestTypeTo(VEHICLE_OBJECT_GROUP, obj, &searchDist) == 0)
        {
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
        else
        {
            obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
        }
        if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0)
        {
            setAButtonIcon(0x14);
        }
        if (ObjTrigger_IsSet(obj) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(2, (void*)obj, -1);
        }
    }
    if ((obj->objectFlags & OBJECT_OBJFLAG_RENDERED) != 0)
    {
        part.vec[0] = 0.0f;
        part.vec[1] = 30.0f;
        part.vec[2] = 0.0f;
        objfx_spawnArcedBurst(obj, 5, 0.75f, 2, 2, 0xf, 18.0f, 18.0f, 2.0f,
                             &part, 0);
    }
}

void drearthcal_init(GameObject* obj, DREarthCalSetup* setup)
{
    obj->anim.rotX = (s16)(setup->yaw << 8);
    obj->objectFlags |= (OBJECT_OBJFLAG_HITDETECT_DISABLED | OBJECT_OBJFLAG_HIDDEN);
}

void drearthcal_release(void)
{
}

void drearthcal_initialise(void)
{
}

ObjectDescriptor12 gDrEarthCalObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
    (ObjectDescriptorCallback)drearthcal_initialise,
    (ObjectDescriptorCallback)drearthcal_release,
    0,
    (ObjectDescriptorCallback)drearthcal_init,
    (ObjectDescriptorCallback)drearthcal_update,
    (ObjectDescriptorCallback)drearthcal_hitDetect,
    (ObjectDescriptorCallback)drearthcal_render,
    (ObjectDescriptorCallback)drearthcal_free,
    (ObjectDescriptorCallback)drearthcal_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)drearthcal_getExtraSize,
    (ObjectDescriptorCallback)drearthcal_func0A,
    0,
};
