/*
 * WCTrexStatu (DLL 658) - a T-Rex statue prop in the Walled City (WC).
 *
 * The statue starts lowered and is "raised" by a map event: at init, if
 * the object's map-event act is already RAISED (and we are not restoring
 * from a save), it is nudged up by a fixed height. Once triggered - either
 * because its raisedBit game bit is already set at init, or via anim event
 * WCTREXSTATU_CALLBACK_TRIGGER - it swaps to the triggered texture and sets
 * userData1, after which hitDetect periodically emits a dust particle effect.
 * getObjectTypeId picks the render model from the placement's modelIndex.
 */
#include "main/dll/partfx_interface.h"
#include "main/dll/WC/dll_0292_wctrexstatu.h"
#include "main/gamebits.h"
#include "main/mapEventTypes.h"
#include "main/objtexture.h"
#include "main/object_render.h"
#include "main/vecmath.h"
#include "main/objseq.h"

#define WCTREXSTATU_CALLBACK_TRIGGER 1

#define WCTREXSTATU_RENDER_TYPE_BASE      0x400
#define WCTREXSTATU_RENDER_TYPE_SHIFT     0xb
#define WCTREXSTATU_TEXTURE_TRIGGERED     0x100
#define WCTREXSTATU_PARTFX_VARIANT_0      0x73f
#define WCTREXSTATU_PARTFX_VARIANT_1      0x740
#define WCTREXSTATU_PARTFX_CHANCE         5
#define WCTREXSTATU_PARTFX_KIND           2
#define WCTREXSTATU_PARTFX_INVALID_HANDLE -1

#define WCTREXSTATU_MAPEVENT_RAISED 2

int wctrexstatu_interactCallback(GameObject* obj, int unused, ObjSeqState* animUpdate)
{
    int i;

    for (i = 0; i < animUpdate->eventCount; i++)
    {
        if (animUpdate->eventIds[i] == WCTREXSTATU_CALLBACK_TRIGGER)
        {
            ObjTextureRuntimeSlot* texture = objFindTexture(obj, 0, 0);

            if (texture != NULL)
            {
                texture->textureId = WCTREXSTATU_TEXTURE_TRIGGERED;
            }
            obj->userData1 = 1;
        }
    }

    return 0;
}

int wctrexstatu_getExtraSize(void)
{
    return 0;
}

int wctrexstatu_getObjectTypeId(GameObject* obj)
{
    ObjAnimComponent* objAnim = &obj->anim;
    int modelIndex = ((WCTrexStatueSetup*)obj->anim.placementData)->modelIndex;
    int modelCount = objAnim->modelInstance->modelCount;

    if (modelIndex >= modelCount)
    {
        modelIndex = 0;
    }
    return (modelIndex << WCTREXSTATU_RENDER_TYPE_SHIFT) | WCTREXSTATU_RENDER_TYPE_BASE;
}

void wctrexstatu_free(void)
{
}

void wctrexstatu_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
    }
}

void wctrexstatu_hitDetect(GameObject* obj)
{
    ObjAnimComponent* objAnim = &obj->anim;
    GameObject* gameObj = obj;

    if (gameObj->userData1 != 0 && randomGetRange(0, WCTREXSTATU_PARTFX_CHANCE) == 0)
    {
        if (objAnim->bankIndex == 0)
        {
            (*gPartfxInterface)
                ->spawnEffect(obj, WCTREXSTATU_PARTFX_VARIANT_0, NULL, WCTREXSTATU_PARTFX_KIND,
                              WCTREXSTATU_PARTFX_INVALID_HANDLE, obj);
        }
        else
        {
            (*gPartfxInterface)
                ->spawnEffect(obj, WCTREXSTATU_PARTFX_VARIANT_1, NULL, WCTREXSTATU_PARTFX_KIND,
                              WCTREXSTATU_PARTFX_INVALID_HANDLE, obj);
        }
    }
}

void wctrexstatu_update(void)
{
}

void wctrexstatu_init(GameObject* obj, WCTrexStatueSetup* setup, int fromLoad)
{
    ObjAnimComponent* objAnim = &obj->anim;
    obj->animEventCallback = wctrexstatu_interactCallback;
    objAnim->bankIndex = setup->modelIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }

    obj->anim.rotX = (s16)(setup->type << 8);
    if (fromLoad == 0)
    {
        if ((*gMapEventInterface)->getMapAct(obj->anim.mapEventSlot) == WCTREXSTATU_MAPEVENT_RAISED)
        {
            obj->anim.localPosY += 30.0f;
        }
    }

    if (mainGetBit(setup->raisedBit) != 0)
    {
        ObjTextureRuntimeSlot* texture = objFindTexture(obj, 0, 0);

        if (texture != NULL)
        {
            texture->textureId = WCTREXSTATU_TEXTURE_TRIGGERED;
        }
        obj->userData1 = 1;
    }
}

void wctrexstatu_release(void)
{
}

void wctrexstatu_initialise(void)
{
}

ObjectDescriptor gWCTrexStatuObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)wctrexstatu_initialise, (ObjectDescriptorCallback)wctrexstatu_release, 0,
    (ObjectDescriptorCallback)wctrexstatu_init, (ObjectDescriptorCallback)wctrexstatu_update,
    (ObjectDescriptorCallback)wctrexstatu_hitDetect, (ObjectDescriptorCallback)wctrexstatu_render,
    (ObjectDescriptorCallback)wctrexstatu_free, (ObjectDescriptorCallback)wctrexstatu_getObjectTypeId,
    wctrexstatu_getExtraSize,
};
