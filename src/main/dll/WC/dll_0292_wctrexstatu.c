/*
 * wctrexstatu (DLL 0x292) - a T-Rex statue prop in the Walled City (WC).
 *
 * The statue starts lowered and is "raised" by a map event: at init, if
 * the object's map-event act is already RAISED (and we are not restoring
 * from a save), it is nudged up by a fixed height. Once triggered - either
 * because its raisedBit game bit is already set at init, or via anim event
 * WCTREXSTATU_CALLBACK_TRIGGER - it swaps to the triggered texture and sets
 * unkF4, after which hitDetect periodically emits a dust particle effect.
 * getObjectTypeId picks the render model from the placement's modelIndex.
 */
#include "main/dll/WC/dll_0292_wctrexstatu.h"
#include "main/effect_interfaces.h"
#include "main/gamebits.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/objanim_update.h"
#include "main/objtexture.h"
#include "main/vecmath.h"
#include "main/object_render_legacy.h"

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

#pragma opt_strength_reduction off
int wctrexstatu_interactCallback(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int i;

    for (i = 0; i < animUpdate->eventCount; i++)
    {
        if (animUpdate->eventIds[i] == WCTREXSTATU_CALLBACK_TRIGGER)
        {
            ObjTextureRuntimeSlot* texture = objFindTexture((GameObject*)obj, 0, 0);

            if (texture != NULL)
            {
                texture->textureId = WCTREXSTATU_TEXTURE_TRIGGERED;
            }
            obj->unkF4 = 1;
        }
    }

    return 0;
}
#pragma opt_strength_reduction reset

int wctrexstatu_getExtraSize(void)
{
    return 0;
}

int wctrexstatu_getObjectTypeId(GameObject* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    int modelIndex = *(s8*)&((WCTrexStatueSetup*)obj->anim.placementData)->modelIndex;
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

void wctrexstatu_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E6E10);
    }
}

void wctrexstatu_hitDetect(GameObject* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    GameObject* gameObj = (GameObject*)obj;

    if (gameObj->unkF4 != 0 && randomGetRange(0, WCTREXSTATU_PARTFX_CHANCE) == 0)
    {
        if (objAnim->bankIndex == 0)
        {
            (*gPartfxInterface)
                ->spawnObject(obj, WCTREXSTATU_PARTFX_VARIANT_0, NULL, WCTREXSTATU_PARTFX_KIND,
                              WCTREXSTATU_PARTFX_INVALID_HANDLE, obj);
        }
        else
        {
            (*gPartfxInterface)
                ->spawnObject(obj, WCTREXSTATU_PARTFX_VARIANT_1, NULL, WCTREXSTATU_PARTFX_KIND,
                              WCTREXSTATU_PARTFX_INVALID_HANDLE, obj);
        }
    }
}

void wctrexstatu_update(void)
{
}

void wctrexstatu_init(GameObject* obj, WCTrexStatueSetup* setup, int fromLoad)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    obj->animEventCallback = wctrexstatu_interactCallback;
    *(u8*)&objAnim->bankIndex = setup->modelIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }

    obj->anim.rotX = (s16)(setup->type << 8);
    if (fromLoad == 0)
    {
        if ((*gMapEventInterface)->getMapAct(obj->anim.mapEventSlot) == WCTREXSTATU_MAPEVENT_RAISED)
        {
            obj->anim.localPosY = obj->anim.localPosY + lbl_803E6E14;
        }
    }

    if ((u32)mainGetBit(setup->raisedBit) != 0)
    {
        ObjTextureRuntimeSlot* texture = objFindTexture((GameObject*)obj, 0, 0);

        if (texture != NULL)
        {
            texture->textureId = WCTREXSTATU_TEXTURE_TRIGGERED;
        }
        obj->unkF4 = 1;
    }
}

void wctrexstatu_release(void)
{
}

void wctrexstatu_initialise(void)
{
}
