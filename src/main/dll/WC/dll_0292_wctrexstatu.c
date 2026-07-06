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
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

#define WCTREXSTATU_CALLBACK_TRIGGER 1

#define WCTREXSTATU_SETUP_TYPE_OFFSET 0x18
#define WCTREXSTATU_SETUP_MODEL_INDEX_OFFSET 0x19
#define WCTREXSTATU_SETUP_RAISED_BIT_OFFSET 0x1e

#define WCTREXSTATU_RENDER_TYPE_BASE 0x400
#define WCTREXSTATU_RENDER_TYPE_SHIFT 0xb
#define WCTREXSTATU_TEXTURE_TRIGGERED 0x100
#define WCTREXSTATU_PARTFX_VARIANT_0 0x73f
#define WCTREXSTATU_PARTFX_VARIANT_1 0x740
#define WCTREXSTATU_PARTFX_CHANCE 5
#define WCTREXSTATU_PARTFX_KIND 2
#define WCTREXSTATU_PARTFX_INVALID_HANDLE -1

#define WCTREXSTATU_MAPEVENT_RAISED 2

typedef struct WCTrexStatueSetup
{
    ObjPlacement base;
    s8 type;
    u8 modelIndex;
    u8 pad1A[WCTREXSTATU_SETUP_RAISED_BIT_OFFSET - 0x1A];
    s16 raisedBit;
    u8 pad20[0x24 - 0x20];
} WCTrexStatueSetup;

STATIC_ASSERT(sizeof(WCTrexStatueSetup) == 0x24);
STATIC_ASSERT(offsetof(WCTrexStatueSetup, type) == WCTREXSTATU_SETUP_TYPE_OFFSET);
STATIC_ASSERT(offsetof(WCTrexStatueSetup, modelIndex) == WCTREXSTATU_SETUP_MODEL_INDEX_OFFSET);
STATIC_ASSERT(offsetof(WCTrexStatueSetup, raisedBit) == WCTREXSTATU_SETUP_RAISED_BIT_OFFSET);

#pragma opt_strength_reduction off
int wctrexstatu_interactCallback(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int i;

    for (i = 0; i < animUpdate->eventCount; i++)
    {
        if (animUpdate->eventIds[i] == WCTREXSTATU_CALLBACK_TRIGGER)
        {
            ObjTextureRuntimeSlot* texture = objFindTexture((void*)obj, 0, 0);

            if (texture != NULL)
            {
                texture->textureId = WCTREXSTATU_TEXTURE_TRIGGERED;
            }
            ((GameObject*)obj)->unkF4 = 1;
        }
    }

    return 0;
}
#pragma opt_strength_reduction reset

int wctrexstatu_getExtraSize(void) { return 0; }

int wctrexstatu_getObjectTypeId(int obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    int modelIndex = *(s8*)&((WCTrexStatueSetup*)((GameObject*)obj)->anim.placementData)->modelIndex;
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

void wctrexstatu_hitDetect(u8* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    GameObject* gameObj = (GameObject*)obj;

    if (gameObj->unkF4 != 0 && randomGetRange(0, WCTREXSTATU_PARTFX_CHANCE) == 0)
    {
        if (objAnim->bankIndex == 0)
        {
            (*gPartfxInterface)->spawnObject(obj, WCTREXSTATU_PARTFX_VARIANT_0, NULL,
                                             WCTREXSTATU_PARTFX_KIND,
                                             WCTREXSTATU_PARTFX_INVALID_HANDLE, obj);
        }
        else
        {
            (*gPartfxInterface)->spawnObject(obj, WCTREXSTATU_PARTFX_VARIANT_1, NULL,
                                             WCTREXSTATU_PARTFX_KIND,
                                             WCTREXSTATU_PARTFX_INVALID_HANDLE, obj);
        }
    }
}

void wctrexstatu_update(void)
{
}

void wctrexstatu_init(int obj, int setup, int fromLoad)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    WCTrexStatueSetup* setupData = (WCTrexStatueSetup*)setup;
    ((GameObject*)obj)->animEventCallback = wctrexstatu_interactCallback;
    *(u8*)&objAnim->bankIndex = setupData->modelIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }

    ((GameObject*)obj)->anim.rotX = (s16)(setupData->type << 8);
    if (fromLoad == 0)
    {
        if ((*gMapEventInterface)->getMapAct(((GameObject*)obj)->anim.mapEventSlot) == WCTREXSTATU_MAPEVENT_RAISED)
        {
            ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY + lbl_803E6E14;
        }
    }

    if ((u32)GameBit_Get(setupData->raisedBit) != 0)
    {
        ObjTextureRuntimeSlot* texture = objFindTexture((void*)obj, 0, 0);

        if (texture != NULL)
        {
            texture->textureId = WCTREXSTATU_TEXTURE_TRIGGERED;
        }
        ((GameObject*)obj)->unkF4 = 1;
    }
}

void wctrexstatu_release(void)
{
}

void wctrexstatu_initialise(void)
{
}
