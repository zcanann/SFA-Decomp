/*
 * DLL 0x219 - a game-bit gated sliding object.
 *
 * Only the object with id DLL_219_MOVING_OBJECT_ID is animated; the
 * remaining ids are inert (update returns immediately). When its game
 * bit is set the object slides its local X down to
 * (placement posX - 30) at speed 0.4; when the bit
 * is clear it slides back up to placement posX at speed 0.2,
 * clamping at each end. init seeds the object's rotX and the state's
 * game bit from the placement record; free releases its expgfx source.
 */
#include "main/gamebits.h"
#include "main/dll/expgfx_interface.h"
#include "main/dll/dll_0219.h"

#define DLL_219_MOVING_OBJECT_ID   0x3a6
#define DLL_219_INERT_OBJECT_ID_LO 0x3ad
#define DLL_219_INERT_OBJECT_ID_HI 0x3ae

int dll_219_getExtraSize_ret_4(void)
{
    return 0x4;
}

int dll_219_getObjectTypeId(void)
{
    return 0x0;
}

void dll_219_free(GameObject* obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void dll_219_render_nop(void)
{
}

void dll_219_hitDetect_nop(void)
{
}

void dll_219_update(GameObject* obj)
{
    ObjPlacement* setup = (ObjPlacement*)obj->anim.placementData;
    Dll219State* state = obj->extra;
    s16 objectId = obj->anim.romDefNo;

    switch (objectId)
    {
    case DLL_219_MOVING_OBJECT_ID:
        break;
    case DLL_219_INERT_OBJECT_ID_LO:
    case DLL_219_INERT_OBJECT_ID_HI:
    default:
        return;
    }

    if (mainGetBit(state->gameBit) != 0)
    {
        if (obj->anim.localPosX > setup->posX - 30.0f)
        {
            obj->anim.localPosX -= 0.4f;
            if (obj->anim.localPosX < setup->posX - 30.0f)
            {
                obj->anim.localPosX = setup->posX - 30.0f;
            }
            return;
        }
    }
    if (mainGetBit(state->gameBit) == 0)
    {
        if (obj->anim.localPosX < setup->posX)
        {
            obj->anim.localPosX += 0.2f;
            if (obj->anim.localPosX > setup->posX)
            {
                obj->anim.localPosX = setup->posX;
            }
        }
    }
}

void dll_219_init(GameObject* obj, Dll219Setup* placement)
{
    Dll219State* state = obj->extra;
    obj->anim.rotX = (s16)(placement->rotX << 8);
    state->gameBit = placement->gameBit;
    obj->objectFlags |= (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED);
}

void dll_219_release_nop(void)
{
}

void dll_219_initialise_nop(void)
{
}

ObjectDescriptor gDll219ObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_219_initialise_nop,
    (ObjectDescriptorCallback)dll_219_release_nop,
    0,
    (ObjectDescriptorCallback)dll_219_init,
    (ObjectDescriptorCallback)dll_219_update,
    (ObjectDescriptorCallback)dll_219_hitDetect_nop,
    (ObjectDescriptorCallback)dll_219_render_nop,
    (ObjectDescriptorCallback)dll_219_free,
    (ObjectDescriptorCallback)dll_219_getObjectTypeId,
    dll_219_getExtraSize_ret_4,
};
