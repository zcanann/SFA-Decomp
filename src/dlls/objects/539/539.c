/*
 * DLL 0x21B (Volcano Force Point family) - a single-axis sliding mover.
 *
 * The object slides along its local Z toward an open/closed extreme while
 * its drive game bit is set; releasing the bit slides it back. setup[0x19]
 * selects the slide direction (negative-Z open vs positive-Z open) and the
 * resting/extended positions are anchored to the placement's posZ.
 *
 * Two enable bits (DLL_21B_ENABLE_BIT_A/B) gate completion: while moving
 * and both enabled the MOVING bit is raised; once the object reaches its
 * extended limit with both still enabled the REACHED bit is raised, and
 * returning home with both clear clears the RESET/REACHED bits.
 *
 * Init reads rotX and the drive game bit from the placement; free releases
 * the object's expgfx source.
 */
#include "main/dll/expgfx_interface.h"
#include "main/dll/dll_021B.h"
#include "main/gamebits_api.h"

#define DLL_21B_ENABLE_BIT_A   0x503
#define DLL_21B_ENABLE_BIT_B   0x504
#define DLL_21B_REACHED_BIT    0x4ec
#define DLL_21B_MOVING_BIT     0x4ed
#define DLL_21B_RESET_BIT      0x4ea
#define DLL_21B_BIT_SET(bit)   (mainGetBit(bit) != 0u)
#define DLL_21B_BIT_CLEAR(bit) (mainGetBit(bit) == 0u)

int dll_21B_getExtraSize_ret_4(void)
{
    return 0x4;
}

int dll_21B_getObjectTypeId(void)
{
    return 0x0;
}

void dll_21B_free(GameObject* obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void dll_21B_render_nop(void)
{
}

void dll_21B_hitDetect_nop(void)
{
}

void dll_21B_update(GameObject* obj)
{
    Dll21BPlacement* setup = (Dll21BPlacement*)obj->anim.placementData;
    Dll21BState* state = obj->extra;

    if (setup->direction == 1)
    {
        if (DLL_21B_BIT_SET(state->driveGameBit) && obj->anim.localPosZ > setup->base.posZ - 60.0f)
        {
            obj->anim.localPosZ -= 0.4f;
            if (DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_A) && DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_B))
            {
                mainSetBits(DLL_21B_MOVING_BIT, 1);
            }
            if (obj->anim.localPosZ <= setup->base.posZ - 60.0f)
            {
                obj->anim.localPosZ = setup->base.posZ - 60.0f;
                if (DLL_21B_BIT_CLEAR(DLL_21B_ENABLE_BIT_A))
                {
                    return;
                }
                if (DLL_21B_BIT_CLEAR(DLL_21B_ENABLE_BIT_B))
                {
                    return;
                }
                mainSetBits(DLL_21B_REACHED_BIT, 1);
            }
            return;
        }
        if (DLL_21B_BIT_CLEAR(state->driveGameBit) && obj->anim.localPosZ < setup->base.posZ)
        {
            obj->anim.localPosZ -= 0.4f;
            if (DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_A) && DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_B))
            {
                mainSetBits(DLL_21B_MOVING_BIT, 1);
            }
            if (obj->anim.localPosZ > setup->base.posZ)
            {
                obj->anim.localPosZ = setup->base.posZ;
                if (DLL_21B_BIT_CLEAR(DLL_21B_ENABLE_BIT_A) && DLL_21B_BIT_CLEAR(DLL_21B_ENABLE_BIT_B))
                {
                    mainSetBits(DLL_21B_RESET_BIT, 0);
                    mainSetBits(DLL_21B_REACHED_BIT, 0);
                }
            }
        }
    }
    else
    {
        if (DLL_21B_BIT_SET(state->driveGameBit) && obj->anim.localPosZ < 60.0f + setup->base.posZ)
        {
            obj->anim.localPosZ += 0.4f;
            if (DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_A) && DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_B))
            {
                mainSetBits(DLL_21B_MOVING_BIT, 1);
            }
            if (obj->anim.localPosZ >= 60.0f + setup->base.posZ)
            {
                obj->anim.localPosZ = 60.0f + setup->base.posZ;
                if (DLL_21B_BIT_CLEAR(DLL_21B_ENABLE_BIT_A))
                {
                    return;
                }
                if (DLL_21B_BIT_CLEAR(DLL_21B_ENABLE_BIT_B))
                {
                    return;
                }
                mainSetBits(DLL_21B_REACHED_BIT, 1);
            }
            return;
        }
        if (DLL_21B_BIT_CLEAR(state->driveGameBit) && obj->anim.localPosZ > setup->base.posZ)
        {
            obj->anim.localPosZ -= 0.4f;
            if (DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_A) && DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_B))
            {
                mainSetBits(DLL_21B_MOVING_BIT, 1);
            }
            if (obj->anim.localPosZ < setup->base.posZ)
            {
                obj->anim.localPosZ = setup->base.posZ;
                if (DLL_21B_BIT_CLEAR(DLL_21B_ENABLE_BIT_A) && DLL_21B_BIT_CLEAR(DLL_21B_ENABLE_BIT_B))
                {
                    mainSetBits(DLL_21B_RESET_BIT, 0);
                    mainSetBits(DLL_21B_REACHED_BIT, 0);
                }
            }
        }
    }
}

void dll_21B_init(GameObject* obj, Dll21BPlacement* init)
{
    Dll21BState* state = obj->extra;
    obj->anim.rotX = (s16)(init->initRotByte << 8);
    state->driveGameBit = init->driveGameBit;
    obj->objectFlags |= (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED);
}

void dll_21B_release_nop(void)
{
}

void dll_21B_initialise_nop(void)
{
}

ObjectDescriptor gDll21BObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_21B_initialise_nop,
    (ObjectDescriptorCallback)dll_21B_release_nop,
    0,
    (ObjectDescriptorCallback)dll_21B_init,
    (ObjectDescriptorCallback)dll_21B_update,
    (ObjectDescriptorCallback)dll_21B_hitDetect_nop,
    (ObjectDescriptorCallback)dll_21B_render_nop,
    (ObjectDescriptorCallback)dll_21B_free,
    (ObjectDescriptorCallback)dll_21B_getObjectTypeId,
    dll_21B_getExtraSize_ret_4,
};
