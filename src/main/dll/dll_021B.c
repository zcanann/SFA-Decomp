#include "main/dll/VF/vf_shared.h"
#include "main/obj_placement.h"
#include "main/game_object.h"

extern f32 lbl_803E60D0;
extern f32 lbl_803E60D4;

int dll_21B_getExtraSize_ret_4(void) { return 0x4; }

int dll_21B_getObjectTypeId(void) { return 0x0; }

void dll_21B_render_nop(void)
{
}

void dll_21B_hitDetect_nop(void)
{
}

#define DLL_21B_ENABLE_BIT_A 0x503
#define DLL_21B_ENABLE_BIT_B 0x504
#define DLL_21B_REACHED_BIT 0x4ec
#define DLL_21B_MOVING_BIT 0x4ed
#define DLL_21B_RESET_BIT 0x4ea
#define DLL_21B_BIT_SET(bit) ((u32)GameBit_Get(bit) != 0u)
#define DLL_21B_BIT_CLEAR(bit) ((u32)GameBit_Get(bit) == 0u)

typedef struct Dll21BState
{
    s16 gameBit;
} Dll21BState;

void dll_21B_release_nop(void)
{
}

void dll_21B_initialise_nop(void)
{
}

void dll_21B_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void dll_21B_init(int* obj, u8* init)
{
    Dll21BState* inner = ((GameObject*)obj)->extra;
    *(s16*)obj = (s16)((s8)init[0x18] << 8);
    inner->gameBit = *(s16*)((char*)init + 0x1e);
    ((GameObject*)obj)->objectFlags |= 0x6000;
}

void dll_21B_update(int obj)
{
    u8* setup = *(u8**)&((GameObject*)obj)->anim.placementData;
    Dll21BState* state = ((GameObject*)obj)->extra;

    if ((s8)setup[0x19] == 1)
    {
        if (DLL_21B_BIT_SET(state->gameBit) &&
            ((GameObject*)obj)->anim.localPosZ > ((ObjPlacement*)setup)->posZ - lbl_803E60D0)
        {
            ((GameObject*)obj)->anim.localPosZ -= lbl_803E60D4;
            if (DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_A) &&
                DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_B))
            {
                GameBit_Set(DLL_21B_MOVING_BIT, 1);
            }
            if (((GameObject*)obj)->anim.localPosZ <= ((ObjPlacement*)setup)->posZ - lbl_803E60D0)
            {
                ((GameObject*)obj)->anim.localPosZ = ((ObjPlacement*)setup)->posZ - lbl_803E60D0;
                if (DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_A) &&
                    DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_B))
                {
                    GameBit_Set(DLL_21B_REACHED_BIT, 1);
                }
            }
            return;
        }
        if (DLL_21B_BIT_CLEAR(state->gameBit) &&
            ((GameObject*)obj)->anim.localPosZ < ((ObjPlacement*)setup)->posZ)
        {
            ((GameObject*)obj)->anim.localPosZ -= lbl_803E60D4;
            if (DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_A) &&
                DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_B))
            {
                GameBit_Set(DLL_21B_MOVING_BIT, 1);
            }
            if (((GameObject*)obj)->anim.localPosZ > ((ObjPlacement*)setup)->posZ)
            {
                ((GameObject*)obj)->anim.localPosZ = ((ObjPlacement*)setup)->posZ;
                if (DLL_21B_BIT_CLEAR(DLL_21B_ENABLE_BIT_A) &&
                    DLL_21B_BIT_CLEAR(DLL_21B_ENABLE_BIT_B))
                {
                    GameBit_Set(DLL_21B_RESET_BIT, 0);
                    GameBit_Set(DLL_21B_REACHED_BIT, 0);
                }
            }
        }
    }
    else
    {
        if (DLL_21B_BIT_SET(state->gameBit) &&
            ((GameObject*)obj)->anim.localPosZ < lbl_803E60D0 + ((ObjPlacement*)setup)->posZ)
        {
            ((GameObject*)obj)->anim.localPosZ += lbl_803E60D4;
            if (DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_A) &&
                DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_B))
            {
                GameBit_Set(DLL_21B_MOVING_BIT, 1);
            }
            if (((GameObject*)obj)->anim.localPosZ >= lbl_803E60D0 + ((ObjPlacement*)setup)->posZ)
            {
                ((GameObject*)obj)->anim.localPosZ = lbl_803E60D0 + ((ObjPlacement*)setup)->posZ;
                if (DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_A) &&
                    DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_B))
                {
                    GameBit_Set(DLL_21B_REACHED_BIT, 1);
                }
            }
            return;
        }
        if (DLL_21B_BIT_CLEAR(state->gameBit) &&
            ((GameObject*)obj)->anim.localPosZ > ((ObjPlacement*)setup)->posZ)
        {
            ((GameObject*)obj)->anim.localPosZ -= lbl_803E60D4;
            if (DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_A) &&
                DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_B))
            {
                GameBit_Set(DLL_21B_MOVING_BIT, 1);
            }
            if (((GameObject*)obj)->anim.localPosZ < ((ObjPlacement*)setup)->posZ)
            {
                ((GameObject*)obj)->anim.localPosZ = ((ObjPlacement*)setup)->posZ;
                if (DLL_21B_BIT_CLEAR(DLL_21B_ENABLE_BIT_A) &&
                    DLL_21B_BIT_CLEAR(DLL_21B_ENABLE_BIT_B))
                {
                    GameBit_Set(DLL_21B_RESET_BIT, 0);
                    GameBit_Set(DLL_21B_REACHED_BIT, 0);
                }
            }
        }
    }
}
