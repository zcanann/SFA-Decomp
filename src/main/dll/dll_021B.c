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
#include "main/dll/VF/vf_shared.h"
#include "main/obj_placement.h"
#include "main/game_object.h"

extern f32 lbl_803E60D0; /* slide limit offset from posZ */
extern f32 lbl_803E60D4; /* per-frame slide step */

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
    s16 driveGameBit;
} Dll21BState;

/* getExtraSize reserves 0x4; the live state is only this 2-byte field. */
STATIC_ASSERT(sizeof(Dll21BState) == 0x2);

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
    Dll21BState* state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = (s16)(*(s8*)((char*)init + 0x18) << 8);
    state->driveGameBit = *(s16*)((char*)init + 0x1e);
    ((GameObject*)obj)->objectFlags |= 0x6000;
}

void dll_21B_update(int obj)
{
    u8* setup = *(u8**)&((GameObject*)obj)->anim.placementData;
    Dll21BState* state = ((GameObject*)obj)->extra;
    f32 limit;

    if ((s8)setup[0x19] == 1)
    {
        if (DLL_21B_BIT_SET(state->driveGameBit) &&
            ((GameObject*)obj)->anim.localPosZ > ((ObjPlacement*)setup)->posZ - lbl_803E60D0)
        {
            ((GameObject*)obj)->anim.localPosZ -= lbl_803E60D4;
            if (DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_A) &&
                DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_B))
            {
                GameBit_Set(DLL_21B_MOVING_BIT, 1);
            }
            limit = ((ObjPlacement*)setup)->posZ - lbl_803E60D0;
            if (((GameObject*)obj)->anim.localPosZ <= limit)
            {
                ((GameObject*)obj)->anim.localPosZ = limit;
                if (DLL_21B_BIT_CLEAR(DLL_21B_ENABLE_BIT_A))
                {
                    return;
                }
                if (DLL_21B_BIT_CLEAR(DLL_21B_ENABLE_BIT_B))
                {
                    return;
                }
                GameBit_Set(DLL_21B_REACHED_BIT, 1);
            }
            return;
        }
        if (DLL_21B_BIT_CLEAR(state->driveGameBit) &&
            ((GameObject*)obj)->anim.localPosZ < ((ObjPlacement*)setup)->posZ)
        {
            ((GameObject*)obj)->anim.localPosZ -= lbl_803E60D4;
            if (DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_A) &&
                DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_B))
            {
                GameBit_Set(DLL_21B_MOVING_BIT, 1);
            }
            if (((ObjPlacement*)setup)->posZ < ((GameObject*)obj)->anim.localPosZ)
            {
                ((GameObject*)obj)->anim.localPosZ = ((ObjPlacement*)setup)->posZ;
                /* both off (vs both-set moving check): clear the status bits */
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
        if (DLL_21B_BIT_SET(state->driveGameBit) &&
            ((GameObject*)obj)->anim.localPosZ < lbl_803E60D0 + ((ObjPlacement*)setup)->posZ)
        {
            ((GameObject*)obj)->anim.localPosZ += lbl_803E60D4;
            if (DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_A) &&
                DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_B))
            {
                GameBit_Set(DLL_21B_MOVING_BIT, 1);
            }
            limit = lbl_803E60D0 + ((ObjPlacement*)setup)->posZ;
            if (((GameObject*)obj)->anim.localPosZ >= limit)
            {
                ((GameObject*)obj)->anim.localPosZ = limit;
                if (DLL_21B_BIT_CLEAR(DLL_21B_ENABLE_BIT_A))
                {
                    return;
                }
                if (DLL_21B_BIT_CLEAR(DLL_21B_ENABLE_BIT_B))
                {
                    return;
                }
                GameBit_Set(DLL_21B_REACHED_BIT, 1);
            }
            return;
        }
        if (DLL_21B_BIT_CLEAR(state->driveGameBit) &&
            ((ObjPlacement*)setup)->posZ < ((GameObject*)obj)->anim.localPosZ)
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
                /* both off (vs both-set moving check): clear the status bits */
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
