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

#define DLL_21B_ENABLE_BIT_A 0x503
#define DLL_21B_ENABLE_BIT_B 0x504
#define DLL_21B_REACHED_BIT 0x4ec
#define DLL_21B_MOVING_BIT 0x4ed
#define DLL_21B_RESET_BIT 0x4ea
#define DLL_21B_BIT_SET(bit) ((u32)GameBit_Get(bit) != 0u)
#define DLL_21B_BIT_CLEAR(bit) ((u32)GameBit_Get(bit) == 0u)

#define DLL_21B_OBJFLAG_HIDDEN 0x4000
#define DLL_21B_OBJFLAG_HITDETECT_DISABLED 0x2000

typedef struct Dll21BState
{
    s16 driveGameBit;
} Dll21BState;

STATIC_ASSERT(sizeof(Dll21BState) == 0x2);

/*
 * Class-specific placement record for DLL 0x21B: the common ObjPlacement
 * head (position / mapId at 0x00..0x17) followed by the slide parameters.
 *  - 0x18 s8 initRotByte: seeds anim.rotX (<<8) at init
 *  - 0x19 s8 direction:   1 selects the negative-Z-open slide convention
 *  - 0x1E s16 driveGameBit: game bit that drives the slide
 */
typedef struct Dll21BPlacement
{
    ObjPlacement base;     /* 0x00 */
    s8 initRotByte;        /* 0x18 */
    s8 direction;          /* 0x19 */
    u8 pad1A[4];           /* 0x1A */
    s16 driveGameBit;      /* 0x1E */
} Dll21BPlacement;

STATIC_ASSERT(offsetof(Dll21BPlacement, initRotByte) == 0x18);
STATIC_ASSERT(offsetof(Dll21BPlacement, direction) == 0x19);
STATIC_ASSERT(offsetof(Dll21BPlacement, driveGameBit) == 0x1e);

int dll_21B_getExtraSize_ret_4(void) { return 0x4; }

int dll_21B_getObjectTypeId(void) { return 0x0; }

void dll_21B_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void dll_21B_render_nop(void)
{
}

void dll_21B_hitDetect_nop(void)
{
}

void dll_21B_update(int obj)
{
    Dll21BPlacement* setup = (Dll21BPlacement*)((GameObject*)obj)->anim.placementData;
    Dll21BState* state = ((GameObject*)obj)->extra;

    if (setup->direction == 1)
    {
        if (DLL_21B_BIT_SET(state->driveGameBit) &&
            ((GameObject*)obj)->anim.localPosZ > setup->base.posZ - 60.0f)
        {
            ((GameObject*)obj)->anim.localPosZ -= 0.4f;
            if (DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_A) &&
                DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_B))
            {
                GameBit_Set(DLL_21B_MOVING_BIT, 1);
            }
            if (((GameObject*)obj)->anim.localPosZ <= setup->base.posZ - 60.0f)
            {
                ((GameObject*)obj)->anim.localPosZ = setup->base.posZ - 60.0f;
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
            ((GameObject*)obj)->anim.localPosZ < setup->base.posZ)
        {
            ((GameObject*)obj)->anim.localPosZ -= 0.4f;
            if (DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_A) &&
                DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_B))
            {
                GameBit_Set(DLL_21B_MOVING_BIT, 1);
            }
            if (((GameObject*)obj)->anim.localPosZ > setup->base.posZ)
            {
                ((GameObject*)obj)->anim.localPosZ = setup->base.posZ;
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
            ((GameObject*)obj)->anim.localPosZ < 60.0f + setup->base.posZ)
        {
            ((GameObject*)obj)->anim.localPosZ += 0.4f;
            if (DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_A) &&
                DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_B))
            {
                GameBit_Set(DLL_21B_MOVING_BIT, 1);
            }
            if (((GameObject*)obj)->anim.localPosZ >= 60.0f + setup->base.posZ)
            {
                ((GameObject*)obj)->anim.localPosZ = 60.0f + setup->base.posZ;
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
            ((GameObject*)obj)->anim.localPosZ > setup->base.posZ)
        {
            ((GameObject*)obj)->anim.localPosZ -= 0.4f;
            if (DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_A) &&
                DLL_21B_BIT_SET(DLL_21B_ENABLE_BIT_B))
            {
                GameBit_Set(DLL_21B_MOVING_BIT, 1);
            }
            if (((GameObject*)obj)->anim.localPosZ < setup->base.posZ)
            {
                ((GameObject*)obj)->anim.localPosZ = setup->base.posZ;
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

void dll_21B_init(int* obj, Dll21BPlacement* init)
{
    Dll21BState* state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = (s16)(init->initRotByte << 8);
    state->driveGameBit = init->driveGameBit;
    ((GameObject*)obj)->objectFlags |= (DLL_21B_OBJFLAG_HIDDEN | DLL_21B_OBJFLAG_HITDETECT_DISABLED);
}

void dll_21B_release_nop(void)
{
}

void dll_21B_initialise_nop(void)
{
}
