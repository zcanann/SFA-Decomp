/*
 * explodeplan (DLL 0x269, object type 0x0) - a static placed prop that is
 * removed from the world by a game bit. The placement stores a removal
 * game bit at +0x1E and a packed rotX byte at +0x18.
 *
 * explodeplan_init applies the rotation and, if the removal bit is already
 * set, hides the model and disables its hit volumes. explodeplan_update
 * re-tests the bit every frame and toggles the hidden flag / hit-detection
 * state so the prop appears or disappears the moment the bit changes.
 * Render is a plain model draw at a fixed scale (lbl_803E69D0).
 */
#include "main/dll/DR/dr_shared.h"
#include "main/game_object.h"

#define EXPLODEPLAN_OBJECT_TYPE_ID 0x0

/* opaque per-instance extra state; no field is read or written by this DLL */
typedef struct ExplodePlanState
{
    u8 pad0[0x4];
} ExplodePlanState;

/* explodeplan placement record (tail past the common ObjPlacement head) */
typedef struct ExplodePlanPlacement
{
    u8 pad0[0x18];
    s8 rotXByte;     /* 0x18: rotX in 1/256 turns */
    u8 pad19[0x1E - 0x19];
    s16 removeGameBit; /* 0x1E: game bit that removes this prop */
} ExplodePlanPlacement;

STATIC_ASSERT(offsetof(ExplodePlanPlacement, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(ExplodePlanPlacement, removeGameBit) == 0x1E);
STATIC_ASSERT(sizeof(ExplodePlanPlacement) == 0x20);

void explodeplan_free(void)
{
}

int explodeplan_getExtraSize(void) { return sizeof(ExplodePlanState); }

int explodeplan_getObjectTypeId(void) { return EXPLODEPLAN_OBJECT_TYPE_ID; }

void explodeplan_hitDetect(void)
{
}

void explodeplan_initialise(void)
{
}

void explodeplan_release(void)
{
}

void explodeplan_render(void* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible)
{
    if (visible != 0)
    {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E69D0);
    }
}

#pragma opt_common_subs off
void explodeplan_init(int obj, char* arg)
{
    ExplodePlanPlacement* def = (ExplodePlanPlacement*)arg;
    ObjHits_EnableObject(obj);
    if (GameBit_Get(def->removeGameBit) != 0)
    {
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        ObjHits_DisableObject(obj);
    }
    ((GameObject*)obj)->anim.rotX = (s16)(def->rotXByte << 8);
}
#pragma opt_common_subs reset


void explodeplan_update(int obj)
{
    ExplodePlanPlacement* placement = *(ExplodePlanPlacement**)&((GameObject*)obj)->anim.placementData;
    if (GameBit_Get(placement->removeGameBit) != 0)
    {
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        ObjHits_DisableObject(obj);
    }
    else
    {
        ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        ObjHits_EnableObject(obj);
    }
}
