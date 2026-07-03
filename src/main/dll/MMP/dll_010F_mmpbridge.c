/*
 * mmpbridge (DLL 0x10F) - Moon Mountain Pass scrolling-texture bridge.
 *
 * The bridge spawns with its hit collision disabled. Once the placement
 * gamebit (MmpBridgePlacement::enableBit) is set, collision is enabled and
 * the surface texture scrolls (offsetS advances by timeDelta each frame)
 * up to a fully-extended offset, animating the bridge into place.
 */

#include "main/game_object.h"
#include "main/objtexture.h"
#include "main/gamebits.h"
#include "main/dll/dll_80220608_shared.h"

#define BRIDGE_TEX_OFFSET_START 0x800
#define BRIDGE_TEX_OFFSET_MAX 0x131f

#define MMPBRIDGE_OBJFLAG_HIDDEN 0x4000
#define MMPBRIDGE_OBJFLAG_HITDETECT_DISABLED 0x2000

typedef struct MmpBridgePlacement
{
    u8 pad0[0x18];
    s8 rotXByte;       /* 0x18: rotX in 1/256 turns */
    u8 pad19[0x1E - 0x19];
    s16 enableBit;     /* 0x1E: gamebit that deploys the bridge */
} MmpBridgePlacement;

__declspec(section ".sdata") extern char lbl_803DBD90[];

void mmp_bridge_free(void)
{
}

void mmp_bridge_render(void)
{
}

void mmp_bridge_hitDetect(void)
{
}

void mmp_bridge_release(void)
{
}

void mmp_bridge_initialise(void)
{
}

int mmp_bridge_getExtraSize(void) { return 0x0; }
int mmp_bridge_getObjectTypeId(void) { return 0x0; }

void mmp_bridge_init(int* obj)
{
    MmpBridgePlacement* placement = (MmpBridgePlacement*)*(int**)&((GameObject*)obj)->anim.placementData;
    ObjTextureRuntimeSlot* tex = objFindTexture(obj, 0, 0);
    if (tex != NULL)
    {
        tex->offsetS = BRIDGE_TEX_OFFSET_START;
    }
    ((GameObject*)obj)->anim.rotX = (s16)(placement->rotXByte << 8);
    ((GameObject*)obj)->objectFlags |= (MMPBRIDGE_OBJFLAG_HIDDEN | MMPBRIDGE_OBJFLAG_HITDETECT_DISABLED);
    ObjHits_DisableObject((int)obj);
    if (GameBit_Get(placement->enableBit) != 0)
    {
        ObjHits_EnableObject((int)obj);
    }
}

void mmp_bridge_update(int* obj)
{
    MmpBridgePlacement* placement = (MmpBridgePlacement*)*(int**)&((GameObject*)obj)->anim.placementData;
    ObjTextureRuntimeSlot* tex;
    int frame;

    if (GameBit_Get(placement->enableBit) != 0)
    {
        tex = objFindTexture(obj, 0, 0);
        if (tex != NULL)
        {
            frame = tex->offsetS + ((int)timeDelta << 3);
            tex->offsetS = frame;
            frame = tex->offsetS + ((int)timeDelta << 3);
            if (frame >= BRIDGE_TEX_OFFSET_MAX)
            {
                tex->offsetS = BRIDGE_TEX_OFFSET_MAX;
            }
            fn_80137948(lbl_803DBD90, tex->offsetS);
        }
        ObjHits_EnableObject((int)obj);
    }
}
