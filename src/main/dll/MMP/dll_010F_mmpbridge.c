/*
 * mmpbridge (DLL 0x10F) - Moon Mountain Pass scrolling-texture bridge.
 *
 * The bridge spawns with its hit collision disabled. Once the placement
 * gamebit (MmpBridgePlacement::enableBit) is set, collision is enabled and
 * the surface texture scrolls (offsetS advances by timeDelta each frame)
 * up to a fully-extended offset, animating the bridge into place.
 */

#include "main/game_object.h"
#include "main/debug.h"
#include "main/objtexture.h"
#include "main/gamebits.h"
#include "main/frame_timing.h"
#include "main/objhits.h"
#include "main/dll/MMP/dll_010F_mmpbridge.h"
#include "main/object_descriptor.h"

char lbl_803DBD90[] = "S %d\n";

#define BRIDGE_TEX_OFFSET_START 0x800
#define BRIDGE_TEX_OFFSET_MAX   0x131f

#define MMPBRIDGE_OBJFLAG_HIDDEN             0x4000
#define MMPBRIDGE_OBJFLAG_HITDETECT_DISABLED 0x2000


int mmp_bridge_getExtraSize(void)
{
    return 0x0;
}
int mmp_bridge_getObjectTypeId(void)
{
    return 0x0;
}

void mmp_bridge_free(void)
{
}

void mmp_bridge_render(void)
{
}

void mmp_bridge_hitDetect(void)
{
}

void mmp_bridge_update(int* obj)
{
    MmpBridgePlacement* placement = (MmpBridgePlacement*)*(int**)&((GameObject*)obj)->anim.placementData;
    ObjTextureRuntimeSlot* tex;
    int frame;

    if (mainGetBit(placement->enableBit) != 0)
    {
        tex = objFindTexture((GameObject*)(obj), 0, 0);
        if (tex != NULL)
        {
            frame = tex->offsetS + ((int)timeDelta << 3);
            tex->offsetS = frame;
            frame = tex->offsetS + ((int)timeDelta << 3);
            if (frame >= BRIDGE_TEX_OFFSET_MAX)
            {
                tex->offsetS = BRIDGE_TEX_OFFSET_MAX;
            }
            logPrintf(lbl_803DBD90, tex->offsetS);
        }
        ObjHits_EnableObject((GameObject*)obj);
    }
}

void mmp_bridge_init(int* obj)
{
    MmpBridgePlacement* placement = (MmpBridgePlacement*)*(int**)&((GameObject*)obj)->anim.placementData;
    ObjTextureRuntimeSlot* tex = objFindTexture((GameObject*)(obj), 0, 0);
    if (tex != NULL)
    {
        tex->offsetS = BRIDGE_TEX_OFFSET_START;
    }
    ((GameObject*)obj)->anim.rotX = (s16)(placement->rotXByte << 8);
    ((GameObject*)obj)->objectFlags |= (MMPBRIDGE_OBJFLAG_HIDDEN | MMPBRIDGE_OBJFLAG_HITDETECT_DISABLED);
    ObjHits_DisableObject((GameObject*)obj);
    if (mainGetBit(placement->enableBit) != 0)
    {
        ObjHits_EnableObject((GameObject*)obj);
    }
}

void mmp_bridge_release(void)
{
}

void mmp_bridge_initialise(void)
{
}

ObjectDescriptor gMMP_BridgeObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    mmp_bridge_initialise,
    mmp_bridge_release,
    0,
    (ObjectDescriptorCallback)mmp_bridge_init,
    (ObjectDescriptorCallback)mmp_bridge_update,
    (ObjectDescriptorCallback)mmp_bridge_hitDetect,
    (ObjectDescriptorCallback)mmp_bridge_render,
    (ObjectDescriptorCallback)mmp_bridge_free,
    (ObjectDescriptorCallback)mmp_bridge_getObjectTypeId,
    mmp_bridge_getExtraSize,
};
