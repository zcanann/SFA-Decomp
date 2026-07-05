/*
 * trickywarp (DLL 0x0100) - the "warp to Tricky" reachability gate.
 *
 * A trickywarp placement watches the player and Tricky relative to the
 * walk/patch-group graph. Once GameBit 0x4E5 (Tricky available) is set
 * and Tricky exists, it caches its own patch group and the ids of the
 * type-'$' rom curves that link to it. Each update it tests whether the
 * player is reachable from that patch group - directly, across a visible
 * curve node whose required/forbidden game bits are satisfied, or via
 * getPatchGroup - and toggles membership of object group 0x4B (the warp
 * candidate set) accordingly. It deactivates itself while on screen
 * (ViewFrustum_IsSphereVisible) so the warp can't trigger in view.
 *
 * This TU is also the home of the ObjectDescriptors for the sibling DLLs
 * built from the same source family (magicplant, trickyguard, staypoint,
 * duster, curvefish); their callbacks live in their own units.
 */
#include "main/frustum.h"
#include "main/game_object.h"
#include "main/dll/dll_00FE_magicplant.h"
#include "main/dll/rom_curve_interface.h"
#include "main/gamebits.h"
#include "main/gameplay_runtime.h"
#include "main/objlib.h"
extern int getPatchGroup(f32* pos, int patchGroup);
extern int Objfsa_GetWalkGroupIndexAtPoint(f32* pos, int mode);
extern f32 lbl_803E38A0;

#define GAMEBIT_TRICKY_AVAILABLE 0x4e5
#define TRICKYWARP_OBJ_GROUP 0x4b
#define ROMCURVE_TYPE_TRICKYWARP '$'

void trickywarp_free(int obj)
{
    TrickyWarpState* state = ((GameObject*)obj)->extra;
    if (state->active != 0)
    {
        ObjGroup_RemoveObject(obj, TRICKYWARP_OBJ_GROUP);
    }
}

int trickywarp_getExtraSize(void) { return sizeof(TrickyWarpState); }

void trickywarp_update(int obj)
{
    TrickyWarpState* state;
    int reachable;
    state = ((GameObject*)obj)->extra;
    reachable = fn_8017FFD0(obj, state);
    if (reachable != 0)
    {
        if (state->active == 0)
        {
            state->active = 1;
            ObjGroup_AddObject(obj, TRICKYWARP_OBJ_GROUP);
        }
    }
    else
    {
        if (state->active != 0)
        {
            state->active = 0;
            ObjGroup_RemoveObject(obj, TRICKYWARP_OBJ_GROUP);
        }
    }
}

typedef struct TrickyWarpCurveEntry
{
    u8 pad00[3];
    u8 entryPatchGroup;
    u8 linkPatchGroups[4];
    u8 pad08[0xc];
    u32 nodeId;
    s8 action;
    s8 type;
} TrickyWarpCurveEntry;

typedef struct TrickyWarpCurveNode
{
    u8 pad00[4];
    u8 linkPatchGroups[4];
    u8 pad08[0x28];
    s16 requiredGameBit;
    s16 forbiddenGameBit;
} TrickyWarpCurveNode;

int fn_8017FFD0(int obj, TrickyWarpState* state)
{
    int curveCount;
    TrickyWarpCurveEntry** curveEntries;
    int i;
    int linkIndex;
    TrickyWarpCurveEntry* entry;
    TrickyWarpCurveNode* node;
    int nodeCount;
    int playerObj;
    int playerPatchGroup;

    if (GameBit_Get(GAMEBIT_TRICKY_AVAILABLE) == 0)
    {
        return 0;
    }
    if (getTrickyObject() == NULL)
    {
        return 0;
    }
    if (state->patchGroup == 0)
    {
        state->patchGroup = Objfsa_GetWalkGroupIndexAtPoint(&((GameObject*)obj)->anim.localPosX, 0);
        if (state->patchGroup != 0)
        {
            curveEntries = (TrickyWarpCurveEntry**)(*gRomCurveInterface)->getCurves(&curveCount);
            nodeCount = 0;
            for (i = 0; i < curveCount; i++)
            {
                entry = curveEntries[i];
                if (entry->type == ROMCURVE_TYPE_TRICKYWARP && entry->entryPatchGroup == 0)
                {
                    for (linkIndex = 0; linkIndex < 4; linkIndex++)
                    {
                        if (entry->linkPatchGroups[linkIndex] == state->patchGroup)
                        {
                            state->curveNodeIds[nodeCount] = entry->nodeId;
                            nodeCount++;
                            break;
                        }
                    }
                }
            }
        }
        else
        {
            return 0;
        }
    }
    if (ViewFrustum_IsSphereVisible(&((GameObject*)obj)->anim.localPosX, lbl_803E38A0) != 0)
    {
        return 0;
    }
    playerObj = (int)Obj_GetPlayerObject();
    playerPatchGroup = Objfsa_GetWalkGroupIndexAtPoint((f32*)(playerObj + 0xc), 0);
    if (playerPatchGroup != 0)
    {
        if (playerPatchGroup == state->patchGroup)
        {
            return 1;
        }
        for (i = 0; i < 0x18; i++)
        {
            if (state->curveNodeIds[i] == 0)
            {
                break;
            }
            node = (TrickyWarpCurveNode*)(*gRomCurveInterface)->getById(state->curveNodeIds[i]);
            if (node != NULL)
            {
                if (node->requiredGameBit == -1 || GameBit_Get(node->requiredGameBit) != 0)
                {
                    if (node->forbiddenGameBit == -1 || GameBit_Get(node->forbiddenGameBit) == 0)
                    {
                        if (node->linkPatchGroups[0] == playerPatchGroup)
                        {
                            return 1;
                        }
                        if (node->linkPatchGroups[1] == playerPatchGroup)
                        {
                            return 1;
                        }
                        if (node->linkPatchGroups[2] == playerPatchGroup)
                        {
                            return 1;
                        }
                        if (node->linkPatchGroups[3] == playerPatchGroup)
                        {
                            return 1;
                        }
                    }
                }
            }
        }
    }
    return getPatchGroup((f32*)(playerObj + 0xc), state->patchGroup);
}

void trickywarp_init(s16* obj, u8* placement)
{
    u32 flags;
    flags = ((GameObject*)obj)->objectFlags;
    flags |= 0x4000;
    ((GameObject*)obj)->objectFlags = flags;
    *obj = (s16)((u32)placement[0x1a] << 8);
}

ObjectDescriptor gMagicPlantObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)MagicPlant_init,
    (ObjectDescriptorCallback)MagicPlant_update,
    0,
    (ObjectDescriptorCallback)MagicPlant_render,
    (ObjectDescriptorCallback)MagicPlant_free,
    (ObjectDescriptorCallback)MagicPlant_getObjectTypeId,
    MagicPlant_getExtraSize,
};

ObjectDescriptor gTrickyWarpObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)trickywarp_init,
    (ObjectDescriptorCallback)trickywarp_update,
    0,
    0,
    (ObjectDescriptorCallback)trickywarp_free,
    0,
    trickywarp_getExtraSize,
};

ObjectDescriptor gTrickyGuardObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)trickyguard_init,
    (ObjectDescriptorCallback)trickyguard_update,
    0,
    0,
    0,
    0,
    0,
};

ObjectDescriptor gStayPointObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)StayPoint_init,
    (ObjectDescriptorCallback)StayPoint_update,
    0,
    0,
    0,
    0,
    0,
};

ObjectDescriptor gDusterObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)duster_init,
    (ObjectDescriptorCallback)duster_update,
    (ObjectDescriptorCallback)duster_hitDetect,
    (ObjectDescriptorCallback)duster_render,
    0,
    0,
    duster_getExtraSize,
};

ObjectDescriptor gCurveFishObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)curvefish_init,
    (ObjectDescriptorCallback)curvefish_update,
    0,
    0,
    0,
    0,
    curvefish_getExtraSize,
};
