#include "main/dll/dusterstate_types.h"
#include "main/frustum.h"
#include "main/game_object.h"
#include "main/dll/cfprisonuncle.h"
#include "main/dll/rom_curve_interface.h"

extern u32 GameBit_Get(int eventId);
extern void* getTrickyObject(void);
extern void* Obj_GetPlayerObject(void);
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int Objfsa_GetWalkGroupIndexAtPoint(f32* pos, int param_2);
extern int getPatchGroup(f32* pos, int patchGroup);

extern f32 lbl_803E38A0;


STATIC_ASSERT(sizeof(DusterStateFlags) == 1);
STATIC_ASSERT(sizeof(DusterState) == 0x20);
STATIC_ASSERT(offsetof(DusterState, moveStepScale) == 0x00);
STATIC_ASSERT(offsetof(DusterState, floorY) == 0x04);
STATIC_ASSERT(offsetof(DusterState, settleTimer) == 0x08);
STATIC_ASSERT(offsetof(DusterState, hitReactTimer) == 0x0a);
STATIC_ASSERT(offsetof(DusterState, completeGameBit) == 0x0c);
STATIC_ASSERT(offsetof(DusterState, activeGameBit) == 0x0e);
STATIC_ASSERT(offsetof(DusterState, heldObjectId) == 0x10);
STATIC_ASSERT(offsetof(DusterState, driftDir) == 0x18);
STATIC_ASSERT(offsetof(DusterState, hitReactActive) == 0x19);
STATIC_ASSERT(offsetof(DusterState, priorityHit) == 0x1a);
STATIC_ASSERT(offsetof(DusterState, active) == 0x1b);
STATIC_ASSERT(offsetof(DusterState, complete) == 0x1c);
STATIC_ASSERT(offsetof(DusterState, useLaunchVelocity) == 0x1d);
STATIC_ASSERT(offsetof(DusterState, flags) == 0x1e);

int trickywarp_getExtraSize(void) { return 0x64; }





void trickywarp_free(int obj)
{
    TrickyWarpState* state = ((GameObject*)obj)->extra;
    if (state->active != 0)
    {
        ObjGroup_RemoveObject(obj, 0x4b);
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
    int n;
    int playerObj;
    int playerPatchGroup;

    if (GameBit_Get(0x4e5) == 0)
    {
        return 0;
    }
    if (getTrickyObject() == NULL)
    {
        return 0;
    }
    if (state->patchGroup == 0)
    {
        state->patchGroup = (u8)Objfsa_GetWalkGroupIndexAtPoint(&((GameObject*)obj)->anim.localPosX, 0);
        if (state->patchGroup != 0)
        {
            curveEntries = (TrickyWarpCurveEntry**)(*gRomCurveInterface)->getCurves(&curveCount);
            n = 0;
            for (i = 0; i < curveCount; i++)
            {
                entry = curveEntries[i];
                if (entry->type == '$' && entry->entryPatchGroup == 0)
                {
                    for (linkIndex = 0; linkIndex < 4; linkIndex++)
                    {
                        if (entry->linkPatchGroups[linkIndex] == state->patchGroup)
                        {
                            state->curveNodeIds[n] = entry->nodeId;
                            n++;
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

void trickywarp_init(s16* obj, u8* param_2)
{
    u32 v;
    v = ((GameObject*)obj)->objectFlags;
    v |= 0x4000;
    ((GameObject*)obj)->objectFlags = (u16)v;
    *obj = (s16)((u32)param_2[0x1a] << 8);
}







void trickywarp_update(int param_1)
{
    int obj = param_1;
    TrickyWarpState* state;
    int r;
    state = ((GameObject*)obj)->extra;
    r = fn_8017FFD0(obj, state);
    if (r != 0)
    {
        if (state->active == 0)
        {
            state->active = 1;
            ObjGroup_AddObject(obj, 0x4b);
        }
    }
    else
    {
        if (state->active != 0)
        {
            state->active = 0;
            ObjGroup_RemoveObject(obj, 0x4b);
        }
    }
}



void trickyguard_update(int* obj);


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
