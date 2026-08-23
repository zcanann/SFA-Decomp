/*
 * DLL 0x100 - TrickyWarp.
 *
 * Tracks player/Tricky reachability through walk patch groups and '$'
 * rom-curve links, registering off-screen objects as warp candidates.
 */
#include "dlls/objects/256_TrickyWarp.h"
#include "main/frustum.h"
#include "main/dll/rom_curve_interface.h"
#include "main/gamebits.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/dll/dll_0014_api.h"
#include "main/dll/rom_curve_def.h"
#include "main/dll/objfsa_query_api.h"
#include "main/objtype.h"

#define TRICKYWARP_OBJ_GROUP          0x4B
#define TRICKYWARP_PATCH_GROUP_NONE   0
#define TRICKYWARP_CURVE_NODE_ID_NONE 0
#define TRICKYWARP_GAMEBIT_NONE       -1
#define TRICKYWARP_CURVE_LINK_COUNT   4
#define ROMCURVE_TYPE_TRICKYWARP      '$'
#define TRICKYWARP_VISIBILITY_RADIUS  19.0f

void TrickyWarp_free(GameObject* obj) {
    TrickyWarpState* state = obj->extra;
    if (state->registeredAsWarpCandidate != 0) {
        objFreeObjectType(obj, TRICKYWARP_OBJ_GROUP);
    }
}

int TrickyWarp_getExtraSize(void) {
    return sizeof(TrickyWarpState);
}

void TrickyWarp_update(GameObject* obj) {
    TrickyWarpState* state;
    int isReachable;

    state = obj->extra;
    isReachable = TrickyWarp_isPlayerReachable(obj, state);
    if (isReachable != 0) {
        if (state->registeredAsWarpCandidate == 0) {
            state->registeredAsWarpCandidate = 1;
            objAddObjectType(obj, TRICKYWARP_OBJ_GROUP);
        }
    } else {
        if (state->registeredAsWarpCandidate != 0) {
            state->registeredAsWarpCandidate = 0;
            objFreeObjectType(obj, TRICKYWARP_OBJ_GROUP);
        }
    }
}

int TrickyWarp_isPlayerReachable(GameObject* obj, TrickyWarpState* state) {
    int curveCount;
    RomCurveDef** curveEntries;
    int curveIndex;
    int linkIndex;
    RomCurveDef* curveEntry;
    RomCurveDef* curveNode;
    int nodeCount;
    GameObject* player;
    int playerPatchGroup;

    if (mainGetBit(GAMEBIT_TrickyWarpEnabled) == 0) {
        return 0;
    }
    if (getTrickyObject() == NULL) {
        return 0;
    }
    if (state->warpPointWalkGroup == TRICKYWARP_PATCH_GROUP_NONE) {
        state->warpPointWalkGroup = Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.localPosX, 0);
        if (state->warpPointWalkGroup != TRICKYWARP_PATCH_GROUP_NONE) {
            curveEntries = (RomCurveDef**)(*gRomCurveInterface)->getCurves(&curveCount);
            nodeCount = 0;
            for (curveIndex = 0; curveIndex < curveCount; curveIndex++) {
                curveEntry = curveEntries[curveIndex];
                if (curveEntry->type == ROMCURVE_TYPE_TRICKYWARP &&
                    curveEntry->walkGroup == TRICKYWARP_PATCH_GROUP_NONE) {
                    for (linkIndex = 0; linkIndex < TRICKYWARP_CURVE_LINK_COUNT; linkIndex++) {
                        if (curveEntry->linkWalkGroups[linkIndex] == state->warpPointWalkGroup) {
                            state->linkedWarpCurveIds[nodeCount] = curveEntry->id;
                            nodeCount++;
                            break;
                        }
                    }
                }
            }
        } else {
            return 0;
        }
    }
    if (ViewFrustum_IsSphereVisible(&obj->anim.localPosX, TRICKYWARP_VISIBILITY_RADIUS) != 0) {
        return 0;
    }
    player = Obj_GetPlayerObject();
    playerPatchGroup = Objfsa_GetWalkGroupIndexAtPoint(&player->anim.localPosX, 0);
    if (playerPatchGroup != TRICKYWARP_PATCH_GROUP_NONE) {
        if (playerPatchGroup == state->warpPointWalkGroup) {
            return 1;
        }
        for (curveIndex = 0; curveIndex < TRICKYWARP_CURVE_NODE_CAPACITY; curveIndex++) {
            if (state->linkedWarpCurveIds[curveIndex] == TRICKYWARP_CURVE_NODE_ID_NONE) {
                break;
            }
            curveNode = (RomCurveDef*)(*gRomCurveInterface)->getById(state->linkedWarpCurveIds[curveIndex]);
            if (curveNode != NULL) {
                if (curveNode->requiredBit == TRICKYWARP_GAMEBIT_NONE || mainGetBit(curveNode->requiredBit) != 0) {
                    if (curveNode->forbiddenBit == TRICKYWARP_GAMEBIT_NONE ||
                        mainGetBit(curveNode->forbiddenBit) == 0) {
                        if (curveNode->linkWalkGroups[0] == playerPatchGroup) {
                            return 1;
                        }
                        if (curveNode->linkWalkGroups[1] == playerPatchGroup) {
                            return 1;
                        }
                        if (curveNode->linkWalkGroups[2] == playerPatchGroup) {
                            return 1;
                        }
                        if (curveNode->linkWalkGroups[3] == playerPatchGroup) {
                            return 1;
                        }
                    }
                }
            }
        }
    }
    return getPatchGroup(&player->anim.localPosX, state->warpPointWalkGroup);
}

void TrickyWarp_init(GameObject* obj, TrickyWarpPlacement* placement) {
    u32 flags;
    flags = obj->objectFlags;
    flags |= OBJECT_OBJFLAG_HIDDEN;
    obj->objectFlags = flags;
    obj->anim.rotX = (s16)((u32)placement->rotXByte << 8);
}

ObjectDescriptor gTrickyWarpObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)TrickyWarp_init,
    (ObjectDescriptorCallback)TrickyWarp_update,
    0,
    0,
    (ObjectDescriptorCallback)TrickyWarp_free,
    0,
    TrickyWarp_getExtraSize,
};
