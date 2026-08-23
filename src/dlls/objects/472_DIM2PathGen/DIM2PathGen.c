/*
 * DIM2PathGen (DLL 0x1D8) - snowball path-generator for Snowhorn Wastes 2.
 * It loads the nearby RomCurve spline for action 10, then alternates between
 * two configured snowball types whenever the spawn timer expires. An inactive
 * snowball is reused from the object-group pool before a new one is allocated.
 */
#include "dlls/objects/472_DIM2PathGen.h"

#include "dlls/objects/471_DIM2SnowBal.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/rom_curve_def.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/objtype.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"

#define DIM2_PATH_GENERATOR_FLAG_SPAWN_TOGGLE 0x01
#define DIM2_PATH_GENERATOR_FLAG_CURVE_BUILT  0x02
#define DIM2_PATH_GENERATOR_FLAG_USE_CURVE    0x04

#define DIM2_PATH_GENERATOR_CURVE_GROUP    21
#define DIM2_PATH_GENERATOR_CURVE_ACTION   10
#define DIM2_PATH_GENERATOR_SNOWBALL_GROUP 47

u8 DIM2PathGenerator_getCurveVals(GameObject* obj, int** outPathX, int** outPathY, int** outPathZ,
                                  int** outPathNodeData) {
    Dim2PathGeneratorState* state = obj->extra;

    *outPathX = (int*)state->pathX;
    *outPathY = (int*)state->pathY;
    *outPathZ = (int*)state->pathZ;
    if (outPathNodeData != NULL) {
        *outPathNodeData = (int*)state->pathNodeData;
    }

    return state->pointCount;
}

int DIM2PathGenerator_getExtraSize(void) {
    return sizeof(Dim2PathGeneratorState);
}

int DIM2PathGenerator_getObjectTypeId(void) {
    return 0;
}

void DIM2PathGenerator_free(GameObject* obj) {
}

void DIM2PathGenerator_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                              s8 visible) {
}

void DIM2PathGenerator_hitDetect(void) {
}

void DIM2PathGenerator_update(GameObject* obj) {
    const Dim2PathGeneratorPlacementView* placement;
    Dim2PathGeneratorState* state = obj->extra;
    int toggle;
    GameObject** objects;
    int objectIndex;
    int curveGroup;
    int count;

    placement = (const Dim2PathGeneratorPlacementView*)obj->anim.placementData;
    if (mainGetBit(placement->activeGameBit) == 0) {
        return;
    }

    if ((state->flags & DIM2_PATH_GENERATOR_FLAG_USE_CURVE) != 0) {
        if ((state->flags & DIM2_PATH_GENERATOR_FLAG_CURVE_BUILT) == 0) {
            int found;

            curveGroup = DIM2_PATH_GENERATOR_CURVE_GROUP;
            found = (*gRomCurveInterface)
                        ->find(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &curveGroup, 1,
                               DIM2_PATH_GENERATOR_CURVE_ACTION);
            if (found != -1) {
                RomCurveDef* curve = (RomCurveDef*)(*gRomCurveInterface)->getById(found);

                (*gRomCurveInterface)->countRandomPoints(curve);
                state->pointCount = (*gRomCurveInterface)
                                        ->buildRandomPoints(curve, state->pathX, state->pathY,
                                                            state->pathZ, state->pathNodeData);
                state->flags |= DIM2_PATH_GENERATOR_FLAG_CURVE_BUILT;
                state->originX = curve->x;
                state->originY = curve->y;
                state->originZ = curve->z;
            }
        }
    } else {
        state->originX = obj->anim.localPosX;
        state->originY = obj->anim.localPosY;
        state->originZ = obj->anim.localPosZ;
    }

    if ((state->spawnTimer -= framesThisStep) > 0) {
        return;
    }

    toggle = state->flags & DIM2_PATH_GENERATOR_FLAG_SPAWN_TOGGLE;
    state->spawnTimer = state->spawnPeriod;
    state->flags &= ~DIM2_PATH_GENERATOR_FLAG_SPAWN_TOGGLE;
    objects = objGetAllOfType(DIM2_PATH_GENERATOR_SNOWBALL_GROUP, &count);
    for (objectIndex = 0; objectIndex < count; objectIndex++) {
        if (state->spawnTypes[toggle] == objects[objectIndex]->anim.romDefNo) {
            Dim2SnowBallPlacement* childPlacementData = *(Dim2SnowBallPlacement**)((char*)objects[objectIndex] + 0x4c);
            int poolIndex;

            childPlacementData->base.posX = state->originX;
            childPlacementData->base.posY = state->originY;
            childPlacementData->base.posZ = state->originZ;
            childPlacementData->base.ident = placement->base.ident;
            DIM2_SNOW_BALL_INTERFACE(objects[objectIndex])
                ->init((GameObject*)objects[objectIndex], (Dim2SnowBallPlacement*)childPlacementData, 1);
            objFreeObjectType(objects[objectIndex], DIM2_PATH_GENERATOR_SNOWBALL_GROUP);
            objGetAllOfType(DIM2_PATH_GENERATOR_SNOWBALL_GROUP, &count);
            for (poolIndex = 0; poolIndex < count; poolIndex++) {
            }
            state->flags |= (toggle ^ 1) & DIM2_PATH_GENERATOR_FLAG_SPAWN_TOGGLE;
            return;
        }
    }

    if ((u8)Obj_CanSetupObject()) {
        Dim2SnowBallPlacement* np =
            (Dim2SnowBallPlacement*)Obj_AllocObjectSetup(sizeof(Dim2SnowBallPlacement), state->spawnTypes[toggle]);

        np->base.posX = state->originX;
        np->base.posY = state->originY;
        np->base.posZ = state->originZ;
        np->base.color[0] = placement->base.color[0];
        np->base.color[2] = placement->base.color[2];
        np->base.color[1] = placement->base.color[1];
        np->base.color[3] = placement->base.color[3];
        np->base.color[3] = 255;
        np->base.mapActFlagsLo = placement->base.mapActFlagsLo;
        np->rotationXByte = (s8)placement->childRotationXByte;
        np->unknown1A = placement->childUnknown1A;
        np->unknown1C = placement->childUnknown1C;
        np->base.ident = placement->base.ident;
        objSetupObject((ObjPlacement*)np, 5, obj->anim.mapEventSlot, -1, NULL);
        state->flags |= (toggle ^ 1) & DIM2_PATH_GENERATOR_FLAG_SPAWN_TOGGLE;
    }
}

void DIM2PathGenerator_init(GameObject* obj, int* placementData) {
    Dim2PathGeneratorState* state;

    obj->anim.rotX = (s16)((u32)((Dim2PathGeneratorPlacementView*)placementData)->childRotationXByte << 8);
    state = obj->extra;
    state->spawnPeriod = ((Dim2PathGeneratorPlacementView*)placementData)->spawnPeriod;
    state->spawnTimer = (s16)((Dim2PathGeneratorPlacementView*)placementData)->initialSpawnDelay;
    state->spawnTypes[0] = (s16)((Dim2PathGeneratorPlacementView*)placementData)->primarySpawnType;
    {
        s16 secondarySpawnType = ((Dim2PathGeneratorPlacementView*)placementData)->secondarySpawnType;

        if (secondarySpawnType == -1) {
            state->spawnTypes[1] = (s16)((Dim2PathGeneratorPlacementView*)placementData)->primarySpawnType;
        } else {
            state->spawnTypes[1] = secondarySpawnType;
        }
    }

    state->flags = (u8)(state->flags | DIM2_PATH_GENERATOR_FLAG_USE_CURVE);
    obj->objectFlags = (u16)(obj->objectFlags | OBJECT_OBJFLAG_HITDETECT_DISABLED);
}

void DIM2PathGenerator_release(void) {
}

void DIM2PathGenerator_initialise(void) {
}

ObjectDescriptor11WithPadding gDIM2PathGeneratorObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
        (ObjectDescriptorCallback)DIM2PathGenerator_initialise,
        (ObjectDescriptorCallback)DIM2PathGenerator_release,
        0,
        (ObjectDescriptorCallback)DIM2PathGenerator_init,
        (ObjectDescriptorCallback)DIM2PathGenerator_update,
        (ObjectDescriptorCallback)DIM2PathGenerator_hitDetect,
        (ObjectDescriptorCallback)DIM2PathGenerator_render,
        (ObjectDescriptorCallback)DIM2PathGenerator_free,
        (ObjectDescriptorCallback)DIM2PathGenerator_getObjectTypeId,
        DIM2PathGenerator_getExtraSize,
        (ObjectDescriptorCallback)DIM2PathGenerator_getCurveVals,
    },
    0,
};
