#ifndef MAIN_DLL_DLL_00D4_SKEETLAWALL_H_
#define MAIN_DLL_DLL_00D4_SKEETLAWALL_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"

typedef struct SkeetlaWallState
{
    u8 negXExtent;
    u8 posXExtent;
    u8 posZExtent;
    u8 negZExtent;
    u8 posYExtent;
    u8 negYExtent;
    u8 shapeFlag;
} SkeetlaWallState;

typedef struct SkeetlaWallPlacement
{
    ObjPlacement base;
    u8 negXExtent;
    u8 posXExtent;
    u8 posZExtent;
    u8 negZExtent;
    u8 posYExtent;
    u8 negYExtent;
    u8 shapeFlag;
} SkeetlaWallPlacement;

STATIC_ASSERT(offsetof(SkeetlaWallState, negXExtent) == 0x0);
STATIC_ASSERT(offsetof(SkeetlaWallState, shapeFlag) == 0x6);
STATIC_ASSERT(sizeof(SkeetlaWallState) == 0x7);
STATIC_ASSERT(offsetof(SkeetlaWallPlacement, negXExtent) == 0x18);
STATIC_ASSERT(offsetof(SkeetlaWallPlacement, posZExtent) == 0x1A);
STATIC_ASSERT(offsetof(SkeetlaWallPlacement, posYExtent) == 0x1C);
STATIC_ASSERT(offsetof(SkeetlaWallPlacement, shapeFlag) == 0x1E);
STATIC_ASSERT(sizeof(SkeetlaWallPlacement) == 0x20);

void SkeetlaWall_setScale(GameObject* obj, f32* outBounds, u8* outShapeFlag);
extern ObjectDescriptor11WithPadding gSkeetlaWallObjDescriptor;

#endif /* MAIN_DLL_DLL_00D4_SKEETLAWALL_H_ */
