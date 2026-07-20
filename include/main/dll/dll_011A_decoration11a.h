#ifndef MAIN_DLL_DLL_011A_DECORATION11A_H_
#define MAIN_DLL_DLL_011A_DECORATION11A_H_

#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct Decoration11ASetup
{
    ObjPlacement base;
    u8 rotZ;
    u8 rotY;
    u8 rotX;
    u8 scale;
} Decoration11ASetup;

typedef struct Decoration11AState
{
    Vec3f boundsMax;
    Vec3f boundsMin;
    f32 radius;
} Decoration11AState;

STATIC_ASSERT(offsetof(Decoration11ASetup, rotZ) == 0x18);
STATIC_ASSERT(offsetof(Decoration11ASetup, rotY) == 0x19);
STATIC_ASSERT(offsetof(Decoration11ASetup, rotX) == 0x1a);
STATIC_ASSERT(offsetof(Decoration11ASetup, scale) == 0x1b);
STATIC_ASSERT(offsetof(Decoration11AState, boundsMax) == 0x00);
STATIC_ASSERT(offsetof(Decoration11AState, boundsMin) == 0x0c);
STATIC_ASSERT(offsetof(Decoration11AState, radius) == 0x18);
STATIC_ASSERT(sizeof(Decoration11AState) == 0x1c);

int decoration11a_getExtraSize(void);
void decoration11a_free(void);
void decoration11a_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void decoration11a_hitDetect(GameObject* obj);
void decoration11a_update(void);
void decoration11a_expandBoundsWithVertex(f32* vertex, f32* maxOut, f32* minOut);
void decoration11a_init(GameObject* obj, Decoration11ASetup* setup);

#endif /* MAIN_DLL_DLL_011A_DECORATION11A_H_ */
