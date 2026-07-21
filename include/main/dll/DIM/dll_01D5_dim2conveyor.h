#ifndef MAIN_DLL_DIM_DLL_01D5_DIM2CONVEYOR_H_
#define MAIN_DLL_DIM_DLL_01D5_DIM2CONVEYOR_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

typedef struct Dim2ConveyorPlacement
{
    ObjPlacement base;
    s8 rotX;
    u8 pad19;
    s16 scrollSpeed;
} Dim2ConveyorPlacement;

STATIC_ASSERT(offsetof(Dim2ConveyorPlacement, rotX) == 0x18);
STATIC_ASSERT(offsetof(Dim2ConveyorPlacement, scrollSpeed) == 0x1A);
STATIC_ASSERT(sizeof(Dim2ConveyorPlacement) == 0x1C);

void dim2conveyor_getScrollVector(GameObject* obj, int unused, f32* outX, f32* outY);
int dim2conveyor_getExtraSize(void);
int dim2conveyor_getObjectTypeId(void);
void dim2conveyor_free(GameObject* obj);
void dim2conveyor_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void dim2conveyor_hitDetect(void);
void dim2conveyor_update(GameObject* obj);
void dim2conveyor_init(GameObject* obj, Dim2ConveyorPlacement* placement);
void dim2conveyor_release(void);
void dim2conveyor_initialise(void);

extern ObjectDescriptor11WithPadding gDIM2ConveyorObjDescriptor;

#endif /* MAIN_DLL_DIM_DLL_01D5_DIM2CONVEYOR_H_ */
