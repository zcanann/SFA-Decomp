#ifndef MAIN_DLL_DIM_DLL_01C9_DIMDISMOUNTPOINT_H_
#define MAIN_DLL_DIM_DLL_01C9_DIMDISMOUNTPOINT_H_

#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"

typedef struct DIMDismountPointPlacement
{
    ObjPlacement head;
    s8 rotX;
} DIMDismountPointPlacement;

typedef struct DIMDismountPointState
{
    f32 planeNX;
    f32 planeNY;
    f32 planeNZ;
    f32 planeD;
} DIMDismountPointState;

typedef struct DIMDismountNeighborInterfaceVTable
{
    void* pad00[8];
    int (*canUseDismountPoint)(GameObject* neighbor, GameObject* dismountPoint);
} DIMDismountNeighborInterfaceVTable;

STATIC_ASSERT(offsetof(DIMDismountPointPlacement, rotX) == 0x18);
STATIC_ASSERT(sizeof(DIMDismountPointState) == 0x10);
STATIC_ASSERT(offsetof(DIMDismountNeighborInterfaceVTable, canUseDismountPoint) == 0x20);

extern ObjectDescriptor12 gDIMDismountPointObjDescriptor;

void DIMDismountPoint_func0B(GameObject* obj, int flag);
int DIMDismountPoint_setScale(GameObject* obj);
int DIMDismountPoint_getExtraSize(void);
int DIMDismountPoint_getObjectTypeId(void);
void DIMDismountPoint_free(GameObject* obj);
void DIMDismountPoint_render(GameObject* obj, int p1, int p2, int p3, int p4, s8 visible);
void DIMDismountPoint_hitDetect(void);
void DIMDismountPoint_update(GameObject* obj);
void DIMDismountPoint_init(GameObject* obj, DIMDismountPointPlacement* placement);
void DIMDismountPoint_release(void);
void DIMDismountPoint_initialise(void);

#endif /* MAIN_DLL_DIM_DLL_01C9_DIMDISMOUNTPOINT_H_ */
