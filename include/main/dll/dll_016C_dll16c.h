#ifndef MAIN_DLL_DLL_016C_DLL16C_H_
#define MAIN_DLL_DLL_016C_DLL16C_H_

#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"

typedef struct Dll16CPlacement
{
    ObjPlacement base;
    u8 pad18[0x27 - 0x18];
    s8 childObjectIndex;
} Dll16CPlacement;

typedef struct Dll16CState
{
    GameObject* linkedObj; /* group-10 object matched by type (364/367) */
    f32 unk04; /* set on anim event 2 */
    f32 snapX; /* path point snapshot taken on anim event 2 */
    f32 snapY;
    f32 snapZ;
    f32 pathPointX; /* path point 1 world position, refreshed in render */
    f32 pathPointY;
    f32 pathPointZ;
    u8 opacity; /* distance fade; 0xFF when unlinked */
    s8 desiredChildObjectIndex; /* lbl_802C2308 selector; -1 = clear */
    s8 activeChildObjectIndex;
    u8 pad23;
} Dll16CState;

typedef struct Dll16CLinkedObjectInterfaceVTable
{
    void* pad00[4];
    void (*render)(GameObject* obj, int p1, int p2, int p3, int p4, int visible);
    void* pad14[5];
    void (*getPosition)(GameObject* obj, f32* x, f32* y, f32* z);
    void* pad2C[3];
    int (*getState)(GameObject* obj);
    void (*setState)(GameObject* obj, int state);
    void (*getBlendRange)(GameObject* obj, f32* start, f32* end);
    void (*getBlendStep)(GameObject* obj, f32* step);
} Dll16CLinkedObjectInterfaceVTable;

STATIC_ASSERT(offsetof(Dll16CPlacement, childObjectIndex) == 0x27);
STATIC_ASSERT(sizeof(Dll16CPlacement) == 0x28);
STATIC_ASSERT(offsetof(Dll16CState, linkedObj) == 0x00);
STATIC_ASSERT(offsetof(Dll16CState, pathPointX) == 0x14);
STATIC_ASSERT(offsetof(Dll16CState, opacity) == 0x20);
STATIC_ASSERT(offsetof(Dll16CState, desiredChildObjectIndex) == 0x21);
STATIC_ASSERT(offsetof(Dll16CState, activeChildObjectIndex) == 0x22);
STATIC_ASSERT(sizeof(Dll16CState) == 0x24);
STATIC_ASSERT(offsetof(Dll16CLinkedObjectInterfaceVTable, render) == 0x10);
STATIC_ASSERT(offsetof(Dll16CLinkedObjectInterfaceVTable, getPosition) == 0x28);
STATIC_ASSERT(offsetof(Dll16CLinkedObjectInterfaceVTable, getState) == 0x38);
STATIC_ASSERT(offsetof(Dll16CLinkedObjectInterfaceVTable, setState) == 0x3C);
STATIC_ASSERT(offsetof(Dll16CLinkedObjectInterfaceVTable, getBlendRange) == 0x40);
STATIC_ASSERT(offsetof(Dll16CLinkedObjectInterfaceVTable, getBlendStep) == 0x44);

extern ObjectDescriptor lbl_80323740;

int dll_16C_getExtraSize(void);
int dll_16C_getObjectTypeId(void);
void dll_16C_free(GameObject* obj);
void dll_16C_render(GameObject* obj, int p1, int p2, int p3, int p4, s8 visible);
void dll_16C_hitDetect(GameObject* obj);
void dll_16C_update(GameObject* obj);
void dll_16C_init(GameObject* obj, Dll16CPlacement* placement);
int dll_16C_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
void dll_16C_release(void);
void dll_16C_initialise(void);
void dll_16C_syncSubObjectTransform(GameObject* dst, GameObject* src, int p1, int p2, int p3, int p4, int visible,
                                    int opacity, int copyTransform);

#endif /* MAIN_DLL_DLL_016C_DLL16C_H_ */
