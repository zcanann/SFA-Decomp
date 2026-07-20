#ifndef MAIN_DLL_WM_DLL_0204_WMTORCH_H_
#define MAIN_DLL_WM_DLL_0204_WMTORCH_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct WmTorchPlacement
{
    ObjPlacement base;
    u8 pad18;
    u8 torchType;  /* 0x19: 0 / 0x7F = resource-0x69 flames, else 0x63 */
    s16 motionRate; /* 0x1A: root-motion scale numerator, default 90.0 when 0 */
    s16 colorIdx;   /* 0x1C: flame color index, default 0x8C when 0 */
} WmTorchPlacement;

STATIC_ASSERT(offsetof(WmTorchPlacement, torchType) == 0x19);
STATIC_ASSERT(offsetof(WmTorchPlacement, motionRate) == 0x1A);
STATIC_ASSERT(offsetof(WmTorchPlacement, colorIdx) == 0x1C);
STATIC_ASSERT(sizeof(WmTorchPlacement) == 0x20);

typedef struct WmTorchState
{
    GameObject* linkedObj;
    f32 motionRate; /* 0x04: from placement motionRate */
    u8 pad08[2];
    s16 colorIdx;   /* 0x0A: from placement colorIdx */
    u8 torchType;   /* placement torchType: 0 / 0x7F / other */
    u8 pad0D[3];
} WmTorchState;

STATIC_ASSERT(offsetof(WmTorchState, linkedObj) == 0x0);
STATIC_ASSERT(offsetof(WmTorchState, motionRate) == 0x4);
STATIC_ASSERT(offsetof(WmTorchState, colorIdx) == 0xA);
STATIC_ASSERT(offsetof(WmTorchState, torchType) == 0xC);
STATIC_ASSERT(sizeof(WmTorchState) == 0x10);

int wmtorch_getExtraSize(void);
int wmtorch_getObjectTypeId(void);
void wmtorch_free(GameObject* obj, int mode);
void wmtorch_render(GameObject* obj, int p1, int p2, int p3, int p4, s8 visible);
void wmtorch_hitDetect(void);
void wmtorch_update(GameObject* obj);
void wmtorch_init(GameObject* obj, WmTorchPlacement* placement);
void wmtorch_release(void);
void wmtorch_initialise(void);

#endif /* MAIN_DLL_WM_DLL_0204_WMTORCH_H_ */
