#ifndef MAIN_DLL_WM_DLL_0204_WMTORCH_H_
#define MAIN_DLL_WM_DLL_0204_WMTORCH_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct WmTorchPlacement
{
    ObjPlacement base;
    u8 pad18;
    u8 torchType; /* 0x19: 0 / 0x7F = resource-0x69 flames, else 0x63 */
    s16 unk1A;    /* 0x1A: state value, default 90.0 when 0 */
    s16 unk1C;    /* 0x1C: state value, default 0x8C when 0 */
} WmTorchPlacement;

STATIC_ASSERT(offsetof(WmTorchPlacement, torchType) == 0x19);
STATIC_ASSERT(offsetof(WmTorchPlacement, unk1C) == 0x1C);

typedef struct WmTorchState
{
    void* linkedObj;
    f32 unk04; /* from placement unk1A */
    u8 pad08[2];
    s16 unk0A;    /* from placement unk1C */
    u8 torchType; /* placement torchType: 0 / 0x7F / other */
    u8 pad0D[3];
} WmTorchState;

STATIC_ASSERT(sizeof(WmTorchState) == 0x10);

int wmtorch_getExtraSize(void);
int wmtorch_getObjectTypeId(void);
void wmtorch_free(GameObject* obj, int mode);
void wmtorch_render(int* obj, int p1, int p2, int p3, int p4, s8 visible);
void wmtorch_hitDetect(void);
void wmtorch_update(GameObject* obj);
void wmtorch_init(u8* obj, u8* params);
void wmtorch_release(void);
void wmtorch_initialise(void);

#endif /* MAIN_DLL_WM_DLL_0204_WMTORCH_H_ */
