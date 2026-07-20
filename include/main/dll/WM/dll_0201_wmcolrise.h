#ifndef MAIN_DLL_WM_DLL_0201_WMCOLRISE_H_
#define MAIN_DLL_WM_DLL_0201_WMCOLRISE_H_

#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"
#include "main/object_descriptor.h"

typedef struct WMColrisePlacement
{
    ObjPlacement base; /* base.posY = the column's rest height */
    s8 rotXByte;       /* 0x18: rotX in 1/256 turns */
    u8 pad19[5];
    s16 gameBit; /* 0x1E: rise-allowed gate, -1 = always */
} WMColrisePlacement;

STATIC_ASSERT(offsetof(WMColrisePlacement, gameBit) == 0x1E);
STATIC_ASSERT(sizeof(WMColrisePlacement) == 0x20);

typedef struct WMColriseState
{
    s16 gameBit;
    s8 raiseTimer;
    u8 pad3;
} WMColriseState;

STATIC_ASSERT(offsetof(WMColrisePlacement, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(WMColriseState, raiseTimer) == 0x2);
STATIC_ASSERT(sizeof(WMColriseState) == 0x4);

int WM_colrise_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int WM_colrise_getExtraSize(void);
int WM_colrise_getObjectTypeId(void);
void WM_colrise_free(void);
void WM_colrise_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void WM_colrise_hitDetect(void);
void WM_colrise_update(GameObject* obj);
void WM_colrise_init(GameObject* obj, WMColrisePlacement* placement);
void WM_colrise_release(void);
void WM_colrise_initialise(void);

extern ObjectDescriptor gWM_colriseObjDescriptor;

#endif /* MAIN_DLL_WM_DLL_0201_WMCOLRISE_H_ */
