#ifndef MAIN_DLL_WM_DLL_0201_WMCOLRISE_H_
#define MAIN_DLL_WM_DLL_0201_WMCOLRISE_H_

#include "ghidra_import.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"

typedef struct WMColrisePlacement
{
    ObjPlacement base; /* base.posY = the column's rest height */
    s8 rotXByte;       /* 0x18: rotX in 1/256 turns */
    u8 pad19[5];
    s16 gameBit; /* 0x1E: rise-allowed gate, -1 = always */
} WMColrisePlacement;

STATIC_ASSERT(offsetof(WMColrisePlacement, gameBit) == 0x1E);

typedef struct WMColriseState
{
    s16 gameBit;
    u8 raiseTimer;
    u8 pad3;
} WMColriseState;

/* the rider registry hanging off anim+0x58 (engine field not yet
   named in ObjAnimComponent): the shared platform helpers push the
   objects standing on this one into riders[]. */
typedef struct ObjRiderRegistry
{
    u8 pad000[0x100];
    int riders[3]; /* 0x100 */
    u8 pad10C[3];
    s8 riderCount; /* 0x10F */
} ObjRiderRegistry;

STATIC_ASSERT(offsetof(ObjRiderRegistry, riderCount) == 0x10F);

int WM_colrise_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);
int WM_colrise_getExtraSize(void);
int WM_colrise_getObjectTypeId(void);
void WM_colrise_free(void);
void WM_colrise_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void WM_colrise_hitDetect(void);
void WM_colrise_update(int* obj);
void WM_colrise_init(s16* obj, s8* def);
void WM_colrise_release(void);
void WM_colrise_initialise(void);

#endif /* MAIN_DLL_WM_DLL_0201_WMCOLRISE_H_ */
