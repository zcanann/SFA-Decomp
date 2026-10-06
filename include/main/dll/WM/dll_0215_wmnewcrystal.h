#ifndef MAIN_DLL_WM_DLL_0215_WMNEWCRYSTAL_H_
#define MAIN_DLL_WM_DLL_0215_WMNEWCRYSTAL_H_

#include "main/dll/partfx_interface.h"

#include "global.h"
#include "game/objects/object.h"
#include "dlls/object_descriptor.h"
#include "game/objects/object_setup.h"
#include "main/objseq.h"

typedef struct WmNewCrystalState
{
    s16 fxState[0x1A];    /* 0x00: primary crystal-orbit effect block */
    s16 secondaryFxState[0x1A]; /* 0x34: secondary crystal-orbit effect block */
    u8 greenBurstsActive;       /* 0x68: green crystal still bursting */
    u8 pad69[3];
} WmNewCrystalState;


STATIC_ASSERT(offsetof(WmNewCrystalState, secondaryFxState) == 0x34);
STATIC_ASSERT(offsetof(WmNewCrystalState, greenBurstsActive) == 0x68);
STATIC_ASSERT(sizeof(WmNewCrystalState) == 0x6C);

int WM_newcrystal_SeqFn(GameObject* obj, int unused, ObjSeqState* actor);
int WM_newcrystal_getExtraSize(void);
int WM_newcrystal_getObjectTypeId(void);
void WM_newcrystal_free(void);
void WM_newcrystal_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void WM_newcrystal_hitDetect(void);
void WM_newcrystal_update(void);
void WM_newcrystal_init(GameObject* obj, ObjPlacement* unused);
void WM_newcrystal_release(void);
void WM_newcrystal_initialise(void);

extern ObjectDescriptor gWM_newcrystalObjDescriptor;

#endif /* MAIN_DLL_WM_DLL_0215_WMNEWCRYSTAL_H_ */
