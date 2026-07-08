#ifndef MAIN_DLL_WM_DLL_020A_WMGENERALSCALES_H_
#define MAIN_DLL_WM_DLL_020A_WMGENERALSCALES_H_

#include "global.h"
#include "main/objanim_update.h"

/* per-object extra state (getExtraSize == 0x8). unk00 is written here
   (0.0 / 800.0 on the slam events) but only read by other TUs. */
typedef struct WmGeneralScalesState
{
    f32 unk00;    /* 0x00 */
    u8 phase;     /* 0x04: 1 = hidden, 2/3 = slam variants, 0 = idle */
    u8 fadeAlpha; /* 0x05: 0 = invisible; ramps by framesThisStep while set */
    u8 pad06[2];
} WmGeneralScalesState;

STATIC_ASSERT(sizeof(WmGeneralScalesState) == 0x8);

int WM_GeneralScales_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);
int WM_GeneralScales_getExtraSize(void);
int WM_GeneralScales_getObjectTypeId(void);
void WM_GeneralScales_free(int* obj);
void WM_GeneralScales_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
void WM_GeneralScales_hitDetect(void);
void WM_GeneralScales_update(void);
void WM_GeneralScales_init(int* obj);
void WM_GeneralScales_release(void);
void WM_GeneralScales_initialise(void);

#endif /* MAIN_DLL_WM_DLL_020A_WMGENERALSCALES_H_ */
