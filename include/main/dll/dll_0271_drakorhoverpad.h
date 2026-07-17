#ifndef MAIN_DLL_DLL_0271_DRAKORHOVERPAD_H_
#define MAIN_DLL_DLL_0271_DRAKORHOVERPAD_H_

#include "main/game_object.h"
#include "main/dll/curve_walker.h"

typedef struct DrakorHoverpadFlags
{
    u8 bit80 : 1;
    u8 b40 : 1;
    u8 bit20 : 1;
    u8 state : 4;
    u8 b01 : 1;
} DrakorHoverpadFlags;

typedef struct DrakorHoverpadPathFlags
{
    u8 p0 : 1;
    u8 p1 : 1;
    u8 p2 : 1;
    u8 f10 : 1;
    u8 f08 : 1;
    u8 f04 : 1;
    u8 p6 : 1;
    u8 p7 : 1;
} DrakorHoverpadPathFlags;

void drakorhoverpad_resetPendingMotion(GameObject* obj);
int drakorhoverpad_handlePathPointEvent(GameObject* obj, u8 eventCode, u8 subCode, void* out);
int drakorhoverpad_update(RomCurveWalker* curve, int maxIndex);

extern f32 gDrakorHoverpadMtx[];
extern f32 lbl_803DC300;
extern f32 lbl_803DC304;
extern f32 lbl_803DC2F8;
extern s16 lbl_803DC2FC;

#endif /* MAIN_DLL_DLL_0271_DRAKORHOVERPAD_H_ */
