#ifndef MAIN_DLL_DLL_0271_DRAKORHOVERPAD_H_
#define MAIN_DLL_DLL_0271_DRAKORHOVERPAD_H_

#include "main/game_object.h"
#include "main/dll/curve_walker.h"

void drakorhoverpad_resetPendingMotion(GameObject* obj);
int drakorhoverpad_handlePathPointEvent(GameObject* obj, u8 eventCode, u8 subCode, void* out);
int drakorhoverpad_update(RomCurveWalker* curve, int maxIndex);

#endif /* MAIN_DLL_DLL_0271_DRAKORHOVERPAD_H_ */
