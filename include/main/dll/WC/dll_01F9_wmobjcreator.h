#ifndef MAIN_DLL_WC_WCPRESSURESWITCH_H_
#define MAIN_DLL_WC_WCPRESSURESWITCH_H_

#include "ghidra_import.h"
#include "main/objanim_update.h"

void WM_ObjCreator_update(int obj);
int WM_Galleon_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);
void WM_Galleon_free(int *obj, int leavingMap);
void WM_Galleon_render(void *obj, int p2, int p3, int p4, int p5, s8 visible);

#endif /* MAIN_DLL_WC_WCPRESSURESWITCH_H_ */
