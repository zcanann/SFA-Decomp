#ifndef MAIN_DLL_WC_WCLASER_H_
#define MAIN_DLL_WC_WCLASER_H_

#include "ghidra_import.h"

void WM_Galleon_update(int *obj);
void WM_Galleon_init(int *obj, u8 *init);
void WM_Galleon_release(void);
void WM_Galleon_initialise(void);

int fn_801F06D8(int p1, int p2, u8 *arg3);

int WM_seqobject_getExtraSize(void);
int WM_seqobject_getObjectTypeId(void);
void WM_seqobject_free(void);
void WM_seqobject_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void WM_seqobject_hitDetect(void);
void WM_seqobject_update(int *obj);
void WM_seqobject_init(int *obj, s8 *def);
void WM_seqobject_release(void);
void WM_seqobject_initialise(void);

int dll_1FB_SeqFn(int *obj, int unused, s16 *p);
int dll_1FB_getExtraSize_ret_12(void);
int dll_1FB_getObjectTypeId(void);
void dll_1FB_free_nop(void);
void dll_1FB_render(int *obj, int p2, int p3, int p4, int p5, s8 visible);
void dll_1FB_hitDetect_nop(void);
void dll_1FB_update(int *obj);
void dll_1FB_init(int *obj, u8 *def);
void dll_1FB_release_nop(void);
void dll_1FB_initialise_nop(void);

int LaserBeam_getExtraSize(void);
int LaserBeam_getObjectTypeId(void);
void LaserBeam_init(int *obj);
void LaserBeam_render(void);
void LaserBeam_hitDetect(void);

#endif /* MAIN_DLL_WC_WCLASER_H_ */
