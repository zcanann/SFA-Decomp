#ifndef MAIN_DLL_WM_DLL_01FA_WMSEQOBJECT_H_
#define MAIN_DLL_WM_DLL_01FA_WMSEQOBJECT_H_

#include "ghidra_import.h"
#include "main/objanim_update.h"

int WM_seqobject_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);
int WM_seqobject_getExtraSize(void);
int WM_seqobject_getObjectTypeId(void);
void WM_seqobject_free(void);
void WM_seqobject_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void WM_seqobject_hitDetect(void);
void WM_seqobject_update(int* obj);
void WM_seqobject_init(int* obj, s8* def);
void WM_seqobject_release(void);
void WM_seqobject_initialise(void);

#endif /* MAIN_DLL_WM_DLL_01FA_WMSEQOBJECT_H_ */
