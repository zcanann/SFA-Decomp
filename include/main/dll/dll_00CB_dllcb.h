#ifndef MAIN_DLL_DLL_00CB_DLLCB_H_
#define MAIN_DLL_DLL_00CB_DLLCB_H_

#include "main/game_object.h"
#include "main/dll/scarab.h"

int fn_801601C4(struct GameObject *obj, GroundBaddieState* p);
int fn_8016043C(int obj, GroundBaddieState* p);
void fn_801606F0(int obj, void* p2, int sub, GroundBaddieState* p);
void fn_8016083C(int* obj, GroundBaddieState* sub, GroundBaddieState* p);
int dll_CB_seqFn(short* obj, int p2, u8* e);
void dll_CB_func0B_nop(void);
void dll_CB_release_nop(void);
void dll_CB_init(int* obj, u8* params, int extra);
void dll_CB_update(int* obj);
int fn_8016052C(void);
int dll_CB_getExtraSize_ret_1040(void);
int dll_CB_getObjectTypeId(void);
s16 dll_CB_setScale(int* obj);
int fn_8016050C(int p1, u8* obj);
int fn_801603E8(int* obj, u8* obj2);
void dll_CB_hitDetect(int* obj);
void dll_CB_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
int fn_801605A8(short* out, u8* obj);
int fn_80160690(short* out, u8* obj);
int fn_8016032C(int* obj, GroundBaddieState* state);
int fn_801605D4(int* obj, GroundBaddieState* def);
void dll_CB_initialise(void);
int fn_80160534(int* obj);
void dll_CB_free(int* obj);

#endif /* MAIN_DLL_DLL_00CB_DLLCB_H_ */
