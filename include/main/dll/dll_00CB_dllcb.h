#ifndef MAIN_DLL_DLL_00CB_DLLCB_H_
#define MAIN_DLL_DLL_00CB_DLLCB_H_

#include "main/game_object.h"
#include "main/dll/baddie_state.h"

int dll_CB_stateHandler5(GameObject* obj, GroundBaddieState* p);
int dll_CB_stateHandler2(GameObject* obj, GroundBaddieState* p);
void dll_CB_seekAndUpdate(int obj, void* p2, int sub, GroundBaddieState* p);
void dll_CB_advanceAI(int* obj, GroundBaddieState* sub, GroundBaddieState* p);
int dll_CB_seqFn(short* obj, int p2, u8* e);
void dll_CB_func0B_nop(void);
void dll_CB_release_nop(void);
void dll_CB_init(int* obj, u8* params, int extra);
void dll_CB_update(int* obj);
int dll_CB_stateHandler0(void);
int dll_CB_getExtraSize_ret_1040(void);
int dll_CB_getObjectTypeId(void);
s16 dll_CB_setScale(int* obj);
int dll_CB_stateHandler1(int p1, u8* obj);
int dll_CB_stateHandler3(int* obj, u8* obj2);
void dll_CB_hitDetect(int* obj);
void dll_CB_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
int dll_CB_moveHandler2(short* out, u8* obj);
int dll_CB_moveHandler0(short* out, u8* obj, f32 timeDelta);
int dll_CB_stateHandler4(int* obj, GroundBaddieState* state);
int dll_CB_moveHandler1(int* obj, GroundBaddieState* def);
void dll_CB_initialise(void);
int dll_CB_moveHandler3(int* obj);
void dll_CB_free(int* obj);

#endif /* MAIN_DLL_DLL_00CB_DLLCB_H_ */
