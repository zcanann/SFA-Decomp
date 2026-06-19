#ifndef MAIN_DLL_MMSHRINE_TORCH1C1_H_
#define MAIN_DLL_MMSHRINE_TORCH1C1_H_

#include "ghidra_import.h"
#include "main/objanim_update.h"

void ecsh_shrine_func0B(u8 idx, f32 *out1, f32 *out2);
void ecsh_shrine_setScale(s16 *out);
void FUN_801c5f28(u16 *param_1);
void FUN_801c61f4(u32 param_1,u32 param_2,ObjAnimUpdateState *animUpdate);
int ecsh_shrine_getExtraSize(void);
int ecsh_shrine_getObjectTypeId(void);
void ecsh_shrine_free(int *obj);
void ecsh_shrine_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void ecsh_shrine_hitDetect(void);

#endif /* MAIN_DLL_MMSHRINE_TORCH1C1_H_ */
