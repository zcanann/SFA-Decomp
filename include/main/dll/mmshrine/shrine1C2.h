#ifndef MAIN_DLL_MMSHRINE_SHRINE1C2_H_
#define MAIN_DLL_MMSHRINE_SHRINE1C2_H_

#include "ghidra_import.h"
#include "main/objanim_update.h"
#include "main/object_descriptor.h"

void ecsh_shrine_update(s16 *obj);
void FUN_801c6dd8(u16 *param_1,int param_2);
void FUN_801c6ddc(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801c6e04(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u16 *param_9);
void FUN_801c70c4(u16 *param_1);
void FUN_801c7390(u32 param_1,u32 param_2,ObjAnimUpdateState *animUpdate);
void FUN_801c74f0(int param_1);
void FUN_801c75a4(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void ecsh_shrine_init(s16 *obj, s8 *def);
void ecsh_shrine_release(void);
void ecsh_shrine_initialise(void);
void gpsh_shrine_free(int *obj);
void gpsh_shrine_render(void *obj, int p2, int p3, int p4, int p5, s8 visible);
int gpsh_shrine_SeqFn(int *obj, int unused, ObjAnimUpdateState *animUpdate);

extern ObjectDescriptor15 gECSH_ShrineObjDescriptor;

#endif /* MAIN_DLL_MMSHRINE_SHRINE1C2_H_ */
