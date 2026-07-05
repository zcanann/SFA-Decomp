#ifndef MAIN_DLL_DLL_13F_H_
#define MAIN_DLL_DLL_13F_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"

extern ObjectDescriptor17 gCollectibleObjDescriptor;
extern ObjectDescriptor gMagicDustObjDescriptor;

int collectible_getExtraSize(void);
int collectible_getObjectTypeId(void);
void collectible_init(int obj,int setup);
int collectible_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);
u8 collectible_func0F(int *obj);
int collectible_setScale(int *obj);
void FUN_80173364(short *param_1,int param_2);
void FUN_80173368(int param_1);
void FUN_801733c0(int param_1);
void collectible_hitDetect(void);
void collectible_release(void);
void collectible_initialise(void);
int magicdust_getExtraSize(void);
void magicdust_free(int param_1);
void magicdust_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

#endif /* MAIN_DLL_DLL_13F_H_ */
