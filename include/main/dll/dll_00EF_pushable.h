#ifndef MAIN_DLL_TRANSPORTER_H_
#define MAIN_DLL_TRANSPORTER_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"
#include "main/dll/dll_00F2_iceblast.h"

extern ObjectDescriptor14 gPushableObjDescriptor;
extern ObjectDescriptor gWarpPointObjDescriptor;
extern ObjectDescriptor gInvHitObjDescriptor;
extern ObjectDescriptor gIceblastObjDescriptor;
extern ObjectDescriptor gFlameblastObjDescriptor;

int pushable_setScale(int *obj, s16 *tgt, int flag, f32 dx, f32 dz);
u32 FUN_80175740(int param_1,int param_2);
void FUN_801757ac(u64 param_1,double param_2,u32 param_3,u32 param_4,
                 int param_5);
void FUN_80175ed4(int param_1);
void pushable_render(int *obj, int p1, int p2, int p3, int p4, s8 visible);
void pushable_hitDetect(int obj);
void FUN_801765c8(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9);
void FUN_8017691c(u64 param_1,u64 param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
u32
FUN_80176920(u64 param_1,double param_2,double param_3,u64 param_4,u64 param_5,
            u64 param_6,u64 param_7,u64 param_8,int param_9,u32 param_10,
            ObjAnimUpdateState *animUpdate,u32 param_12,u32 param_13,u32 param_14,
            u32 param_15,u32 param_16);
void FUN_801769e8(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,u32 param_10,u32 param_11,int param_12,int param_13,
                 u32 param_14,u32 param_15,u32 param_16);
void FUN_80177204(short *param_1,int param_2);
void FUN_80177208(int param_1);
void FUN_8017724c(int param_1);
void invhit_update(int *obj);
void FUN_801776f0(int param_1);
void FUN_80177710(u16 *param_1);
void FUN_80177874(int param_1,int param_2);
void FUN_801778d0(int param_1);
u32
FUN_801778e0(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
            u64 param_5,u64 param_6,u64 param_7,u64 param_8,int param_9,
            int param_10);

int pushable_getExtraSize(void);
int pushable_getObjectTypeId(void);

int WarpPoint_getExtraSize(void);
int WarpPoint_getObjectTypeId(void);
int WarpPoint_SeqFn(int *obj, int unused, ObjAnimUpdateState *animUpdate);

int invhit_getExtraSize(void);
int invhit_getObjectTypeId(void);
void invhit_render(int *obj, int a, int b, int c, int d);
void invhit_hitDetect(void);
void invhit_release(void);
void invhit_initialise(void);

/* iceblast_* callbacks + IceblastPlacement now come from dll_00F2_iceblast.h */

int flameblast_getExtraSize(void);

#endif /* MAIN_DLL_TRANSPORTER_H_ */
