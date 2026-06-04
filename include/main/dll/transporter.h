#ifndef MAIN_DLL_TRANSPORTER_H_
#define MAIN_DLL_TRANSPORTER_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor14 gPushableObjDescriptor;
extern ObjectDescriptor gWarpPointObjDescriptor;
extern ObjectDescriptor gInvHitObjDescriptor;
extern ObjectDescriptor gIceblastObjDescriptor;
extern ObjectDescriptor gFlameblastObjDescriptor;

int pushable_setScale(int *obj, s16 *tgt, int flag, f32 dx, f32 dz);
uint FUN_80175740(int param_1,int param_2);
void FUN_801757ac(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 int param_5);
void FUN_80175ed4(int param_1);
void pushable_render(int *obj, int p1, int p2, int p3, int p4, s8 visible);
void pushable_hitDetect(int *obj);
void FUN_801765c8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9);
void FUN_8017691c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
undefined4
FUN_80176920(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,int param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16);
void FUN_801769e8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,int param_12,int param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16);
void FUN_80177204(short *param_1,int param_2);
void FUN_80177208(int param_1);
void FUN_8017724c(int param_1);
void invhit_update(int *obj);
void FUN_801776f0(int param_1);
void FUN_80177710(ushort *param_1);
void FUN_80177874(int param_1,int param_2);
void FUN_801778d0(int param_1);
undefined4
FUN_801778e0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
            int param_10);

int pushable_getExtraSize(void);
int pushable_getObjectTypeId(void);

int WarpPoint_getExtraSize(void);
int WarpPoint_getObjectTypeId(void);

int invhit_getExtraSize(void);
int invhit_getObjectTypeId(void);
void invhit_render(int *obj, int a, int b, int c, int d);
void invhit_hitDetect(void);
void invhit_release(void);
void invhit_initialise(void);

int iceblast_getExtraSize(void);
int iceblast_getObjectTypeId(void);
void iceblast_free(void);
void iceblast_render(int *obj, int a, int b, int c, int d);
void iceblast_hitDetect(void);
void iceblast_release(void);
void iceblast_initialise(void);

int flameblast_getExtraSize(void);

#endif /* MAIN_DLL_TRANSPORTER_H_ */
