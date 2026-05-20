#ifndef MAIN_DLL_ANIM_H_
#define MAIN_DLL_ANIM_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"
#include "main/dll/anim_internal.h"

extern ObjectDescriptor12 gDB_eggObjDescriptor;
extern ObjectDescriptor12 gDrakorEnergyObjDescriptor;
extern ObjectDescriptor gDBHoleControl1ObjDescriptor;
extern ObjectDescriptor10WithPadding gDFP_LevelControlObjDescriptor;
extern ObjectDescriptor gDFP_ObjCreatorObjDescriptor;
extern ObjectDescriptor gDoorswitchObjDescriptor;
extern ObjectDescriptor gDFP_seqpointObjDescriptor;
extern ObjectDescriptor gDFP_TorchObjDescriptor;

void FUN_801feb30(void);
void FUN_801ff8b8(short *param_1);
undefined4 FUN_801ff90c(int param_1,undefined4 param_2,int param_3);
void FUN_801ff9e0(int param_1);
void drakorenergy_update(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                         undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                         short *param_9);
void FUN_801ffe30(int param_1,int param_2);
void FUN_801ffec4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
void FUN_8020019c(void);
undefined4 FUN_8020040c(int param_1,int param_2);
undefined4 FUN_80200474(int param_1,int param_2);
undefined4 FUN_802004c8(int param_1,int param_2);
undefined4 FUN_80200550(double param_1,ushort *param_2,int param_3);
undefined4
FUN_80200558(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16);
undefined4
FUN_80200740(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16);
void FUN_8020096c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
void FUN_80200970(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
void FUN_80200974(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
void FUN_80200c9c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
void FUN_80200f44(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
void FUN_80200f48(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
void FUN_80200f4c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
undefined4
FUN_80201260(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16);
undefined4
FUN_802014c8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16);
undefined4
FUN_80201658(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16);
undefined4
FUN_802017a0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16);
void FUN_802019d8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
undefined4 FUN_80201c9c(int param_1,int param_2);
void FUN_80201df4(undefined4 param_1,undefined4 param_2,float *param_3,int param_4);
undefined4
FUN_80202004(double param_1,double param_2,undefined8 param_3,double param_4,ushort *param_5,
            int param_6);
undefined4
FUN_80202130(double param_1,double param_2,undefined8 param_3,double param_4,ushort *param_5,
            int param_6);
void FUN_80202268(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10);
void FUN_80202414(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10);
void FUN_802026cc(undefined4 param_1,undefined4 param_2,int param_3);
void FUN_802028f0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9);
void FUN_802029ec(void);
void FUN_80202b34(int param_1);
void FUN_80202b70(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8);
void FUN_80203338(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10,int param_11);
void FUN_8020333c(void);
void FUN_8020335c(void);
void FUN_80203360(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);
void FUN_802035a8(int param_1);
void FUN_802035cc(int param_1);
void FUN_802035f4(int param_1);
void FUN_80203688(undefined2 *param_1,int param_2);
void FUN_8020368c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
void FUN_802039e8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
undefined4 FUN_80203c7c(int param_1);
void FUN_80203cdc(int param_1);
void FUN_80203d00(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
void FUN_80203fd8(int param_1,int param_2);
void FUN_80203fdc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10);
void FUN_80204078(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9);
void FUN_80204238(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9);
void FUN_80204320(int param_1);
void FUN_80204348(uint param_1);
void FUN_802047d0(undefined2 *param_1,int param_2);
void FUN_802047d4(void);
void FUN_802047f4(void);
void FUN_80204814(void);
void FUN_80204834(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,int param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16);
void FUN_80204bb4(int param_1);
void FUN_80204bdc(int param_1);
void FUN_80204f1c(undefined2 *param_1,int param_2);
void FUN_80204f20(undefined4 param_1);
void FUN_80204f7c(int param_1);
void FUN_802051e0(uint param_1);

extern char sDoorswitchInitNoLongerSupported[];

int doorswitch_getExtraSize(void);
int doorswitch_func08(void);
void doorswitch_free(void);
void doorswitch_render(void);
void doorswitch_hitDetect(void);
void doorswitch_update(void);
void doorswitch_init(void);
void doorswitch_release(void);
void doorswitch_initialise(void);

int dbegg_func0B(void);
void dbegg_setScale(void);
int dbegg_getExtraSize(void);
int dbegg_func08(void);
void dbegg_free(void);
void dbegg_render(void);
void dbegg_hitDetect(void);
void dbegg_update(void);
void dbegg_init(void);
void dbegg_release(void);
void dbegg_initialise(void);

int GCRobotBlast_getExtraSize(void);
int GCRobotBlast_func08_ret_0(void);
void GCRobotBlast_free(void);
void GCRobotBlast_render(void);
void GCRobotBlast_hitDetect(void);
void GCRobotBlast_update(void);
void GCRobotBlast_init(int obj, s8 *p);
void GCRobotBlast_release(void);
void GCRobotBlast_initialise(void);

int DrakorEnergy_setScale(int *obj);
void DrakorEnergy_func0B_nop(void);
int drakorenergy_getExtraSize(void);
int drakorenergy_func08(void);
void drakorenergy_free(void);
void drakorenergy_render(int obj, int p1, int p2, int p3, int p4, s8 visible);
void drakorenergy_hitDetect(void);
void drakorenergy_init(void);
void drakorenergy_release(void);
void drakorenergy_initialise(void);

s16 DBstealerworm_setScale(int *obj);
int dbstealerworm_getExtraSize(void);
int dbstealerworm_func08(void);
void dbstealerworm_free(void);
void dbstealerworm_render(void);
void dbstealerworm_hitDetect(void);
void dbstealerworm_update(void);
void dbstealerworm_init(void);
void dbstealerworm_release(void);
void dbstealerworm_initialise(void);

int dbholecontrol1_getExtraSize(void);
int dbholecontrol1_func08(void);
void dbholecontrol1_free(int x);
void dbholecontrol1_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dbholecontrol1_hitDetect(void);
void dbholecontrol1_update(void);
void dbholecontrol1_init(void);
void dbholecontrol1_release(void);
void dbholecontrol1_initialise(void);

void dfplevelcontrol_setScale(void);
int dfplevelcontrol_getExtraSize(void);
int dfplevelcontrol_func08(void);
void dfplevelcontrol_free(int x);
void dfplevelcontrol_render(void);
void dfplevelcontrol_hitDetect(void);
void dfplevelcontrol_update(void);
void dfplevelcontrol_init(void);
void dfplevelcontrol_release(void);
void dfplevelcontrol_initialise(void);

int dfpobjcreator_getExtraSize(void);
int dfpobjcreator_func08(void);
void dfpobjcreator_free(void);
void dfpobjcreator_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dfpobjcreator_hitDetect(void);
void dfpobjcreator_update(void);
void dfpobjcreator_init(void);
void dfpobjcreator_release(void);
void dfpobjcreator_initialise(void);

int dfpseqpoint_getExtraSize(void);
int dfpseqpoint_func08(void);
void dfpseqpoint_free(void);
void dfpseqpoint_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dfpseqpoint_hitDetect(void);
void dfpseqpoint_update(void);
void dfpseqpoint_init(void);
void dfpseqpoint_release(void);
void dfpseqpoint_initialise(void);

int DFP_Torch_getExtraSize(void);
int DFP_Torch_func08(void);
void DFP_Torch_free(void);
void DFP_Torch_render(void);
void DFP_Torch_hitDetect(void);
void DFP_Torch_update(void);
void DFP_Torch_init(void);
void DFP_Torch_release(void);
void DFP_Torch_initialise(void);

#endif /* MAIN_DLL_ANIM_H_ */
