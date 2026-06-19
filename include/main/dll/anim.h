#ifndef MAIN_DLL_ANIM_H_
#define MAIN_DLL_ANIM_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"
#include "main/dll/anim_internal.h"
#include "main/objanim_update.h"

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
u32 FUN_801ff90c(int obj, u32 unused, ObjAnimUpdateState *animUpdate);
void FUN_801ff9e0(int param_1);
void drakorenergy_update(int obj);
void FUN_801ffe30(int param_1,int param_2);
void FUN_801ffec4(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_8020019c(void);
u32 FUN_8020040c(int param_1,int param_2);
u32 FUN_80200474(int param_1,int param_2);
u32 FUN_802004c8(int param_1,int param_2);
u32 FUN_80200550(double param_1,u16 *param_2,int param_3);
u32
FUN_80200558(u64 param_1,double param_2,double param_3,u64 param_4,u64 param_5,
            u64 param_6,u64 param_7,u64 param_8,u32 param_9,int param_10,
            u32 param_11,u32 param_12,u32 param_13,u32 param_14,
            u32 param_15,u32 param_16);
u32
FUN_80200740(u64 param_1,double param_2,double param_3,u64 param_4,u64 param_5,
            u64 param_6,u64 param_7,u64 param_8,int param_9,int param_10,
            u32 param_11,u32 param_12,u32 param_13,u32 param_14,
            u32 param_15,u32 param_16);
void FUN_8020096c(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_80200970(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_80200974(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_80200c9c(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_80200f44(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_80200f48(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_80200f4c(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
u32
FUN_80201260(u64 param_1,double param_2,double param_3,u64 param_4,u64 param_5,
            u64 param_6,u64 param_7,u64 param_8,u32 param_9,int param_10,
            u32 param_11,u32 param_12,u32 param_13,u32 param_14,
            u32 param_15,u32 param_16);
u32
FUN_802014c8(u64 param_1,double param_2,double param_3,u64 param_4,u64 param_5,
            u64 param_6,u64 param_7,u64 param_8,int param_9,int param_10,
            u32 param_11,u32 param_12,u32 param_13,u32 param_14,
            u32 param_15,u32 param_16);
u32
FUN_80201658(u64 param_1,double param_2,double param_3,u64 param_4,u64 param_5,
            u64 param_6,u64 param_7,u64 param_8,int param_9,int param_10,
            u32 param_11,u32 param_12,u32 param_13,u32 param_14,
            u32 param_15,u32 param_16);
u32
FUN_802017a0(u64 param_1,double param_2,double param_3,u64 param_4,u64 param_5,
            u64 param_6,u64 param_7,u64 param_8,int param_9,int param_10,
            u32 param_11,u32 param_12,u32 param_13,u32 param_14,
            u32 param_15,u32 param_16);
void FUN_802019d8(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
u32 FUN_80201c9c(int param_1,int param_2);
void FUN_80201df4(u32 param_1,u32 param_2,float *param_3,int param_4);
u32
FUN_80202004(double param_1,double param_2,u64 param_3,double param_4,u16 *param_5,
            int param_6);
u32
FUN_80202130(double param_1,double param_2,u64 param_3,double param_4,u16 *param_5,
            int param_6);
void FUN_80202268(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,int param_10);
void FUN_80202414(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,int param_10);
void FUN_802026cc(u32 param_1,u32 param_2,int param_3);
void FUN_802028f0(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9);
void FUN_802029ec(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_80202b34(int param_1);
void FUN_80202b70(u64 param_1,double param_2,double param_3,double param_4,u64 param_5
                 ,u64 param_6,u64 param_7,u64 param_8);
void FUN_80203338(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,int param_10,int param_11);
void FUN_8020333c(void);
void FUN_8020335c(void);
void FUN_80203360(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,ObjAnimUpdateState *animUpdate,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void FUN_802035a8(int param_1);
void FUN_802035cc(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_802035f4(int param_1);
void FUN_80203688(u16 *param_1,int param_2);
void FUN_8020368c(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_802039e8(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
u32 FUN_80203c7c(int param_1);
void FUN_80203cdc(int param_1);
void FUN_80203d00(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_80203fd8(int param_1,int param_2);
void FUN_80203fdc(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,int param_10);
void FUN_80204078(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9);
void FUN_80204238(int obj);
void FUN_80204320(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_80204348(u32 param_1);
void FUN_802047d0(u16 *param_1,int param_2);
void FUN_802047d4(void);
void FUN_802047f4(void);
void FUN_80204814(void);
void FUN_80204834(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,ObjAnimUpdateState *animUpdate,int param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void FUN_80204bb4(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_80204bdc(int param_1);
void FUN_80204f1c(u16 *param_1,int param_2);
void FUN_80204f20(int obj);
void FUN_80204f7c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_802051e0(u32 param_1);

extern char sDoorswitchInitNoLongerSupported[];

int doorswitch_getExtraSize(void);
int doorswitch_getObjectTypeId(void);
void doorswitch_free(void);
void doorswitch_render(void);
void doorswitch_hitDetect(void);
void doorswitch_update(void);
void doorswitch_init(void);
void doorswitch_release(void);
void doorswitch_initialise(void);

int dbegg_func0B(int obj, f32* v);
int dbegg_setScale(int obj);
int dbegg_getExtraSize(void);
int dbegg_getObjectTypeId(void);
void dbegg_free(int x);
void dbegg_render(int obj, int p1, int p2, int p3, int p4, s8 visible);
void dbegg_hitDetect(int obj);
void dbegg_update(int obj);
void dbegg_init(int obj);
void dbegg_release(void);
void dbegg_initialise(void);

int GCRobotBlast_getExtraSize(void);
int GCRobotBlast_func08_ret_0(void);
int GCRobotBlast_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);
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
int drakorenergy_getObjectTypeId(void);
void drakorenergy_free(void);
void drakorenergy_render(int obj, int p1, int p2, int p3, int p4, s8 visible);
void drakorenergy_hitDetect(void);
void drakorenergy_init(int *obj, u8 *init);
void drakorenergy_release(void);
void drakorenergy_initialise(void);

s16 DBstealerworm_setScale(int *obj);
int dbstealerworm_getExtraSize(void);
int dbstealerworm_getObjectTypeId(void);
void dbstealerworm_free(int *obj);
void dbstealerworm_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void dbstealerworm_hitDetect(int obj);
void dbstealerworm_update(u8 *objp);
void dbstealerworm_init(int *obj, u8 *def, int param3);
void dbstealerworm_release(void);
void dbstealerworm_initialise(void);

int dbholecontrol1_getExtraSize(void);
int dbholecontrol1_getObjectTypeId(void);
void dbholecontrol1_free(int x);
void dbholecontrol1_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dbholecontrol1_hitDetect(void);
void dbholecontrol1_update(int *obj);
void dbholecontrol1_init(int *obj, u8 *params);
int dbholecontrol1_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);
void dbholecontrol1_release(void);
void dbholecontrol1_initialise(void);

void dfplevelcontrol_setScale(int unused, u8 *out);
int dfplevelcontrol_getExtraSize(void);
int dfplevelcontrol_getObjectTypeId(void);
void dfplevelcontrol_free(int x);
void dfplevelcontrol_render(void);
void dfplevelcontrol_hitDetect(void);
void dfplevelcontrol_update(int obj);
void dfplevelcontrol_init(int obj, int param2);
void dfplevelcontrol_release(void);
void dfplevelcontrol_initialise(void);

int dfpobjcreator_getExtraSize(void);
int dfpobjcreator_getObjectTypeId(void);
void dfpobjcreator_free(int obj, int flag);
void dfpobjcreator_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dfpobjcreator_hitDetect(void);
void dfpobjcreator_update(int obj);
void dfpobjcreator_init(int obj, s8 *def);
void dfpobjcreator_release(void);
void dfpobjcreator_initialise(void);

int dfpseqpoint_getExtraSize(void);
int dfpseqpoint_getObjectTypeId(void);
void dfpseqpoint_free(void);
void dfpseqpoint_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dfpseqpoint_hitDetect(void);
void dfpseqpoint_update(int obj);
void dfpseqpoint_init(int *obj, u8 *init);
int dfpseqpoint_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);
void dfpseqpoint_release(void);
void dfpseqpoint_initialise(void);

int dll_22C_getExtraSize_ret_16(void);
int dll_22C_getObjectTypeId(void);
void dll_22C_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dll_22C_init(int obj, char *p);
int dll_22C_SeqFn(void);
void dll_22C_hitDetect_nop(void);
void dll_22C_release_nop(void);
void dll_22C_initialise_nop(void);

int DFP_Torch_getExtraSize(void);
int DFP_Torch_getObjectTypeId(void);
void DFP_Torch_free(int obj);
void DFP_Torch_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void DFP_Torch_hitDetect(void);
void DFP_Torch_update(int obj);
void DFP_Torch_init(int obj, int param2);
void DFP_Torch_release(void);
void DFP_Torch_initialise(void);

#endif /* MAIN_DLL_ANIM_H_ */
