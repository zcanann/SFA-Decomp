#ifndef MAIN_DLL_GENPROPS_H_
#define MAIN_DLL_GENPROPS_H_

#include "ghidra_import.h"
#include "main/dll/checkpoint4.h"
#include "main/dll/dll_0015_curves.h"
#include "main/object_descriptor.h"
#include "main/objanim.h"
#include "main/objanim_update.h"

int mikabomb_getExtraSize();
int mikabomb_getObjectTypeId();
void mikabomb_free();
void mikabomb_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void mikabomb_hitDetect();
void mikabomb_update(int *obj);
void mikabomb_init();
void mikabomb_release(void);
void mikabomb_initialise(void);
void FUN_8016b2e4(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,int param_10);
void FUN_8016b39c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_8016b3c4(u32 param_1);
int mikabombshadow_getExtraSize(void);
int mikabombshadow_getObjectTypeId(void);
void mikabombshadow_free(void);
void mikabombshadow_render(int *obj, int p2, int p3, int p4, int p5, s8 visible);
void mikabombshadow_hitDetect(void);
void mikabombshadow_update();
void mikabombshadow_init();
void mikabombshadow_release(void);
void mikabombshadow_initialise(void);
void FUN_8016b7d4(u16 *param_1);
int StaticCamera_getExtraSize(void);
int StaticCamera_getObjectTypeId(void);
void StaticCamera_free(int x);
void StaticCamera_render(int p1,int p2,int p3,int p4,int p5,s8 visible);
void StaticCamera_hitDetect(void);
void StaticCamera_update(void);
void StaticCamera_init();
void StaticCamera_release(void);
void StaticCamera_initialise(void);
void FUN_8016b970(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_8016b9a8(int param_1);
int gcbaddieshield_getExtraSize(void);
int gcbaddieshield_getObjectTypeId(void);
void gcbaddieshield_free(void);
void gcbaddieshield_render(int *obj, int p2, int p3, int p4, int p5, s8 visible);
void gcbaddieshield_hitDetect(void);
void gcbaddieshield_update();
void gcbaddieshield_init(int *obj, void *initData);
void gcbaddieshield_release(void);
void gcbaddieshield_initialise(void);
void FUN_8016ba18(u16 *param_1);
int baddieinterestp_getExtraSize(void);
int baddieinterestp_getObjectTypeId(void);
void baddieinterestp_free(void);
void baddieinterestp_render(int p1,int p2,int p3,int p4,int p5,s8 visible);
void baddieinterestp_hitDetect(void);
void baddieinterestp_update();
void baddieinterestp_init(void);
void baddieinterestp_release(void);
void baddieinterestp_initialise(void);
void staticCamera_free(int param_1);
void staticCamera_render(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void staticCamera_init(short *param_1,int param_2,int param_3);
void FUN_8016bbb8(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_8016bbec(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 short *param_9);
void FUN_8016bd30(int param_1,int param_2);
void FUN_8016bd80(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_8016bda8(void);
void FUN_8016c0a0(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,int param_10);
void FUN_8016c1e0(u16 *param_1);
void FUN_8016c388(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9);
void FUN_8016c710(int param_1,int param_2);
void FUN_8016c8a4(int param_1);
void FUN_8016ca4c(int param_1);
void FUN_8016cacc(void);
void FUN_8016cc88(int param_1);
void FUN_8016ceb4(int param_1,int param_2);
u32 FUN_8016d03c(GameObject *obj,u32 unused,ObjAnimUpdateState *animUpdate);
void FUN_8016d150(int param_1);
void FUN_8016d188(int param_1,int param_2);
void FUN_8016d994(int param_1,u8 param_2,u8 param_3);
void FUN_8016d9a4(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 *param_9);
void FUN_8016dc58(void);
void FUN_8016ddd8(void);
void FUN_8016dddc(void);
void FUN_8016e5b0(u32 param_1,char param_2,char param_3);
void FUN_8016e658(int param_1);
void FUN_8016e668(u32 param_1);
void FUN_8016e7e8(int param_1);
void FUN_8016e834(int param_1);
void FUN_8016e858(int param_1);
void staff_func0E(void);
void FUN_8016ecf8(int param_1);
void FUN_8016edac(void);
void FUN_8016edb0(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
u8 FUN_8016edb4(int param_1);
u32 FUN_8016edc0(GameObject *obj,u32 unused,ObjAnimUpdateState *animUpdate);
void FUN_8016ee98(int param_1,int param_2,int param_3);
void FUN_8016f038(int param_1);
void FUN_8016f09c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_8016f29c(int param_1);
void FUN_8016f3d8(u64 param_1,double param_2,double param_3,double param_4,u64 param_5
                 ,u64 param_6,u64 param_7,u64 param_8,short *param_9);
void FUN_8016fc2c(void);
void FUN_8016fc30(int param_1);
void FUN_8016fc50(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u16 *param_9);
void FUN_8016fe58(int param_1,int param_2);
int FUN_8016fef4(double param_1,double param_2,double param_3,u64 param_4,u64 param_5,
                u64 param_6,u64 param_7,u64 param_8,int param_9);
void FUN_80170048(void);
void FUN_80170978(int param_1);
void FUN_801709dc(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_80170df4(void);
void FUN_80170df8(int param_1);
void FUN_80170e48(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_80170e70(int param_1);
void FUN_80170ed8(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_80170f60(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u16 *param_9);
void FUN_80170f64(u16 *param_1,int param_2);
void sideload_update(int param_1);
void FUN_8017121c(int param_1);
void FUN_80171240(int param_1,int param_2);
void FUN_801712a8(double param_1,double param_2,double param_3,int param_4);
u32 FUN_80171310(int param_1);
void FUN_80171354(int param_1,int param_2);
void FUN_801713ac(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9);
void curve_setScale(void);
void curve_free(void);
int curve_func11(void);
int curve_getExtraSize(void);
int curve_getObjectTypeId(void);
void curve_init(ObjAnimComponent *obj, CurvePlacementParams *params);
void curve_render(int p1,int p2,int p3,int p4,int p5,s8 visible);
int dll_F7_getExtraSize(void);
int dll_F7_getObjectTypeId(void);
void dll_F7_hitDetect(void);
void dll_F7_release(void);
void dll_F7_initialise(void);

extern ObjectDescriptor gMikaBombObjDescriptor;
extern ObjectDescriptor gMikaBombShadowObjDescriptor;
extern ObjectDescriptor gStaticCameraObjDescriptor;
extern ObjectDescriptor gGCbaddieShieldObjDescriptor;
extern ObjectDescriptor gBaddieInterestPObjDescriptor;
extern ObjectDescriptor gAnimatedObjDescriptor;
extern ObjectDescriptor gDIM2RoofRubObjDescriptor;
extern ObjectDescriptor gDepthOfFieldPointObjDescriptor;
extern ObjectDescriptor23 gStaffObjDescriptor;
extern ObjectDescriptor10WithPadding gFireballObjDescriptor;
extern ObjectDescriptor gShieldObjDescriptor;
extern ObjectDescriptor13 gFlameThrowerSpeObjDescriptor;
extern ObjectDescriptor12 gCurveObjDescriptor;
extern ObjectDescriptor gReStartMarkerObjDescriptor;
extern ObjectDescriptor dll_F7;

int depthoffieldpoint_SeqFn(int *obj, int unused, ObjAnimUpdateState *animUpdate);
int Fireball_SeqFn(int *obj, int unused, ObjAnimUpdateState *animUpdate);

int kaldachompspit_getObjectTypeId(void);
int kaldachompspit_getExtraSize(void);
void animatedobj_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
void animatedobj_update(int* obj);
void dim2roofrub_render(int* obj, int p2, int p3, int p4, int p5);
void dim2roofrub_update(int* obj);
void staff_free(int* obj);
void staff_modelMtxFn(int* obj, int p4, int p5);
s16 staff_getHitReactValue(int* obj);
s32 staff_func16(int* obj);
void fireball_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void flamethrowerspe_func0B(int* obj);
void flamethrowerspe_render(void);
void shield_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
void dll_F7_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);


/* extern-cleanup: consolidated prototypes (true-def sigs) */
void animatedobj_free(int* obj, int seqFlag);
void animatedobj_init(int* obj, int* params);
void dim2roofrub_init(int* obj, int* params);
void staff_update(int* obj);
void staff_init(int* obj);
void staff_release(void);
void staff_initialise(void);
void staff_hitDetectGeometry(int* obj);
void dll_F7_free(int obj);
void shield_free(int obj);

#endif /* MAIN_DLL_GENPROPS_H_ */
