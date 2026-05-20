#ifndef MAIN_DLL_GENPROPS_H_
#define MAIN_DLL_GENPROPS_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

int mikabomb_getExtraSize();
int mikabomb_func08();
void mikabomb_free();
void mikabomb_render();
void mikabomb_hitDetect();
void mikabomb_update(uint param_1,int param_2);
void mikabomb_init();
void mikabomb_release(void);
void mikabomb_initialise(void);
void FUN_8016b2e4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10);
void FUN_8016b39c(int param_1);
void FUN_8016b3c4(uint param_1);
int mikabombshadow_getExtraSize(void);
int mikabombshadow_func08(void);
void mikabombshadow_free(void);
void mikabombshadow_render(int *obj, int p2, int p3, int p4, int p5, s8 visible);
void mikabombshadow_hitDetect(void);
void mikabombshadow_update();
void mikabombshadow_init();
void mikabombshadow_release(void);
void mikabombshadow_initialise(void);
void FUN_8016b7d4(undefined2 *param_1);
int StaticCamera_getExtraSize(void);
int StaticCamera_func08(void);
void StaticCamera_free(int x);
void StaticCamera_render(int p1,int p2,int p3,int p4,int p5,s8 visible);
void StaticCamera_hitDetect(void);
void StaticCamera_update(void);
void StaticCamera_init();
void StaticCamera_release(void);
void StaticCamera_initialise(void);
void FUN_8016b970(int param_1);
void FUN_8016b9a8(int param_1);
int gcbaddieshield_getExtraSize(void);
int gcbaddieshield_func08(void);
void gcbaddieshield_free(void);
void gcbaddieshield_render();
void gcbaddieshield_hitDetect(void);
void gcbaddieshield_update();
void gcbaddieshield_init(int *obj, void *initData);
void gcbaddieshield_release(void);
void gcbaddieshield_initialise(void);
void FUN_8016ba18(undefined2 *param_1);
int baddieinterestp_getExtraSize(void);
int baddieinterestp_func08(void);
void baddieinterestp_free(void);
void baddieinterestp_render(int p1,int p2,int p3,int p4,int p5,s8 visible);
void baddieinterestp_hitDetect(void);
void baddieinterestp_update();
void baddieinterestp_init(void);
void baddieinterestp_release(void);
void baddieinterestp_initialise(void);
void staticCamera_free(int param_1);
void staticCamera_render(int param_1);
void staticCamera_init(short *param_1,int param_2,int param_3);
void FUN_8016bbb8(int param_1);
void FUN_8016bbec(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9);
void FUN_8016bd30(int param_1,int param_2);
void FUN_8016bd80(int param_1);
void FUN_8016bda8(void);
void FUN_8016c0a0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10);
void FUN_8016c1e0(ushort *param_1);
void FUN_8016c388(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9);
void FUN_8016c710(int param_1,int param_2);
void FUN_8016c8a4(int param_1);
void FUN_8016ca4c(int param_1);
void FUN_8016cacc(void);
void FUN_8016cc88(int param_1);
void FUN_8016ceb4(int param_1,int param_2);
undefined4 FUN_8016d03c(int param_1,undefined4 param_2,int param_3);
void FUN_8016d150(int param_1);
void FUN_8016d188(int param_1,int param_2);
void FUN_8016d994(int param_1,undefined param_2,undefined param_3);
void FUN_8016d9a4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 *param_9);
void FUN_8016dc58(void);
void FUN_8016ddd8(void);
void FUN_8016dddc(void);
void FUN_8016e5b0(uint param_1,char param_2,char param_3);
void FUN_8016e658(int param_1);
void FUN_8016e668(uint param_1);
void FUN_8016e7e8(int param_1);
void FUN_8016e834(int param_1);
void FUN_8016e858(int param_1);
void FUN_8016e8cc(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9);
void FUN_8016ecf8(int param_1);
void FUN_8016edac(void);
void FUN_8016edb0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);
undefined FUN_8016edb4(int param_1);
undefined4 FUN_8016edc0(int param_1,undefined4 param_2,int param_3);
void FUN_8016ee98(int param_1,int param_2,int param_3);
void FUN_8016f038(int param_1);
void FUN_8016f09c(void);
void FUN_8016f29c(int param_1);
void FUN_8016f3d8(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9);
void FUN_8016fc2c(void);
void FUN_8016fc30(int param_1);
void FUN_8016fc50(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9);
void FUN_8016fe58(int param_1,int param_2);
int FUN_8016fef4(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
                undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9);
void FUN_80170048(void);
void FUN_80170978(int param_1);
void FUN_801709dc(void);
void FUN_80170df4(void);
void FUN_80170df8(int param_1);
void FUN_80170e48(int param_1);
void FUN_80170e70(int param_1);
void FUN_80170ed8(void);
void FUN_80170f60(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9);
void FUN_80170f64(undefined2 *param_1,int param_2);
void checkpoint4_render(int param_1);
void checkpoint4_init(ushort *param_1,int param_2);
void sideload_update(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                    undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                    int param_9);
void FUN_8017121c(int param_1);
void FUN_80171240(int param_1,int param_2);
void FUN_801712a8(double param_1,double param_2,double param_3,int param_4);
undefined4 FUN_80171310(int param_1);
void FUN_80171354(int param_1,int param_2);
void FUN_801713ac(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9);

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
extern ObjectDescriptor lbl_80320B38;
extern ObjectDescriptor11WithPadding gCheckpoint4ObjDescriptor;

#endif /* MAIN_DLL_GENPROPS_H_ */
