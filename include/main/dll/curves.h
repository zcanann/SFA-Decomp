#ifndef MAIN_DLL_CURVES_H_
#define MAIN_DLL_CURVES_H_

#include "ghidra_import.h"

#define ROMCURVE_MAX_CURVES 0x514
#define ROMCURVE_ID_OFFSET 0x14
#define ROMCURVE_LINK_FLAGS_OFFSET 0x1b
#define ROMCURVE_LINK_IDS_OFFSET 0x1c
#define ROMCURVE_LINK_ID_STRIDE sizeof(u32)
#define ROMCURVE_LINK_COUNT 4
#define ROMCURVE_LINK_ID_NONE 0xffffffff
#define ROMCURVE_TYPE_ACTION 0x15
#define ROMCURVE_GETCURVES_MAX_POINTS 0x23

typedef struct RomCurveDef {
  u8 pad00[0x08];
  f32 x;
  f32 y;
  f32 z;
  u32 id;
  s8 action;
  s8 type;
  u8 pad1A;
  s8 blockedLinkMask;
  u32 linkIds[ROMCURVE_LINK_COUNT];
} RomCurveDef;

typedef struct RomCurvePoint {
  f32 x;
  f32 y;
  f32 z;
  f32 w;
  u32 flags;
  u8 type;
} RomCurvePoint;

undefined4
RomCurve_projectPointToAdjacentWindow(double x,double y,double z,u32 *curveIds,
                                      float *outLateralOffset,float *outVerticalOffset,
                                      float *outPhase);
undefined4 FUN_800e1b2c(double param_1,undefined8 param_2,double param_3,int param_4,int param_5);
int curves_distFn15(u32 curveId,f32 x,f32 y,f32 z,f32 *outDistance);
int curves_distanceToNearestOfType16(double param_1,double param_2,double param_3,int param_4);
void RomCurve_func13(undefined4 param_1,undefined4 param_2,uint param_3,int *param_4);
void RomCurve_func11(undefined4 param_1,undefined4 param_2,int param_3,int *param_4);
int RomCurve_getRandomLinkedOfTypes(int param_1,int param_2,int param_3,int *param_4);
int curves_findByAction(int action);
f32 curves_distXZ(f32 x,f32 z,uint curveId);
f32 curves_distFn0B(int obj,uint curveId);
void curves_find(undefined8 param_1,double param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 *param_6,undefined4 *param_7,undefined4 *param_8);
undefined4 RomCurve_findByIdWithIndex(uint curveId,int *outIndex);
void RomCurve_func20(undefined4 param_1,undefined4 param_2,int param_3,int param_4,int param_5);
int RomCurve_countRandomPoints(int param_1);
void RomCurve_func1E(undefined4 param_1,undefined4 param_2,float *param_3,float *param_4);
void RomCurve_getAdjacentWindow(int param_1,int *param_2);
int RomCurve_getNearestAdjacentLink(double param_1,double param_2,double param_3,int param_4,
                                    int param_5);
f32 RomCurve_distanceToSegment(f32 x,f32 y,f32 z,float *segment);
int RomCurve_getRandomBlockedLink(RomCurveDef *curve,int excludeLinkId);
int curves_getIds_18(RomCurveDef *curve,int excludeLinkId,int *outIds);
int RomCurve_getRandomUnblockedLink(RomCurveDef *curve,int excludeLinkId);
RomCurveDef *RomCurve_getById(uint curveId);
void RomCurve_find(undefined8 param_1,double param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,int param_6);
void curves_remove(RomCurveDef *curve);
void curves_addCurveDef(RomCurveDef *curve);
void curves_initialise(void);
void curves_release(void);
void curves_countRandomPoints(int obj,uint *curve);
void FUN_800e49c0(int param_1,uint *param_2);
void fn_800E56A4(int obj,f32 *state);
void fn_800E58FC(int obj,f32 *state);
void fn_800E5CBC(short *param_1,int param_2);
void fn_800E5E38(int obj,u32 *state);
void fn_800E5F1C(int obj,u32 *state);
void FUN_800e4db4(int param_1,int param_2);
void FUN_800e4db8(int param_1,int param_2);
void fn_800E618C(int obj,f32 *state);
void objFn_800e64f4(int obj,u32 *state);
void objFn_800e67ac(int obj,u32 *state);
void dll_15_func0A(int obj,u32 *state);
f32 dll_15_func0B(int obj,f32 x,f32 baseY,f32 z,f32 height);
double FUN_800e56bc(undefined8 param_1,double param_2,double param_3,double param_4,int param_5);
RomCurvePoint *curves_getCurves(f32 x,f32 z,int curve,u32 *outCount,int param_5);
void dll_15_func08(void);
void FUN_800e6140(undefined4 param_1,uint *param_2);
void dll_15_func06(void);
void FUN_800e65c8(uint *param_1,byte param_2,uint param_3,uint param_4,undefined param_5,
                 undefined param_6);
void curves_clear(uint *param_1,int param_2,uint param_3,int param_4);
int pushable_savePos(int obj);
uint playerHasKrazoaSpirit(u8 checkStoryBits,uint bit);
void saveFileStruct_setCheatActive(uint param_1,u8 param_2);

#endif /* MAIN_DLL_CURVES_H_ */
