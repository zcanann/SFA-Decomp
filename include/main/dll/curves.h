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

typedef struct RomCurveDef {
  u8 pad00[0x08];
  f32 x;
  f32 y;
  f32 z;
  u32 id;
  u8 pad18[ROMCURVE_LINK_FLAGS_OFFSET - 0x18];
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
fn_800E1B24(double x,double y,double z,u32 *curveIds,float *outLateralOffset,
            float *outVerticalOffset,float *outPhase);
undefined4 FUN_800e1b2c(double param_1,undefined8 param_2,double param_3,int param_4,int param_5);
void FUN_800e1c00(undefined8 param_1,double param_2,double param_3);
int curves_distanceToNearestOfType16(double param_1,double param_2,double param_3,int param_4);
void FUN_800e2090(undefined4 param_1,undefined4 param_2,uint param_3,int *param_4);
void FUN_800e2590(undefined4 param_1,undefined4 param_2,int param_3,int *param_4);
int RomCurve_getRandomLinkedOfTypes(int param_1,int param_2,int param_3,int *param_4);
f32 curves_distXZ(f32 param_1,f32 param_2,uint param_3);
f32 RomCurve_distanceToObject(int param_1,uint param_2);
void curves_find(undefined8 param_1,double param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 *param_6,undefined4 *param_7,undefined4 *param_8);
undefined4 RomCurve_findByIdWithIndex(uint curveId,int *outIndex);
void FUN_800e31dc(undefined4 param_1,undefined4 param_2,int param_3,int param_4,int param_5);
int FUN_800e3ad4(int param_1);
void FUN_800e3cec(undefined4 param_1,undefined4 param_2,float *param_3,float *param_4);
void RomCurve_getAdjacentWindow(int param_1,int *param_2);
int RomCurve_getNearestAdjacentLink(double param_1,double param_2,double param_3,int param_4,
                                    int param_5);
f32 RomCurve_distanceToSegment(f32 x,f32 y,f32 z,float *segment);
int RomCurve_getRandomBlockedLink(int curve,int excludeLinkId);
int RomCurve_getRandomUnblockedLink(int curve,int excludeLinkId);
RomCurveDef *RomCurve_getById(uint curveId);
void FUN_800e4628(undefined8 param_1,double param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,int param_6);
void curves_remove(int curve);
void curves_addCurveDef(int param_1);
void curves_initialise(void);
void curves_release(void);
void curves_countRandomPoints(int obj,uint *curve);
void FUN_800e49c0(int param_1,uint *param_2);
void FUN_800e49c4(void);
void FUN_800e4c64(short *param_1,int param_2);
void FUN_800e4db4(int param_1,int param_2);
void FUN_800e4db8(int param_1,int param_2);
void FUN_800e4dbc(void);
void FUN_800e514c(void);
void FUN_800e5428(void);
void FUN_800e5570(void);
double FUN_800e56bc(undefined8 param_1,double param_2,double param_3,double param_4,int param_5);
RomCurvePoint *curves_getCurves(f32 x,f32 z,int curve,u32 *outCount,int param_5);
void FUN_800e58b8(void);
void FUN_800e6140(undefined4 param_1,uint *param_2);
void FUN_800e61a4(void);
void FUN_800e65c8(uint *param_1,byte param_2,uint param_3,uint param_4,undefined param_5,
                 undefined param_6);
void curves_clear(uint *param_1,int param_2,uint param_3,int param_4);
uint FUN_800e6680(char param_1,uint param_2);
void gameplay_setDebugOptionEnabled(uint param_1,u8 param_2);

#endif /* MAIN_DLL_CURVES_H_ */
