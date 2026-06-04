#ifndef MAIN_DLL_CURVES_H_
#define MAIN_DLL_CURVES_H_

#include "global.h"
#include "ghidra_import.h"

#define ROMCURVE_MAX_CURVES 0x514
#define ROMCURVE_DEF_SIZE 0x2c
#define ROMCURVE_POINT_SIZE 0x18
#define ROMCURVE_X_OFFSET 0x08
#define ROMCURVE_Y_OFFSET 0x0c
#define ROMCURVE_Z_OFFSET 0x10
#define ROMCURVE_ID_OFFSET 0x14
#define ROMCURVE_ACTION_OFFSET 0x18
#define ROMCURVE_TYPE_OFFSET 0x19
#define ROMCURVE_LINK_FLAGS_OFFSET 0x1b
#define ROMCURVE_LINK_IDS_OFFSET 0x1c
#define ROMCURVE_LINK_ID_STRIDE sizeof(u32)
#define ROMCURVE_LINK_COUNT 4
#define ROMCURVE_LINK_ID_NONE 0xffffffff
#define ROMCURVE_LINK_SEARCH_RESULT_COUNT ROMCURVE_LINK_COUNT
#define ROMCURVE_LINK_SEARCH_QUEUE_CAPACITY 0x28
#define ROMCURVE_PLACEMENT_ROT_Z_OFFSET 0x2c
#define ROMCURVE_PLACEMENT_ROT_Y_OFFSET 0x2d
#define ROMCURVE_PLACEMENT_ROT_X_OFFSET 0x2e
#define ROMCURVE_PLACEMENT_EXT_SIZE 0x30
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

typedef struct RomCurvePlacementDef {
  RomCurveDef base;
  s8 rotZ;
  s8 rotY;
  u8 rotX;
  u8 pad2F;
} RomCurvePlacementDef;

typedef struct RomCurvePoint {
  f32 x;
  f32 y;
  f32 z;
  f32 w;
  u32 flags;
  u8 type;
} RomCurvePoint;

STATIC_ASSERT(sizeof(RomCurveDef) == ROMCURVE_DEF_SIZE);
STATIC_ASSERT(offsetof(RomCurveDef, x) == ROMCURVE_X_OFFSET);
STATIC_ASSERT(offsetof(RomCurveDef, y) == ROMCURVE_Y_OFFSET);
STATIC_ASSERT(offsetof(RomCurveDef, z) == ROMCURVE_Z_OFFSET);
STATIC_ASSERT(offsetof(RomCurveDef, id) == ROMCURVE_ID_OFFSET);
STATIC_ASSERT(offsetof(RomCurveDef, action) == ROMCURVE_ACTION_OFFSET);
STATIC_ASSERT(offsetof(RomCurveDef, type) == ROMCURVE_TYPE_OFFSET);
STATIC_ASSERT(offsetof(RomCurveDef, blockedLinkMask) == ROMCURVE_LINK_FLAGS_OFFSET);
STATIC_ASSERT(offsetof(RomCurveDef, linkIds) == ROMCURVE_LINK_IDS_OFFSET);

STATIC_ASSERT(sizeof(RomCurvePlacementDef) == ROMCURVE_PLACEMENT_EXT_SIZE);
STATIC_ASSERT(offsetof(RomCurvePlacementDef, rotZ) == ROMCURVE_PLACEMENT_ROT_Z_OFFSET);
STATIC_ASSERT(offsetof(RomCurvePlacementDef, rotY) == ROMCURVE_PLACEMENT_ROT_Y_OFFSET);
STATIC_ASSERT(offsetof(RomCurvePlacementDef, rotX) == ROMCURVE_PLACEMENT_ROT_X_OFFSET);

STATIC_ASSERT(sizeof(RomCurvePoint) == ROMCURVE_POINT_SIZE);
STATIC_ASSERT(offsetof(RomCurvePoint, flags) == 0x10);
STATIC_ASSERT(offsetof(RomCurvePoint, type) == 0x14);

undefined4
RomCurve_projectPointToAdjacentWindow(f32 x,f32 y,f32 z,u32 *curveIds,
                                      float *outLateralOffset,float *outVerticalOffset,
                                      float *outPhase);
undefined4 FUN_800e1b2c(double param_1,undefined8 param_2,double param_3,int param_4,int param_5);
int curves_distFn15(u32 curveId,f32 x,f32 y,f32 z,f32 *outDistance);
int curves_distanceToNearestOfType16(f32 x,f32 y,f32 z,int param_4);
void RomCurve_func13(uint curveId,int typeFilter,uint param_3,int *param_4);
void RomCurve_func11(RomCurveDef *curve,int typeFilter,int actionFilter,int *outCurveId);
int RomCurve_getRandomLinkedOfTypes(RomCurveDef *curve,int *types,int typeCount,int *previousLinkId);
int curves_findByAction(int action);
f32 curves_distXZ(f32 x,f32 z,uint curveId);
f32 curves_distFn0B(int obj,uint curveId);
f32 curves_find(int type,int action,f32 x,f32 y,f32 z,f32 *outX,f32 *outY,f32 *outZ);
RomCurveDef *RomCurve_findByIdWithIndex(uint curveId,int *outIndex);
void RomCurve_func20(undefined4 param_1,undefined4 param_2,int param_3,int param_4,int param_5);
int RomCurve_countRandomPoints(RomCurveDef *curve);
void RomCurve_func1E(uint *curveIds,float *outX,float *outY,float *outZ);
void RomCurve_getAdjacentWindow(RomCurveDef *curve,int *outIds);
int RomCurve_getNearestAdjacentLink(f32 x,f32 y,f32 z,RomCurveDef *curve,int excludeLinkId);
f32 RomCurve_distanceToSegment(f32 x,f32 y,f32 z,float *segment);
int RomCurve_getRandomBlockedLink(RomCurveDef *curve,int excludeLinkId);
int RomCurve_getLinkIds(RomCurveDef *curve,int excludeLinkId,int *outIds);
int RomCurve_getRandomUnblockedLink(RomCurveDef *curve,int excludeLinkId);
RomCurveDef *RomCurve_getById(uint curveId);
int RomCurve_find(int *types,int typeCount,f32 x,f32 y,f32 z,int action);
void curves_remove(RomCurveDef *curve);
void curves_addCurveDef(RomCurveDef *curve);
void curves_initialise(void);
void curves_release(void);
void curves_countRandomPoints(int obj,uint *curve);
void FUN_800e49c0(int param_1,uint *param_2);
void fn_800E56A4(int obj,f32 *state);
void fn_800E58FC(int obj,f32 *state);
void fn_800E5CBC(short *param_1,int param_2);
void fn_800E5E38(int obj,f32 *state);
void fn_800E5F1C(int obj,f32 *state);
void FUN_800e4db4(int param_1,int param_2);
void FUN_800e4db8(int param_1,int param_2);
void curves_updateLocalPointCollision(int obj,f32 *state);
void curves_preparePointCollisionFrame(int obj,u32 *state);
void curves_updateLocalPointTransforms(int obj,u32 *state);
void dll_15_func0A(int obj,u32 *state);
f32 dll_15_func0B(int obj,f32 x,f32 baseY,f32 z,f32 height);
double FUN_800e56bc(undefined8 param_1,double param_2,double param_3,double param_4,int param_5);
RomCurvePoint *curves_getCurves(f32 x,f32 z,int obj,u32 *outCount,int queryAll);
void dll_15_func08(ushort *curveObj,uint *state,uint updateValue,f32 step);
void FUN_800e6140(undefined4 param_1,uint *param_2);
void dll_15_func05(u32 *state,int count,u32 source,f32 *radii,s8 *types);
void dll_15_func06(ushort *curveObj,uint *state);
void FUN_800e65c8(uint *param_1,byte param_2,uint param_3,uint param_4,undefined param_5,
                 undefined param_6);
void curves_setLocalPointCollisionEx(u8* obj, int a, u32 b, u32 c, int d, int e);
void curves_clear(uint *param_1,int param_2,uint param_3,int param_4);
int pushable_savePos(int obj);
uint playerHasKrazoaSpirit(u8 checkStoryBits,uint bit);
void saveFileStruct_setCheatActive(uint param_1,u8 param_2);

#endif /* MAIN_DLL_CURVES_H_ */
