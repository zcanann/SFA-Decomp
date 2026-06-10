#include "main/dll/baddie_state.h"
#include "main/dll/objfsa.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/objanim.h"

extern void OSReport(const char *fmt, ...);

/* RomCurveWalker now lives in main/dll/curve_walker.h (lifted per the
 * deref-cleanup wave; curves.h re-exports it). */
#include "main/dll/curve_walker.h"

typedef struct RomCurveSegmentProjection {
  f32 startX;
  f32 startY;
  f32 startZ;
  f32 endX;
  f32 endY;
  f32 endZ;
  f32 nearestX;
  f32 nearestY;
  f32 nearestZ;
} RomCurveSegmentProjection;
extern undefined4 FUN_800033a8();
extern undefined4 FUN_80003494();
extern undefined4 FUN_80006a10();
extern undefined4 FUN_80006a18();
extern undefined4 FUN_80006a1c();
extern undefined4 FUN_80006a30();
extern char FUN_80006a64();
extern undefined8 FUN_80006a68();
extern byte FUN_80006b20();
extern undefined4 FUN_80006b28();
extern undefined4 FUN_80006b30();
extern uint GameBit_Get(int eventId);
extern double FUN_80017714();
extern uint FUN_80017730();
extern undefined4 FUN_80017754();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017778();
extern undefined FUN_8002fc3c();
extern undefined4 FUN_800571f8();
extern int FUN_8005b398();
extern int FUN_800620e8();
extern int objBboxFn_800640cc(f32 *from,f32 *to,f32 radius,int mode,void *hit,int obj,int p7,
                              int p8,int p9,int p10);
extern undefined4 FUN_800723a0();
extern undefined4 FUN_800d8088();
extern undefined4 FUN_800d8240();
extern int RomCurve_projectPointToAdjacentWindow();
extern int curves_distFn15();
extern RomCurveDef *RomCurve_findByIdWithIndex(uint curveId,int *outIndex);
extern int mathFn_800dbff0(float *point);
extern void *romCurves[];
extern s32 nRomCurves;
extern undefined4 RomCurve_getAdjacentWindow();
extern f32 RomCurve_distanceToSegment(f32 x,f32 y,f32 z,RomCurveSegmentProjection *segment);
extern int FUN_80286818();
extern undefined4 FUN_80286824();
extern undefined8 FUN_8028682c();
extern undefined8 FUN_80286838();
extern undefined8 FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286864();
extern undefined4 FUN_80286870();
extern undefined4 FUN_80286878();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern f32 sqrtf(f32 x);
extern uint countLeadingZeros();
extern void voxmaps_worldToGrid(f32 *world,s16 *grid);
extern int voxmaps_traceLine(s16 *start,s16 *end,void *coordOut,u8 *occOut,int skipFirst);

extern char DAT_803120d8;
extern undefined2 DAT_8039d748;
extern undefined4 DAT_8039d74a;
extern undefined4 DAT_8039d758;
extern undefined4 DAT_8039d768;
extern undefined4 DAT_8039d76a;
extern undefined4 DAT_8039d76c;
extern undefined4 DAT_8039d76e;
extern undefined4 DAT_8039d770;
extern undefined4 DAT_8039d772;
extern undefined4 DAT_8039d774;
extern short DAT_8039d778;
extern short DAT_803a0748;
extern undefined4 DAT_803a074a;
extern undefined4 DAT_803a074c;
extern undefined4 DAT_803a074e;
extern undefined4 DAT_803a0750;
extern undefined4 DAT_803a0752;
extern undefined4 DAT_803a0754;
extern undefined4 DAT_803a0756;
extern undefined4 DAT_803a0758;
extern undefined4 DAT_803a075c;
extern undefined4 DAT_803a0760;
extern undefined4 DAT_803a0764;
extern undefined4 DAT_803a0768;
extern undefined4 DAT_803a076a;
extern undefined4 DAT_803a076c;
extern undefined4 DAT_803a2390;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd71c;
extern undefined4 DAT_803de0b0;
extern undefined4 DAT_803de0b4;
extern undefined4 DAT_803de0c0;
extern undefined4 DAT_803de0ce;
extern undefined4 DAT_803de0cf;
extern undefined4 DAT_803de0d0;
extern undefined4 DAT_803de0e0;
extern undefined4 DAT_803de0e4;
extern undefined4 DAT_803de0f0;
extern f64 DOUBLE_803e1218;
extern f64 DOUBLE_803e1260;
extern f64 DOUBLE_803e1268;
extern f64 DOUBLE_803e12a8;
extern f32 lbl_803DC074;
extern f32 lbl_803DE0C4;
extern f32 lbl_803DE0C8;
extern f32 lbl_803E11F0;
extern f32 lbl_803E1204;
extern f32 lbl_803E1208;
extern f32 lbl_803E1234;
extern f32 lbl_803E1238;
extern f32 lbl_803E123C;
extern f32 lbl_803E1240;
extern f32 lbl_803E1244;
extern f32 lbl_803E1248;
extern f32 lbl_803E124C;
extern f32 lbl_803E1250;
extern f32 lbl_803E1270;
extern f32 lbl_803E1274;
extern f32 lbl_803E1278;
extern f32 lbl_803E127C;
extern f32 lbl_803E1280;
extern f32 lbl_803E1284;
extern f32 lbl_803E1288;
extern f32 lbl_803E128C;
extern f32 lbl_803E1290;
extern f32 lbl_803E12B0;
extern f32 lbl_803E12B4;
extern f32 lbl_803E12B8;
extern f32 lbl_803E12BC;
extern f32 lbl_803E12C0;
extern f32 gFloatOne;

typedef struct ObjfsaRomCurveDef {
  u8 pad00[0x08];
  f32 x;
  f32 y;
  f32 z;
  u32 id;
  s8 action;
  s8 type;
  u8 pad1A;
  s8 blockedLinkMask;
  s32 linkIds[4];
} ObjfsaRomCurveDef;
extern f32 lbl_803E12C4;
extern f32 lbl_803E12C8;
extern f32 lbl_803E12CC;
extern f32 lbl_803E12D0;
extern f32 lbl_803E12D4;
extern f32 lbl_803E05F0;
extern f32 lbl_803E0644;
extern int lbl_803DD460;
extern int lbl_803DD464;
extern int lbl_803DD468;
extern char sObjfsaFoundNewWalkGroupPatch[];
extern char sObjfsaIsPointWithinPatchGroupError[];

#define OBJFSA_PATCHGROUP_PATCH_COUNT 4
#define OBJFSA_PATCHGROUP_STRIDE 0x28
#define OBJFSA_PATCHGROUP_PATCHES_OFFSET 0x3024
#define OBJFSA_ACTIVE_WALKGROUPS_OFFSET 0x4C48
#define OBJFSA_WALKGROUP_COUNT 0xB5

typedef struct ObjfsaPatchPlane {
  s16 normalX;
  s16 normalZ;
} ObjfsaPatchPlane;

typedef struct ObjfsaPatch {
  ObjfsaPatchPlane planes[OBJFSA_PATCHGROUP_PATCH_COUNT];
  f32 planeOffsets[OBJFSA_PATCHGROUP_PATCH_COUNT];
  s16 maxY;
  s16 minY;
  u16 groupId;
  s16 exit0X;
  s16 exit0Z;
  s16 exit1X;
  s16 exit1Z;
  u8 pad2E[2];
} ObjfsaPatch;

typedef struct ObjfsaWalkGroup {
  ObjfsaPatchPlane planes[OBJFSA_PATCHGROUP_PATCH_COUNT];
  f32 planeOffsets[OBJFSA_PATCHGROUP_PATCH_COUNT];
  s16 maxY;
  s16 minY;
  u8 patchIndices[OBJFSA_PATCHGROUP_PATCH_COUNT];
} ObjfsaWalkGroup;

typedef struct ObjfsaWalkGroupPatchInfo {
  u8 walkGroupIndex;
  u8 patchMask;
  u16 patchGroupIds[OBJFSA_PATCHGROUP_PATCH_COUNT];
} ObjfsaWalkGroupPatchInfo;

extern ObjfsaPatch lbl_8039CAE8[];
extern ObjfsaWalkGroup lbl_8039FAE8[];
extern u8 lbl_803A1730[];

static inline ObjfsaPatch *Objfsa_GetPatch(int patchIndex) {
  return &lbl_8039CAE8[patchIndex];
}

static inline ObjfsaWalkGroup *Objfsa_GetWalkGroup(int groupIndex) {
  return &lbl_8039FAE8[groupIndex];
}

static inline u8 *Objfsa_GetPatchGroupPatchList(int groupIndex) {
  return Objfsa_GetWalkGroup(groupIndex)->patchIndices;
}

static inline u8 Objfsa_IsWalkGroupActive(int groupIndex) {
  return lbl_803A1730[groupIndex];
}

static inline int Objfsa_IsPointInsidePatch(const float *point, const ObjfsaPatch *patch) {
  int edgeIndex;

  if (point[1] >= (f32)patch->maxY || (f32)patch->minY >= point[1]) {
    return 0;
  }

  for (edgeIndex = 0; edgeIndex < OBJFSA_PATCHGROUP_PATCH_COUNT; edgeIndex++) {
    if (patch->planeOffsets[edgeIndex] +
            point[0] * (f32)patch->planes[edgeIndex].normalX +
            point[2] * (f32)patch->planes[edgeIndex].normalZ >
        lbl_803E05F0) {
      return 0;
    }
  }
  return 1;
}

static inline int Objfsa_IsPointInsideWalkGroup(const float *point,
                                                const ObjfsaWalkGroup *walkGroup) {
  int edgeIndex;

  if (point[1] >= (f32)walkGroup->maxY || (f32)walkGroup->minY >= point[1]) {
    return 0;
  }

  for (edgeIndex = 0; edgeIndex < OBJFSA_PATCHGROUP_PATCH_COUNT; edgeIndex++) {
    if (walkGroup->planeOffsets[edgeIndex] +
            point[0] * (f32)walkGroup->planes[edgeIndex].normalX +
            point[2] * (f32)walkGroup->planes[edgeIndex].normalZ >
        lbl_803E05F0) {
      return 0;
    }
  }
  return 1;
}

static inline u16 Objfsa_GetLinkedWalkGroup(u16 patchGroupId,uint currentWalkGroupIndex) {
  if (((countLeadingZeros(0xff - currentWalkGroupIndex) >> 5) & patchGroupId) != 0) {
    return (patchGroupId & 0xff00) >> 8;
  }
  return patchGroupId & 0xff;
}

/*
 * --INFO--
 *
 * Function: player_setScale
 * EN v1.0 Address: 0x800D8F90
 * EN v1.0 Size: 256b
 * EN v1.1 Address: 0x800D8FE0
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern u8 lbl_803DD440;
extern f32 lbl_803E0570;
typedef struct PlayerMoveBuf {
  f32 a;
  f32 b;
  f32 c;
  u8 padC[2];
  s16 angleDelta;
  u8 pad10[2];
  u8 flag;
  s8 ids[8];
  s8 count;
} PlayerMoveBuf;

#pragma scheduling off
#pragma peephole off
void player_setScale(f32 dt, short *moveState, uint *obj, uint flags)
{
  PlayerMoveBuf buf;
  s8 *ptr;
  int i;
  f32 stopVal;

  buf.flag = 0;
  *(s8 *)&((BaddieState *)obj)->moveDone = (s8)ObjAnim_AdvanceCurrentMove(
      ((BaddieState *)obj)->moveSpeed, dt, (int)moveState, (ObjAnimEventList *)&buf);

  ((BaddieState *)obj)->eventFlags = 0;
  ptr = (s8 *)&buf;
  for (i = 0; i < buf.count; i++) {
    ((BaddieState *)obj)->eventFlags |= 1 << ptr[0x13];
    ptr++;
  }

  *obj &= ~0x10000;

  if (buf.flag != 0) {
    if ((flags & 0x10) != 0) {
      if ((flags & 1) != 0) {
        *(f32 *)((char *)obj + 0x2b4) = -buf.c;
      }
      if ((flags & 2) != 0) {
        *(f32 *)((char *)obj + 0x2b4) = buf.a;
      }
      if ((flags & 4) != 0) {
        *(f32 *)((char *)obj + 0x2b4) = buf.b;
      }
      if ((flags & 8) != 0) {
        *moveState += buf.angleDelta;
      }
    } else {
      if ((flags & 1) != 0) {
        ((BaddieState *)obj)->animSpeedA = (f32)(-(f64)buf.c / dt);
      }
      if ((flags & 2) != 0) {
        ((BaddieState *)obj)->animSpeedB = (f32)((f64)buf.a / dt);
      }
      if ((flags & 8) != 0) {
        *moveState += buf.angleDelta;
      }
      if ((flags & 4) != 0) {
        *(f32 *)((char *)obj + 0x288) = (f32)((f64)buf.b / dt);
        *obj |= 0x10000;
      }
    }
  } else {
    stopVal = lbl_803E0570;
    ((BaddieState *)obj)->animSpeedA = stopVal;
    ((BaddieState *)obj)->animSpeedB = stopVal;
  }

  lbl_803DD440 = 1;
}

/*
 * --INFO--
 *
 * Function: FUN_800d9090
 * EN v1.0 Address: 0x800D9090
 * EN v1.0 Size: 104b
 * EN v1.1 Address: 0x800D9108
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_800d9de0
 * EN v1.0 Address: 0x800D9DE0
 * EN v1.0 Size: 1972b
 * EN v1.1 Address: 0x800DA4C8
 * EN v1.1 Size: 1772b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_800d9de0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            float *param_9,float param_10,undefined4 param_11,undefined4 param_12,
            undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  undefined4 uVar2;
  undefined4 extraout_r4;
  undefined4 extraout_r4_00;
  double dVar3;
  double dVar4;
  
  fVar1 = param_9[0x28];
  if (((fVar1 == 0.0) || (param_9[0x29] == 0.0)) || (param_10 == 0.0)) {
    uVar2 = 1;
  }
  else {
    if (param_9[0x20] == 0.0) {
      param_9[0x27] = fVar1;
      param_9[0x28] = param_9[0x29];
      param_9[0x29] = param_10;
      FUN_80003494((uint)(param_9 + 0x2a),(uint)(param_9 + 0x2e),0x10);
      FUN_80003494((uint)(param_9 + 0x32),(uint)(param_9 + 0x36),0x10);
      uVar2 = 0x10;
      FUN_80003494((uint)(param_9 + 0x3a),(uint)(param_9 + 0x3e),0x10);
      param_9[0x2e] = *(float *)((int)param_9[0x28] + 8);
      param_9[0x2f] = *(float *)((int)param_9[0x29] + 8);
      dVar3 = (double)FUN_80293f90();
      param_9[0x30] =
           lbl_803E1250 *
           (float)((double)(float)((double)CONCAT44(0x43300000,
                                                    (uint)*(byte *)((int)param_9[0x28] + 0x2e)) -
                                  DOUBLE_803e1268) * dVar3);
      dVar3 = (double)FUN_80293f90();
      param_9[0x31] =
           lbl_803E1250 *
           (float)((double)(float)((double)CONCAT44(0x43300000,
                                                    (uint)*(byte *)((int)param_9[0x29] + 0x2e)) -
                                  DOUBLE_803e1268) * dVar3);
      param_9[0x36] = *(float *)((int)param_9[0x28] + 0xc);
      param_9[0x37] = *(float *)((int)param_9[0x29] + 0xc);
      dVar3 = (double)FUN_80293f90();
      param_9[0x38] =
           lbl_803E1250 *
           (float)((double)(float)((double)CONCAT44(0x43300000,
                                                    (uint)*(byte *)((int)param_9[0x28] + 0x2e)) -
                                  DOUBLE_803e1268) * dVar3);
      dVar3 = (double)FUN_80293f90();
      param_9[0x39] =
           lbl_803E1250 *
           (float)((double)(float)((double)CONCAT44(0x43300000,
                                                    (uint)*(byte *)((int)param_9[0x29] + 0x2e)) -
                                  DOUBLE_803e1268) * dVar3);
      param_9[0x3e] = *(float *)((int)param_9[0x28] + 0x10);
      param_9[0x3f] = *(float *)((int)param_9[0x29] + 0x10);
      dVar3 = (double)FUN_80294964();
      param_9[0x40] =
           lbl_803E1250 *
           (float)((double)(float)((double)CONCAT44(0x43300000,
                                                    (uint)*(byte *)((int)param_9[0x28] + 0x2e)) -
                                  DOUBLE_803e1268) * dVar3);
      dVar4 = (double)FUN_80294964();
      dVar3 = DOUBLE_803e1268;
      dVar4 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                               (uint)*(byte *)((int)param_9[0x29] +
                                                                              0x2e)) -
                                             DOUBLE_803e1268) * dVar4);
      param_9[0x41] = (float)((double)lbl_803E1250 * dVar4);
      if (param_9[0x24] != 0.0) {
        FUN_80006a18(dVar4,dVar3,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9,
                     extraout_r4_00,uVar2,param_12,param_13,param_14,param_15,param_16);
        if (lbl_803E1248 <= *param_9) {
          *param_9 = lbl_803E124C;
        }
      }
    }
    else {
      param_9[0x27] = fVar1;
      param_9[0x28] = param_9[0x29];
      param_9[0x29] = param_10;
      FUN_80003494((uint)(param_9 + 0x2e),(uint)(param_9 + 0x2a),0x10);
      FUN_80003494((uint)(param_9 + 0x36),(uint)(param_9 + 0x32),0x10);
      uVar2 = 0x10;
      FUN_80003494((uint)(param_9 + 0x3e),(uint)(param_9 + 0x3a),0x10);
      param_9[0x2a] = *(float *)((int)param_9[0x29] + 8);
      param_9[0x2b] = *(float *)((int)param_9[0x28] + 8);
      dVar3 = (double)FUN_80293f90();
      param_9[0x2c] =
           lbl_803E1250 *
           (float)((double)(float)((double)CONCAT44(0x43300000,
                                                    (uint)*(byte *)((int)param_9[0x29] + 0x2e)) -
                                  DOUBLE_803e1268) * dVar3);
      dVar3 = (double)FUN_80293f90();
      param_9[0x2d] =
           lbl_803E1250 *
           (float)((double)(float)((double)CONCAT44(0x43300000,
                                                    (uint)*(byte *)((int)param_9[0x28] + 0x2e)) -
                                  DOUBLE_803e1268) * dVar3);
      param_9[0x32] = *(float *)((int)param_9[0x29] + 0xc);
      param_9[0x33] = *(float *)((int)param_9[0x28] + 0xc);
      dVar3 = (double)FUN_80293f90();
      param_9[0x34] =
           lbl_803E1250 *
           (float)((double)(float)((double)CONCAT44(0x43300000,
                                                    (uint)*(byte *)((int)param_9[0x29] + 0x2e)) -
                                  DOUBLE_803e1268) * dVar3);
      dVar3 = (double)FUN_80293f90();
      param_9[0x35] =
           lbl_803E1250 *
           (float)((double)(float)((double)CONCAT44(0x43300000,
                                                    (uint)*(byte *)((int)param_9[0x28] + 0x2e)) -
                                  DOUBLE_803e1268) * dVar3);
      param_9[0x3a] = *(float *)((int)param_9[0x29] + 0x10);
      param_9[0x3b] = *(float *)((int)param_9[0x28] + 0x10);
      dVar3 = (double)FUN_80294964();
      param_9[0x3c] =
           lbl_803E1250 *
           (float)((double)(float)((double)CONCAT44(0x43300000,
                                                    (uint)*(byte *)((int)param_9[0x29] + 0x2e)) -
                                  DOUBLE_803e1268) * dVar3);
      dVar4 = (double)FUN_80294964();
      dVar3 = DOUBLE_803e1268;
      dVar4 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                               (uint)*(byte *)((int)param_9[0x28] +
                                                                              0x2e)) -
                                             DOUBLE_803e1268) * dVar4);
      param_9[0x3d] = (float)((double)lbl_803E1250 * dVar4);
      if (param_9[0x24] != 0.0) {
        FUN_80006a18(dVar4,dVar3,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9,
                     extraout_r4,uVar2,param_12,param_13,param_14,param_15,param_16);
        if (*param_9 <= lbl_803E1270) {
          *param_9 = lbl_803E1274;
        }
      }
    }
    uVar2 = 0;
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_800da594
 * EN v1.0 Address: 0x800DA594
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x800DABB4
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800da594(double param_1,float *param_2)
{
  if (lbl_803E1270 < *param_2) {
    if (lbl_803E1248 <= *param_2) {
      *param_2 = lbl_803E124C;
    }
  }
  else {
    *param_2 = lbl_803E1274;
  }
  FUN_80006a10(param_1,param_2);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800da5e8
 * EN v1.0 Address: 0x800DA5E8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800DAC0C
 * EN v1.1 Size: 1628b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
bool FUN_800da5e8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 float *param_9,float param_10,float param_11,float param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
    return 0;
}


/*
 * --INFO--
 *
 * Function: FUN_800da700
 * EN v1.0 Address: 0x800DA700
 * EN v1.0 Size: 336b
 * EN v1.1 Address: 0x800DB36C
 * EN v1.1 Size: 324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800da700(undefined4 param_1,undefined4 param_2,int param_3)
{
  float fVar1;
  float fVar2;
  float fVar3;
  float *pfVar4;
  int *piVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  double dVar9;
  double in_f31;
  double dVar10;
  double in_ps31_1;
  undefined8 uVar11;
  int local_38 [12];
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar11 = FUN_80286838();
  pfVar4 = (float *)((ulonglong)uVar11 >> 0x20);
  piVar5 = (int *)(**(code **)(*DAT_803dd71c + 0x10))(local_38);
  dVar10 = (double)lbl_803E1278;
  for (iVar8 = 0; iVar8 < local_38[0]; iVar8 = iVar8 + 1) {
    iVar7 = *piVar5;
    if ((((((iVar7 != 0) && (*(char *)(iVar7 + 0x19) == '$')) &&
          (((uint)uVar11 == 0xffffffff || ((uint)*(byte *)(iVar7 + 3) == (uint)uVar11)))) &&
         ((param_3 == -1 || (*(char *)(iVar7 + 0x1a) == param_3)))) &&
        (((int)*(short *)(iVar7 + 0x30) == 0xffffffff ||
         (uVar6 = GameBit_Get((int)*(short *)(iVar7 + 0x30)), uVar6 != 0)))) &&
       ((((int)*(short *)(iVar7 + 0x32) == 0xffffffff ||
         (uVar6 = GameBit_Get((int)*(short *)(iVar7 + 0x32)), uVar6 == 0)) &&
        (fVar1 = *pfVar4 - *(float *)(iVar7 + 8), fVar2 = pfVar4[1] - *(float *)(iVar7 + 0xc),
        fVar3 = pfVar4[2] - *(float *)(iVar7 + 0x10),
        dVar9 = (double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2), dVar9 < dVar10)))) {
      dVar10 = dVar9;
    }
    piVar5 = piVar5 + 1;
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800da850
 * EN v1.0 Address: 0x800DA850
 * EN v1.0 Size: 16b
 * EN v1.1 Address: 0x800DB4B0
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800da850(uint param_1,undefined *param_2)
{
  *param_2 = (char)(param_1 & 0xffff);
  param_2[1] = (char)((param_1 & 0xffff) >> 8);
  return;
}


/*
 * --INFO--
 *
 * Function: FUN_800db110
 * EN v1.0 Address: 0x800DB110
 * EN v1.0 Size: 480b
 * EN v1.1 Address: 0x800DBCD8
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined2
FUN_800db110(float *param_1,int param_2,undefined4 param_3,undefined4 param_4,byte param_5)
{
  byte bVar1;
  uint uVar2;
  uint uVar3;
  
  bVar1 = 0;
  do {
    if (3 < bVar1) {
      return 0;
    }
    if (((&DAT_803a2390)[param_2] != '\0') &&
       (uVar2 = (uint)(byte)(&DAT_803a076c)[param_2 * 0x28 + (uint)bVar1], uVar2 != 0)) {
      if ((param_1[1] <
           (float)((double)CONCAT44(0x43300000,
                                    (int)(short)(&DAT_8039d768)[uVar2 * 0x18] ^ 0x80000000) -
                  DOUBLE_803e1260)) &&
         ((float)((double)CONCAT44(0x43300000,(int)(short)(&DAT_8039d76a)[uVar2 * 0x18] ^ 0x80000000
                                  ) - DOUBLE_803e1260) < param_1[1])) {
        param_5 = 0;
        uVar3 = 0;
        while ((param_5 < 4 &&
               (*(float *)(&DAT_8039d748 + uVar2 * 0x18 + (uint)param_5 * 2 + 8) +
                *param_1 *
                (float)((double)CONCAT44(0x43300000,
                                         (int)(short)(&DAT_8039d748)[uVar2 * 0x18 + (uVar3 & 0xff)]
                                         ^ 0x80000000) - DOUBLE_803e1260) +
                param_1[2] *
                (float)((double)CONCAT44(0x43300000,
                                         (int)(short)(&DAT_8039d748)
                                                     [uVar2 * 0x18 + (uVar3 & 0xff) + 1] ^
                                         0x80000000) - DOUBLE_803e1260) <= lbl_803E1270))) {
          param_5 = param_5 + 1;
          uVar3 = uVar3 + 2;
        }
      }
      if (param_5 == 4) {
        return (&DAT_8039d76c)[uVar2 * 0x18];
      }
    }
    bVar1 = bVar1 + 1;
  } while( true );
}


/*
 * --INFO--
 *
 * Function: FUN_800db47c
 * EN v1.0 Address: 0x800DB47C
 * EN v1.0 Size: 532b
 * EN v1.1 Address: 0x800DBF88
 * EN v1.1 Size: 464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800db47c(float *param_1,undefined *param_2)
{
  uint uVar1;
  uint uVar2;
  byte bVar3;
  uint uVar4;
  uint uVar5;
  byte unaff_r31;
  
  uVar2 = FUN_800db820(param_1);
  if ((param_2 != (undefined *)0x0) && ((uVar2 & 0xff) != 0)) {
    *param_2 = (char)uVar2;
    param_2[1] = 0;
    uVar1 = 1;
    for (bVar3 = 0; bVar3 < 4; bVar3 = bVar3 + 1) {
      uVar5 = (uint)bVar3;
      uVar4 = (uint)(byte)(&DAT_803a076c)[(uVar2 & 0xff) * 0x28 + uVar5];
      if (uVar4 == 0) {
        *(undefined2 *)(param_2 + uVar5 * 2 + 2) = 0;
      }
      else {
        *(undefined2 *)(param_2 + uVar5 * 2 + 2) = (&DAT_8039d76c)[uVar4 * 0x18];
        if (param_1[1] <
            (float)((double)CONCAT44(0x43300000,
                                     (int)(short)(&DAT_8039d768)[uVar4 * 0x18] ^ 0x80000000) -
                   DOUBLE_803e1260)) {
          if ((float)((double)CONCAT44(0x43300000,
                                       (int)(short)(&DAT_8039d76a)[uVar4 * 0x18] ^ 0x80000000) -
                     DOUBLE_803e1260) < param_1[1]) {
            uVar5 = 0;
            for (unaff_r31 = 0; unaff_r31 < 4; unaff_r31 = unaff_r31 + 1) {
              if (lbl_803E1270 <
                  *(float *)(&DAT_8039d748 + uVar4 * 0x18 + (uint)unaff_r31 * 2 + 8) +
                  *param_1 *
                  (float)((double)CONCAT44(0x43300000,
                                           (int)(short)(&DAT_8039d748)
                                                       [uVar4 * 0x18 + (uVar5 & 0xff)] ^ 0x80000000)
                         - DOUBLE_803e1260) +
                  param_1[2] *
                  (float)((double)CONCAT44(0x43300000,
                                           (int)(short)(&DAT_8039d748)
                                                       [uVar4 * 0x18 + (uVar5 & 0xff) + 1] ^
                                           0x80000000) - DOUBLE_803e1260)) break;
              uVar5 = uVar5 + 2;
            }
          }
        }
        if (unaff_r31 == 4) {
          param_2[1] = param_2[1] | (byte)uVar1;
        }
      }
      uVar1 = (uVar1 & 0x7f) << 1;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800db690
 * EN v1.0 Address: 0x800DB690
 * EN v1.0 Size: 400b
 * EN v1.1 Address: 0x800DC158
 * EN v1.1 Size: 292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
ushort FUN_800db690(float *param_1)
{
  uint uVar1;
  byte bVar2;
  undefined2 *puVar3;
  int iVar4;
  
  puVar3 = &DAT_8039d748;
  iVar4 = DAT_803de0e4;
  if (0 < DAT_803de0e4) {
    do {
      if ((param_1[1] <
           (float)((double)CONCAT44(0x43300000,(int)(short)puVar3[0x10] ^ 0x80000000) -
                  DOUBLE_803e1260)) &&
         ((float)((double)CONCAT44(0x43300000,(int)(short)puVar3[0x11] ^ 0x80000000) -
                 DOUBLE_803e1260) < param_1[1])) {
        bVar2 = 0;
        uVar1 = 0;
        while ((bVar2 < 4 &&
               (*(float *)(puVar3 + (uint)bVar2 * 2 + 8) +
                *param_1 *
                (float)((double)CONCAT44(0x43300000,(int)(short)puVar3[uVar1 & 0xff] ^ 0x80000000) -
                       DOUBLE_803e1260) +
                param_1[2] *
                (float)((double)CONCAT44(0x43300000,
                                         (int)(short)puVar3[(uVar1 & 0xff) + 1] ^ 0x80000000) -
                       DOUBLE_803e1260) <= lbl_803E1270))) {
          bVar2 = bVar2 + 1;
          uVar1 = uVar1 + 2;
        }
        if (bVar2 == 4) {
          return puVar3[0x12];
        }
      }
      puVar3 = puVar3 + 0x18;
      iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800db820
 * EN v1.0 Address: 0x800DB820
 * EN v1.0 Size: 1096b
 * EN v1.1 Address: 0x800DC27C
 * EN v1.1 Size: 936b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_800db820(float *param_1)
{
  short sVar1;
  short sVar2;
  uint uVar3;
  int iVar4;
  byte bVar5;
  
  sVar2 = (short)DAT_803de0e0;
  if (DAT_803de0e0 == 0xb4) {
    sVar1 = 0;
  }
  else {
    sVar1 = sVar2 + 1;
  }
  do {
    iVar4 = (int)sVar2;
    if (iVar4 == sVar1) {
      if ((&DAT_803a2390)[iVar4] != '\0') {
        if ((param_1[1] <
             (float)((double)CONCAT44(0x43300000,
                                      (int)(short)(&DAT_803a0768)[iVar4 * 0x14] ^ 0x80000000) -
                    DOUBLE_803e1260)) &&
           ((float)((double)CONCAT44(0x43300000,
                                     (int)(short)(&DAT_803a076a)[iVar4 * 0x14] ^ 0x80000000) -
                   DOUBLE_803e1260) < param_1[1])) {
          bVar5 = 0;
          uVar3 = 0;
          while ((bVar5 < 4 &&
                 (*(float *)(&DAT_803a0748 + iVar4 * 0x14 + (uint)bVar5 * 2 + 8) +
                  *param_1 *
                  (float)((double)CONCAT44(0x43300000,
                                           (int)(short)(&DAT_803a0748)
                                                       [iVar4 * 0x14 + (uVar3 & 0xff)] ^ 0x80000000)
                         - DOUBLE_803e1260) +
                  param_1[2] *
                  (float)((double)CONCAT44(0x43300000,
                                           (int)(short)(&DAT_803a0748)
                                                       [iVar4 * 0x14 + (uVar3 & 0xff) + 1] ^
                                           0x80000000) - DOUBLE_803e1260) <= lbl_803E1270))) {
            bVar5 = bVar5 + 1;
            uVar3 = uVar3 + 2;
          }
          if (bVar5 == 4) {
            DAT_803de0e0 = (int)sVar2;
            return (int)sVar2;
          }
        }
      }
      return 0;
    }
    iVar4 = (int)sVar2;
    if ((&DAT_803a2390)[iVar4] != '\0') {
      if ((param_1[1] <
           (float)((double)CONCAT44(0x43300000,
                                    (int)(short)(&DAT_803a0768)[iVar4 * 0x14] ^ 0x80000000) -
                  DOUBLE_803e1260)) &&
         ((float)((double)CONCAT44(0x43300000,(int)(short)(&DAT_803a076a)[iVar4 * 0x14] ^ 0x80000000
                                  ) - DOUBLE_803e1260) < param_1[1])) {
        bVar5 = 0;
        uVar3 = 0;
        while ((bVar5 < 4 &&
               (*(float *)(&DAT_803a0748 + iVar4 * 0x14 + (uint)bVar5 * 2 + 8) +
                *param_1 *
                (float)((double)CONCAT44(0x43300000,
                                         (int)(short)(&DAT_803a0748)[iVar4 * 0x14 + (uVar3 & 0xff)]
                                         ^ 0x80000000) - DOUBLE_803e1260) +
                param_1[2] *
                (float)((double)CONCAT44(0x43300000,
                                         (int)(short)(&DAT_803a0748)
                                                     [iVar4 * 0x14 + (uVar3 & 0xff) + 1] ^
                                         0x80000000) - DOUBLE_803e1260) <= lbl_803E1270))) {
          bVar5 = bVar5 + 1;
          uVar3 = uVar3 + 2;
        }
        if (bVar5 == 4) {
          DAT_803de0e0 = (int)sVar2;
          return (int)sVar2;
        }
      }
    }
    iVar4 = (int)sVar1;
    if ((&DAT_803a2390)[iVar4] != '\0') {
      if ((param_1[1] <
           (float)((double)CONCAT44(0x43300000,
                                    (int)(short)(&DAT_803a0768)[iVar4 * 0x14] ^ 0x80000000) -
                  DOUBLE_803e1260)) &&
         ((float)((double)CONCAT44(0x43300000,(int)(short)(&DAT_803a076a)[iVar4 * 0x14] ^ 0x80000000
                                  ) - DOUBLE_803e1260) < param_1[1])) {
        bVar5 = 0;
        uVar3 = 0;
        while ((bVar5 < 4 &&
               (*(float *)(&DAT_803a0748 + iVar4 * 0x14 + (uint)bVar5 * 2 + 8) +
                *param_1 *
                (float)((double)CONCAT44(0x43300000,
                                         (int)(short)(&DAT_803a0748)[iVar4 * 0x14 + (uVar3 & 0xff)]
                                         ^ 0x80000000) - DOUBLE_803e1260) +
                param_1[2] *
                (float)((double)CONCAT44(0x43300000,
                                         (int)(short)(&DAT_803a0748)
                                                     [iVar4 * 0x14 + (uVar3 & 0xff) + 1] ^
                                         0x80000000) - DOUBLE_803e1260) <= lbl_803E1270))) {
          bVar5 = bVar5 + 1;
          uVar3 = uVar3 + 2;
        }
        if (bVar5 == 4) {
          DAT_803de0e0 = (int)sVar1;
          return (int)sVar1;
        }
      }
    }
    sVar2 = sVar2 + -1;
    if (sVar2 == -1) {
      sVar2 = 0xb4;
    }
    sVar1 = sVar1 + 1;
    if (sVar1 == 0xb5) {
      sVar1 = 0;
    }
  } while( true );
}


/*
 * --INFO--
 *
 * Function: FUN_800dd3e4
 * EN v1.0 Address: 0x800DD3E4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800DD8CC
 * EN v1.1 Size: 2208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_800dd3e4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            float *param_9,undefined4 param_10,uint param_11)
{
    return 0;
}


/*
 * --INFO--
 *
 * Function: FUN_800dd62c
 * EN v1.0 Address: 0x800DD62C
 * EN v1.0 Size: 2048b
 * EN v1.1 Address: 0x800DE41C
 * EN v1.1 Size: 1880b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_800dd62c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            float *param_9,uint param_10,undefined4 param_11,int param_12,int param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  uint uVar1;
  undefined4 extraout_r4;
  undefined4 extraout_r4_00;
  undefined4 uVar2;
  float fVar3;
  double dVar4;
  double dVar5;
  
  if (((param_9 != (float *)0x0) && (param_9[0x28] != 0.0)) && (param_9[0x29] != 0.0)) {
    param_9[0x27] = param_9[0x28];
    param_9[0x28] = param_9[0x29];
    FUN_80003494((uint)(param_9 + 0x2a),(uint)(param_9 + 0x2e),0x10);
    FUN_80003494((uint)(param_9 + 0x32),(uint)(param_9 + 0x36),0x10);
    FUN_80003494((uint)(param_9 + 0x3a),(uint)(param_9 + 0x3e),0x10);
    if (param_9[0x20] == 0.0) {
      uVar1 = FUN_800dd50c((int)param_9[0x28],-1,param_10);
    }
    else {
      uVar1 = FUN_800dd3ec((int)param_9[0x28],-1,param_10);
    }
    if (uVar1 == 0xffffffff) {
      param_9[0x29] = 0.0;
    }
    else {
      if ((int)uVar1 < 0) {
        fVar3 = 0.0;
      }
      else {
        param_13 = DAT_803de0f0 + -1;
        param_12 = 0;
        while (param_12 <= param_13) {
          param_10 = param_13 + param_12 >> 1;
          fVar3 = (float)(int)romCurves[param_10];
          if (*(uint *)((int)fVar3 + 0x14) < uVar1) {
            param_12 = param_10 + 1;
          }
          else {
            if (*(uint *)((int)fVar3 + 0x14) <= uVar1) goto LAB_800de544;
            param_13 = param_10 - 1;
          }
        }
        fVar3 = 0.0;
      }
LAB_800de544:
      param_9[0x29] = fVar3;
      if (param_9[0x29] != 0.0) {
        if (param_9[0x20] == 0.0) {
          param_9[0x2e] = *(float *)((int)param_9[0x28] + 8);
          param_9[0x2f] = *(float *)((int)param_9[0x29] + 8);
          dVar4 = (double)FUN_80293f90();
          param_9[0x30] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x28] + 0x2e))
                                      - DOUBLE_803e12a8) * dVar4);
          dVar4 = (double)FUN_80293f90();
          param_9[0x31] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x29] + 0x2e))
                                      - DOUBLE_803e12a8) * dVar4);
          param_9[0x36] = *(float *)((int)param_9[0x28] + 0xc);
          param_9[0x37] = *(float *)((int)param_9[0x29] + 0xc);
          dVar4 = (double)FUN_80293f90();
          param_9[0x38] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x28] + 0x2e))
                                      - DOUBLE_803e12a8) * dVar4);
          dVar4 = (double)FUN_80293f90();
          param_9[0x39] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x29] + 0x2e))
                                      - DOUBLE_803e12a8) * dVar4);
          param_9[0x3e] = *(float *)((int)param_9[0x28] + 0x10);
          param_9[0x3f] = *(float *)((int)param_9[0x29] + 0x10);
          dVar4 = (double)FUN_80294964();
          param_9[0x40] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x28] + 0x2e))
                                      - DOUBLE_803e12a8) * dVar4);
          dVar5 = (double)FUN_80294964();
          dVar4 = DOUBLE_803e12a8;
          dVar5 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                   (uint)*(byte *)((int)param_9[0x29
                                                  ] + 0x2e)) - DOUBLE_803e12a8) * dVar5);
          param_9[0x41] = (float)((double)lbl_803E1290 * dVar5);
          uVar2 = extraout_r4_00;
        }
        else {
          param_9[0x2e] = *(float *)((int)param_9[0x28] + 8);
          param_9[0x2f] = *(float *)((int)param_9[0x27] + 8);
          dVar4 = (double)FUN_80293f90();
          param_9[0x30] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x28] + 0x2e))
                                      - DOUBLE_803e12a8) * dVar4);
          dVar4 = (double)FUN_80293f90();
          param_9[0x31] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x27] + 0x2e))
                                      - DOUBLE_803e12a8) * dVar4);
          param_9[0x36] = *(float *)((int)param_9[0x28] + 0xc);
          param_9[0x37] = *(float *)((int)param_9[0x27] + 0xc);
          dVar4 = (double)FUN_80293f90();
          param_9[0x38] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x28] + 0x2e))
                                      - DOUBLE_803e12a8) * dVar4);
          dVar4 = (double)FUN_80293f90();
          param_9[0x39] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x27] + 0x2e))
                                      - DOUBLE_803e12a8) * dVar4);
          param_9[0x3e] = *(float *)((int)param_9[0x28] + 0x10);
          param_9[0x3f] = *(float *)((int)param_9[0x27] + 0x10);
          dVar4 = (double)FUN_80294964();
          param_9[0x40] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,
                                                        (uint)*(byte *)((int)param_9[0x28] + 0x2e))
                                      - DOUBLE_803e12a8) * dVar4);
          dVar5 = (double)FUN_80294964();
          dVar4 = DOUBLE_803e12a8;
          dVar5 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                   (uint)*(byte *)((int)param_9[0x27
                                                  ] + 0x2e)) - DOUBLE_803e12a8) * dVar5);
          param_9[0x41] = (float)((double)lbl_803E1290 * dVar5);
          uVar2 = extraout_r4;
        }
        if (param_9[0x24] != 0.0) {
          FUN_80006a18(dVar5,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9,
                       uVar2,param_10,param_12,param_13,fVar3,param_15,param_16);
        }
        if (param_9[0x20] == 0.0) {
          FUN_80006a10((double)lbl_803E12B4,param_9);
        }
        else {
          FUN_80006a10((double)lbl_803E12B0,param_9);
        }
        return 0;
      }
    }
  }
  return 1;
}


/*
 * --INFO--
 *
 * Function: FUN_800ddf84
 * EN v1.0 Address: 0x800DDF84
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800DED20
 * EN v1.1 Size: 956b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_800ddf84(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            float *param_9,float param_10,undefined4 param_11,undefined4 param_12,
            undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800ddf8c
 * EN v1.0 Address: 0x800DDF8C
 * EN v1.0 Size: 2572b
 * EN v1.1 Address: 0x800DF0DC
 * EN v1.1 Size: 2428b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_800ddf8c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            float *param_9)
{
  undefined4 extraout_r4;
  undefined4 extraout_r4_00;
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  float fVar4;
  uint uVar5;
  float fVar6;
  undefined4 in_r9;
  undefined4 in_r10;
  double dVar7;
  double dVar8;
  uint local_88 [4];
  uint local_78 [4];
  undefined4 local_68;
  uint uStack_64;
  undefined4 local_60;
  uint uStack_5c;
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  undefined4 local_10;
  uint uStack_c;
  
  if (((param_9 != (float *)0x0) && (param_9[0x28] != 0.0)) && (param_9[0x29] != 0.0)) {
    param_9[0x27] = param_9[0x28];
    param_9[0x28] = param_9[0x29];
    FUN_80003494((uint)(param_9 + 0x2a),(uint)(param_9 + 0x2e),0x10);
    FUN_80003494((uint)(param_9 + 0x32),(uint)(param_9 + 0x36),0x10);
    FUN_80003494((uint)(param_9 + 0x3a),(uint)(param_9 + 0x3e),0x10);
    if (param_9[0x20] == 0.0) {
      fVar4 = param_9[0x28];
      iVar2 = 0;
      uVar5 = *(uint *)((int)fVar4 + 0x1c);
      if (((-1 < (int)uVar5) && ((*(byte *)((int)fVar4 + 0x1b) & 1) == 0)) && (uVar5 != 0xffffffff))
      {
        iVar2 = 1;
        local_88[0] = uVar5;
      }
      uVar5 = *(uint *)((int)fVar4 + 0x20);
      iVar3 = iVar2;
      if (((-1 < (int)uVar5) && ((*(byte *)((int)fVar4 + 0x1b) & 2) == 0)) && (uVar5 != 0xffffffff))
      {
        iVar3 = iVar2 + 1;
        local_88[iVar2] = uVar5;
      }
      uVar5 = *(uint *)((int)fVar4 + 0x24);
      iVar2 = iVar3;
      if (((-1 < (int)uVar5) && ((*(byte *)((int)fVar4 + 0x1b) & 4) == 0)) && (uVar5 != 0xffffffff))
      {
        iVar2 = iVar3 + 1;
        local_88[iVar3] = uVar5;
      }
      uVar5 = *(uint *)((int)fVar4 + 0x28);
      iVar3 = iVar2;
      if (((-1 < (int)uVar5) && ((*(byte *)((int)fVar4 + 0x1b) & 8) == 0)) && (uVar5 != 0xffffffff))
      {
        iVar3 = iVar2 + 1;
        local_88[iVar2] = uVar5;
      }
      if (iVar3 == 0) {
        uVar5 = 0xffffffff;
      }
      else {
        uVar5 = randomGetRange(0,iVar3 - 1);
        uVar5 = local_88[uVar5];
      }
    }
    else {
      fVar4 = param_9[0x28];
      iVar2 = 0;
      uVar5 = *(uint *)((int)fVar4 + 0x1c);
      if (((-1 < (int)uVar5) && ((*(byte *)((int)fVar4 + 0x1b) & 1) != 0)) && (uVar5 != 0xffffffff))
      {
        iVar2 = 1;
        local_78[0] = uVar5;
      }
      uVar5 = *(uint *)((int)fVar4 + 0x20);
      iVar3 = iVar2;
      if (((-1 < (int)uVar5) && ((*(byte *)((int)fVar4 + 0x1b) & 2) != 0)) && (uVar5 != 0xffffffff))
      {
        iVar3 = iVar2 + 1;
        local_78[iVar2] = uVar5;
      }
      uVar5 = *(uint *)((int)fVar4 + 0x24);
      iVar2 = iVar3;
      if (((-1 < (int)uVar5) && ((*(byte *)((int)fVar4 + 0x1b) & 4) != 0)) && (uVar5 != 0xffffffff))
      {
        iVar2 = iVar3 + 1;
        local_78[iVar3] = uVar5;
      }
      uVar5 = *(uint *)((int)fVar4 + 0x28);
      iVar3 = iVar2;
      if (((-1 < (int)uVar5) && ((*(byte *)((int)fVar4 + 0x1b) & 8) != 0)) && (uVar5 != 0xffffffff))
      {
        iVar3 = iVar2 + 1;
        local_78[iVar2] = uVar5;
      }
      if (iVar3 == 0) {
        uVar5 = 0xffffffff;
      }
      else {
        uVar5 = randomGetRange(0,iVar3 - 1);
        uVar5 = local_78[uVar5];
      }
    }
    if (uVar5 == 0xffffffff) {
      param_9[0x29] = 0.0;
    }
    else {
      if ((int)uVar5 < 0) {
        fVar6 = 0.0;
      }
      else {
        fVar4 = (float)(DAT_803de0f0 + -1);
        iVar3 = 0;
        while (iVar3 <= (int)fVar4) {
          iVar2 = (int)fVar4 + iVar3 >> 1;
          fVar6 = (float)(int)romCurves[iVar2];
          if (*(uint *)((int)fVar6 + 0x14) < uVar5) {
            iVar3 = iVar2 + 1;
          }
          else {
            if (*(uint *)((int)fVar6 + 0x14) <= uVar5) goto LAB_800df42c;
            fVar4 = (float)(iVar2 + -1);
          }
        }
        fVar6 = 0.0;
      }
LAB_800df42c:
      param_9[0x29] = fVar6;
      if (param_9[0x29] != 0.0) {
        if (param_9[0x20] == 0.0) {
          param_9[0x2e] = *(float *)((int)param_9[0x28] + 8);
          param_9[0x2f] = *(float *)((int)param_9[0x29] + 8);
          uStack_c = (int)*(char *)((int)param_9[0x28] + 0x2c) << 8 ^ 0x80000000;
          local_10 = 0x43300000;
          dVar7 = (double)FUN_80293f90();
          uStack_14 = (uint)*(byte *)((int)param_9[0x28] + 0x2e);
          local_18 = 0x43300000;
          param_9[0x30] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e12a8) *
                      dVar7);
          uStack_1c = (int)*(char *)((int)param_9[0x29] + 0x2c) << 8 ^ 0x80000000;
          local_20 = 0x43300000;
          dVar7 = (double)FUN_80293f90();
          uStack_24 = (uint)*(byte *)((int)param_9[0x29] + 0x2e);
          local_28 = 0x43300000;
          param_9[0x31] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e12a8) *
                      dVar7);
          param_9[0x36] = *(float *)((int)param_9[0x28] + 0xc);
          param_9[0x37] = *(float *)((int)param_9[0x29] + 0xc);
          uStack_2c = (int)*(char *)((int)param_9[0x28] + 0x2d) << 8 ^ 0x80000000;
          local_30 = 0x43300000;
          dVar7 = (double)FUN_80293f90();
          uStack_34 = (uint)*(byte *)((int)param_9[0x28] + 0x2e);
          local_38 = 0x43300000;
          param_9[0x38] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e12a8) *
                      dVar7);
          uStack_3c = (int)*(char *)((int)param_9[0x29] + 0x2d) << 8 ^ 0x80000000;
          local_40 = 0x43300000;
          dVar7 = (double)FUN_80293f90();
          uStack_44 = (uint)*(byte *)((int)param_9[0x29] + 0x2e);
          local_48 = 0x43300000;
          param_9[0x39] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e12a8) *
                      dVar7);
          param_9[0x3e] = *(float *)((int)param_9[0x28] + 0x10);
          param_9[0x3f] = *(float *)((int)param_9[0x29] + 0x10);
          uStack_4c = (int)*(char *)((int)param_9[0x28] + 0x2c) << 8 ^ 0x80000000;
          local_50 = 0x43300000;
          dVar7 = (double)FUN_80294964();
          uStack_54 = (uint)*(byte *)((int)param_9[0x28] + 0x2e);
          local_58 = 0x43300000;
          param_9[0x40] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e12a8) *
                      dVar7);
          uStack_5c = (int)*(char *)((int)param_9[0x29] + 0x2c) << 8 ^ 0x80000000;
          local_60 = 0x43300000;
          dVar8 = (double)FUN_80294964();
          dVar7 = DOUBLE_803e12a8;
          uStack_64 = (uint)*(byte *)((int)param_9[0x29] + 0x2e);
          local_68 = 0x43300000;
          dVar8 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack_64) -
                                                 DOUBLE_803e12a8) * dVar8);
          param_9[0x41] = (float)((double)lbl_803E1290 * dVar8);
          uVar1 = extraout_r4_00;
        }
        else {
          param_9[0x2e] = *(float *)((int)param_9[0x28] + 8);
          param_9[0x2f] = *(float *)((int)param_9[0x27] + 8);
          uStack_64 = (int)*(char *)((int)param_9[0x28] + 0x2c) << 8 ^ 0x80000000;
          local_68 = 0x43300000;
          dVar7 = (double)FUN_80293f90();
          uStack_5c = (uint)*(byte *)((int)param_9[0x28] + 0x2e);
          local_60 = 0x43300000;
          param_9[0x30] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e12a8) *
                      dVar7);
          uStack_54 = (int)*(char *)((int)param_9[0x27] + 0x2c) << 8 ^ 0x80000000;
          local_58 = 0x43300000;
          dVar7 = (double)FUN_80293f90();
          uStack_4c = (uint)*(byte *)((int)param_9[0x27] + 0x2e);
          local_50 = 0x43300000;
          param_9[0x31] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e12a8) *
                      dVar7);
          param_9[0x36] = *(float *)((int)param_9[0x28] + 0xc);
          param_9[0x37] = *(float *)((int)param_9[0x27] + 0xc);
          uStack_44 = (int)*(char *)((int)param_9[0x28] + 0x2d) << 8 ^ 0x80000000;
          local_48 = 0x43300000;
          dVar7 = (double)FUN_80293f90();
          uStack_3c = (uint)*(byte *)((int)param_9[0x28] + 0x2e);
          local_40 = 0x43300000;
          param_9[0x38] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e12a8) *
                      dVar7);
          uStack_34 = (int)*(char *)((int)param_9[0x27] + 0x2d) << 8 ^ 0x80000000;
          local_38 = 0x43300000;
          dVar7 = (double)FUN_80293f90();
          uStack_2c = (uint)*(byte *)((int)param_9[0x27] + 0x2e);
          local_30 = 0x43300000;
          param_9[0x39] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e12a8) *
                      dVar7);
          param_9[0x3e] = *(float *)((int)param_9[0x28] + 0x10);
          param_9[0x3f] = *(float *)((int)param_9[0x27] + 0x10);
          uStack_24 = (int)*(char *)((int)param_9[0x28] + 0x2c) << 8 ^ 0x80000000;
          local_28 = 0x43300000;
          dVar7 = (double)FUN_80294964();
          uStack_1c = (uint)*(byte *)((int)param_9[0x28] + 0x2e);
          local_20 = 0x43300000;
          param_9[0x40] =
               lbl_803E1290 *
               (float)((double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e12a8) *
                      dVar7);
          uStack_14 = (int)*(char *)((int)param_9[0x27] + 0x2c) << 8 ^ 0x80000000;
          local_18 = 0x43300000;
          dVar8 = (double)FUN_80294964();
          dVar7 = DOUBLE_803e12a8;
          uStack_c = (uint)*(byte *)((int)param_9[0x27] + 0x2e);
          local_10 = 0x43300000;
          dVar8 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack_c) -
                                                 DOUBLE_803e12a8) * dVar8);
          param_9[0x41] = (float)((double)lbl_803E1290 * dVar8);
          uVar1 = extraout_r4;
        }
        if (param_9[0x24] != 0.0) {
          FUN_80006a18(dVar8,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9,
                       uVar1,iVar3,fVar4,fVar6,uVar5,in_r9,in_r10);
        }
        if (param_9[0x20] == 0.0) {
          FUN_80006a10((double)lbl_803E12B4,param_9);
        }
        else {
          FUN_80006a10((double)lbl_803E12B0,param_9);
        }
        return 0;
      }
    }
  }
  return 1;
}

/*
 * --INFO--
 *
 * Function: FUN_800de998
 * EN v1.0 Address: 0x800DE998
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800DFA58
 * EN v1.1 Size: 2400b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_800de998(double param_1,undefined8 param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,float *param_9,int param_10,
            undefined4 param_11,int param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: curves_findNearObj
 * EN v1.0 Address: 0x800E0134
 * EN v1.0 Size: 696b
 * EN v1.1 Address: 0x800E03B8
 * EN v1.1 Size: 696b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
int curves_findNearObj(int obj,int *curveTypes,int typeCount,int action,char bboxMode)
{
  ObjfsaRomCurveDef *curve;
  ObjfsaRomCurveDef *bestCurve;
  ObjfsaRomCurveDef *bestActionCurve;
  f32 bestDistance;
  f32 bestActionDistance;
  f32 dx;
  f32 dy;
  f32 dz;
  f32 distance;
  f32 objPos[3];
  f32 curvePos[3];
  s16 objGrid[4];
  s16 curveGrid[4];
  u8 traceHit;
  int bboxHit[34];
  int curveIndex;
  int typeIndex;

  bestDistance = lbl_803E12BC;
  bestCurve = NULL;
  bestActionDistance = bestDistance;
  bestActionCurve = NULL;

  objPos[0] = *(f32 *)(obj + 0xc);
  objPos[1] = lbl_803E12C0 + *(f32 *)(obj + 0x10);
  objPos[2] = *(f32 *)(obj + 0x14);
  voxmaps_worldToGrid(objPos,objGrid);

  for (curveIndex = 0; curveIndex < nRomCurves; curveIndex++) {
    curve = (ObjfsaRomCurveDef *)romCurves[curveIndex];
    typeIndex = 0;
    do {
      if ((curve->type == curveTypes[typeIndex]) || (typeCount < 1)) {
        dx = curve->x - ((GameObject *)obj)->anim.localPosX;
        dy = curve->y - ((GameObject *)obj)->anim.localPosY;
        dz = curve->z - ((GameObject *)obj)->anim.localPosZ;
        distance = sqrtf(dz * dz + (dx * dx + dy * dy));
        if (distance < bestDistance) {
          curvePos[0] = curve->x;
          curvePos[1] = lbl_803E12C0 + curve->y;
          curvePos[2] = curve->z;
          voxmaps_worldToGrid(curvePos,curveGrid);
          if (((traceHit = 0, voxmaps_traceLine(curveGrid,objGrid,NULL,&traceHit,0) != 0) ||
               (traceHit == 1)) &&
              (objBboxFn_800640cc((f32 *)(obj + 0xc),curvePos,gFloatOne,0,bboxHit,obj,
                                  (s8)bboxMode,-1,0,0) == 0)) {
            bestDistance = distance;
            bestCurve = curve;
          }
        }
        typeIndex = typeCount;
        if ((curve->action == action) && (distance < bestActionDistance)) {
          curvePos[0] = curve->x;
          curvePos[1] = lbl_803E12C0 + curve->y;
          curvePos[2] = curve->z;
          voxmaps_worldToGrid(curvePos,curveGrid);
          if (((traceHit = 0, voxmaps_traceLine(curveGrid,objGrid,NULL,&traceHit,0) != 0) ||
               (traceHit == 1)) &&
              (objBboxFn_800640cc((f32 *)(obj + 0xc),curvePos,gFloatOne,0,bboxHit,obj,
                                  (s8)bboxMode,-1,0,0) == 0)) {
            bestActionDistance = distance;
            bestActionCurve = curve;
          }
        }
      }
      typeIndex++;
    } while (typeIndex < typeCount);
  }
  if (bestActionCurve != NULL) {
    bestCurve = bestActionCurve;
  }
  if (bestCurve != NULL) {
    return bestCurve->id;
  }
  return -1;
}

/*
 * --INFO--
 *
 * Function: FUN_800dece0
 * EN v1.0 Address: 0x800DECE0
 * EN v1.0 Size: 1476b
 * EN v1.1 Address: 0x800E0670
 * EN v1.1 Size: 1572b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on


static inline int Objfsa_FindRomCurveById(int curveId) {
    int lo;
    int hi;
    int mid;
    int curve;
    u32 id;

    if (curveId < 0) {
        return 0;
    }

    lo = 0;
    hi = nRomCurves - 1;
    id = (u32)curveId;
    while (lo <= hi) {
        mid = (hi + lo) >> 1;
        curve = (int)romCurves[mid];
        if (id > ((ObjfsaRomCurveDef *)curve)->id) {
            lo = mid + 1;
        } else if (id < ((ObjfsaRomCurveDef *)curve)->id) {
            hi = mid - 1;
        } else {
            return curve;
        }
    }

    return 0;
}

/*
 * --INFO--
 *
 * Function: curves_lengthFn24
 * EN v1.0 Address: 0x800E0E18
 * EN v1.0 Size: 1888b
 * EN v1.1 Address: 0x800E109C
 * EN v1.1 Size: 1888b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
f32 curves_lengthFn24(u32 a, u32 b, f32 *posA, f32 *posB, f32 t1, f32 t2)
{
    int cand1[4];
    int cand2[4];
    int cand3[4];
    f32 total;
    int reachedForward;
    int done;
    int cur;
    int found;
    int next;
    int count;
    u32 mask;
    int n;
    int k;
    int nextId;
    int slot;
    int blocked;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 *tmpPos;

    if (a == b) {
        dx = posB[0] - posA[0];
        dy = posB[1] - posA[1];
        dz = posB[2] - posA[2];
        total = sqrtf(dx * dx + dy * dy + dz * dz);
        if (t2 < t1) {
            total = -total;
        }
        return total;
    }

    reachedForward = 0;
    done = 0;
    found = a;
    while (done == 0) {
        blocked = 1;
        for (slot = 0; slot < 4; slot++) {
            if (*(int *)(found + 0x1C + slot * 4) != -1 && (*(s8 *)(found + 0x1B) & (1 << slot)) == 0) {
                blocked = 0;
                break;
            }
        }
        if (blocked != 0) {
            done = 1;
            reachedForward = 0;
        } else {
            count = 0;
            mask = 1;
            for (k = 0; k < 4; k++) {
                n = *(int *)(found + 0x1C + k * 4);
                if (n > -1 && (*(s8 *)(found + 0x1B) & mask) == 0 && n != 0) {
                    cand1[count] = n;
                    count++;
                }
                mask <<= 1;
            }
            if (count != 0) {
                nextId = cand1[(int)randomGetRange(0, count - 1)];
            } else {
                nextId = -1;
            }
            found = Objfsa_FindRomCurveById(nextId);
            if (found == b) {
                done = 1;
                reachedForward = 1;
            }
        }
    }

    if (reachedForward == 0) {
        cur = a;
        a = b;
        b = cur;
        tmpPos = posA;
        posA = posB;
        posB = tmpPos;
    }

    count = 0;
    mask = 1;
    for (k = 0; k < 4; k++) {
        n = *(int *)(a + 0x1C + k * 4);
        if (n > -1 && (*(s8 *)(a + 0x1B) & mask) == 0 && n != 0) {
            cand2[count] = n;
            count++;
        }
        mask <<= 1;
    }
    if (count != 0) {
        nextId = cand2[(int)randomGetRange(0, count - 1)];
    } else {
        nextId = -1;
    }
    found = Objfsa_FindRomCurveById(nextId);
    a = found;
    dx = *(f32 *)(found + 0x8) - posA[0];
    dy = *(f32 *)(found + 0xC) - posA[1];
    dz = *(f32 *)(found + 0x10) - posA[2];
    total = sqrtf(dx * dx + dy * dy + dz * dz);
    done = 0;

    while (done == 0) {
        if (a == b) {
            done = 1;
            dx = posB[0] - *(f32 *)(a + 0x8);
            dy = posB[1] - *(f32 *)(a + 0xC);
            dz = posB[2] - *(f32 *)(a + 0x10);
            total = total + sqrtf(dx * dx + dy * dy + dz * dz);
        } else {
            count = 0;
            mask = 1;
            for (k = 0; k < 4; k++) {
                n = *(int *)(a + 0x1C + k * 4);
                if (n > -1 && (*(s8 *)(a + 0x1B) & mask) == 0 && n != 0) {
                    cand3[count] = n;
                    count++;
                }
                mask <<= 1;
            }
            if (count != 0) {
                nextId = cand3[(int)randomGetRange(0, count - 1)];
            } else {
                nextId = -1;
            }
            next = Objfsa_FindRomCurveById(nextId);
            dx = *(f32 *)(next + 0x8) - *(f32 *)(a + 0x8);
            dy = *(f32 *)(next + 0xC) - *(f32 *)(a + 0xC);
            dz = *(f32 *)(next + 0x10) - *(f32 *)(a + 0x10);
            total = total + sqrtf(dx * dx + dy * dy + dz * dz);
            a = next;
        }
    }

    if (reachedForward == 0) {
        total = -total;
    }
    return total;
}

/*
 * --INFO--
 *
 * Function: curves_getPos
 * EN v1.0 Address: 0x800E1578
 * EN v1.0 Size: 592b
 * EN v1.1 Address: 0x800E17FC
 * EN v1.1 Size: 592b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: walkGroupFn_800db3e4
 * EN v1.0 Address: 0x800DB3E4
 * EN v1.0 Size: 1268b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int walkGroupFn_800db3e4(float *prevPoint,float *nextPoint,uint currentWalkGroupIndex)
{
  u8 k;
  u8 k2;
  uint pidx;
  uint lpidx;
  uint clz;
  uint lidx;
  u16 pgid;
  u8 i;
  u8 j;
  ObjfsaPatch *patch;
  ObjfsaPatch *lp;
  ObjfsaWalkGroup *wg;
  f32 y;

  wg = &lbl_8039FAE8[currentWalkGroupIndex];
  for (k = 0; k < 4; k++) {
    pidx = wg->patchIndices[k];
    if (pidx == 0) {
      continue;
    }
    patch = &lbl_8039CAE8[pidx];
    y = prevPoint[1];
    if (y < (f32)patch->maxY && y > (f32)patch->minY) {
      i = 0;
      j = 0;
      for (; i < 4; i++, j += 2) {
        if (patch->planeOffsets[i] +
                (prevPoint[0] * (f32)((s16 *)patch)[j] +
                 prevPoint[2] * (f32)((s16 *)patch)[j + 1]) >
            0.0f) {
          break;
        }
      }
      if (i == 4) {
        y = nextPoint[1];
        if (y < (f32)patch->maxY && y > (f32)patch->minY) {
          i = 0;
          j = 0;
          for (; i < 4; i++, j += 2) {
            if (patch->planeOffsets[i] +
                    (nextPoint[0] * (f32)((s16 *)patch)[j] +
                     nextPoint[2] * (f32)((s16 *)patch)[j + 1]) >
                0.0f) {
              break;
            }
          }
          if (i == 4) {
            return currentWalkGroupIndex;
          }
        }
      }
    }
  }

  for (k = 0; k < 4; k++) {
    pidx = wg->patchIndices[k];
    if (pidx == 0) {
      continue;
    }
    patch = &lbl_8039CAE8[pidx];
    clz = (uint)__cntlzw(0xff - currentWalkGroupIndex);
    pgid = patch->groupId;
    if (((clz >> 5) & pgid) == 0) {
      lidx = pgid & 0xff;
    } else {
      lidx = (int)(pgid & 0xff00) >> 8;
    }
    for (k2 = 0; k2 < 4; k2++) {
      lpidx = *((u8 *)lbl_8039FAE8 + lidx * OBJFSA_PATCHGROUP_STRIDE + k2 + 0x24);
      if (lpidx == 0) {
        continue;
      }
      lp = &lbl_8039CAE8[lpidx];
      if (lp->groupId != pgid) {
        y = prevPoint[1];
        if (y < (f32)lp->maxY && y > (f32)lp->minY) {
          i = 0;
          j = 0;
          for (; i < 4; i++, j += 2) {
            if (lp->planeOffsets[i] +
                    (prevPoint[0] * (f32)((s16 *)lp)[j] +
                     prevPoint[2] * (f32)((s16 *)lp)[j + 1]) >
                0.0f) {
              break;
            }
          }
          if (i == 4) {
            y = nextPoint[1];
            if (y < (f32)lp->maxY && y > (f32)lp->minY) {
              i = 0;
              j = 0;
              for (; i < 4; i++, j += 2) {
                if (lp->planeOffsets[i] +
                        (nextPoint[0] * (f32)((s16 *)lp)[j] +
                         nextPoint[2] * (f32)((s16 *)lp)[j + 1]) >
                    0.0f) {
                  break;
                }
              }
              if (i == 4) {
                OSReport(sObjfsaFoundNewWalkGroupPatch, lidx);
                return lidx;
              }
            }
          }
        }
      }
    }
  }

  return 0;
}

/*
 * --INFO--
 *
 * Function: isPointWithinPatchGroup
 * EN v1.0 Address: 0x800DB8D8
 * EN v1.0 Size: 372b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint isPointWithinPatchGroup(float *point,uint patchGroupIndex,int groupId)
{
  u8 k;
  uint pidx;
  uint j;
  ObjfsaPatch *patch;
  f32 y;

  for (k = 0; k < 4; k++) {
    pidx = lbl_8039FAE8[patchGroupIndex].patchIndices[k];
    if (pidx != 0) {
      patch = &lbl_8039CAE8[pidx];
      if (patch->groupId == groupId) {
        y = point[1];
        if (y < (f32)patch->maxY && y > (f32)patch->minY) {
          patchGroupIndex = 0;
          j = 0;
          for (; (patchGroupIndex & 0xff) < 4; patchGroupIndex++, j += 2) {
            if (patch->planeOffsets[patchGroupIndex & 0xff] +
                    (point[0] * (f32)((s16 *)patch)[j & 0xff] +
                     point[2] * (f32)((s16 *)patch)[(j & 0xff) + 1]) >
                0.0f) {
              break;
            }
          }
        }
        return (uint)__cntlzw(4 - (patchGroupIndex & 0xff)) >> 5;
      }
    }
  }
  OSReport(sObjfsaIsPointWithinPatchGroupError);
  return 0;
}

/*
 * --INFO--
 *
 * Function: getPatchGroup
 * EN v1.0 Address: 0x800DBA4C
 * EN v1.0 Size: 344b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
u16 getPatchGroup(float *point,int patchGroupIndex,undefined4 param_3,undefined4 param_4,
                  u8 startPatchIndex)
{
  char *base;
  u8 *active;
  char *wg;
  ObjfsaPatch *patch;
  u8 k;
  uint pidx;
  u8 i;
  u8 j;
  f32 y;

  base = (char *)lbl_8039CAE8;
  active = (u8 *)(base + patchGroupIndex + OBJFSA_ACTIVE_WALKGROUPS_OFFSET);
  wg = base + patchGroupIndex * OBJFSA_PATCHGROUP_STRIDE + 0x3000;

  for (k = 0; k < 4; k++) {
    if (*active == 0) {
      continue;
    }
    pidx = *(u8 *)(wg + k + 0x24);
    if (pidx == 0) {
      continue;
    }
    patch = (ObjfsaPatch *)(base + pidx * 0x30);
    y = point[1];
    if (y < (f32)patch->maxY && y > (f32)patch->minY) {
      i = 0;
      j = 0;
      for (; i < 4; i++, j += 2) {
        if (patch->planeOffsets[i] +
                (point[0] * (f32)((s16 *)patch)[j] +
                 point[2] * (f32)((s16 *)patch)[j + 1]) >
            0.0f) {
          break;
        }
      }
    }
    if (i == 4) {
      return patch->groupId;
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: isInWalkGroupOrPatch
 * EN v1.0 Address: 0x800DBBA4
 * EN v1.0 Size: 344b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole on
uint isInWalkGroupOrPatch(float *point)
{
  s16 idx;
  s16 i;
  ObjfsaPatch *patch;
  s16 *nz;
  s16 *nx;
  char *offs;
  int count;
  f32 y;

  if (mathFn_800dbff0(point) != 0) {
    return 1;
  }

  idx = 1;
  patch = &lbl_8039CAE8[1];
  count = lbl_803DD468;
  for (; idx < count; idx++, patch++) {
    y = point[1];
    if (y < (f32)patch->maxY && y > (f32)patch->minY) {
      i = 0;
      nz = (s16 *)patch;
      nx = (s16 *)patch;
      offs = (char *)patch;
      for (; i < 4; i++, offs += 4, nz += 2, nx += 2) {
        if (*(f32 *)(offs + 0x10) +
                (point[0] * (f32)nx[0] + point[2] * (f32)nz[1]) >
            0.0f) {
          break;
        }
      }
      if (i == 4) {
        return 1;
      }
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: Objfsa_GetWalkGroupIndexAtPoint
 * EN v1.0 Address: 0x800DBCFC
 * EN v1.0 Size: 464b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
int Objfsa_GetWalkGroupIndexAtPoint(float *point,ObjfsaWalkGroupPatchInfo *patchInfo)
{
  uint wgi;
  ObjfsaWalkGroup *wg;
  u8 k;
  u8 mask;
  uint pidx;
  u8 i;
  u8 j;
  ObjfsaPatch *patch;
  f32 y;

  wgi = (u8)mathFn_800dbff0(point);
  if (patchInfo != NULL && wgi != 0) {
    patchInfo->walkGroupIndex = wgi;
    patchInfo->patchMask = 0;
    k = 0;
    mask = 1;
    wg = &lbl_8039FAE8[wgi];
    for (; k < 4; k++, mask <<= 1) {
      pidx = wg->patchIndices[k];
      if (pidx != 0) {
        patch = &lbl_8039CAE8[pidx];
        patchInfo->patchGroupIds[k] = patch->groupId;
        y = point[1];
        if (y < (f32)patch->maxY && y > (f32)patch->minY) {
          i = 0;
          j = 0;
          for (; i < 4; i++, j += 2) {
            if (patch->planeOffsets[i] +
                    (point[0] * (f32)((s16 *)patch)[j] +
                     point[2] * (f32)((s16 *)patch)[j + 1]) >
                0.0f) {
              break;
            }
          }
        }
        if (i == 4) {
          patchInfo->patchMask |= mask;
        }
      } else {
        patchInfo->patchGroupIds[k] = 0;
      }
    }
  }
  return wgi;
}

/*
 * --INFO--
 *
 * Function: Objfsa_GetPatchGroupIdAtPoint
 * EN v1.0 Address: 0x800DBECC
 * EN v1.0 Size: 292b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
u16 Objfsa_GetPatchGroupIdAtPoint(float *point)
{
  int n;
  ObjfsaPatch *patch = lbl_8039CAE8;

  for (n = lbl_803DD468; n > 0; n--) {
    f32 y = point[1];
    if (y < (f32)patch->maxY && y > (f32)patch->minY) {
      f32 x;
      f32 z;
      u8 i;
      u8 j;
      z = point[2];
      x = point[0];
      j = i = 0;
      for (; i < 4; i++, j += 2) {
        if (patch->planeOffsets[i] +
                (x * (f32)((s16 *)patch)[j] + z * (f32)((s16 *)patch)[j + 1]) >
            0.0f) {
          break;
        }
      }
      if (i == 4) {
        return patch->groupId;
      }
    }
    patch++;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: mathFn_800dbff0
 * EN v1.0 Address: 0x800DBFF0
 * EN v1.0 Size: 936b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#define WALKGROUP_TRY_RETURN(idx)                                                  \
    if (Objfsa_IsWalkGroupActive(idx)) {                                           \
        g = &lbl_8039FAE8[idx];                                                    \
        y = point[1];                                                              \
        if (y < (f32)g->maxY && y > (f32)g->minY) {                                \
            z = point[2];                                                          \
            x = point[0];                                                          \
            i = 0;                                                                 \
            j = i;                                                                 \
            for (; i < 4; i++, j += 2) {                                           \
                if (g->planeOffsets[i] +                                           \
                        (x * (f32)((s16 *)g)[j] + z * (f32)((s16 *)g)[j + 1]) >    \
                    0.0f) {                                                        \
                    break;                                                         \
                }                                                                  \
            }                                                                      \
            if (i == 4) {                                                          \
                lbl_803DD464 = (idx);                                              \
                return (idx);                                                      \
            }                                                                      \
        }                                                                          \
    }

int mathFn_800dbff0(float *point)
{
    s16 down;
    s16 up;
    ObjfsaWalkGroup *g;
    f32 y;
    f32 z;
    f32 x;
    u8 i;
    u8 j;

    down = (s16)lbl_803DD464;
    if (lbl_803DD464 == OBJFSA_WALKGROUP_COUNT - 1) {
        up = 0;
    } else {
        up = down + 1;
    }

    while (down != up) {
        WALKGROUP_TRY_RETURN(down);
        WALKGROUP_TRY_RETURN(up);

        down--;
        if (down == -1) {
            down = OBJFSA_WALKGROUP_COUNT - 1;
        }
        up++;
        if (up == OBJFSA_WALKGROUP_COUNT) {
            up = 0;
        }
    }

    WALKGROUP_TRY_RETURN(down);
    return 0;
}

/*
 * --INFO--
 *
 * Function: RomCurve_findProjectedCurveFromStart
 * EN v1.0 Address: 0x800DFE64
 * EN v1.0 Size: 720b
 * EN v1.1 Address: 0x800E1A4C
 * EN v1.1 Size: 860b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling on
#pragma peephole on
void player_release(void) {}
void player_initialise(void) {}
void UIController_release(void) {}
void UIController_initialise(void) {}
void dll_12_func0A_nop(void) {}
void dll_12_func08_nop(void) {}
void dll_12_func07_nop(void) {}
void dll_12_func04_nop(void) {}
void dll_12_func03_nop(void) {}
void dll_12_func05_nop(void) {}
void Dummy12_release(void) {}
void Dummy12_initialise(void) {}
void doNothing_onTrickyFree(void) {}
void doNothing_onTrickyInit(void) {}

/* 8b "li r3, N; blr" returners. */
int dll_12_func06_ret_0(void) { return 0x0; }

/* sda21 accessors. */
extern u32 lbl_803DD430;
void player_setOverride(u32 x) { lbl_803DD430 = x; }

/* Pattern wrappers. */
extern u32 lbl_803DD458;
void dll_12_func09(void) { lbl_803DD458 = 0x3; }

/* player_init: memset constructor */
extern void *memset(void *dst, int val, u32 n);
extern f32 lbl_803E05BC;
extern f32 lbl_803E05C8;
extern f32 lbl_803E05CC;
extern f32 lbl_803E05F4;
extern int Curve_AdvanceAlongPath(float *p, f32 dt);
#pragma scheduling off
#pragma peephole off
void player_init(int unused, void *obj, int a, int b) {
    memset(obj, 0, 0x35c);
    *(s16 *)((char *)obj + 0x26c) = (s16)a;
    *(s16 *)((char *)obj + 0x26e) = (s16)b;
    ((BaddieState *)obj)->moveJustStartedA = 1;
    ((BaddieState *)obj)->moveJustStartedB = 1;
    *(f32 *)((char *)obj + 0x2b8) = lbl_803E05BC;
    *(s32 *)((char *)obj + 0x33c) = -1;
    *(s32 *)((char *)obj + 0x340) = -1;
    *(u8 *)((char *)obj + 0x358) = 0;
}

/* fn_800D9F38 ? large init updating multiple float fields based on b's bytes */
extern float mathSinf(double angle);
extern float mathCosf(double x);
extern f32 lbl_803E05D0;
extern f32 lbl_803E05D4;
extern f32 lbl_803E05D8;
int fn_800D9F38(void *a, void *b) {
    char *A = (char *)a;
    char *B = (char *)b;
    if (*(u32 *)(A + 0xa0) == 0 || *(u32 *)(A + 0xa4) == 0 || b == 0) return 1;
    *(void **)(A + 0xa4) = b;
    if (*(int *)(A + 0x80) != 0) {
        /* branch1 */
        f32 t;
        *(f32 *)(A + 0xa8) = *(f32 *)(B + 0x8);
        t = (float)(u32)*(u8 *)(B + 0x2e) *
            mathSinf(lbl_803E05D4 * (float)((s32)((s8)*(B + 0x2c)) << 8) / lbl_803E05D8);
        *(f32 *)(A + 0xb0) = lbl_803E05D0 * t;
        *(f32 *)(A + 0xc8) = *(f32 *)(B + 0xc);
        t = (float)(u32)*(u8 *)(B + 0x2e) *
            mathSinf(lbl_803E05D4 * (float)((s32)((s8)*(B + 0x2d)) << 8) / lbl_803E05D8);
        *(f32 *)(A + 0xd0) = lbl_803E05D0 * t;
        *(f32 *)(A + 0xe8) = *(f32 *)(B + 0x10);
        t = (float)(u32)*(u8 *)(B + 0x2e) *
            mathCosf(lbl_803E05D4 * (float)((s32)((s8)*(B + 0x2c)) << 8) / lbl_803E05D8);
        *(f32 *)(A + 0xf0) = lbl_803E05D0 * t;
    } else {
        /* branch2 */
        f32 t;
        *(f32 *)(A + 0xbc) = *(f32 *)(B + 0x8);
        t = (float)(u32)*(u8 *)(B + 0x2e) *
            mathSinf(lbl_803E05D4 * (float)((s32)((s8)*(B + 0x2c)) << 8) / lbl_803E05D8);
        *(f32 *)(A + 0xc4) = lbl_803E05D0 * t;
        *(f32 *)(A + 0xdc) = *(f32 *)(B + 0xc);
        t = (float)(u32)*(u8 *)(B + 0x2e) *
            mathSinf(lbl_803E05D4 * (float)((s32)((s8)*(B + 0x2d)) << 8) / lbl_803E05D8);
        *(f32 *)(A + 0xe4) = lbl_803E05D0 * t;
        *(f32 *)(A + 0xfc) = *(f32 *)(B + 0x10);
        t = (float)(u32)*(u8 *)(B + 0x2e) *
            mathCosf(lbl_803E05D4 * (float)((s32)((s8)*(B + 0x2c)) << 8) / lbl_803E05D8);
        *(f32 *)(A + 0x104) = lbl_803E05D0 * t;
    }
    return 0;
}

/* player_updateVel */
extern f32 lbl_803E05A4;
extern f32 lbl_803E05A8;
extern u8 lbl_803DD434;
extern u8 lbl_803DD44E;
extern u8 lbl_803DD44F;
extern f32 timeDelta;
extern u8 lbl_803DD450;
extern f64 lbl_803E0598;
extern f32 lbl_803E0588;
extern f32 lbl_803E05B4;
extern f32 lbl_803E05C0;
extern f32 lbl_803E05C4;
extern f32 lbl_803DD444;
extern f32 lbl_803DD448;
extern void fn_800D915C(int pos, int *obj, void *fnTable, f32 fval);
extern void fn_800D8414(char *pos, char *state);
extern void player_applyVelocityStep(char *pos, char *state, f32 dt);
extern void setMatrixFromObjectPos(f32 *matrix, void *objpos);
extern void Matrix_TransformPoint(f32 *matrix, f32 x, f32 y, f32 z, f32 *outX, f32 *outY, f32 *outZ);
extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z);

void playerRunStateMachine(char *pos, char *state, float dt, int stateFns) {
    int changed;
    int done;
    int iterations;
    int currentState;
    int result;
    void (*exitFn)(char *, char *);

    changed = 0;
    iterations = 0;
    lbl_803DD450 = 0;
    lbl_803DD440 = 0;

    if (*(s16 *)(state + 0x274) != *(s16 *)(state + 0x276)) {
        *(u8 *)(state + 0x27a) = 1;
        *(s16 *)(state + 0x338) = 0;
    }

    do {
        done = 0;
        currentState = *(s16 *)(state + 0x274);
        result = (*(int (**)(char *, char *, f32))(stateFns + currentState * 4))(pos, state, dt);
        if (result > 0) {
            *(s16 *)(state + 0x276) = *(s16 *)(state + 0x274);
            *(s16 *)(state + 0x274) = (s16)(result - 1);
            exitFn = *(void (**)(char *, char *))(state + 0x304);
            if (exitFn != 0) {
                exitFn(pos, state);
                *(void **)(state + 0x304) = 0;
            }
            *(void **)(state + 0x304) = *(void **)(state + 0x308);
            *(u8 *)(state + 0x27a) = 1;
            *(s16 *)(state + 0x338) = 0;
            *(u8 *)(state + 0x34d) = 0;
            *(u8 *)(state + 0x34c) = 0;
            *(u8 *)(state + 0x356) = 0;
            *(s16 *)(state + 0x278) = 0;
            if (*(int *)(pos + 0x54) != 0) {
                *(u8 *)(*(int *)(pos + 0x54) + 0x70) = 0;
            }
        } else if (result < 0) {
            result = -result;
            *(s16 *)(state + 0x274) = (s16)result;
            if (result != currentState) {
                *(s16 *)(state + 0x276) = (s16)currentState;
                exitFn = *(void (**)(char *, char *))(state + 0x304);
                if (exitFn != 0) {
                    exitFn(pos, state);
                    *(void **)(state + 0x304) = 0;
                }
                *(void **)(state + 0x304) = *(void **)(state + 0x308);
                *(u8 *)(state + 0x27a) = 1;
                *(s16 *)(state + 0x338) = 0;
                *(u8 *)(state + 0x34d) = 0;
                *(u8 *)(state + 0x34c) = 0;
                *(u8 *)(state + 0x356) = 0;
                *(s16 *)(state + 0x278) = 0;
                if (*(int *)(pos + 0x54) != 0) {
                    *(u8 *)(*(int *)(pos + 0x54) + 0x70) = 0;
                }
            }
            done = 1;
            changed = 1;
        } else {
            done = 1;
        }

        iterations++;
        if (iterations > 0xff) {
            done = 1;
        }
    } while (done == 0);

    if (changed == 0) {
        *(u8 *)(state + 0x27a) = 0;
    }
    *(s16 *)(state + 0x276) = *(s16 *)(state + 0x274);

    if (lbl_803DD440 == 0 && ((s32)*(s8 *)(state + 0x34c) & 1) == 0) {
        u8 animEvents[0x1c];
        int i;

        animEvents[0x1b] = 0;
        *(s8 *)(state + 0x346) = ((int (*)(int, f32, f32, void *))ObjAnim_AdvanceCurrentMove)(
            (int)pos, *(f32 *)(state + 0x2a0), dt, (ObjAnimEventList *)animEvents);
        *(u32 *)(state + 0x314) = 0;
        for (i = 0; i < (s8)animEvents[0x1b]; i++) {
            *(u32 *)(state + 0x314) |= 1 << (s32)(s8)animEvents[0x13 + i];
        }
        *(u32 *)state &= 0xfffeffff;
    }

    if ((*(u32 *)state & 0x4000) == 0) {
        int decay;

        decay = (s32)((f32)((f64)*(s16 *)(pos + 2) - lbl_803E0598) * dt * lbl_803E05C0);
        *(s16 *)(pos + 2) = *(s16 *)(pos + 2) - (s16)decay;
        decay = (s32)((f32)((f64)*(s16 *)(pos + 4) - lbl_803E0598) * dt * lbl_803E05C0);
        *(s16 *)(pos + 4) = *(s16 *)(pos + 4) - (s16)decay;
    }
}

void player_update(char *pos, char *state, float dt, float pathDt, int stateFns, int auxStateFns) {
    struct {
        s16 rotX;
        s16 rotY;
        s16 rotZ;
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } localTransform;
    f32 matrix[16];
    int keepPathControls;
    int attachment;
    int mapBlock;
    int overrideObj;
    f32 dx;
    f32 dz;
    f32 dist;
    f32 limit;

    keepPathControls = 1;
    lbl_803DD44E = 0;

    attachment = *(int *)(state + 0x2d0);
    if (attachment != 0) {
        dx = *(f32 *)(attachment + 0xc) - *(f32 *)(pos + 0xc);
        dz = *(f32 *)(attachment + 0x14) - *(f32 *)(pos + 0x14);
        *(f32 *)(state + 0x2c0) = sqrtf(dx * dx + dz * dz);
    } else {
        *(f32 *)(state + 0x2c0) = lbl_803E0570;
    }

    if ((*(u32 *)state & 0x8000) != 0 && *(int *)(pos + 0xc0) == 0) {
        fn_800D915C((int)pos, (int *)state, (void *)auxStateFns, dt);
        *(s16 *)(state + 0x32e) = (s16)((f32)*(s16 *)(state + 0x32e) + dt);
        if ((f32)*(s16 *)(state + 0x32e) > lbl_803E05C4) {
            *(s16 *)(state + 0x32e) = 10000;
        }
    }

    *(u32 *)state |= 0x8000;

    if (*(int *)(state + 0x27c) != 0) {
        localTransform.rotX = *(s16 *)(pos + 0);
        localTransform.rotY = *(s16 *)(pos + 2);
        localTransform.rotZ = *(s16 *)(pos + 4);
        localTransform.scale = lbl_803E0588;
        localTransform.x = lbl_803E0570;
        localTransform.y = lbl_803E0570;
        localTransform.z = lbl_803E0570;
        setMatrixFromObjectPos(matrix, &localTransform);

        attachment = *(int *)(state + 0x27c);
        Matrix_TransformPoint(matrix, lbl_803E0570, *(f32 *)&lbl_803E0570, lbl_803E0588,
                              (f32 *)(attachment + 0x4), (f32 *)(attachment + 0x8), (f32 *)(attachment + 0xc));
        attachment = *(int *)(state + 0x27c);
        Matrix_TransformPoint(matrix, lbl_803E0570, lbl_803E0588, lbl_803E0570,
                              (f32 *)(attachment + 0x10), (f32 *)(attachment + 0x14), (f32 *)(attachment + 0x18));
        attachment = *(int *)(state + 0x27c);
        Matrix_TransformPoint(matrix, lbl_803E0588, lbl_803E0570, *(f32 *)&lbl_803E0570,
                              (f32 *)(attachment + 0x1c), (f32 *)(attachment + 0x20), (f32 *)(attachment + 0x24));
    }

    if ((*(u32 *)state & 0x1000000) == 0) {
        fn_800D8414(pos, state);
    }

    *(u32 *)state &= 0xffdfffff;
    *(u8 *)(state + 0x34d) = 0;
    lbl_803DD434 = 0;
    *(u32 *)state &= 0xfff7ffff;
    *(u8 *)(state + 0x34c) = 0;
    lbl_803DD44F = 0;

    playerRunStateMachine(pos, state, dt, stateFns);

    *(s16 *)(state + 0x338) = (s16)((f32)*(s16 *)(state + 0x338) + dt);
    if ((f32)*(s16 *)(state + 0x338) > lbl_803E05C4) {
        *(s16 *)(state + 0x338) = 10000;
    }

    lbl_803DD448 = *(f32 *)(pos + 0xc);
    lbl_803DD444 = *(f32 *)(pos + 0x14);
    mapBlock = objPosToMapBlockIdx(*(f32 *)(pos + 0x18), *(f32 *)(pos + 0x1c), *(f32 *)(pos + 0x20));
    if (mapBlock == -1 && *(int *)(pos + 0x30) == 0) {
        *(u32 *)state |= 0x200000;
        keepPathControls = 0;
    }

    if ((*(u32 *)state & 0x1000000) == 0) {
        player_applyVelocityStep(pos, state, dt);
    }

    overrideObj = lbl_803DD430;
    if (overrideObj != 0) {
        dx = *(f32 *)(overrideObj + 0xc) - lbl_803DD448;
        dz = *(f32 *)(overrideObj + 0x14) - lbl_803DD444;
        dist = sqrtf(dx * dx + dz * dz);
        if (dist < lbl_803E05BC) {
            limit = sqrtf((*(f32 *)(pos + 0xc) - lbl_803DD448) * (*(f32 *)(pos + 0xc) - lbl_803DD448) +
                          (*(f32 *)(pos + 0x14) - lbl_803DD444) * (*(f32 *)(pos + 0x14) - lbl_803DD444));
            if (limit < lbl_803E05B4) {
                limit = lbl_803E05B4;
            }

            if (dist < lbl_803E0588) {
                *(f32 *)(pos + 0xc) = *(f32 *)(overrideObj + 0xc);
                *(f32 *)(pos + 0x14) = *(f32 *)(overrideObj + 0x14);
            } else {
                if (limit > dist) {
                    limit = dist;
                }
                *(f32 *)(pos + 0xc) = dx / dist * limit + lbl_803DD448;
                *(f32 *)(pos + 0x14) = dz / dist * limit + lbl_803DD444;
            }
        }
    }

    lbl_803DD430 = 0;

    if ((*(u32 *)state & 0x1000000) == 0 && (*(u32 *)state & 0x400000) == 0 && keepPathControls != 0) {
        (*gPathControlInterface)->update(pos, state + 0x4, dt);
        (*gPathControlInterface)->apply(pos, state + 0x4);
        (*gPathControlInterface)->advance(pos, state + 0x4, pathDt);

        if (((s32)*(s8 *)(state + 0x264) & 0x10) == 0) {
            *(u32 *)state &= 0xfffbffff;
        } else {
            *(u32 *)state |= 0x40000;
        }

        if ((*(u32 *)state & 0x800000) != 0) {
            if (((s32)*(s8 *)(state + 0x264) & 2) != 0 || *(u8 *)(state + 0x262) != 0) {
                *(f32 *)(pos + 0x24) = (*(f32 *)(pos + 0xc) - *(f32 *)(*(int *)(pos + 0x54) + 0x10)) / dt;
                *(f32 *)(pos + 0x2c) = (*(f32 *)(pos + 0x14) - *(f32 *)(*(int *)(pos + 0x54) + 0x18)) / dt;
            }
            *(u32 *)state &= 0xff7fffff;
        }
    }
}

void player_updateVel(char *p, char *obj, int unused) {
    float fcos, fsin;
    if (((s32)(s8)*(obj + 0x34c) & 1) != 0) {
        fcos = mathSinf(lbl_803E05A4 * (float)(s32)*(s16 *)p / lbl_803E05A8);
        fsin = mathCosf(lbl_803E05A4 * (float)(s32)*(s16 *)p / lbl_803E05A8);
        if (((s32)(s8)*(obj + 0x34c) & 8) != 0) {
            *(f32 *)(obj + 0x280) = -*(f32 *)(p + 0x2c) * fsin - *(f32 *)(p + 0x24) * fcos;
            *(f32 *)(obj + 0x294) = *(f32 *)(obj + 0x280);
        } else {
            *(f32 *)(obj + 0x284) = *(f32 *)(p + 0x24) * fsin - *(f32 *)(p + 0x2c) * fcos;
            *(f32 *)(obj + 0x280) = -*(f32 *)(p + 0x2c) * fsin - *(f32 *)(p + 0x24) * fcos;
            if (((s32)(s8)*(obj + 0x34c) & 4) != 0) {
                *(f32 *)(obj + 0x294) = sqrtf(*(f32 *)(p + 0x24) * *(f32 *)(p + 0x24) +
                                                *(f32 *)(p + 0x2c) * *(f32 *)(p + 0x2c));
            }
        }
        *(s8 *)(obj + 0x34c) = 0;
        *(u32 *)obj |= 0x80000;
        lbl_803DD434 = 1;
        lbl_803DD44F = 0;
        lbl_803DD44E = 1;
        playerRunStateMachine(p, obj, timeDelta, unused);
    }
}


/* RomCurve_setA4: similar to fn_800D9F38 branch2 with different consts */
extern f32 lbl_803E0610;
extern f32 lbl_803E0614;
extern f32 lbl_803E0618;
void RomCurve_setA4(void *a, void *b) {
    char *A = (char *)a;
    f32 t;
    if (b != 0 && (u32)b != *(u32 *)(A + 0xa4)) {
        *(void **)(A + 0xa4) = b;
        *(f32 *)(A + 0xbc) = *(f32 *)((*(char **)(A + 0xa4)) + 0x8);
        t = (float)(u32)*(u8 *)((*(char **)(A + 0xa4)) + 0x2e) *
            mathSinf(lbl_803E0614 * (float)((s32)((s8)*((*(char **)(A + 0xa4)) + 0x2c)) << 8) / lbl_803E0618);
        *(f32 *)(A + 0xc4) = lbl_803E0610 * t;
        *(f32 *)(A + 0xdc) = *(f32 *)((*(char **)(A + 0xa4)) + 0xc);
        t = (float)(u32)*(u8 *)((*(char **)(A + 0xa4)) + 0x2e) *
            mathSinf(lbl_803E0614 * (float)((s32)((s8)*((*(char **)(A + 0xa4)) + 0x2d)) << 8) / lbl_803E0618);
        *(f32 *)(A + 0xe4) = lbl_803E0610 * t;
        *(f32 *)(A + 0xfc) = *(f32 *)((*(char **)(A + 0xa4)) + 0x10);
        t = (float)(u32)*(u8 *)((*(char **)(A + 0xa4)) + 0x2e) *
            mathCosf(lbl_803E0614 * (float)((s32)((s8)*((*(char **)(A + 0xa4)) + 0x2c)) << 8) / lbl_803E0618);
        *(f32 *)(A + 0x104) = lbl_803E0610 * t;
    }
}

extern void Curve_BuildHermiteCoeffs(void);
extern void Curve_EvalHermite(void);
extern void curvesMove(float *state);
extern void curvesSetupMoveNetworkCurve(float *state);
extern f32 gFloatZero;
extern f32 gFloatNegOne;
extern void *memcpy(void *dst, const void *src, u32 n);

int RomCurve_setClosed(float *state, int closed) {
    float savedPhase;
    float t;
    void *tmpCurve;

    if (closed == ((RomCurveWalker *)state)->reverse) {
        return 0;
    }
    if (((RomCurveWalker *)state)->nodeA0 == 0 || ((RomCurveWalker *)state)->node9C == 0) {
        return 1;
    }

    savedPhase = state[0];
    ((RomCurveWalker *)state)->reverse = closed;
    tmpCurve = ((RomCurveWalker *)state)->node9C;
    ((RomCurveWalker *)state)->node9C = ((RomCurveWalker *)state)->nodeA4;
    ((RomCurveWalker *)state)->nodeA4 = tmpCurve;

    ((RomCurveWalker *)state)->hermX2[0] = *(f32 *)((char *)((RomCurveWalker *)state)->nodeA0 + 0x8);
    ((RomCurveWalker *)state)->hermX2[1] = *(f32 *)((char *)((RomCurveWalker *)state)->nodeA4 + 0x8);
    t = (float)(u32)*(u8 *)((char *)((RomCurveWalker *)state)->nodeA0 + 0x2e) *
        mathSinf(lbl_803E0614 *
                    (float)((s32)((s8)*((char *)((RomCurveWalker *)state)->nodeA0 + 0x2c)) << 8) /
                    lbl_803E0618);
    ((RomCurveWalker *)state)->hermX2[2] = lbl_803E0610 * t;
    t = (float)(u32)*(u8 *)((char *)((RomCurveWalker *)state)->nodeA4 + 0x2e) *
        mathSinf(lbl_803E0614 *
                    (float)((s32)((s8)*((char *)((RomCurveWalker *)state)->nodeA4 + 0x2c)) << 8) /
                    lbl_803E0618);
    ((RomCurveWalker *)state)->hermX2[3] = lbl_803E0610 * t;

    ((RomCurveWalker *)state)->hermY2[0] = *(f32 *)((char *)((RomCurveWalker *)state)->nodeA0 + 0xc);
    ((RomCurveWalker *)state)->hermY2[1] = *(f32 *)((char *)((RomCurveWalker *)state)->nodeA4 + 0xc);
    t = (float)(u32)*(u8 *)((char *)((RomCurveWalker *)state)->nodeA0 + 0x2e) *
        mathSinf(lbl_803E0614 *
                    (float)((s32)((s8)*((char *)((RomCurveWalker *)state)->nodeA0 + 0x2d)) << 8) /
                    lbl_803E0618);
    ((RomCurveWalker *)state)->hermY2[2] = lbl_803E0610 * t;
    t = (float)(u32)*(u8 *)((char *)((RomCurveWalker *)state)->nodeA4 + 0x2e) *
        mathSinf(lbl_803E0614 *
                    (float)((s32)((s8)*((char *)((RomCurveWalker *)state)->nodeA4 + 0x2d)) << 8) /
                    lbl_803E0618);
    ((RomCurveWalker *)state)->hermY2[3] = lbl_803E0610 * t;

    ((RomCurveWalker *)state)->hermZ2[0] = *(f32 *)((char *)((RomCurveWalker *)state)->nodeA0 + 0x10);
    ((RomCurveWalker *)state)->hermZ2[1] = *(f32 *)((char *)((RomCurveWalker *)state)->nodeA4 + 0x10);
    t = (float)(u32)*(u8 *)((char *)((RomCurveWalker *)state)->nodeA0 + 0x2e) *
        mathCosf(lbl_803E0614 *
            (float)((s32)((s8)*((char *)((RomCurveWalker *)state)->nodeA0 + 0x2c)) << 8) / lbl_803E0618);
    ((RomCurveWalker *)state)->hermZ2[2] = lbl_803E0610 * t;
    t = (float)(u32)*(u8 *)((char *)((RomCurveWalker *)state)->nodeA4 + 0x2e) *
        mathCosf(lbl_803E0614 *
            (float)((s32)((s8)*((char *)((RomCurveWalker *)state)->nodeA4 + 0x2c)) << 8) / lbl_803E0618);
    ((RomCurveWalker *)state)->hermZ2[3] = lbl_803E0610 * t;

    if (RomCurve_goNextPoint(state) != 0) {
        return 1;
    }

    ((RomCurveWalker *)state)->node94 = Curve_EvalHermite;
    ((RomCurveWalker *)state)->node98 = Curve_BuildHermiteCoeffs;
    *(float **)(state + 0x21) = state + 0x2a;
    *(float **)(state + 0x22) = state + 0x32;
    *(float **)(state + 0x23) = state + 0x3a;
    *(s32 *)(state + 0x24) = 8;
    curvesMove(state);
    state[0] = savedPhase;
    return 0;
}

#define ROMCURVE_ADD_LINK(off, mask, wantSet)                                     \
    neighborId = *(s32 *)(curve + (off));                                         \
    if (neighborId > -1 && (((*(s8 *)(curve + 0x1b) & (mask)) != 0) == (wantSet)) && \
        neighborId != -1) {                                                       \
        candidateIds[candidateCount++] = neighborId;                              \
    }

#define ROMCURVE_REFRESH_CONTROL(secondOff)                                       \
    *(f32 *)(stateBytes + 0xb8) = *(f32 *)(*(s32 *)(stateBytes + 0xa0) + 0x8);    \
    *(f32 *)(stateBytes + 0xbc) = *(f32 *)(*(s32 *)(stateBytes + (secondOff)) + 0x8); \
    t = (float)(u32)*(u8 *)(*(s32 *)(stateBytes + 0xa0) + 0x2e) *                 \
        mathSinf(lbl_803E0614 *                                                \
                    (float)((s32)*(s8 *)(*(s32 *)(stateBytes + 0xa0) + 0x2c) << 8) / \
                    lbl_803E0618);                                                \
    *(f32 *)(stateBytes + 0xc0) = lbl_803E0610 * t;                               \
    t = (float)(u32)*(u8 *)(*(s32 *)(stateBytes + (secondOff)) + 0x2e) *          \
        mathSinf(lbl_803E0614 *                                                \
                    (float)((s32)*(s8 *)(*(s32 *)(stateBytes + (secondOff)) + 0x2c) << 8) / \
                    lbl_803E0618);                                                \
    *(f32 *)(stateBytes + 0xc4) = lbl_803E0610 * t;                               \
    *(f32 *)(stateBytes + 0xd8) = *(f32 *)(*(s32 *)(stateBytes + 0xa0) + 0xc);    \
    *(f32 *)(stateBytes + 0xdc) = *(f32 *)(*(s32 *)(stateBytes + (secondOff)) + 0xc); \
    t = (float)(u32)*(u8 *)(*(s32 *)(stateBytes + 0xa0) + 0x2e) *                 \
        mathSinf(lbl_803E0614 *                                                \
                    (float)((s32)*(s8 *)(*(s32 *)(stateBytes + 0xa0) + 0x2d) << 8) / \
                    lbl_803E0618);                                                \
    *(f32 *)(stateBytes + 0xe0) = lbl_803E0610 * t;                               \
    t = (float)(u32)*(u8 *)(*(s32 *)(stateBytes + (secondOff)) + 0x2e) *          \
        mathSinf(lbl_803E0614 *                                                \
                    (float)((s32)*(s8 *)(*(s32 *)(stateBytes + (secondOff)) + 0x2d) << 8) / \
                    lbl_803E0618);                                                \
    *(f32 *)(stateBytes + 0xe4) = lbl_803E0610 * t;                               \
    *(f32 *)(stateBytes + 0xf8) = *(f32 *)(*(s32 *)(stateBytes + 0xa0) + 0x10);   \
    *(f32 *)(stateBytes + 0xfc) = *(f32 *)(*(s32 *)(stateBytes + (secondOff)) + 0x10); \
    t = (float)(u32)*(u8 *)(*(s32 *)(stateBytes + 0xa0) + 0x2e) *                 \
        mathCosf(lbl_803E0614 *                                                        \
            (float)((s32)*(s8 *)(*(s32 *)(stateBytes + 0xa0) + 0x2c) << 8) / lbl_803E0618); \
    *(f32 *)(stateBytes + 0x100) = lbl_803E0610 * t;                              \
    t = (float)(u32)*(u8 *)(*(s32 *)(stateBytes + (secondOff)) + 0x2e) *          \
        mathCosf(lbl_803E0614 *                                                        \
            (float)((s32)*(s8 *)(*(s32 *)(stateBytes + (secondOff)) + 0x2c) << 8) / \
            lbl_803E0618);                                                        \
    *(f32 *)(stateBytes + 0x104) = lbl_803E0610 * t

u8 RomCurve_goNextPoint(float *state) {
    char *stateBytes;
    int candidateIds[4];
    int candidateCount;
    int neighborId;
    int curve;
    int low;
    int high;
    int mid;
    int nextCurve;
    float t;

    if (state == NULL) {
        return 1;
    }
    stateBytes = (char *)state;
    if (((RomCurveWalker *)stateBytes)->nodeA0 == NULL || ((RomCurveWalker *)stateBytes)->nodeA4 == NULL) {
        return 1;
    }

    ((RomCurveWalker *)stateBytes)->node9C = ((RomCurveWalker *)stateBytes)->nodeA0;
    ((RomCurveWalker *)stateBytes)->nodeA0 = ((RomCurveWalker *)stateBytes)->nodeA4;
    memcpy(stateBytes + 0xa8, stateBytes + 0xb8, 0x10);
    memcpy(stateBytes + 0xc8, stateBytes + 0xd8, 0x10);
    memcpy(stateBytes + 0xe8, stateBytes + 0xf8, 0x10);

    curve = *(s32 *)&((RomCurveWalker *)stateBytes)->nodeA0;
    candidateCount = 0;
    if (((RomCurveWalker *)stateBytes)->reverse == 0) {
        ROMCURVE_ADD_LINK(0x1c, 1, 0);
        ROMCURVE_ADD_LINK(0x20, 2, 0);
        ROMCURVE_ADD_LINK(0x24, 4, 0);
        ROMCURVE_ADD_LINK(0x28, 8, 0);
    } else {
        ROMCURVE_ADD_LINK(0x1c, 1, 1);
        ROMCURVE_ADD_LINK(0x20, 2, 1);
        ROMCURVE_ADD_LINK(0x24, 4, 1);
        ROMCURVE_ADD_LINK(0x28, 8, 1);
    }

    if (candidateCount == 0) {
        neighborId = -1;
    } else {
        neighborId = candidateIds[randomGetRange(0, candidateCount - 1)];
    }
    if (neighborId == -1) {
        ((RomCurveWalker *)stateBytes)->nodeA4 = NULL;
        return 1;
    }

    if (neighborId < 0) {
        nextCurve = 0;
    } else {
        low = 0;
        high = nRomCurves - 1;
        nextCurve = 0;
        while (low <= high) {
            mid = (low + high) >> 1;
            nextCurve = (s32)romCurves[mid];
            if (*(u32 *)(nextCurve + 0x14) < (u32)neighborId) {
                low = mid + 1;
            } else if (*(u32 *)(nextCurve + 0x14) <= (u32)neighborId) {
                break;
            } else {
                high = mid - 1;
            }
        }
        if (low > high) {
            nextCurve = 0;
        }
    }

    *(s32 *)&((RomCurveWalker *)stateBytes)->nodeA4 = nextCurve;
    if (((RomCurveWalker *)stateBytes)->nodeA4 == NULL) {
        return 1;
    }

    if (((RomCurveWalker *)stateBytes)->reverse == 0) {
        ROMCURVE_REFRESH_CONTROL(0xa4);
    } else {
        ROMCURVE_REFRESH_CONTROL(0x9c);
    }

    if (((RomCurveWalker *)stateBytes)->moveNetwork != 0) {
        curvesSetupMoveNetworkCurve(state);
    }
    if (((RomCurveWalker *)stateBytes)->reverse == 0) {
        ((void (*)(float *, double))Curve_AdvanceAlongPath)(state, gFloatOne);
    } else {
        ((void (*)(float *, double))Curve_AdvanceAlongPath)(state, gFloatNegOne);
    }
    return 0;
}


#pragma scheduling on
#pragma peephole on
static inline f32 RomCurveNode_GetHermiteTangent(void *node, int angleOffset, int useSin)
{
    f32 angle;
    f32 trig;

    angle = lbl_803E05D4 * (f32)((s32)*(s8 *)((char *)node + angleOffset) << 8) / lbl_803E05D8;
    if (useSin) {
        trig = mathCosf(angle);
    } else {
        trig = mathSinf(angle);
    }
    return lbl_803E05D0 * ((f32)(u32)*(u8 *)((char *)node + 0x2e) * trig);
}


int RomCurve_getControlPointId_2A(int curve, int exclude, int pickIdx);
int RomCurve_getControlPointId_2B(int curve, int exclude, int pickIdx);


#pragma scheduling off
#pragma peephole off
int RomCurve_func29(float *state, int pickIdx)
{
    char *stateBytes;
    int nextId;
    int nextCurve;
    f32 t;

    if (state == NULL) {
        return 1;
    }

    stateBytes = (char *)state;
    if (((RomCurveWalker *)stateBytes)->nodeA0 == NULL || ((RomCurveWalker *)stateBytes)->nodeA4 == NULL) {
        return 1;
    }

    ((RomCurveWalker *)stateBytes)->node9C = ((RomCurveWalker *)stateBytes)->nodeA0;
    ((RomCurveWalker *)stateBytes)->nodeA0 = ((RomCurveWalker *)stateBytes)->nodeA4;
    memcpy(stateBytes + 0xa8, stateBytes + 0xb8, 0x10);
    memcpy(stateBytes + 0xc8, stateBytes + 0xd8, 0x10);
    memcpy(stateBytes + 0xe8, stateBytes + 0xf8, 0x10);

    if (((RomCurveWalker *)stateBytes)->reverse != 0) {
        nextId = RomCurve_getControlPointId_2B(*(s32 *)&((RomCurveWalker *)stateBytes)->nodeA0, -1, pickIdx);
    } else {
        nextId = RomCurve_getControlPointId_2A(*(s32 *)&((RomCurveWalker *)stateBytes)->nodeA0, -1, pickIdx);
    }

    if (nextId == -1) {
        goto failClear;
    }

    nextCurve = Objfsa_FindRomCurveById(nextId);
    *(s32 *)&((RomCurveWalker *)stateBytes)->nodeA4 = nextCurve;
    if (((RomCurveWalker *)stateBytes)->nodeA4 == NULL) {
        goto fail;
    }

    if (((RomCurveWalker *)stateBytes)->reverse != 0) {
        ROMCURVE_REFRESH_CONTROL(0x9c);
    } else {
        ROMCURVE_REFRESH_CONTROL(0xa4);
    }

    if (((RomCurveWalker *)stateBytes)->moveNetwork != 0) {
        curvesSetupMoveNetworkCurve(state);
    }

    if (((RomCurveWalker *)stateBytes)->reverse != 0) {
        ((void (*)(float *, double))Curve_AdvanceAlongPath)(state, gFloatNegOne);
    } else {
        ((void (*)(float *, double))Curve_AdvanceAlongPath)(state, gFloatOne);
    }

    return 0;

failClear:
    ((RomCurveWalker *)stateBytes)->nodeA4 = NULL;
fail:
    return 1;
}

int RomCurve_getControlPointId_2A(int curve, int exclude, int pickIdx) {
    int candidates[4];
    int neighbor;
    int count = 0;
    u32 mask = 1;
    int i;
    for (i = 0; i < 4; i++) {
        neighbor = ((ObjfsaRomCurveDef *)curve)->linkIds[i];
        if (neighbor > -1 && ((s32)((ObjfsaRomCurveDef *)curve)->blockedLinkMask & mask) == 0 && neighbor != exclude) {
            candidates[count++] = neighbor;
        }
        mask <<= 1;
    }
    if (count != 0) {
        if (pickIdx > count - 1) pickIdx = count - 1;
        if (pickIdx == -1) {
            pickIdx = (int)randomGetRange(0, count - 1);
        }
        return candidates[pickIdx];
    }
    return -1;
}

int RomCurve_getControlPointId_2B(int curve, int exclude, int pickIdx) {
    int candidates[4];
    int neighbor;
    int count = 0;
    u32 mask = 1;
    int i;
    for (i = 0; i < 4; i++) {
        neighbor = ((ObjfsaRomCurveDef *)curve)->linkIds[i];
        if (neighbor > -1 && ((s32)((ObjfsaRomCurveDef *)curve)->blockedLinkMask & mask) != 0 && neighbor != exclude) {
            candidates[count++] = neighbor;
        }
        mask <<= 1;
    }
    if (count != 0) {
        if (pickIdx > count - 1) pickIdx = count - 1;
        if (pickIdx == -1) {
            pickIdx = (int)randomGetRange(0, count - 1);
        }
        return candidates[pickIdx];
    }
    return -1;
}

extern f32 lbl_803E0648;
extern f32 lbl_803E064C;
extern f32 lbl_803E0650;
extern f32 lbl_803E0654;

int RomCurve_findProjectedCurveFromStart(f32 x,f32 y,f32 z,int curve,float *outPhase)
{
  int projected;
  int linkId;
  float lateralOffset;
  float verticalOffset;
  float phase;
  int adjacentWindow[4];
  int candidates[4];
  u32 mask;
  int count;
  int n;
  int k;

  while (!((((ObjfsaRomCurveDef *)curve)->linkIds[0] == -1 || (*(u8 *)&((ObjfsaRomCurveDef *)curve)->blockedLinkMask & 1) != 0) &&
           (((ObjfsaRomCurveDef *)curve)->linkIds[1] == -1 || (*(u8 *)&((ObjfsaRomCurveDef *)curve)->blockedLinkMask & 2) != 0) &&
           (((ObjfsaRomCurveDef *)curve)->linkIds[2] == -1 || (*(u8 *)&((ObjfsaRomCurveDef *)curve)->blockedLinkMask & 4) != 0) &&
           (((ObjfsaRomCurveDef *)curve)->linkIds[3] == -1 || (*(u8 *)&((ObjfsaRomCurveDef *)curve)->blockedLinkMask & 8) != 0))) {
    RomCurve_getAdjacentWindow(curve, adjacentWindow);
    projected = RomCurve_projectPointToAdjacentWindow(x, y, z, adjacentWindow,
                                                      &lateralOffset, &verticalOffset, &phase);
    if (projected != 0 && lateralOffset > lbl_803E0648 && lateralOffset < lbl_803E064C &&
        verticalOffset > lbl_803E0650 && verticalOffset < lbl_803E0654) {
      *outPhase = phase;
      return curve;
    }

    count = 0;
    mask = 1;
    for (k = 0; k < 4; k++) {
      n = ((ObjfsaRomCurveDef *)curve)->linkIds[k];
      if (n > -1 && (((ObjfsaRomCurveDef *)curve)->blockedLinkMask & mask) == 0 && n != 0) {
        candidates[count++] = n;
      }
      mask <<= 1;
    }
    if (count != 0) {
      linkId = candidates[(int)randomGetRange(0, count - 1)];
    } else {
      linkId = -1;
    }
    curve = Objfsa_FindRomCurveById(linkId);
  }

  *outPhase = gFloatZero;
  return curve;
}

void curves_getPos(f32 phase,int curve,float *outX,float *outY,float *outZ)
{
  f32 dy;
  f32 dz;
  int linkId;
  int c2;
  int candidates[4];
  u32 mask;
  int count;
  int n;
  int k;

  count = 0;
  mask = 1;
  for (k = 0; k < 4; k++) {
    n = *(int *)(curve + 0x1C + k * 4);
    if (n > -1 && (*(s8 *)(curve + 0x1B) & mask) == 0 && n != 0) {
      candidates[count++] = n;
    }
    mask <<= 1;
  }
  if (count != 0) {
    linkId = candidates[(int)randomGetRange(0, count - 1)];
  } else {
    linkId = -1;
  }
  c2 = Objfsa_FindRomCurveById(linkId);

  if (c2 == 0) {
    *outX = *(f32 *)(curve + 8);
    *outY = *(f32 *)(curve + 0xc);
    *outZ = *(f32 *)(curve + 0x10);
  } else {
    dy = *(f32 *)(c2 + 0xc) - *(f32 *)(curve + 0xc);
    dz = *(f32 *)(c2 + 0x10) - *(f32 *)(curve + 0x10);
    *outX = (*(f32 *)(c2 + 8) - *(f32 *)(curve + 8)) * phase + *(f32 *)(curve + 8);
    *outY = dy * phase + *(f32 *)(curve + 0xc);
    *outZ = dz * phase + *(f32 *)(curve + 0x10);
  }
}



int RomCurve_func2C(float *state, int unused, int startCurveId)
{
    char *stateBytes;
    int currentCurve;
    int nextId;
    int nextCurve;
    f32 t;

    if (state == NULL) {
        return 1;
    }
    if (startCurveId == -1) {
        return 1;
    }

    stateBytes = (char *)state;
    if (((RomCurveWalker *)stateBytes)->reverse != 0) {
        currentCurve = Objfsa_FindRomCurveById(startCurveId);
        *(s32 *)&((RomCurveWalker *)stateBytes)->nodeA0 = currentCurve;
        nextId = RomCurve_getControlPointId_2A(currentCurve, -1, -1);
        if (nextId == -1) {
            return 1;
        }
        startCurveId = nextId;
    }

    currentCurve = Objfsa_FindRomCurveById(startCurveId);
    *(s32 *)&((RomCurveWalker *)stateBytes)->nodeA0 = currentCurve;
    if (((RomCurveWalker *)stateBytes)->nodeA0 == NULL) {
        ((RomCurveWalker *)stateBytes)->nodeA0 = NULL;
        return 1;
    }

    if (((RomCurveWalker *)stateBytes)->reverse == 0) {
        nextId = RomCurve_getControlPointId_2A(currentCurve, -1, -1);
    } else {
        nextId = RomCurve_getControlPointId_2B(currentCurve, -1, -1);
    }
    if (nextId == -1) {
        return 1;
    }

    nextCurve = Objfsa_FindRomCurveById(nextId);
    *(s32 *)&((RomCurveWalker *)stateBytes)->nodeA4 = nextCurve;
    if (((RomCurveWalker *)stateBytes)->nodeA4 == NULL) {
        ((RomCurveWalker *)stateBytes)->nodeA4 = NULL;
        return 1;
    }

    ROMCURVE_REFRESH_CONTROL(0xa4);
    if (RomCurve_goNextPoint(state) != 0) {
        return 1;
    }

    ((RomCurveWalker *)stateBytes)->node94 = Curve_EvalHermite;
    ((RomCurveWalker *)stateBytes)->node98 = Curve_BuildHermiteCoeffs;
    ((RomCurveWalker *)stateBytes)->unk84 = stateBytes + 0xa8;
    ((RomCurveWalker *)stateBytes)->unk88 = stateBytes + 0xc8;
    ((RomCurveWalker *)stateBytes)->unk8C = stateBytes + 0xe8;
    ((RomCurveWalker *)stateBytes)->moveNetwork = 8;
    curvesMove(state);
    return 0;
}

int RomCurve_get(float *state, int obj, int *curveTypes, int curveType, f32 maxDistance)
{
    char *stateBytes;
    int curveId;
    int currentCurve;
    int nextId;
    int nextCurve;
    int distanceCurve;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 distance;
    f32 t;

    if (state == NULL) {
        return 1;
    }

    stateBytes = (char *)state;
    curveId = ((int (*)(int, int *, int, int, char))curves_findNearObj)(obj, curveTypes, 1, curveType, 0xc);
    if (curveId == -1) {
        return 1;
    }

    if (((RomCurveWalker *)stateBytes)->reverse != 0) {
        currentCurve = Objfsa_FindRomCurveById(curveId);
        *(s32 *)&((RomCurveWalker *)stateBytes)->nodeA0 = currentCurve;
        nextId = RomCurve_getControlPointId_2A(currentCurve, -1, -1);
        if (nextId == -1) {
            return 1;
        }
        curveId = nextId;
    }

    currentCurve = Objfsa_FindRomCurveById(curveId);
    *(s32 *)&((RomCurveWalker *)stateBytes)->nodeA0 = currentCurve;
    if (((RomCurveWalker *)stateBytes)->nodeA0 == NULL) {
        ((RomCurveWalker *)stateBytes)->nodeA0 = NULL;
        return 1;
    }

    if (((RomCurveWalker *)stateBytes)->reverse == 0) {
        nextId = RomCurve_getControlPointId_2A(currentCurve, -1, -1);
    } else {
        nextId = RomCurve_getControlPointId_2B(currentCurve, -1, -1);
    }
    if (nextId == -1) {
        return 1;
    }

    nextCurve = Objfsa_FindRomCurveById(nextId);
    *(s32 *)&((RomCurveWalker *)stateBytes)->nodeA4 = nextCurve;
    if (((RomCurveWalker *)stateBytes)->nodeA4 == NULL) {
        ((RomCurveWalker *)stateBytes)->nodeA4 = NULL;
        return 1;
    }

    if (maxDistance != gFloatZero) {
        if (((RomCurveWalker *)stateBytes)->reverse != 0) {
            distanceCurve = *(s32 *)&((RomCurveWalker *)stateBytes)->nodeA4;
        } else {
            distanceCurve = *(s32 *)&((RomCurveWalker *)stateBytes)->nodeA0;
        }
        dx = *(f32 *)(distanceCurve + 0x8) - ((GameObject *)obj)->anim.localPosX;
        dy = *(f32 *)(distanceCurve + 0xc) - ((GameObject *)obj)->anim.localPosY;
        dz = *(f32 *)(distanceCurve + 0x10) - ((GameObject *)obj)->anim.localPosZ;
        distance = sqrtf(dx * dx + dy * dy + dz * dz);
        if (distance > maxDistance) {
            return 1;
        }
    }

    ROMCURVE_REFRESH_CONTROL(0xa4);
    if (RomCurve_goNextPoint(state) != 0) {
        return 1;
    }

    ((RomCurveWalker *)stateBytes)->node94 = Curve_EvalHermite;
    ((RomCurveWalker *)stateBytes)->node98 = Curve_BuildHermiteCoeffs;
    ((RomCurveWalker *)stateBytes)->unk84 = stateBytes + 0xa8;
    ((RomCurveWalker *)stateBytes)->unk88 = stateBytes + 0xc8;
    ((RomCurveWalker *)stateBytes)->unk8C = stateBytes + 0xe8;
    ((RomCurveWalker *)stateBytes)->moveNetwork = 8;
    curvesMove(state);
    return 0;
}

int RomCurve_func1C(u32 startCurve, int unused1, int unused2, int *previousCurveId)
{
    int startIndex;
    int candidateCount;
    u32 cur;
    int directSlot;
    int directLinkId;
    u32 directCurve;
    int directIndex;
    int queueCount;
    int queueIndex;
    int queueCurve;
    int linkSlot;
    int linkId;
    int linkCurve;
    int linkIndex;
    int insertIndex;
    int selectedIndex;
    int i;
    int j;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 distance;
    f32 linkDistance;
    f32 candidateDistances[4];
    int candidateIds[4];
    f32 queueDistances[40];
    int queueIndices[40];
    u8 visited[0x514];

    if (startCurve == 0) {
        return -1;
    }
    if (RomCurve_findByIdWithIndex(*(s32 *)(startCurve + 0x14), &startIndex) == 0) {
        return -1;
    }

    candidateCount = 0;
    cur = startCurve;
    for (directSlot = 0; directSlot < 4; directSlot++, cur += 4) {
        directLinkId = *(s32 *)(cur + 0x1c);
        if (directLinkId <= -1) {
            continue;
        }

        for (i = 0; i < 0x514; i++) {
            visited[i] = 0;
        }
        visited[startIndex] = 1;

        directCurve = (u32)RomCurve_findByIdWithIndex(*(s32 *)(cur + 0x1c), &directIndex);
        if (directCurve == 0) {
            continue;
        }

        dx = *(f32 *)(directCurve + 0x10) - *(f32 *)(startCurve + 0x10);
        dy = *(f32 *)(directCurve + 0x8) - *(f32 *)(startCurve + 0x8);
        dz = *(f32 *)(directCurve + 0xc) - *(f32 *)(startCurve + 0xc);
        queueDistances[0] = dx * dx + dy * dy + dz * dz;
        queueIndices[0] = directIndex;
        visited[directIndex] = 1;
        queueCount = 1;

        while (queueCount > 0) {
            queueCount--;
            queueIndex = queueIndices[queueCount];
            queueCurve = (int)romCurves[queueIndex];
            distance = queueDistances[queueCount];

            if (*(u8 *)(queueCurve + 0x34) == 1) {
                candidateDistances[candidateCount] = distance;
                candidateIds[candidateCount] = directLinkId;
                candidateCount++;
                break;
            }

            for (linkSlot = 0; linkSlot < 4; linkSlot++) {
                linkId = *(s32 *)(queueCurve + 0x1c + linkSlot * 4);
                if (linkId <= -1) {
                    continue;
                }

                linkCurve = (int)RomCurve_findByIdWithIndex(linkId, &linkIndex);
                if (linkCurve == 0 || visited[linkIndex] != 0 || queueCount >= 0x28) {
                    continue;
                }

                dx = *(f32 *)(queueCurve + 0x10) - *(f32 *)(linkCurve + 0x10);
                dy = *(f32 *)(queueCurve + 0x8) - *(f32 *)(linkCurve + 0x8);
                dz = *(f32 *)(queueCurve + 0xc) - *(f32 *)(linkCurve + 0xc);
                linkDistance = distance + dx * dx + dy * dy + dz * dz;

                insertIndex = 0;
                while (insertIndex < queueCount && queueDistances[insertIndex] > linkDistance) {
                    insertIndex++;
                }
                for (j = queueCount; j > insertIndex; j--) {
                    queueIndices[j] = queueIndices[j - 1];
                    queueDistances[j] = queueDistances[j - 1];
                }
                queueIndices[insertIndex] = linkIndex;
                queueDistances[insertIndex] = linkDistance;
                visited[linkIndex] = 1;
                queueCount++;
            }
        }
    }

    if (candidateCount == 0) {
        return -1;
    }
    if (candidateCount == 1) {
        *previousCurveId = *(s32 *)(startCurve + 0x14);
        return candidateIds[0];
    }

    for (i = 0; i < candidateCount; i++) {
        if (*previousCurveId == candidateIds[i]) {
            for (j = i; j < candidateCount - 1; j++) {
                candidateIds[j] = candidateIds[j + 1];
                candidateDistances[j] = candidateDistances[j + 1];
            }
            candidateCount--;
            i--;
        }
    }

    if (candidateCount <= 0) {
        return -1;
    }

    *previousCurveId = *(s32 *)(startCurve + 0x14);
    selectedIndex = 0;
    for (i = 0; i < candidateCount; i++) {
        if (candidateDistances[i] < candidateDistances[selectedIndex]) {
            selectedIndex = i;
        }
    }
    return candidateIds[selectedIndex];
}

/* RomCurve_stepClamped: keep the curve phase just inside the endpoints, then advance it. */
#pragma peephole on
void RomCurve_stepClamped(float *state, f32 dt) {
    if (*state <= lbl_803E05F0) {
        *state = lbl_803E05F4;
    } else if (*state >= lbl_803E05C8) {
        *state = lbl_803E05CC;
    }
    Curve_AdvanceAlongPath(state, dt);
}


extern int curveFn_800da23c(float *state, void *targetCurve);

#pragma peephole off
int curveFn_800da23c(float *state,void *targetCurve)
{
    char *stateBytes;

    stateBytes = (char *)state;
    if (((RomCurveWalker *)stateBytes)->nodeA0 == NULL ||
        ((RomCurveWalker *)stateBytes)->nodeA4 == NULL ||
        targetCurve == NULL) {
        return 1;
    }

    ((RomCurveWalker *)stateBytes)->node9C = ((RomCurveWalker *)stateBytes)->nodeA0;
    ((RomCurveWalker *)stateBytes)->nodeA0 = ((RomCurveWalker *)stateBytes)->nodeA4;
    ((RomCurveWalker *)stateBytes)->nodeA4 = targetCurve;

    if (((RomCurveWalker *)stateBytes)->reverse != 0) {
        memcpy(stateBytes + 0xb8,stateBytes + 0xa8,0x10);
        memcpy(stateBytes + 0xd8,stateBytes + 0xc8,0x10);
        memcpy(stateBytes + 0xf8,stateBytes + 0xe8,0x10);

        ((RomCurveWalker *)stateBytes)->hermX[0] = *(f32 *)((char *)((RomCurveWalker *)stateBytes)->nodeA4 + 0x8);
        ((RomCurveWalker *)stateBytes)->hermX[1] = *(f32 *)((char *)((RomCurveWalker *)stateBytes)->nodeA0 + 0x8);
        ((RomCurveWalker *)stateBytes)->hermX[2] =
            RomCurveNode_GetHermiteTangent(((RomCurveWalker *)stateBytes)->nodeA4,0x2c,0);
        ((RomCurveWalker *)stateBytes)->hermX[3] =
            RomCurveNode_GetHermiteTangent(((RomCurveWalker *)stateBytes)->nodeA0,0x2c,0);

        ((RomCurveWalker *)stateBytes)->hermY[0] = *(f32 *)((char *)((RomCurveWalker *)stateBytes)->nodeA4 + 0xc);
        ((RomCurveWalker *)stateBytes)->hermY[1] = *(f32 *)((char *)((RomCurveWalker *)stateBytes)->nodeA0 + 0xc);
        ((RomCurveWalker *)stateBytes)->hermY[2] =
            RomCurveNode_GetHermiteTangent(((RomCurveWalker *)stateBytes)->nodeA4,0x2d,0);
        ((RomCurveWalker *)stateBytes)->hermY[3] =
            RomCurveNode_GetHermiteTangent(((RomCurveWalker *)stateBytes)->nodeA0,0x2d,0);

        ((RomCurveWalker *)stateBytes)->hermZ[0] = *(f32 *)((char *)((RomCurveWalker *)stateBytes)->nodeA4 + 0x10);
        ((RomCurveWalker *)stateBytes)->hermZ[1] = *(f32 *)((char *)((RomCurveWalker *)stateBytes)->nodeA0 + 0x10);
        ((RomCurveWalker *)stateBytes)->hermZ[2] =
            RomCurveNode_GetHermiteTangent(((RomCurveWalker *)stateBytes)->nodeA4,0x2c,1);
        ((RomCurveWalker *)stateBytes)->hermZ[3] =
            RomCurveNode_GetHermiteTangent(((RomCurveWalker *)stateBytes)->nodeA0,0x2c,1);

        if (((RomCurveWalker *)stateBytes)->moveNetwork != 0) {
            curvesSetupMoveNetworkCurve(state);
            if (*state <= lbl_803E05F0) {
                *state = lbl_803E05F4;
            }
        }
    } else {
        memcpy(stateBytes + 0xa8,stateBytes + 0xb8,0x10);
        memcpy(stateBytes + 0xc8,stateBytes + 0xd8,0x10);
        memcpy(stateBytes + 0xe8,stateBytes + 0xf8,0x10);

        ((RomCurveWalker *)stateBytes)->hermX2[0] = *(f32 *)((char *)((RomCurveWalker *)stateBytes)->nodeA0 + 0x8);
        ((RomCurveWalker *)stateBytes)->hermX2[1] = *(f32 *)((char *)((RomCurveWalker *)stateBytes)->nodeA4 + 0x8);
        ((RomCurveWalker *)stateBytes)->hermX2[2] =
            RomCurveNode_GetHermiteTangent(((RomCurveWalker *)stateBytes)->nodeA0,0x2c,0);
        ((RomCurveWalker *)stateBytes)->hermX2[3] =
            RomCurveNode_GetHermiteTangent(((RomCurveWalker *)stateBytes)->nodeA4,0x2c,0);

        ((RomCurveWalker *)stateBytes)->hermY2[0] = *(f32 *)((char *)((RomCurveWalker *)stateBytes)->nodeA0 + 0xc);
        ((RomCurveWalker *)stateBytes)->hermY2[1] = *(f32 *)((char *)((RomCurveWalker *)stateBytes)->nodeA4 + 0xc);
        ((RomCurveWalker *)stateBytes)->hermY2[2] =
            RomCurveNode_GetHermiteTangent(((RomCurveWalker *)stateBytes)->nodeA0,0x2d,0);
        ((RomCurveWalker *)stateBytes)->hermY2[3] =
            RomCurveNode_GetHermiteTangent(((RomCurveWalker *)stateBytes)->nodeA4,0x2d,0);

        ((RomCurveWalker *)stateBytes)->hermZ2[0] = *(f32 *)((char *)((RomCurveWalker *)stateBytes)->nodeA0 + 0x10);
        ((RomCurveWalker *)stateBytes)->hermZ2[1] = *(f32 *)((char *)((RomCurveWalker *)stateBytes)->nodeA4 + 0x10);
        ((RomCurveWalker *)stateBytes)->hermZ2[2] =
            RomCurveNode_GetHermiteTangent(((RomCurveWalker *)stateBytes)->nodeA0,0x2c,1);
        ((RomCurveWalker *)stateBytes)->hermZ2[3] =
            RomCurveNode_GetHermiteTangent(((RomCurveWalker *)stateBytes)->nodeA4,0x2c,1);

        if (((RomCurveWalker *)stateBytes)->moveNetwork != 0) {
            curvesSetupMoveNetworkCurve(state);
            if (*state >= lbl_803E05C8) {
                *state = lbl_803E05CC;
            }
        }
    }

    return 0;
}

#pragma peephole on
int fn_800DA980(float *state,void *fromCurve,void *toCurve,void *targetCurve)
{
    char *stateBytes;

    stateBytes = (char *)state;
    ((RomCurveWalker *)stateBytes)->nodeA0 = fromCurve;
    ((RomCurveWalker *)stateBytes)->nodeA4 = toCurve;

    if (((RomCurveWalker *)stateBytes)->reverse != 0) {
        ((RomCurveWalker *)stateBytes)->hermX[0] = *(f32 *)((char *)toCurve + 0x8);
        ((RomCurveWalker *)stateBytes)->hermX[1] = *(f32 *)((char *)fromCurve + 0x8);
        ((RomCurveWalker *)stateBytes)->hermX[2] = RomCurveNode_GetHermiteTangent(toCurve,0x2c,0);
        ((RomCurveWalker *)stateBytes)->hermX[3] = RomCurveNode_GetHermiteTangent(fromCurve,0x2c,0);

        ((RomCurveWalker *)stateBytes)->hermY[0] = *(f32 *)((char *)toCurve + 0xc);
        ((RomCurveWalker *)stateBytes)->hermY[1] = *(f32 *)((char *)fromCurve + 0xc);
        ((RomCurveWalker *)stateBytes)->hermY[2] = RomCurveNode_GetHermiteTangent(toCurve,0x2d,0);
        ((RomCurveWalker *)stateBytes)->hermY[3] = RomCurveNode_GetHermiteTangent(fromCurve,0x2d,0);

        ((RomCurveWalker *)stateBytes)->hermZ[0] = *(f32 *)((char *)toCurve + 0x10);
        ((RomCurveWalker *)stateBytes)->hermZ[1] = *(f32 *)((char *)fromCurve + 0x10);
        ((RomCurveWalker *)stateBytes)->hermZ[2] = RomCurveNode_GetHermiteTangent(toCurve,0x2c,1);
        ((RomCurveWalker *)stateBytes)->hermZ[3] = RomCurveNode_GetHermiteTangent(fromCurve,0x2c,1);
    } else {
        ((RomCurveWalker *)stateBytes)->hermX2[0] = *(f32 *)((char *)fromCurve + 0x8);
        ((RomCurveWalker *)stateBytes)->hermX2[1] = *(f32 *)((char *)toCurve + 0x8);
        ((RomCurveWalker *)stateBytes)->hermX2[2] = RomCurveNode_GetHermiteTangent(fromCurve,0x2c,0);
        ((RomCurveWalker *)stateBytes)->hermX2[3] = RomCurveNode_GetHermiteTangent(toCurve,0x2c,0);

        ((RomCurveWalker *)stateBytes)->hermY2[0] = *(f32 *)((char *)fromCurve + 0xc);
        ((RomCurveWalker *)stateBytes)->hermY2[1] = *(f32 *)((char *)toCurve + 0xc);
        ((RomCurveWalker *)stateBytes)->hermY2[2] = RomCurveNode_GetHermiteTangent(fromCurve,0x2d,0);
        ((RomCurveWalker *)stateBytes)->hermY2[3] = RomCurveNode_GetHermiteTangent(toCurve,0x2d,0);

        ((RomCurveWalker *)stateBytes)->hermZ2[0] = *(f32 *)((char *)fromCurve + 0x10);
        ((RomCurveWalker *)stateBytes)->hermZ2[1] = *(f32 *)((char *)toCurve + 0x10);
        ((RomCurveWalker *)stateBytes)->hermZ2[2] = RomCurveNode_GetHermiteTangent(fromCurve,0x2c,1);
        ((RomCurveWalker *)stateBytes)->hermZ2[3] = RomCurveNode_GetHermiteTangent(toCurve,0x2c,1);
    }

    if (curveFn_800da23c(state,targetCurve) != 0) {
        return 1;
    }

    ((RomCurveWalker *)stateBytes)->node94 = Curve_EvalHermite;
    ((RomCurveWalker *)stateBytes)->node98 = Curve_BuildHermiteCoeffs;
    *(float **)&((RomCurveWalker *)stateBytes)->unk84 = (float *)(stateBytes + 0xa8);
    *(float **)&((RomCurveWalker *)stateBytes)->unk88 = (float *)(stateBytes + 0xc8);
    *(float **)&((RomCurveWalker *)stateBytes)->unk8C = (float *)(stateBytes + 0xe8);
    ((RomCurveWalker *)stateBytes)->moveNetwork = 8;
    curvesMove(state);
    return 0;
}

extern f32 lbl_803E05F8;

#pragma peephole off
void *Objfsa_FindNearestCurveType24(int pos, int p4_filter, int p5_filter) {
    int count;
    int *hit;
    int *bestHit;
    int **list = (int **)(*gRomCurveInterface)->getCurves(&count);
    f32 minDist = lbl_803E05F8;
    int i;
    bestHit = 0;
    for (i = count; i > 0; i--) {
        hit = *list;
        if (hit != 0
            && (s8)*((u8 *)hit + 0x19) == 0x24
            && (p4_filter == -1 || *((u8 *)hit + 3) == p4_filter)
            && (p5_filter == -1 || (s8)*((u8 *)hit + 0x1A) == p5_filter)) {
            f32 dx = *(f32 *)pos - *(f32 *)((char *)hit + 8);
            f32 dy = *(f32 *)(pos + 4) - *(f32 *)((char *)hit + 0xC);
            f32 d;
            f32 dz = *(f32 *)(pos + 8) - *(f32 *)((char *)hit + 0x10);
            d = dy * dy;
            d += dx * dx;
            d += dz * dz;
            if (d < minDist) {
                minDist = d;
                bestHit = hit;
            }
        }
        list++;
    }
    return bestHit;
}

void *Objfsa_FindNearestEnabledCurveType24(int pos, int p4_filter, int p5_filter) {
    int count;
    int **list;
    int i;
    int *hit;
    int *bestHit;
    s16 gbId;
    f32 minDist;
    int **tmp = (int **)(*gRomCurveInterface)->getCurves(&count);
    minDist = lbl_803E05F8;
    bestHit = 0;
    i = 0;
    list = tmp;
    for (; i < count; i++) {
        hit = *list;
        if (hit != 0
            && (s8)*((u8 *)hit + 0x19) == 0x24
            && (p4_filter == -1 || *((u8 *)hit + 3) == p4_filter)
            && (p5_filter == -1 || (s8)*((u8 *)hit + 0x1A) == p5_filter)) {
            gbId = *(s16 *)((char *)hit + 0x30);
            if (gbId == -1 || GameBit_Get(gbId) != 0) {
                gbId = *(s16 *)((char *)hit + 0x32);
                if (gbId == -1 || GameBit_Get(gbId) == 0) {
                    f32 dx = *(f32 *)pos - *(f32 *)((char *)hit + 8);
                    f32 dy = *(f32 *)(pos + 4) - *(f32 *)((char *)hit + 0xC);
                    f32 d;
                    f32 dz = *(f32 *)(pos + 8) - *(f32 *)((char *)hit + 0x10);
                    d = dy * dy;
                    d += dx * dx;
                    d += dz * dz;
                    if (d < minDist) {
                        minDist = d;
                        bestHit = hit;
                    }
                }
            }
        }
        list++;
    }
    return bestHit;
}




extern void mapBlockFn_80059c2c(u8 *outFlags);
extern f32 lbl_803E0600;
extern f32 lbl_803E0604;
extern f32 lbl_803E05FC;

extern f32 lbl_803E0608;
extern f32 lbl_803E060C;
extern char sObjfsaMissingPatchExitPoint0[];
extern char sObjfsaMissingPatchExitPoint1[];

#define OBJFSA_CORNER(BASE, OFF, POSOFF)                                        \
    (f32)((f32)*(s8 *)(OFF) * scale + *(f32 *)((BASE) + (POSOFF)))

#define OBJFSA_SET_PLANE(P, K, XA, ZA)                                          \
    len = sqrtf(dxn * dxn + dzn * dzn);                                         \
    if (len != lbl_803E05F0) {                                                  \
        dxn = dxn / len;                                                        \
        dzn = dzn / len;                                                        \
    }                                                                           \
    (P).planes[K].normalX = (s16)(lbl_803E05FC * dxn);                          \
    (P).planes[K].normalZ = (s16)(lbl_803E05FC * dzn);                          \
    (P).planeOffsets[K] = -((f32)(P).planes[K].normalX * (XA) +                 \
                            (f32)(P).planes[K].normalZ * (ZA))

#define OBJFSA_WG(GRP) ((ObjfsaWalkGroup *)((char *)patchBase + (GRP) * OBJFSA_PATCHGROUP_STRIDE + 0x3000))

#define OBJFSA_EXIT_INSIDE(GRP, XF, ZF)                                         \
    ez = (f32)(ZF);                                                             \
    ex = (f32)(XF);                                                             \
    j2 = 0;                                                                     \
    for (e = 0; e < 4; e++) {                                                   \
        if (lbl_803E05F0 <                                                      \
            OBJFSA_WG(GRP)->planeOffsets[e] +                                   \
                ex * (f32)((s16 *)OBJFSA_WG(GRP))[j2 & 0xff] +                  \
                ez * (f32)((s16 *)OBJFSA_WG(GRP))[(j2 & 0xff) + 1]) {           \
            break;                                                              \
        }                                                                       \
        j2 += 2;                                                                \
    }

#define OBJFSA_NEWPATCH (patchBase[lbl_803DD468])

void walkgroupFindExitPointFn_800dc398(void)
{
    ObjfsaPatch *patchBase = lbl_8039CAE8;
    u8 blockFlags[0x78];
    u8 pairs[364];
    int flagIndex;
    int checksum;
    int curveCount;
    int **curveList;
    int **listWalk;
    int listIndex;
    int curve;
    int linked;
    int slot;
    int back;
    int myId;
    int npi;
    int iter;
    int pi;
    uint gi;
    u8 ga;
    u8 gb;
    u8 e;
    uint j2;
    u16 pairId;
    u8 found;
    int searchCount;
    ObjfsaWalkGroup *wg;
    ObjfsaPatch *p;
    ObjfsaPatch *sp;
    u8 *pp;
    char *slotPtr;
    char *lp;
    f32 scale;
    f32 fdx;
    f32 fdz;
    f32 div;
    f32 dxn;
    f32 dzn;
    f32 len;
    f32 ex;
    f32 ez;
    f32 z1;
    f32 x1;
    f32 x0;
    f32 z0;
    f32 x2;
    f32 z2;
    f32 x3;
    f32 z3;
    f32 fy0;
    f32 fy1;

    mapBlockFn_80059c2c(blockFlags);

    checksum = 1;
    for (flagIndex = 0; flagIndex < 120; flagIndex++) {
        if (blockFlags[flagIndex] != 0) {
            checksum *= flagIndex;
        }
    }

    if ((u32)checksum != (u32)lbl_803DD460) {
        lbl_803DD460 = checksum;
        scale = lbl_803E0600;
        if (blockFlags[2] == 0 && blockFlags[0x34] == 0) {
            scale = lbl_803E0604;
        }

        curveList = (int **)(*gRomCurveInterface)->getCurves(&curveCount);
        memset((char *)patchBase + OBJFSA_ACTIVE_WALKGROUPS_OFFSET, 0, OBJFSA_WALKGROUP_COUNT);
        sp = patchBase;
        for (pi = 8; pi != 0; pi--) {
            sp[0].groupId = 0;
            sp[1].groupId = 0;
            sp[2].groupId = 0;
            sp[3].groupId = 0;
            sp[4].groupId = 0;
            sp[5].groupId = 0;
            sp[6].groupId = 0;
            sp[7].groupId = 0;
            sp[8].groupId = 0;
            sp[9].groupId = 0;
            sp[10].groupId = 0;
            sp[11].groupId = 0;
            sp[12].groupId = 0;
            sp[13].groupId = 0;
            sp[14].groupId = 0;
            sp[15].groupId = 0;
            sp[16].groupId = 0;
            sp[17].groupId = 0;
            sp[18].groupId = 0;
            sp[19].groupId = 0;
            sp[20].groupId = 0;
            sp[21].groupId = 0;
            sp[22].groupId = 0;
            sp[23].groupId = 0;
            sp[24].groupId = 0;
            sp[25].groupId = 0;
            sp[26].groupId = 0;
            sp[27].groupId = 0;
            sp[28].groupId = 0;
            sp[29].groupId = 0;
            sp[30].groupId = 0;
            sp[31].groupId = 0;
            sp += 32;
        }

        lbl_803DD468 = 1;
        listWalk = curveList;
        for (listIndex = 0; listIndex < curveCount; listIndex++) {
            curve = (int)*listWalk;
            if (*(s8 *)(curve + 0x19) == 0x26) {
                gi = *(u8 *)(curve + 3);
                wg = (ObjfsaWalkGroup *)((char *)patchBase + gi * OBJFSA_PATCHGROUP_STRIDE + 0x3000);
                *((u8 *)patchBase + gi + OBJFSA_ACTIVE_WALKGROUPS_OFFSET) = 1;

                x0 = OBJFSA_CORNER(curve, curve + 0x4, 0x8);
                z0 = OBJFSA_CORNER(curve, curve + 0x5, 0x10);
                x1 = OBJFSA_CORNER(curve, curve + 0x6, 0x8);
                z1 = OBJFSA_CORNER(curve, curve + 0x7, 0x10);

                dxn = z1 - z0;
                dzn = x0 - x1;
                OBJFSA_SET_PLANE(*wg, 0, x0, z0);

                x2 = OBJFSA_CORNER(curve, curve + 0x30, 0x8);
                z2 = OBJFSA_CORNER(curve, curve + 0x31, 0x10);
                dxn = z2 - z1;
                dzn = x1 - x2;
                OBJFSA_SET_PLANE(*wg, 1, x1, z1);

                x3 = OBJFSA_CORNER(curve, curve + 0x32, 0x8);
                z3 = OBJFSA_CORNER(curve, curve + 0x33, 0x10);
                dxn = z3 - z2;
                dzn = x2 - x3;
                OBJFSA_SET_PLANE(*wg, 2, x2, z2);

                dxn = OBJFSA_CORNER(curve, curve + 0x5, 0x10) - z3;
                dzn = x3 - OBJFSA_CORNER(curve, curve + 0x4, 0x8);
                OBJFSA_SET_PLANE(*wg, 3, x3, z3);

                wg->maxY = (s16)(lbl_803E05D0 * (f32)*(s8 *)(curve + 0x18) +
                                 *(f32 *)(curve + 0xc));
                wg->minY = (s16)-(lbl_803E05D0 * (f32)*(s8 *)(curve + 0x1a) -
                                  *(f32 *)(curve + 0xc));

                slotPtr = (char *)curve;
                for (slot = 0; slot < 4; slot++) {
                    wg->patchIndices[slot] = 0;
                    if (*(s32 *)(slotPtr + 0x1c) > -1 &&
                        (linked = (int)(*gRomCurveInterface)->getById(*(s32 *)(slotPtr + 0x1c))) != 0) {
                        ga = *(u8 *)(curve + 3);
                        gb = *(u8 *)(linked + 3);
                        if (ga < gb) {
                            pairId = ((u16)gb << 8) | ga;
                        } else {
                            pairId = ((u16)ga << 8) | gb;
                        }

                        found = 1;
                        sp = &patchBase[1];
                        searchCount = lbl_803DD468 - 1;
                        if (lbl_803DD468 > 1) {
                            do {
                                if (pairId == sp->groupId) {
                                    wg->patchIndices[slot] = found;
                                    break;
                                }
                                sp++;
                                found++;
                                searchCount--;
                            } while (searchCount != 0);
                        }

                        npi = lbl_803DD468;
                        if (wg->patchIndices[slot] == 0) {
                            back = 0;
                            myId = *(s32 *)(curve + 0x14);
                            if (*(s32 *)(linked + 0x1c) != myId &&
                                (back = 1, *(s32 *)(linked + 0x20) != myId) &&
                                (back = 2, *(s32 *)(linked + 0x24) != myId) &&
                                (back = 3, *(s32 *)(linked + 0x28) != myId)) {
                                back = 4;
                            }
                            wg->patchIndices[slot] = (u8)lbl_803DD468;
                            patchBase[npi].groupId = pairId;
                            pairs[npi * 2] = *(u8 *)(curve + 3);
                            pairs[npi * 2 + 1] = *(u8 *)(linked + 3);

                            x0 = OBJFSA_CORNER(curve, slotPtr + 0x34, 0x8);
                            z0 = OBJFSA_CORNER(curve, slotPtr + 0x35, 0x10);
                            x1 = OBJFSA_CORNER(curve, slotPtr + 0x36, 0x8);
                            z1 = OBJFSA_CORNER(curve, slotPtr + 0x37, 0x10);
                            patchBase[npi].exit0X = (s16)((x0 + x1) * lbl_803E0608);
                            patchBase[npi].exit0Z = (s16)((z0 + z1) * lbl_803E0608);

                            dxn = z1 - z0;
                            dzn = x0 - x1;
                            OBJFSA_SET_PLANE(patchBase[npi], 0, x0, z0);

                            lp = (char *)(linked + back * 4);
                            x2 = OBJFSA_CORNER(linked, lp + 0x34, 0x8);
                            z2 = OBJFSA_CORNER(linked, lp + 0x35, 0x10);
                            dxn = z2 - z1;
                            dzn = x1 - x2;
                            OBJFSA_SET_PLANE(OBJFSA_NEWPATCH, 1, x1, z1);

                            x3 = OBJFSA_CORNER(linked, lp + 0x36, 0x8);
                            z3 = OBJFSA_CORNER(linked, lp + 0x37, 0x10);
                            OBJFSA_NEWPATCH.exit1X = (s16)((x2 + x3) * lbl_803E0608);
                            OBJFSA_NEWPATCH.exit1Z = (s16)((z2 + z3) * lbl_803E0608);

                            dxn = z3 - z2;
                            dzn = x2 - x3;
                            OBJFSA_SET_PLANE(OBJFSA_NEWPATCH, 2, x2, z2);

                            dxn = OBJFSA_CORNER(curve, slotPtr + 0x35, 0x10) - z3;
                            dzn = x3 - OBJFSA_CORNER(curve, slotPtr + 0x34, 0x8);
                            OBJFSA_SET_PLANE(OBJFSA_NEWPATCH, 3, x3, z3);

                            fy0 = lbl_803E05D0 * (f32)*(s8 *)(curve + 0x18) +
                                  *(f32 *)(curve + 0xc);
                            fy1 = lbl_803E05D0 * (f32)*(s8 *)(linked + 0x18) +
                                  *(f32 *)(linked + 0xc);
                            if (fy0 <= fy1) {
                                OBJFSA_NEWPATCH.maxY = (s16)fy1;
                            } else {
                                OBJFSA_NEWPATCH.maxY = (s16)fy0;
                            }
                            fy0 = -(lbl_803E05D0 * (f32)*(s8 *)(curve + 0x1a) -
                                    *(f32 *)(curve + 0xc));
                            fy1 = -(lbl_803E05D0 * (f32)*(s8 *)(linked + 0x1a) -
                                    *(f32 *)(linked + 0xc));
                            if (fy1 <= fy0) {
                                OBJFSA_NEWPATCH.minY = (s16)fy1;
                            } else {
                                OBJFSA_NEWPATCH.minY = (s16)fy0;
                            }
                            lbl_803DD468++;
                        }
                    }
                    slotPtr += 4;
                }
            }
            listWalk++;
        }

        pp = pairs;
        div = lbl_803E060C;
        p = patchBase;
        for (pi = 1; pp += 2, pi < lbl_803DD468; pi++) {
            ga = pp[0];
            gb = pp[1];
            fdx = (f32)(p[1].exit1X - p[1].exit0X);
            fdz = (f32)(p[1].exit1Z - p[1].exit0Z);

            iter = 0;
            do {
                OBJFSA_EXIT_INSIDE(ga, p[1].exit0X, p[1].exit0Z);
                if (e == 4) goto exit0Done;
                OBJFSA_EXIT_INSIDE(gb, p[1].exit0X, p[1].exit0Z);
                if (e == 4) goto exit0Done;
                p[1].exit0X = (s16)((f32)p[1].exit0X + fdx / div);
                p[1].exit0Z = (s16)((f32)p[1].exit0Z + fdz / div);
            } while (iter++ != 100);
            OSReport(sObjfsaMissingPatchExitPoint0, p[1].groupId & 0xff,
                     (int)(uint)p[1].groupId >> 8);
exit0Done:
            iter = 0;
            do {
                OBJFSA_EXIT_INSIDE(ga, p[1].exit1X, p[1].exit1Z);
                if (e == 4) goto exit1Done;
                OBJFSA_EXIT_INSIDE(gb, p[1].exit1X, p[1].exit1Z);
                if (e == 4) goto exit1Done;
                p[1].exit1X = (s16)((f32)p[1].exit1X - fdx / div);
                p[1].exit1Z = (s16)((f32)p[1].exit1Z - fdz / div);
            } while (iter++ != 100);
            OSReport(sObjfsaMissingPatchExitPoint1, p[1].groupId & 0xff,
                     (int)(uint)p[1].groupId >> 8);
exit1Done:
            p++;
        }
    }
}

int RomCurve_func1B(double x, double y, double z, int curve, int preferredNeighborId) {
    float bestDistances[2];
    int bestNeighborIds[2];
    RomCurveSegmentProjection segment;
    int i;
    int neighborId;
    int neighborCurve;
    int slot;
    float dx;
    float dy;
    float dz;
    float distance;

    bestNeighborIds[1] = -1;
    bestNeighborIds[0] = -1;
    bestDistances[1] = lbl_803E0644;
    bestDistances[0] = lbl_803E0644;

    segment.startX = *(f32 *)(curve + 0x8);
    segment.startY = *(f32 *)(curve + 0xc);
    segment.startZ = *(f32 *)(curve + 0x10);

    for (i = 0; i < 4; i++) {
        neighborId = *(int *)(curve + 0x1c + i * 4);
        if (neighborId > -1) {
            neighborCurve = Objfsa_FindRomCurveById(neighborId);
            if (neighborCurve != 0) {
                segment.endX = *(f32 *)(neighborCurve + 0x8);
                segment.endY = *(f32 *)(neighborCurve + 0xc);
                segment.endZ = *(f32 *)(neighborCurve + 0x10);

                RomCurve_distanceToSegment(x, y, z, &segment);
                dx = segment.nearestX - x;
                dy = segment.nearestY - y;
                dz = segment.nearestZ - z;
                distance = dz * dz + dx * dx + dy * dy;
                slot = (preferredNeighborId == neighborId);
                if (distance < bestDistances[slot]) {
                    bestDistances[slot] = distance;
                    bestNeighborIds[slot] = neighborId;
                }
            }
        }
    }

    if (bestNeighborIds[0] != -1) {
        return bestNeighborIds[0];
    }
    if (bestNeighborIds[1] != -1) {
        return bestNeighborIds[1];
    }
    return -1;
}

int RomCurve_func16(double x, double y, double z) {
    u32 candidateIds[24];
    int candidateCount;
    int i;
    int curve;
    int *curveList;
    int out;
    int category;
    int currentCurve;
    u32 *top;
    int *p;
    u32 *end;

    candidateCount = 0;
    curveList = (int *)romCurves;
    for (i = 0; i < nRomCurves && candidateCount < 20; i++) {
        curve = *curveList;
        if (*(s8 *)(curve + 0x19) == 0x17) {
            candidateIds[candidateCount++] = *(u32 *)(curve + 0x14);
        }
        curveList++;
    }

    while (candidateCount != 0) {
        top = &candidateIds[candidateCount];
        if (curves_distFn15(x, y, z, candidateIds[0], &out) != 0) {
            return candidateIds[0];
        }

        currentCurve = Objfsa_FindRomCurveById(candidateIds[0]);
        category = *(s8 *)(currentCurve + 0x18);
        i = 0;
        p = (int *)candidateIds;
        end = top;
        while (i < candidateCount) {
            currentCurve = Objfsa_FindRomCurveById(*p);
            if (*(s8 *)(currentCurve + 0x18) == category) {
                candidateCount--;
                end--;
                *p = *end;
            } else {
                i++;
                p++;
            }
        }
    }

    return -1;
}

/* UIController dispatch through the shared GameUI interface. */
extern u8 gameTimerIsRunning(void *p, int a, int b);
extern void hudNumberFn_80014060(void *p);
extern void gameTimerRun(void *p);
#pragma scheduling on
#pragma peephole on
void UIController_frameStart(void) {
    (*gGameUIInterface)->frameStart();
}
void UIController_frameEnd(void) {
    (*gGameUIInterface)->frameEnd();
}
#pragma scheduling off
#pragma peephole off
void UIController_render(void *p, int a, int b) {
    if (gameTimerIsRunning(p, a, b) != 0) {
        gameTimerRun(p);
    }
    hudNumberFn_80014060(p);
    (*gGameUIInterface)->render(p, a, b);
}

/* player_setState */
void player_setState(void *ctx, void *p, int new_state) {
    void *q;
    if (*(s16 *)((char *)p + 0x274) == new_state) goto end;
    *(s16 *)((char *)p + 0x276) = *(s16 *)((char *)p + 0x274);
    *(s16 *)((char *)p + 0x274) = (s16)new_state;
    {
        void (*fn)(void) = *(void (**)(void))((char *)p + 0x304);
        if (fn != 0) {
            fn();
            *(void **)((char *)p + 0x304) = 0;
        }
    }
    *(void **)((char *)p + 0x304) = *(void **)((char *)p + 0x308);
end:
    *(s16 *)((char *)p + 0x338) = 0;
    *(u8 *)((char *)p + 0x27a) = 1;
    *(u8 *)((char *)p + 0x34d) = 0;
    *(u8 *)((char *)p + 0x34c) = 0;
    *(u8 *)((char *)p + 0x356) = 0;
    *(s16 *)((char *)p + 0x278) = 0;
    q = *(void **)((char *)ctx + 0x54);
    if (q != 0) *(u8 *)((char *)q + 0x70) = 0;
}

/* walkPath_writeU16LE: split a path id into two little-endian bytes. */
void walkPath_writeU16LE(u32 v, u8 *dst) {
    v = v & 0xffff;
    dst[0] = (u8)v;
    dst[1] = (u8)((s32)v >> 8);
}

/* fn_800D9EE8: triple xor swap of 0x9c/0xa4, clamp *p */
#pragma scheduling on
void fn_800D9EE8(float *p) {
    u32 *a = (u32 *)((char *)p + 0x9c);
    u32 *b = (u32 *)((char *)p + 0xa4);
    *a ^= *b;
    *b ^= *a;
    *a ^= *b;
    if (*p >= lbl_803E05C8) {
        *p = lbl_803E05CC;
    }
}


#pragma scheduling off
int fn_800DB240(int p1, f32 *outVec, u16 id)
{
  extern f32 vec3f_distanceSquared(int, int);
  u8 i;
  char *entry;
  f32 d1;

  for (i = 0; i < 256; i++) {
    if (*(u16 *)((char *)lbl_8039CAE8 + (u32)i * 48 + 36) == id) break;
  }

  entry = (char *)lbl_8039CAE8 + (u32)i * 48;

  outVec[0] = (f32)(s32)*(s16 *)(entry + 38);
  outVec[1] = *(f32 *)(p1 + 4);
  outVec[2] = (f32)(s32)*(s16 *)(entry + 40);
  d1 = vec3f_distanceSquared(p1, (int)outVec);

  outVec[0] = (f32)(s32)*(s16 *)(entry + 42);
  outVec[2] = (f32)(s32)*(s16 *)(entry + 44);

  if (vec3f_distanceSquared(p1, (int)outVec) < d1) {
    return 1;
  }

  outVec[0] = (f32)(s32)*(s16 *)(entry + 38);
  outVec[2] = (f32)(s32)*(s16 *)(entry + 40);
  return 1;
}

void fn_800D915C(int p1, int *obj, void *fnTable, f32 fval)
{
    int flag30 = 0;
    int i = 0;
    int done;
    s16 startState;
    int result;
    if (((BaddieState *)obj)->unk270 != ((BaddieState *)obj)->unk272) {
        ((BaddieState *)obj)->moveJustStartedB = 1;
        ((BaddieState *)obj)->unk32E = 0;
    }
    do {
        done = 0;
        startState = ((BaddieState *)obj)->unk270;
        result = ((int (*)(int, int *, f32))((int **)fnTable)[startState])(p1, obj, fval);
        if (result > 0) {
            ((BaddieState *)obj)->unk272 = ((BaddieState *)obj)->unk270;
            ((BaddieState *)obj)->unk270 = result - 1;
            ((BaddieState *)obj)->moveJustStartedB = 1;
            ((BaddieState *)obj)->unk32E = 0;
        } else if (result < 0) {
            result = -result;
            if (result == startState) {
                ((BaddieState *)obj)->moveJustStartedB = 0;
            } else {
                ((BaddieState *)obj)->unk272 = startState;
                ((BaddieState *)obj)->moveJustStartedB = 1;
                ((BaddieState *)obj)->unk32E = 0;
            }
            ((BaddieState *)obj)->unk270 = result;
            done = 1;
            flag30 = 1;
        } else {
            done = 1;
        }
        i++;
        if (i > 0xff) {
            done = 1;
        }
    } while (done == 0);
    ((BaddieState *)obj)->unk272 = ((BaddieState *)obj)->unk270;
    if (flag30 == 0) {
        ((BaddieState *)obj)->moveJustStartedB = 0;
        if ((f32)*(s16 *)((char *)obj + 0x338) > lbl_803E05BC) {
            ((BaddieState *)obj)->moveJustStartedB = 0;
        }
    }
}
