#include "ghidra_import.h"
#include "dolphin/os.h"
#include "main/dll/curves.h"
#include <string.h>


#pragma peephole off
#pragma scheduling off
extern undefined4 FUN_80003494();
extern undefined4 FUN_800068f4();
extern undefined4 FUN_800068f8();
extern uint GameBit_Get(int eventId);
extern void Obj_TransformLocalPointToWorld(f32 x,f32 y,f32 z,f32 *outX,f32 *outY,f32 *outZ,u32 obj);
extern double FUN_80017714();
extern f32 vec3f_distanceSquared(f32 *posA,f32 *posB);
extern int FUN_80017730();
extern s16 getAngle(f32 deltaX,f32 deltaZ);
extern void mtxRotateByVec3s(float *outMtx, short *angles);
extern void Matrix_TransformPoint(float *mtx, double x, double y, double z, float *ox, float *oy, float *oz);
extern void setMatrixFromObjectPos(float *mtx, void *obj);
extern u8 framesThisStep;
extern f32 lbl_803E0668;
extern f32 lbl_803E068C;
extern undefined4 FUN_8001774c();
extern undefined4 FUN_80017754();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017778();
extern int *ObjList_GetObjects(int *startIndex,int *objectCount);
extern int ObjHits_IsObjectEnabled();
extern undefined4 ObjHits_AddContactObject();
extern undefined4 FUN_80061fc8();
extern int FUN_800620e8();
extern int objBboxFn_800640cc(void *hitOut,void *pos,f32 radius,int mode,void *bbox,int obj,
                              int p7,int p8,int p9,int p10);
extern int FUN_800632f4();
extern void fn_80063368(int obj);
extern int hitDetectFn_80065e50(int obj,f32 x,f32 y,f32 z,void *out,int p5,int p6);
extern undefined FUN_80063a68();
extern undefined4 FUN_80063a74();
extern void hitDetectFn_80067958(int obj,void *startPoints,void *endPoints,int pointCount,
                                 void *hitResults,int arg6);
extern undefined4 FUN_800723a0();
extern void PSVECSubtract(f32 *a,f32 *b,f32 *out);
extern f32 PSVECMag(f32 *v);
extern undefined4 FUN_80247eb8();
extern double SeekTwiceBeforeRead();
extern undefined8 FUN_8028680c();
extern undefined8 FUN_80286810();
extern undefined8 FUN_80286828();
extern undefined8 FUN_8028682c();
extern undefined8 FUN_80286830();
extern undefined8 FUN_80286834();
extern undefined8 FUN_80286838();
extern longlong FUN_8028683c();
extern undefined4 FUN_80286858();
extern undefined4 TRKNubMainLoop();
extern undefined4 FUN_80286874();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern double FUN_80293900();
extern f32 sqrtf(f32 x);
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern uint countLeadingZeros();

extern RomCurveDef *romCurves[];
extern RomCurvePoint sCurvesHitPoints[ROMCURVE_GETCURVES_MAX_POINTS];
extern undefined4 DAT_803dc070;
extern RomCurveDef *lbl_803DD470;
extern RomCurveDef *lbl_803DD474;
extern int nRomCurves;
extern u32 sCurvesCachedHitCount;
extern u32 sCurvesCachedHitObj;
extern f64 DOUBLE_803e12a8;
extern f64 DOUBLE_803e12f0;
extern f64 DOUBLE_803e1318;
extern f32 gFloatNegOne;
extern f32 lbl_803E1290;
extern f32 gFloatOne;
extern f32 gFloatZero;
extern f32 gFloatHalf;
extern f32 lbl_803E0644;
extern f32 lbl_803E12B0;
extern f32 lbl_803E12B4;
extern f32 lbl_803E12B8;
extern f32 lbl_803E065C;
extern f32 lbl_803E0660;
extern f32 lbl_803E0664;
extern f32 lbl_803E0678;
extern f32 lbl_803E067C;
extern f32 lbl_803E0680;
extern f32 lbl_803E0684;
extern f32 lbl_803E0688;
extern f32 lbl_803E0690;
extern f32 lbl_803E06A0;
extern f32 lbl_803E06A4;
extern f32 lbl_803E06A8;
extern f32 lbl_803E06AC;
extern f32 lbl_803E06B0;
extern f32 lbl_803E06B4;
extern f32 lbl_803E06B8;
extern f32 lbl_803E06BC;
extern f32 lbl_803E12C4;
extern f32 lbl_803E12D8;
extern f32 lbl_803E12DC;
extern f32 lbl_803E12E4;
extern f32 lbl_803E12E8;
extern f32 lbl_803E12EC;
extern f32 lbl_803E12F8;
extern f32 lbl_803E12FC;
extern f32 lbl_803E1300;
extern f32 lbl_803E1304;
extern f32 lbl_803E1308;
extern f32 lbl_803E130C;
extern f32 lbl_803E1320;
extern f32 lbl_803E1324;
extern f32 lbl_803E1328;
extern f32 lbl_803E132C;
extern f32 lbl_803E1330;
extern f32 lbl_803E1334;
extern f32 lbl_803E1338;
extern f32 lbl_803E133C;
extern f32 lbl_803E1340;
extern char sCurvesMaxRomCurvesExceeded[];

typedef struct CurvesHitScratch {
  u8 unk0[0x40];
  f32 scale;
  u8 unk44[0x10];
  u8 type;
  u8 unk55[0x13];
} CurvesHitScratch;

typedef struct CurvesTransformScratch {
  s16 angles[3];
  s16 pad06;
  f32 scale;
  f32 x;
  f32 y;
  f32 z;
} CurvesTransformScratch;

static inline u32 RomCurve_GetId(RomCurveDef *curve) {
  return curve->id;
}

static inline int RomCurve_IsLinkIdValid(int linkId) {
  return -1 < linkId;
}

static inline RomCurveDef *RomCurve_FindByIdInline(u32 curveId) {
  RomCurveDef *curve;
  int high;
  int low;
  int mid;

  if ((s32)curveId < 0) {
    return NULL;
  }

  high = nRomCurves - 1;
  low = 0;
  while (low <= high) {
    mid = (high + low) >> 1;
    curve = romCurves[mid];
    if (curveId > curve->id) {
      low = mid + 1;
    } else if (curveId < curve->id) {
      high = mid - 1;
    } else {
      return curve;
    }
  }

  return NULL;
}

int RomCurve_segmentIntersectsOriginRayXZ(RomCurveDef *a,RomCurveDef *b,f32 x,f32 unusedY,
                                          f32 z,f32 unusedW);

/*
 * --INFO--
 *
 * Function: RomCurve_projectPointToAdjacentWindow
 * EN v1.0 Address: 0x800E1B24
 * EN v1.0 Size: 1048b
 * EN v1.1 Address: 0x800E1DA8
 * EN v1.1 Size: 1048b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
RomCurve_projectPointToAdjacentWindow(f32 x,f32 y,f32 z,u32 *curveIds,
                                      float *outLateralOffset,float *outVerticalOffset,
                                      float *outPhase)
{
  RomCurveDef *curves[4];
  RomCurveDef *prevCurve;
  RomCurveDef *segmentStart;
  RomCurveDef *segmentEnd;
  RomCurveDef *nextCurve;
  f32 segmentDx;
  f32 segmentDy;
  f32 segmentDz;
  f32 tangentDx;
  f32 tangentDz;
  f32 nextTangentDx;
  f32 nextTangentDz;
  f32 tangentLen;
  f32 nextTangentLen;
  f32 startDenom;
  f32 endDenom;
  f32 startPhase;
  f32 endPhase;
  f32 phase;
  f32 segmentLen;
  f32 lateralX;
  f32 lateralZ;
  int i;

  for (i = 0; i < 4; i++) {
    curves[i] = RomCurve_FindByIdInline(curveIds[i]);
  }

  prevCurve = curves[0];
  segmentStart = curves[1];
  segmentEnd = curves[2];
  nextCurve = curves[3];

  segmentDx = segmentEnd->x - segmentStart->x;
  segmentDz = segmentEnd->z - segmentStart->z;
  tangentDx = segmentDx;
  tangentDz = segmentDz;
  if (prevCurve != NULL) {
    tangentDx = segmentStart->x - prevCurve->x;
    tangentDz = segmentStart->z - prevCurve->z;
  }
  tangentDx = gFloatHalf * (tangentDx + segmentDx);
  tangentDz = gFloatHalf * (tangentDz + segmentDz);
  tangentLen = sqrtf(tangentDx * tangentDx + tangentDz * tangentDz);
  if (tangentLen != gFloatZero) {
    tangentDx = tangentDx / tangentLen;
    tangentDz = tangentDz / tangentLen;
  }

  startDenom = tangentDx * segmentDx + tangentDz * segmentDz;
  startPhase = gFloatZero;
  if (startDenom != gFloatZero) {
    startPhase =
        -(-((tangentDx * segmentStart->x) + (tangentDz * segmentStart->z)) +
          ((tangentDx * x) + (tangentDz * z))) /
        startDenom;
  }

  nextTangentDx = segmentDx;
  nextTangentDz = segmentDz;
  if (nextCurve != NULL) {
    nextTangentDx = nextCurve->x - segmentEnd->x;
    nextTangentDz = nextCurve->z - segmentEnd->z;
  }
  nextTangentDx = gFloatHalf * (nextTangentDx + segmentDx);
  nextTangentDz = gFloatHalf * (nextTangentDz + segmentDz);
  nextTangentLen = sqrtf(nextTangentDx * nextTangentDx + nextTangentDz * nextTangentDz);
  if (nextTangentLen != gFloatZero) {
    nextTangentDx = nextTangentDx / nextTangentLen;
    nextTangentDz = nextTangentDz / nextTangentLen;
  }

  endDenom = nextTangentDx * segmentDx + nextTangentDz * segmentDz;
  endPhase = gFloatZero;
  if (endDenom != gFloatZero) {
    endPhase =
        -(-((nextTangentDx * segmentEnd->x) + (nextTangentDz * segmentEnd->z)) +
          ((nextTangentDx * x) + (nextTangentDz * z))) /
        endDenom;
  }

  phase = -startPhase / (endPhase - startPhase);
  if ((phase < gFloatZero) || (gFloatOne <= phase)) {
    return 0;
  }

  segmentDy = segmentEnd->y - segmentStart->y;
  segmentLen = sqrtf(segmentDz * segmentDz + segmentDx * segmentDx + segmentDy * segmentDy);
  lateralX = segmentDx;
  lateralZ = segmentDz;
  if (gFloatZero < segmentLen) {
    lateralX = -segmentDx * (gFloatOne / segmentLen);
    lateralZ = -segmentDz * (gFloatOne / segmentLen);
  }

  *outLateralOffset = -(((segmentDx * phase + segmentStart->x) * lateralZ) -
                        ((segmentDz * phase + segmentStart->z) * lateralX)) +
                      (x * lateralZ - z * lateralX);
  *outVerticalOffset = y - (segmentDy * phase + segmentStart->y);
  *outPhase = phase;
  return 1;
}

/*
 * --INFO--
 *
 * Function: FUN_800e1b2c
 * EN v1.0 Address: 0x800E1B2C
 * EN v1.0 Size: 212b
 * EN v1.1 Address: 0x800E21C0
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800e1b2c(double param_1,undefined8 param_2,double param_3,int param_4,int param_5)
{
  float fVar1;
  float fVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  
  dVar3 = (double)*(float *)(param_4 + 8);
  dVar5 = (double)*(float *)(param_4 + 0x10);
  dVar4 = (double)*(float *)(param_5 + 8);
  dVar6 = (double)*(float *)(param_5 + 0x10);
  fVar2 = (float)(dVar4 * dVar5 - (double)(float)(dVar3 * dVar6));
  fVar1 = fVar2 + (float)(param_1 * (double)(float)(dVar6 - dVar5) +
                         (double)(float)(param_3 * (double)(float)(dVar3 - dVar4)));
  if (((fVar1 <= lbl_803E12B8) && (lbl_803E12B8 <= fVar2)) ||
     ((lbl_803E12B8 <= fVar1 && (fVar2 < lbl_803E12B8)))) {
    fVar2 = (float)(-param_3 * dVar3 + (double)(float)(param_1 * dVar5));
    fVar1 = (float)(-param_3 * dVar4 + (double)(float)(param_1 * dVar6));
    if (((fVar2 <= lbl_803E12B8) && (lbl_803E12B8 <= fVar1)) ||
       ((lbl_803E12B8 <= fVar2 && (fVar1 < lbl_803E12B8)))) {
      return 1;
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: curves_distFn15
 * EN v1.0 Address: 0x800E1FF4
 * EN v1.0 Size: 536b
 * EN v1.1 Address: 0x800E2278
 * EN v1.1 Size: 544b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int curves_distFn15(u32 curveId,f32 x,f32 y,f32 z,f32 *outDistance)
{
  RomCurveDef *curve;
  RomCurveDef *nextCurve;
  u32 nextCurveId;
  u32 previousCurveId;
  int linkIndex;
  int hitCount;
  f32 dx;
  f32 dy;
  f32 dz;
  f32 distance;

  curve = RomCurve_FindByIdInline(curveId);
  hitCount = 0;
  *outDistance = lbl_803E065C;
  do {
    nextCurveId = ROMCURVE_LINK_ID_NONE;
    linkIndex = 0;
    nextCurve = curve;
    while ((linkIndex < ROMCURVE_LINK_COUNT) && (nextCurveId == ROMCURVE_LINK_ID_NONE)) {
      if ((curve->blockedLinkMask & (1 << linkIndex)) == 0) {
        nextCurveId = nextCurve->linkIds[0];
      }
      nextCurve = (RomCurveDef *)((u8 *)nextCurve + ROMCURVE_LINK_ID_STRIDE);
      linkIndex++;
    }

    nextCurve = curve;
    if (nextCurveId != ROMCURVE_LINK_ID_NONE) {
      nextCurve = RomCurve_FindByIdInline(nextCurveId);
      if (RomCurve_segmentIntersectsOriginRayXZ(curve,nextCurve,x,y,z,lbl_803E0660) != 0) {
        dx = curve->x - x;
        dy = curve->y - y;
        dz = curve->z - z;
        distance = sqrtf(dz * dz + dx * dx + dy * dy);
        if (distance < *outDistance) {
          *outDistance = distance;
        }
        hitCount++;
      }
    }
    previousCurveId = nextCurveId;
    curve = nextCurve;
  } while ((previousCurveId != curveId) && (nextCurveId != ROMCURVE_LINK_ID_NONE));

  return hitCount & 1;
}

/*
 * --INFO--
 *
 * Function: curves_distanceToNearestOfType16
 * EN v1.0 Address: 0x800E2214
 * EN v1.0 Size: 372b
 * EN v1.1 Address: 0x800E2498
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int curves_distanceToNearestOfType16(f32 x,f32 y,f32 z,int param_4)
{
  float dx;
  float dy;
  float dz;
  int *objects;
  int obj;
  RomCurveDef *curve;
  int i;
  float distance;
  double nearestCurveId;
  double nearestDistance;
  int objectCount;
  int startIndex;
  
  objects = ObjList_GetObjects(&startIndex,&objectCount);
  nearestCurveId = (double)lbl_803E12B0;
  nearestDistance = (double)lbl_803E12B8;
  for (i = 0; i < objectCount; i = i + 1) {
    obj = objects[i];
    if ((((*(short *)(obj + 0x44) == 0x2c) && (*(char *)(obj + 0xac) != param_4)) &&
        (curve = *(RomCurveDef **)(obj + 0x4c), curve != NULL)) &&
       ((curve->type == 0x16 &&
         ((dx = *(float *)(obj + 0x18) - x,
         dy = *(float *)(obj + 0x1c) - y,
         dz = *(float *)(obj + 0x20) - z,
         distance = sqrtf(dz * dz + (dx * dx + dy * dy)),
         (double)lbl_803E12B0 == nearestCurveId || (distance < nearestDistance)))))) {
      nearestCurveId = (double)curve->id;
      nearestDistance = distance;
    }
  }
  return (int)nearestCurveId;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: RomCurve_func13
 * EN v1.0 Address: 0x800E2090
 * EN v1.0 Size: 1280b
 * EN v1.1 Address: 0x800E260C
 * EN v1.1 Size: 1416b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void RomCurve_func13(uint curveId,int typeFilter,uint param_3,int *param_4)
{
  float fVar1;
  float fVar2;
  float fVar3;
  bool bVar4;
  int iVar5;
  int iVar6;
  float *pfVar7;
  uint uVar8;
  char *pcVar9;
  undefined *puVar10;
  undefined4 *puVar11;
  int iVar12;
  undefined4 *puVar13;
  float *pfVar14;
  int iVar15;
  int iVar16;
  int iVar17;
  undefined4 *puVar18;
  float *pfVar19;
  int iVar20;
  int iVar21;
  undefined4 *puVar22;
  float *pfVar23;
  int iVar24;
  int iVar25;
  uint uVar26;
  double dVar27;
  char local_6e4 [4];
  int local_6e0;
  int local_6dc;
  float local_6d8 [4];
  undefined4 local_6c8 [4];
  float local_6b8 [40];
  int local_618 [40];
  char local_578 [48];
  undefined local_548 [1344];

  iVar5 = RomCurve_findByIdWithIndex(curveId,&local_6e0);
  if (iVar5 != 0) {
    iVar16 = 0;
    iVar17 = 0;
    pfVar14 = local_6d8;
    puVar18 = local_6c8;
    pfVar19 = pfVar14;
    iVar20 = iVar5;
    do {
      if (-1 < *(int *)(iVar20 + 0x1c)) {
        pcVar9 = local_578;
        iVar25 = 0x1b;
        iVar12 = 0;
        do {
          iVar24 = iVar12;
          *pcVar9 = '\0';
          pcVar9[1] = '\0';
          pcVar9[2] = '\0';
          pcVar9[3] = '\0';
          pcVar9[4] = '\0';
          pcVar9[5] = '\0';
          pcVar9[6] = '\0';
          pcVar9[7] = '\0';
          pcVar9[8] = '\0';
          pcVar9[9] = '\0';
          pcVar9[10] = '\0';
          pcVar9[0xb] = '\0';
          pcVar9[0xc] = '\0';
          pcVar9[0xd] = '\0';
          pcVar9[0xe] = '\0';
          pcVar9[0xf] = '\0';
          pcVar9[0x10] = '\0';
          pcVar9[0x11] = '\0';
          pcVar9[0x12] = '\0';
          pcVar9[0x13] = '\0';
          pcVar9[0x14] = '\0';
          pcVar9[0x15] = '\0';
          pcVar9[0x16] = '\0';
          pcVar9[0x17] = '\0';
          pcVar9[0x18] = '\0';
          pcVar9[0x19] = '\0';
          pcVar9[0x1a] = '\0';
          pcVar9[0x1b] = '\0';
          pcVar9[0x1c] = '\0';
          pcVar9[0x1d] = '\0';
          pcVar9[0x1e] = '\0';
          pcVar9[0x1f] = '\0';
          pcVar9[0x20] = '\0';
          pcVar9[0x21] = '\0';
          pcVar9[0x22] = '\0';
          pcVar9[0x23] = '\0';
          pcVar9[0x24] = '\0';
          pcVar9[0x25] = '\0';
          pcVar9[0x26] = '\0';
          pcVar9[0x27] = '\0';
          pcVar9[0x28] = '\0';
          pcVar9[0x29] = '\0';
          pcVar9[0x2a] = '\0';
          pcVar9[0x2b] = '\0';
          pcVar9[0x2c] = '\0';
          pcVar9[0x2d] = '\0';
          pcVar9[0x2e] = '\0';
          pcVar9[0x2f] = '\0';
          pcVar9 = pcVar9 + 0x30;
          iVar12 = iVar24 + 0x30;
          iVar25 = iVar25 + -1;
        } while (iVar25 != 0);
        puVar10 = local_548 + iVar24;
        iVar25 = 0x514 - iVar12;
        if (iVar12 < 0x514) {
          do {
            *puVar10 = 0;
            puVar10 = puVar10 + 1;
            iVar25 = iVar25 + -1;
          } while (iVar25 != 0);
        }
        local_578[local_6e0] = '\x01';
        iVar12 = RomCurve_findByIdWithIndex(*(uint *)(iVar20 + 0x1c),&local_6dc);
        if (iVar12 != 0) {
          fVar1 = *(float *)(iVar12 + 0x10) - *(float *)(iVar5 + 0x10);
          fVar2 = *(float *)(iVar12 + 8) - *(float *)(iVar5 + 8);
          fVar3 = *(float *)(iVar12 + 0xc) - *(float *)(iVar5 + 0xc);
          local_6b8[0] = fVar1 * fVar1 + fVar2 * fVar2 + fVar3 * fVar3;
          iVar12 = 1;
          local_618[0] = local_6dc;
          local_578[local_6dc] = '\x01';
          bVar4 = false;
          puVar22 = puVar18;
          pfVar23 = pfVar19;
          do {
            if (iVar12 < 1) {
              bVar4 = true;
            }
            else {
              iVar12 = iVar12 + -1;
              local_6dc = local_618[iVar12];
              iVar25 = (int)romCurves[local_618[iVar12]];
              dVar27 = (double)local_6b8[iVar12];
              if ((((int)*(char *)(iVar25 + 0x19) == typeFilter) || (typeFilter == -1)) &&
                 ((*(byte *)(iVar25 + 0x31) == param_3 ||
                  ((*(byte *)(iVar25 + 0x32) == param_3 || (*(byte *)(iVar25 + 0x33) == param_3)))))
                 ) {
                bVar4 = true;
                *pfVar23 = local_6b8[iVar12];
                if (iVar16 < 4) {
                  *puVar22 = *(undefined4 *)(iVar25 + 0x14);
                  pfVar19 = pfVar19 + 1;
                  puVar18 = puVar18 + 1;
                  pfVar23 = pfVar23 + 1;
                  puVar22 = puVar22 + 1;
                  local_6e4[iVar16] = (char)iVar17;
                  iVar16 = iVar16 + 1;
                }
              }
              else {
                iVar15 = 0;
                iVar24 = iVar12 * 4;
                iVar21 = iVar25;
                do {
                  if ((((-1 < (int)*(uint *)(iVar21 + 0x1c)) &&
                       (iVar6 = RomCurve_findByIdWithIndex(*(uint *)(iVar21 + 0x1c),&local_6dc), iVar6 != 0)) &&
                      (local_578[local_6dc] == '\0')) && (iVar12 < 0x28)) {
                    fVar1 = *(float *)(iVar25 + 0x10) - *(float *)(iVar6 + 0x10);
                    fVar2 = *(float *)(iVar25 + 8) - *(float *)(iVar6 + 8);
                    fVar3 = *(float *)(iVar25 + 0xc) - *(float *)(iVar6 + 0xc);
                    fVar1 = fVar1 * fVar1 +
                            (float)(dVar27 + (double)(fVar2 * fVar2)) + fVar3 * fVar3;
                    iVar6 = 0;
                    for (pfVar7 = local_6b8; (iVar6 < iVar12 && (fVar1 < *pfVar7));
                        pfVar7 = pfVar7 + 1) {
                      iVar6 = iVar6 + 1;
                    }
                    puVar11 = (undefined4 *)((int)local_618 + iVar24);
                    puVar13 = (undefined4 *)((int)local_6b8 + iVar24);
                    uVar8 = iVar12 - iVar6;
                    if (iVar6 < iVar12) {
                      uVar26 = uVar8 >> 3;
                      if (uVar26 != 0) {
                        do {
                          *puVar11 = puVar11[-1];
                          *puVar13 = puVar13[-1];
                          puVar11[-1] = puVar11[-2];
                          puVar13[-1] = puVar13[-2];
                          puVar11[-2] = puVar11[-3];
                          puVar13[-2] = puVar13[-3];
                          puVar11[-3] = puVar11[-4];
                          puVar13[-3] = puVar13[-4];
                          puVar11[-4] = puVar11[-5];
                          puVar13[-4] = puVar13[-5];
                          puVar11[-5] = puVar11[-6];
                          puVar13[-5] = puVar13[-6];
                          puVar11[-6] = puVar11[-7];
                          puVar13[-6] = puVar13[-7];
                          puVar11[-7] = puVar11[-8];
                          puVar13[-7] = puVar13[-8];
                          puVar11 = puVar11 + -8;
                          puVar13 = puVar13 + -8;
                          uVar26 = uVar26 - 1;
                        } while (uVar26 != 0);
                        uVar8 = uVar8 & 7;
                        if (uVar8 == 0) goto LAB_800e2a50;
                      }
                      do {
                        *puVar11 = puVar11[-1];
                        *puVar13 = puVar13[-1];
                        puVar11 = puVar11 + -1;
                        puVar13 = puVar13 + -1;
                        uVar8 = uVar8 - 1;
                      } while (uVar8 != 0);
                    }
LAB_800e2a50:
                    iVar12 = iVar12 + 1;
                    iVar24 = iVar24 + 4;
                    local_6b8[iVar6] = fVar1;
                    local_618[iVar6] = local_6dc;
                    local_578[local_6dc] = '\x01';
                  }
                  iVar21 = iVar21 + 4;
                  iVar15 = iVar15 + 1;
                } while (iVar15 < 4);
              }
            }
          } while (!bVar4);
        }
      }
      iVar20 = iVar20 + 4;
      iVar17 = iVar17 + 1;
    } while (iVar17 < 4);
    if (0 < iVar16) {
      iVar5 = 0;
      iVar20 = 0;
      if (0 < iVar16) {
        do {
          if (*pfVar14 < local_6d8[iVar5]) {
            iVar5 = iVar20;
          }
          pfVar14 = pfVar14 + 1;
          iVar20 = iVar20 + 1;
          iVar16 = iVar16 + -1;
        } while (iVar16 != 0);
      }
      if (param_4 != (int *)0x0) {
        *param_4 = (int)local_6e4[iVar5];
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: RomCurve_func11
 * EN v1.0 Address: 0x800E2590
 * EN v1.0 Size: 1528b
 * EN v1.1 Address: 0x800E2B94
 * EN v1.1 Size: 1612b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void RomCurve_func11(RomCurveDef *curve,int typeFilter,int actionFilter,int *outCurveId)
{
  float fVar1;
  float fVar2;
  float fVar3;
  bool bVar4;
  int iVar5;
  int iVar6;
  float *pfVar7;
  char *pcVar8;
  undefined *puVar9;
  undefined4 *puVar10;
  uint uVar11;
  uint uVar12;
  int iVar13;
  undefined4 *puVar14;
  int iVar15;
  int *piVar16;
  int iVar17;
  int iVar18;
  float *pfVar19;
  float *pfVar20;
  int iVar21;
  int iVar22;
  float *pfVar23;
  int iVar24;
  int iVar25;
  uint uVar26;
  double dVar27;
  int local_6d8;
  int local_6d4;
  float local_6d0 [4];
  int local_6c0 [4];
  float local_6b0 [40];
  int local_610 [40];
  char local_570 [48];
  undefined local_540 [1336];

  iVar15 = (int)curve;
  if ((iVar15 != 0) && (iVar5 = RomCurve_findByIdWithIndex(*(uint *)(iVar15 + 0x14),&local_6d8), iVar5 != 0)) {
    iVar5 = 0;
    iVar18 = 0;
    pfVar19 = local_6d0;
    pfVar20 = pfVar19;
    iVar21 = iVar15;
    do {
      if (-1 < *(int *)(iVar21 + 0x1c)) {
        pcVar8 = local_570;
        iVar25 = 0x1b;
        iVar13 = 0;
        do {
          iVar24 = iVar13;
          *pcVar8 = '\0';
          pcVar8[1] = '\0';
          pcVar8[2] = '\0';
          pcVar8[3] = '\0';
          pcVar8[4] = '\0';
          pcVar8[5] = '\0';
          pcVar8[6] = '\0';
          pcVar8[7] = '\0';
          pcVar8[8] = '\0';
          pcVar8[9] = '\0';
          pcVar8[10] = '\0';
          pcVar8[0xb] = '\0';
          pcVar8[0xc] = '\0';
          pcVar8[0xd] = '\0';
          pcVar8[0xe] = '\0';
          pcVar8[0xf] = '\0';
          pcVar8[0x10] = '\0';
          pcVar8[0x11] = '\0';
          pcVar8[0x12] = '\0';
          pcVar8[0x13] = '\0';
          pcVar8[0x14] = '\0';
          pcVar8[0x15] = '\0';
          pcVar8[0x16] = '\0';
          pcVar8[0x17] = '\0';
          pcVar8[0x18] = '\0';
          pcVar8[0x19] = '\0';
          pcVar8[0x1a] = '\0';
          pcVar8[0x1b] = '\0';
          pcVar8[0x1c] = '\0';
          pcVar8[0x1d] = '\0';
          pcVar8[0x1e] = '\0';
          pcVar8[0x1f] = '\0';
          pcVar8[0x20] = '\0';
          pcVar8[0x21] = '\0';
          pcVar8[0x22] = '\0';
          pcVar8[0x23] = '\0';
          pcVar8[0x24] = '\0';
          pcVar8[0x25] = '\0';
          pcVar8[0x26] = '\0';
          pcVar8[0x27] = '\0';
          pcVar8[0x28] = '\0';
          pcVar8[0x29] = '\0';
          pcVar8[0x2a] = '\0';
          pcVar8[0x2b] = '\0';
          pcVar8[0x2c] = '\0';
          pcVar8[0x2d] = '\0';
          pcVar8[0x2e] = '\0';
          pcVar8[0x2f] = '\0';
          pcVar8 = pcVar8 + 0x30;
          iVar13 = iVar24 + 0x30;
          iVar25 = iVar25 + -1;
        } while (iVar25 != 0);
        puVar9 = local_540 + iVar24;
        iVar25 = 0x514 - iVar13;
        if (iVar13 < 0x514) {
          do {
            *puVar9 = 0;
            puVar9 = puVar9 + 1;
            iVar25 = iVar25 + -1;
          } while (iVar25 != 0);
        }
        local_570[local_6d8] = '\x01';
        iVar13 = RomCurve_findByIdWithIndex(*(uint *)(iVar21 + 0x1c),&local_6d4);
        if (iVar13 != 0) {
          fVar1 = *(float *)(iVar13 + 0x10) - *(float *)(iVar15 + 0x10);
          fVar2 = *(float *)(iVar13 + 8) - *(float *)(iVar15 + 8);
          fVar3 = *(float *)(iVar13 + 0xc) - *(float *)(iVar15 + 0xc);
          local_6b0[0] = fVar1 * fVar1 + fVar2 * fVar2 + fVar3 * fVar3;
          iVar13 = 1;
          local_610[0] = local_6d4;
          local_570[local_6d4] = '\x01';
          bVar4 = false;
          pfVar23 = pfVar20;
          do {
            if (iVar13 < 1) {
              bVar4 = true;
            }
            else {
              iVar13 = iVar13 + -1;
              local_6d4 = local_610[iVar13];
              iVar25 = (int)romCurves[local_610[iVar13]];
              dVar27 = (double)local_6b0[iVar13];
              if (((int)*(char *)(iVar25 + 0x19) == typeFilter) &&
                 ((actionFilter == -1 || (actionFilter == *(char *)(iVar25 + 0x18))))) {
                bVar4 = true;
                *pfVar23 = local_6b0[iVar13];
                pfVar20 = pfVar20 + 1;
                pfVar23 = pfVar23 + 1;
                local_6b0[iVar5 + -4] = *(float *)(iVar21 + 0x1c);
                iVar5 = iVar5 + 1;
              }
              else {
                iVar17 = 0;
                iVar24 = iVar13 * 4;
                iVar22 = iVar25;
                do {
                  if ((((-1 < (int)*(uint *)(iVar22 + 0x1c)) &&
                       (iVar6 = RomCurve_findByIdWithIndex(*(uint *)(iVar22 + 0x1c),&local_6d4), iVar6 != 0)) &&
                      (local_570[local_6d4] == '\0')) && (iVar13 < 0x28)) {
                    fVar1 = *(float *)(iVar25 + 0x10) - *(float *)(iVar6 + 0x10);
                    fVar2 = *(float *)(iVar25 + 8) - *(float *)(iVar6 + 8);
                    fVar3 = *(float *)(iVar25 + 0xc) - *(float *)(iVar6 + 0xc);
                    fVar1 = fVar1 * fVar1 +
                            (float)(dVar27 + (double)(fVar2 * fVar2)) + fVar3 * fVar3;
                    iVar6 = 0;
                    for (pfVar7 = local_6b0; (iVar6 < iVar13 && (fVar1 < *pfVar7));
                        pfVar7 = pfVar7 + 1) {
                      iVar6 = iVar6 + 1;
                    }
                    puVar10 = (undefined4 *)((int)local_610 + iVar24);
                    puVar14 = (undefined4 *)((int)local_6b0 + iVar24);
                    uVar11 = iVar13 - iVar6;
                    if (iVar6 < iVar13) {
                      uVar26 = uVar11 >> 3;
                      if (uVar26 != 0) {
                        do {
                          *puVar10 = puVar10[-1];
                          *puVar14 = puVar14[-1];
                          puVar10[-1] = puVar10[-2];
                          puVar14[-1] = puVar14[-2];
                          puVar10[-2] = puVar10[-3];
                          puVar14[-2] = puVar14[-3];
                          puVar10[-3] = puVar10[-4];
                          puVar14[-3] = puVar14[-4];
                          puVar10[-4] = puVar10[-5];
                          puVar14[-4] = puVar14[-5];
                          puVar10[-5] = puVar10[-6];
                          puVar14[-5] = puVar14[-6];
                          puVar10[-6] = puVar10[-7];
                          puVar14[-6] = puVar14[-7];
                          puVar10[-7] = puVar10[-8];
                          puVar14[-7] = puVar14[-8];
                          puVar10 = puVar10 + -8;
                          puVar14 = puVar14 + -8;
                          uVar26 = uVar26 - 1;
                        } while (uVar26 != 0);
                        uVar11 = uVar11 & 7;
                        if (uVar11 == 0) goto LAB_800e2fbc;
                      }
                      do {
                        *puVar10 = puVar10[-1];
                        *puVar14 = puVar14[-1];
                        puVar10 = puVar10 + -1;
                        puVar14 = puVar14 + -1;
                        uVar11 = uVar11 - 1;
                      } while (uVar11 != 0);
                    }
LAB_800e2fbc:
                    iVar13 = iVar13 + 1;
                    iVar24 = iVar24 + 4;
                    local_6b0[iVar6] = fVar1;
                    local_610[iVar6] = local_6d4;
                    local_570[local_6d4] = '\x01';
                  }
                  iVar22 = iVar22 + 4;
                  iVar17 = iVar17 + 1;
                } while (iVar17 < 4);
              }
            }
          } while (!bVar4);
        }
      }
      iVar21 = iVar21 + 4;
      iVar18 = iVar18 + 1;
    } while (iVar18 < 4);
    if (iVar5 != 0) {
      if (iVar5 == 1) {
        *outCurveId = *(int *)(iVar15 + 0x14);
      }
      else if (1 < iVar5) {
        iVar21 = 0;
        for (iVar18 = 0; iVar18 < iVar5; iVar18 = iVar18 + 1) {
          piVar16 = (int *)((int)local_6c0 + iVar21);
          if (*outCurveId == *piVar16) {
            puVar10 = (undefined4 *)((int)local_6d0 + iVar21);
            uVar11 = (iVar5 + -1) - iVar18;
            if (iVar18 < iVar5 + -1) {
              uVar26 = uVar11 >> 3;
              uVar12 = uVar11;
              if (uVar26 == 0) goto LAB_800e3130;
              do {
                *piVar16 = piVar16[1];
                *puVar10 = puVar10[1];
                piVar16[1] = piVar16[2];
                puVar10[1] = puVar10[2];
                piVar16[2] = piVar16[3];
                puVar10[2] = puVar10[3];
                piVar16[3] = piVar16[4];
                puVar10[3] = puVar10[4];
                piVar16[4] = piVar16[5];
                puVar10[4] = puVar10[5];
                piVar16[5] = piVar16[6];
                puVar10[5] = puVar10[6];
                piVar16[6] = piVar16[7];
                puVar10[6] = puVar10[7];
                piVar16[7] = piVar16[8];
                puVar10[7] = puVar10[8];
                piVar16 = piVar16 + 8;
                puVar10 = puVar10 + 8;
                iVar21 = iVar21 + 0x20;
                uVar26 = uVar26 - 1;
              } while (uVar26 != 0);
              for (uVar12 = uVar11 & 7; uVar12 != 0; uVar12 = uVar12 - 1) {
LAB_800e3130:
                *piVar16 = piVar16[1];
                *puVar10 = puVar10[1];
                piVar16 = piVar16 + 1;
                puVar10 = puVar10 + 1;
                iVar21 = iVar21 + 4;
              }
              iVar18 = iVar18 + uVar11;
            }
            iVar5 = iVar5 + -1;
          }
          iVar21 = iVar21 + 4;
        }
        *outCurveId = *(int *)(iVar15 + 0x14);
        iVar15 = 0;
        iVar21 = 0;
        if (0 < iVar5) {
          do {
            if (*pfVar19 < local_6d0[iVar15]) {
              iVar15 = iVar21;
            }
            pfVar19 = pfVar19 + 1;
            iVar21 = iVar21 + 1;
            iVar5 = iVar5 + -1;
          } while (iVar5 != 0);
        }
      }
    }
  }
  TRKNubMainLoop();
  return;
}

/*
 * --INFO--
 *
 * Function: RomCurve_getRandomLinkedOfTypes
 * EN v1.0 Address: 0x800E2F5C
 * EN v1.0 Size: 572b
 * EN v1.1 Address: 0x800E31E0
 * EN v1.1 Size: 980b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int RomCurve_getRandomLinkedOfTypes(RomCurveDef *curve,int *types,int typeCount,int *previousLinkId)
{
  int candidates[7];
  int candidateCount;
  int linkIndex;
  int typeIndex;
  int low;
  int high;
  int mid;
  int removeCount;
  int *candidate;
  u32 linkId;
  RomCurveDef *linkedCurve;

  if (curve == NULL) {
    candidates[0] = ROMCURVE_LINK_ID_NONE;
  } else {
    candidateCount = 0;
    for (linkIndex = 0; linkIndex < ROMCURVE_LINK_COUNT; linkIndex++) {
      linkId = curve->linkIds[linkIndex];
      if ((s32)linkId > -1) {
        if ((s32)linkId < 0) {
          linkedCurve = NULL;
        } else {
          low = 0;
          high = nRomCurves - 1;
          while (low <= high) {
            mid = (high + low) >> 1;
            linkedCurve = romCurves[mid];
            if (linkId > linkedCurve->id) {
              low = mid + 1;
            } else if (linkId < linkedCurve->id) {
              high = mid - 1;
            } else {
              goto foundLinkedCurve;
            }
          }
          linkedCurve = NULL;
        }

foundLinkedCurve:
        for (typeIndex = 0; typeIndex < typeCount; typeIndex++) {
          if (linkedCurve->type == types[typeIndex]) {
            candidates[candidateCount] = linkId;
            candidateCount++;
            typeIndex = typeCount;
          }
        }
      }
    }

    if (candidateCount == 0) {
      candidates[0] = ROMCURVE_LINK_ID_NONE;
    } else if (candidateCount == 1) {
      *previousLinkId = curve->id;
    } else if (candidateCount < 2) {
      candidates[0] = ROMCURVE_LINK_ID_NONE;
    } else {
      for (linkIndex = 0; linkIndex < candidateCount; linkIndex++) {
        candidate = &candidates[linkIndex];
        if (*previousLinkId == *candidate) {
          removeCount = (candidateCount - 1) - linkIndex;
          while (linkIndex < candidateCount - 1) {
            *candidate = candidate[1];
            candidate++;
            linkIndex++;
          }
          linkIndex += removeCount - 1;
          candidateCount--;
        }
      }
      *previousLinkId = curve->id;
      candidates[0] = candidates[randomGetRange(0,candidateCount - 1)];
    }
  }
  return candidates[0];
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: curves_distXZ
 * EN v1.0 Address: 0x800E3330
 * EN v1.0 Size: 176b
 * EN v1.1 Address: 0x800E35B4
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
f32 curves_distXZ(f32 x,f32 z,uint curveId)
{
  RomCurveDef *curve;
  f32 dx;
  f32 dz;

  curve = RomCurve_FindByIdInline(curveId);
  if (curve == NULL) {
    return gFloatNegOne;
  }

  dx = curve->x - x;
  dz = curve->z - z;
  return sqrtf(dx * dx + dz * dz);
}

/*
 * --INFO--
 *
 * Function: curves_distFn0B
 * EN v1.0 Address: 0x800E33E0
 * EN v1.0 Size: 208b
 * EN v1.1 Address: 0x800E3664
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
f32 curves_distFn0B(int obj,uint curveId)
{
  RomCurveDef *curve;
  f32 dx;
  f32 dy;
  f32 dz;

  curve = RomCurve_FindByIdInline(curveId);
  if (curve == NULL || obj == 0) {
    return gFloatNegOne;
  }

  dx = curve->x - *(f32 *)(obj + 0x0c);
  dy = curve->y - *(f32 *)(obj + 0x10);
  dz = curve->z - *(f32 *)(obj + 0x14);
  return sqrtf(dx * dx + dy * dy + dz * dz);
}

#pragma scheduling off
#pragma peephole off
int curves_isNotPoint(int *obj) {
    int i;
    for (i = 0; i < 4; i++) {
        if (*(int *)((char *)obj + 0x1c + i * 4) != -1 &&
            (*(s8 *)((char *)obj + 0x1b) & (1 << i)) == 0) {
            return 0;
        }
    }
    return 1;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int curves_isPoint(int *obj) {
    int i;
    for (i = 0; i < 4; i++) {
        if (*(int *)((char *)obj + 0x1c + i * 4) != -1 &&
            (*(s8 *)((char *)obj + 0x1b) & (1 << i)) != 0) {
            return 0;
        }
    }
    return 1;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: curves_find
 * EN v1.0 Address: 0x800E34B0
 * EN v1.0 Size: 564b
 * EN v1.1 Address: 0x800E3734
 * EN v1.1 Size: 584b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
f32 curves_find(int type,int action,f32 x,f32 y,f32 z,f32 *outX,f32 *outY,f32 *outZ)
{
  int curveIndex;
  int linkIndex;
  int high;
  int low;
  int mid;
  u32 linkId;
  RomCurveDef *curve;
  RomCurveDef *linkedCurve;
  f32 pointX;
  f32 pointY;
  f32 pointZ;
  f32 zero;
  f32 distance;
  f32 bestDistance;
  f32 absDistance;
  f32 absBestDistance;
  f32 segment[9];

  pointX = x;
  pointY = y;
  pointZ = z;
  zero = gFloatZero;
  *outZ = zero;
  *outY = zero;
  *outX = zero;
  bestDistance = lbl_803E0644;
  for (curveIndex = 0; curveIndex < nRomCurves; curveIndex++) {
    curve = romCurves[curveIndex];
    if ((curve->action == action) && (curve->type == type)) {
      segment[0] = curve->x;
      segment[1] = curve->y;
      segment[2] = curve->z;
      for (linkIndex = 0; linkIndex < ROMCURVE_LINK_COUNT; linkIndex++) {
        if (((s32)curve->blockedLinkMask & (1 << linkIndex)) == 0) {
          linkId = curve->linkIds[linkIndex];
          if ((s32)linkId < 0) {
            linkedCurve = NULL;
          }
          else {
            high = nRomCurves - 1;
            low = 0;
            while (low <= high) {
              mid = (high + low) >> 1;
              linkedCurve = romCurves[mid];
              if (linkId > linkedCurve->id) {
                low = mid + 1;
              }
              else if (linkId < linkedCurve->id) {
                high = mid - 1;
              }
              else {
                goto foundLinkedCurve;
              }
            }
            linkedCurve = NULL;
          }

foundLinkedCurve:
          if (linkedCurve != NULL) {
            segment[3] = linkedCurve->x;
            segment[4] = linkedCurve->y;
            segment[5] = linkedCurve->z;
            distance = RomCurve_distanceToSegment(pointX,pointY,pointZ,segment);
            absBestDistance = bestDistance;
            if (bestDistance < gFloatZero) {
              absBestDistance = -bestDistance;
            }
            absDistance = distance;
            if (distance < gFloatZero) {
              absDistance = -distance;
            }
            if (absDistance < absBestDistance) {
              lbl_803DD474 = curve;
              lbl_803DD470 = linkedCurve;
              bestDistance = distance;
              *outX = segment[6];
              *outY = segment[7];
              *outZ = segment[8];
            }
          }
        }
      }
    }
  }
  return bestDistance;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: RomCurve_findByIdWithIndex
 * EN v1.0 Address: 0x800E36F8
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x800E397C
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
undefined4 RomCurve_findByIdWithIndex(uint curveId,int *outIndex)
{
  int high;
  int low;
  int mid;

  *outIndex = -1;
  if ((int)curveId < 0) {
    return 0;
  }
  high = nRomCurves + -1;
  low = 0;
  while (high >= low) {
    mid = high + low >> 1;
    if (curveId > RomCurve_GetId(romCurves[mid])) {
      low = mid + 1;
    }
    else if (curveId < RomCurve_GetId(romCurves[mid])) {
      high = mid + -1;
    }
    else {
      *outIndex = mid;
      return (undefined4)romCurves[mid];
    }
  }
  *outIndex = -1;
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: RomCurve_func20
 * EN v1.0 Address: 0x800E31DC
 * EN v1.0 Size: 2296b
 * EN v1.1 Address: 0x800E3A00
 * EN v1.1 Size: 2996b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void RomCurve_func20(undefined4 param_1,undefined4 param_2,int param_3,int param_4,int param_5)
{
  bool bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  double dVar11;
  undefined8 uVar12;
  uint local_a8 [4];
  uint local_98 [4];
  undefined4 local_88;
  uint uStack_84;
  undefined4 local_80;
  uint uStack_7c;
  undefined4 local_78;
  uint uStack_74;
  undefined4 local_70;
  uint uStack_6c;
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
  
  uVar12 = FUN_8028682c();
  iVar3 = (int)((ulonglong)uVar12 >> 0x20);
  iVar2 = (int)uVar12;
  bVar1 = false;
  if ((*(int *)(iVar3 + 0x1c) == -1) || ((*(byte *)(iVar3 + 0x1b) & 1) != 0)) {
    if ((*(int *)(iVar3 + 0x20) == -1) || ((*(byte *)(iVar3 + 0x1b) & 2) != 0)) {
      if ((*(int *)(iVar3 + 0x24) == -1) || ((*(byte *)(iVar3 + 0x1b) & 4) != 0)) {
        if ((*(int *)(iVar3 + 0x28) == -1) || ((*(byte *)(iVar3 + 0x1b) & 8) != 0)) {
          bVar1 = true;
        }
        else {
          bVar1 = false;
        }
      }
      else {
        bVar1 = false;
      }
    }
    else {
      bVar1 = false;
    }
  }
  iVar10 = 0;
  iVar9 = 0;
  iVar8 = 0;
  if (bVar1) {
    while (iVar8 = iVar3, iVar8 != 0) {
      bVar1 = false;
      if ((*(int *)(iVar8 + 0x1c) == -1) || ((*(byte *)(iVar8 + 0x1b) & 1) == 0)) {
        if ((*(int *)(iVar8 + 0x20) == -1) || ((*(byte *)(iVar8 + 0x1b) & 2) == 0)) {
          if ((*(int *)(iVar8 + 0x24) == -1) || ((*(byte *)(iVar8 + 0x1b) & 4) == 0)) {
            if ((*(int *)(iVar8 + 0x28) == -1) || ((*(byte *)(iVar8 + 0x1b) & 8) == 0)) {
              bVar1 = true;
            }
            else {
              bVar1 = false;
            }
          }
          else {
            bVar1 = false;
          }
        }
        else {
          bVar1 = false;
        }
      }
      if (bVar1) break;
      iVar3 = 0;
      uVar5 = *(uint *)(iVar8 + 0x1c);
      if (((-1 < (int)uVar5) && ((*(byte *)(iVar8 + 0x1b) & 1) != 0)) && (uVar5 != 0)) {
        iVar3 = 1;
        local_a8[0] = uVar5;
      }
      uVar5 = *(uint *)(iVar8 + 0x20);
      iVar4 = iVar3;
      if (((-1 < (int)uVar5) && ((*(byte *)(iVar8 + 0x1b) & 2) != 0)) && (uVar5 != 0)) {
        iVar4 = iVar3 + 1;
        local_a8[iVar3] = uVar5;
      }
      uVar5 = *(uint *)(iVar8 + 0x24);
      iVar3 = iVar4;
      if (((-1 < (int)uVar5) && ((*(byte *)(iVar8 + 0x1b) & 4) != 0)) && (uVar5 != 0)) {
        iVar3 = iVar4 + 1;
        local_a8[iVar4] = uVar5;
      }
      uVar5 = *(uint *)(iVar8 + 0x28);
      iVar4 = iVar3;
      if (((-1 < (int)uVar5) && ((*(byte *)(iVar8 + 0x1b) & 8) != 0)) && (uVar5 != 0)) {
        iVar4 = iVar3 + 1;
        local_a8[iVar3] = uVar5;
      }
      if (iVar4 == 0) {
        uVar5 = 0xffffffff;
      }
      else {
        uVar5 = randomGetRange(0,iVar4 - 1);
        uVar5 = local_a8[uVar5];
      }
      if ((int)uVar5 < 0) {
        iVar3 = 0;
      }
      else {
        iVar7 = nRomCurves + -1;
        iVar4 = 0;
        while (iVar4 <= iVar7) {
          iVar6 = iVar7 + iVar4 >> 1;
          iVar3 = (int)romCurves[iVar6];
          if (*(uint *)(iVar3 + 0x14) < uVar5) {
            iVar4 = iVar6 + 1;
          }
          else {
            if (*(uint *)(iVar3 + 0x14) <= uVar5) goto LAB_800e41e4;
            iVar7 = iVar6 + -1;
          }
        }
        iVar3 = 0;
      }
LAB_800e41e4:
      if (iVar3 != 0) {
        if (param_5 != 0) {
          *(undefined *)(param_5 + (iVar10 >> 2)) = *(undefined *)(iVar8 + 0x19);
        }
        *(undefined4 *)(iVar2 + iVar9) = *(undefined4 *)(iVar8 + 8);
        *(undefined4 *)(param_3 + iVar9) = *(undefined4 *)(iVar8 + 0xc);
        iVar4 = iVar9 + 4;
        *(undefined4 *)(param_4 + iVar9) = *(undefined4 *)(iVar8 + 0x10);
        *(undefined4 *)(iVar2 + iVar4) = *(undefined4 *)(iVar3 + 8);
        *(undefined4 *)(param_3 + iVar4) = *(undefined4 *)(iVar3 + 0xc);
        *(undefined4 *)(param_4 + iVar4) = *(undefined4 *)(iVar3 + 0x10);
        uStack_2c = (int)*(char *)(iVar8 + 0x2c) << 8 ^ 0x80000000;
        local_30 = 0x43300000;
        dVar11 = (double)FUN_80293f90();
        uStack_34 = (uint)*(byte *)(iVar8 + 0x2e);
        local_38 = 0x43300000;
        *(float *)(iVar2 + iVar9 + 8) =
             lbl_803E1290 *
             (float)((double)(f32)(s32)uStack_34 *
                    dVar11);
        uStack_3c = (int)*(char *)(iVar8 + 0x2d) << 8 ^ 0x80000000;
        local_40 = 0x43300000;
        dVar11 = (double)FUN_80293f90();
        uStack_44 = (uint)*(byte *)(iVar8 + 0x2e);
        local_48 = 0x43300000;
        *(float *)(param_3 + iVar9 + 8) =
             lbl_803E1290 *
             (float)((double)(f32)(s32)uStack_44 *
                    dVar11);
        uStack_4c = (int)*(char *)(iVar8 + 0x2c) << 8 ^ 0x80000000;
        local_50 = 0x43300000;
        dVar11 = (double)FUN_80294964();
        uStack_54 = (uint)*(byte *)(iVar8 + 0x2e);
        local_58 = 0x43300000;
        iVar8 = iVar10 + 3;
        *(float *)(param_4 + (iVar10 + 2) * 4) =
             lbl_803E1290 *
             (float)((double)(f32)(s32)uStack_54 *
                    dVar11);
        uStack_5c = (int)*(char *)(iVar3 + 0x2c) << 8 ^ 0x80000000;
        local_60 = 0x43300000;
        dVar11 = (double)FUN_80293f90();
        uStack_64 = (uint)*(byte *)(iVar3 + 0x2e);
        local_68 = 0x43300000;
        *(float *)(iVar2 + iVar9 + 0xc) =
             lbl_803E1290 *
             (float)((double)(f32)(s32)uStack_64 *
                    dVar11);
        uStack_6c = (int)*(char *)(iVar3 + 0x2d) << 8 ^ 0x80000000;
        local_70 = 0x43300000;
        dVar11 = (double)FUN_80293f90();
        uStack_74 = (uint)*(byte *)(iVar3 + 0x2e);
        local_78 = 0x43300000;
        *(float *)(param_3 + iVar9 + 0xc) =
             lbl_803E1290 *
             (float)((double)(f32)(s32)uStack_74 *
                    dVar11);
        uStack_7c = (int)*(char *)(iVar3 + 0x2c) << 8 ^ 0x80000000;
        local_80 = 0x43300000;
        dVar11 = (double)FUN_80294964();
        uStack_84 = (uint)*(byte *)(iVar3 + 0x2e);
        local_88 = 0x43300000;
        iVar10 = iVar10 + 4;
        iVar9 = iVar9 + 0x10;
        *(float *)(param_4 + iVar8 * 4) =
             lbl_803E1290 *
             (float)((double)(f32)(s32)uStack_84 *
                    dVar11);
      }
    }
  }
  else {
    while (iVar9 = iVar3, iVar9 != 0) {
      bVar1 = false;
      if ((*(int *)(iVar9 + 0x1c) == -1) || ((*(byte *)(iVar9 + 0x1b) & 1) != 0)) {
        if ((*(int *)(iVar9 + 0x20) == -1) || ((*(byte *)(iVar9 + 0x1b) & 2) != 0)) {
          if ((*(int *)(iVar9 + 0x24) == -1) || ((*(byte *)(iVar9 + 0x1b) & 4) != 0)) {
            if ((*(int *)(iVar9 + 0x28) == -1) || ((*(byte *)(iVar9 + 0x1b) & 8) != 0)) {
              bVar1 = true;
            }
            else {
              bVar1 = false;
            }
          }
          else {
            bVar1 = false;
          }
        }
        else {
          bVar1 = false;
        }
      }
      if (bVar1) break;
      iVar3 = 0;
      uVar5 = *(uint *)(iVar9 + 0x1c);
      if (((-1 < (int)uVar5) && ((*(byte *)(iVar9 + 0x1b) & 1) == 0)) && (uVar5 != 0)) {
        iVar3 = 1;
        local_98[0] = uVar5;
      }
      uVar5 = *(uint *)(iVar9 + 0x20);
      iVar4 = iVar3;
      if (((-1 < (int)uVar5) && ((*(byte *)(iVar9 + 0x1b) & 2) == 0)) && (uVar5 != 0)) {
        iVar4 = iVar3 + 1;
        local_98[iVar3] = uVar5;
      }
      uVar5 = *(uint *)(iVar9 + 0x24);
      iVar3 = iVar4;
      if (((-1 < (int)uVar5) && ((*(byte *)(iVar9 + 0x1b) & 4) == 0)) && (uVar5 != 0)) {
        iVar3 = iVar4 + 1;
        local_98[iVar4] = uVar5;
      }
      uVar5 = *(uint *)(iVar9 + 0x28);
      iVar4 = iVar3;
      if (((-1 < (int)uVar5) && ((*(byte *)(iVar9 + 0x1b) & 8) == 0)) && (uVar5 != 0)) {
        iVar4 = iVar3 + 1;
        local_98[iVar3] = uVar5;
      }
      if (iVar4 == 0) {
        uVar5 = 0xffffffff;
      }
      else {
        uVar5 = randomGetRange(0,iVar4 - 1);
        uVar5 = local_98[uVar5];
      }
      if ((int)uVar5 < 0) {
        iVar3 = 0;
      }
      else {
        iVar7 = nRomCurves + -1;
        iVar4 = 0;
        while (iVar4 <= iVar7) {
          iVar6 = iVar7 + iVar4 >> 1;
          iVar3 = (int)romCurves[iVar6];
          if (*(uint *)(iVar3 + 0x14) < uVar5) {
            iVar4 = iVar6 + 1;
          }
          else {
            if (*(uint *)(iVar3 + 0x14) <= uVar5) goto LAB_800e3ca0;
            iVar7 = iVar6 + -1;
          }
        }
        iVar3 = 0;
      }
LAB_800e3ca0:
      if (iVar3 != 0) {
        if (param_5 != 0) {
          *(undefined *)(param_5 + (iVar10 >> 2)) = *(undefined *)(iVar9 + 0x19);
        }
        *(undefined4 *)(iVar2 + iVar8) = *(undefined4 *)(iVar9 + 8);
        *(undefined4 *)(param_3 + iVar8) = *(undefined4 *)(iVar9 + 0xc);
        iVar4 = iVar8 + 4;
        *(undefined4 *)(param_4 + iVar8) = *(undefined4 *)(iVar9 + 0x10);
        *(undefined4 *)(iVar2 + iVar4) = *(undefined4 *)(iVar3 + 8);
        *(undefined4 *)(param_3 + iVar4) = *(undefined4 *)(iVar3 + 0xc);
        *(undefined4 *)(param_4 + iVar4) = *(undefined4 *)(iVar3 + 0x10);
        uStack_84 = (int)*(char *)(iVar9 + 0x2c) << 8 ^ 0x80000000;
        local_88 = 0x43300000;
        dVar11 = (double)FUN_80293f90();
        uStack_7c = (uint)*(byte *)(iVar9 + 0x2e);
        local_80 = 0x43300000;
        *(float *)(iVar2 + iVar8 + 8) =
             lbl_803E1290 *
             (float)((double)(f32)(s32)uStack_7c *
                    dVar11);
        uStack_74 = (int)*(char *)(iVar9 + 0x2d) << 8 ^ 0x80000000;
        local_78 = 0x43300000;
        dVar11 = (double)FUN_80293f90();
        uStack_6c = (uint)*(byte *)(iVar9 + 0x2e);
        local_70 = 0x43300000;
        *(float *)(param_3 + iVar8 + 8) =
             lbl_803E1290 *
             (float)((double)(f32)(s32)uStack_6c *
                    dVar11);
        uStack_64 = (int)*(char *)(iVar9 + 0x2c) << 8 ^ 0x80000000;
        local_68 = 0x43300000;
        dVar11 = (double)FUN_80294964();
        uStack_5c = (uint)*(byte *)(iVar9 + 0x2e);
        local_60 = 0x43300000;
        iVar9 = iVar10 + 3;
        *(float *)(param_4 + (iVar10 + 2) * 4) =
             lbl_803E1290 *
             (float)((double)(f32)(s32)uStack_5c *
                    dVar11);
        uStack_54 = (int)*(char *)(iVar3 + 0x2c) << 8 ^ 0x80000000;
        local_58 = 0x43300000;
        dVar11 = (double)FUN_80293f90();
        uStack_4c = (uint)*(byte *)(iVar3 + 0x2e);
        local_50 = 0x43300000;
        *(float *)(iVar2 + iVar8 + 0xc) =
             lbl_803E1290 *
             (float)((double)(f32)(s32)uStack_4c *
                    dVar11);
        uStack_44 = (int)*(char *)(iVar3 + 0x2d) << 8 ^ 0x80000000;
        local_48 = 0x43300000;
        dVar11 = (double)FUN_80293f90();
        uStack_3c = (uint)*(byte *)(iVar3 + 0x2e);
        local_40 = 0x43300000;
        *(float *)(param_3 + iVar8 + 0xc) =
             lbl_803E1290 *
             (float)((double)(f32)(s32)uStack_3c *
                    dVar11);
        uStack_34 = (int)*(char *)(iVar3 + 0x2c) << 8 ^ 0x80000000;
        local_38 = 0x43300000;
        dVar11 = (double)FUN_80294964();
        uStack_2c = (uint)*(byte *)(iVar3 + 0x2e);
        local_30 = 0x43300000;
        iVar10 = iVar10 + 4;
        iVar8 = iVar8 + 0x10;
        *(float *)(param_4 + iVar9 * 4) =
             lbl_803E1290 *
             (float)((double)(f32)(s32)uStack_2c *
                    dVar11);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: RomCurve_countRandomPoints
 * EN v1.0 Address: 0x800E3AD4
 * EN v1.0 Size: 536b
 * EN v1.1 Address: 0x800E45B4
 * EN v1.1 Size: 672b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int RomCurve_countRandomPoints(RomCurveDef *curve)
{
  u32 linkIds[ROMCURVE_LINK_COUNT];
  u32 *linkIdList;
  u32 linkId;
  int linkCount;
  int count;
  int low;
  int high;
  int mid;
  int mask;
  RomCurveDef *nextCurve;

  count = 1;
  linkIdList = linkIds;
  goto checkCurve;

chooseNext:
  linkCount = 0;
  mask = 1;
  linkId = curve->linkIds[0];
  if (((s32)linkId > -1) && ((curve->blockedLinkMask & mask) == 0) && (linkId != 0)) {
    linkCount = 1;
    linkIdList[0] = linkId;
  }
  mask <<= 1;
  linkId = curve->linkIds[1];
  if (((s32)linkId > -1) && ((curve->blockedLinkMask & mask) == 0) && (linkId != 0)) {
    linkIdList[linkCount] = linkId;
    linkCount++;
  }
  mask <<= 1;
  linkId = curve->linkIds[2];
  if (((s32)linkId > -1) && ((curve->blockedLinkMask & mask) == 0) && (linkId != 0)) {
    linkIdList[linkCount] = linkId;
    linkCount++;
  }
  mask <<= 1;
  linkId = curve->linkIds[3];
  if (((s32)linkId > -1) && ((curve->blockedLinkMask & mask) == 0) && (linkId != 0)) {
    linkIdList[linkCount] = linkId;
    linkCount++;
  }

  if (linkCount == 0) {
    linkId = ROMCURVE_LINK_ID_NONE;
  } else {
    linkId = linkIdList[randomGetRange(0, linkCount - 1)];
  }

  if ((s32)linkId < 0) {
    curve = NULL;
  } else {
    high = nRomCurves - 1;
    low = 0;
    while (low <= high) {
      mid = (high + low) >> 1;
      nextCurve = romCurves[mid];
      if (linkId > nextCurve->id) {
        low = mid + 1;
      } else if (linkId < nextCurve->id) {
        high = mid - 1;
      } else {
        curve = nextCurve;
        goto foundCurve;
      }
    }
    curve = NULL;
  }

foundCurve:
  if (curve != NULL) {
    count++;
  }

checkCurve:
  if (curve == NULL) {
    return count;
  }
  mask = 1;
  if (((s32)curve->linkIds[0] != -1) && ((curve->blockedLinkMask & mask) == 0)) {
    goto chooseNext;
  }
  mask <<= 1;
  if (((s32)curve->linkIds[1] != -1) && ((curve->blockedLinkMask & mask) == 0)) {
    goto chooseNext;
  }
  mask <<= 1;
  if (((s32)curve->linkIds[2] != -1) && ((curve->blockedLinkMask & mask) == 0)) {
    goto chooseNext;
  }
  mask <<= 1;
  if (((s32)curve->linkIds[3] != -1) && ((curve->blockedLinkMask & mask) == 0)) {
    goto chooseNext;
  }
  return count;
}

/*
 * --INFO--
 *
 * Function: RomCurve_func1E
 * EN v1.0 Address: 0x800E3CEC
 * EN v1.0 Size: 492b
 * EN v1.1 Address: 0x800E4854
 * EN v1.1 Size: 500b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void RomCurve_func1E(undefined4 param_1,undefined4 param_2,float *param_3,float *param_4)
{
  uint *puVar1;
  float *pfVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  float *pfVar9;
  float *pfVar10;
  int *piVar11;
  uint uVar12;
  int iVar13;
  undefined8 uVar14;
  int local_28 [10];
  
  uVar14 = FUN_8028683c();
  pfVar2 = (float *)uVar14;
  iVar4 = 0;
  piVar3 = local_28;
  iVar13 = 4;
  pfVar9 = param_4;
  pfVar10 = param_3;
  piVar11 = piVar3;
  do {
    puVar1 = (uint *)((ulonglong)uVar14 >> 0x20);
    uVar12 = *puVar1;
    if ((int)uVar12 < 0) {
      iVar8 = 0;
    }
    else {
      iVar7 = nRomCurves + -1;
      iVar5 = 0;
      while (iVar5 <= iVar7) {
        iVar6 = iVar7 + iVar5 >> 1;
        iVar8 = (int)romCurves[iVar6];
        if (*(uint *)(iVar8 + 0x14) < uVar12) {
          iVar5 = iVar6 + 1;
        }
        else {
          if (*(uint *)(iVar8 + 0x14) <= uVar12) goto LAB_800e48f4;
          iVar7 = iVar6 + -1;
        }
      }
      iVar8 = 0;
    }
LAB_800e48f4:
    *piVar11 = iVar8;
    iVar5 = *piVar11;
    if (iVar5 != 0) {
      *(undefined4 *)uVar14 = *(undefined4 *)(iVar5 + 8);
      *pfVar10 = *(float *)(iVar5 + 0xc);
      *pfVar9 = *(float *)(iVar5 + 0x10);
      iVar4 = iVar4 + 1;
    }
    piVar11 = piVar11 + 1;
    uVar14 = CONCAT44(puVar1 + 1,(undefined4 *)uVar14 + 1);
    pfVar10 = pfVar10 + 1;
    pfVar9 = pfVar9 + 1;
    iVar13 = iVar13 + -1;
    if (iVar13 == 0) {
      if (((1 < iVar4) && (local_28[1] != 0)) && (local_28[2] != 0)) {
        iVar4 = 0;
        iVar13 = 4;
        do {
          if (*piVar3 == 0) {
            if (iVar4 == 0) {
              *pfVar2 = *(float *)(local_28[1] + 8) +
                        (*(float *)(local_28[1] + 8) - *(float *)(local_28[2] + 8));
              *param_3 = *(float *)(local_28[1] + 0xc) +
                         (*(float *)(local_28[1] + 0xc) - *(float *)(local_28[2] + 0xc));
              *param_4 = *(float *)(local_28[1] + 0x10) +
                         (*(float *)(local_28[1] + 0x10) - *(float *)(local_28[2] + 0x10));
            }
            else if (iVar4 == 3) {
              *pfVar2 = *(float *)(local_28[2] + 8) +
                        (*(float *)(local_28[2] + 8) - *(float *)(local_28[1] + 8));
              *param_3 = *(float *)(local_28[2] + 0xc) +
                         (*(float *)(local_28[2] + 0xc) - *(float *)(local_28[1] + 0xc));
              *param_4 = *(float *)(local_28[2] + 0x10) +
                         (*(float *)(local_28[2] + 0x10) - *(float *)(local_28[1] + 0x10));
            }
          }
          piVar3 = piVar3 + 1;
          pfVar2 = pfVar2 + 1;
          param_3 = param_3 + 1;
          param_4 = param_4 + 1;
          iVar4 = iVar4 + 1;
          iVar13 = iVar13 + -1;
        } while (iVar13 != 0);
      }
      FUN_80286888();
      return;
    }
  } while( true );
}

/*
 * --INFO--
 *
 * Function: RomCurve_getAdjacentWindow
 * EN v1.0 Address: 0x800E47C4
 * EN v1.0 Size: 572b
 * EN v1.1 Address: 0x800E4A48
 * EN v1.1 Size: 572b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void RomCurve_getAdjacentWindow(RomCurveDef *curve,int *outIds)
{
  u32 linkId;
  u32 adjacentId;
  int low;
  int high;
  int mid;
  int i;
  RomCurveDef *adjacent;

  outIds[0] = ROMCURVE_LINK_ID_NONE;
  outIds[1] = ROMCURVE_LINK_ID_NONE;
  outIds[2] = ROMCURVE_LINK_ID_NONE;
  outIds[3] = ROMCURVE_LINK_ID_NONE;
  if (curve == NULL) {
    return;
  }

  outIds[1] = curve->id;
  for (i = 0; i < ROMCURVE_LINK_COUNT; i++) {
    linkId = curve->linkIds[i];
    if (linkId != ROMCURVE_LINK_ID_NONE) {
      if ((curve->blockedLinkMask & (1 << i)) != 0) {
        outIds[0] = linkId;
      } else {
        outIds[2] = linkId;
      }
    }
  }

  adjacentId = outIds[2];
  if ((s32)adjacentId <= -1) {
    return;
  }
  if ((s32)adjacentId < 0) {
    adjacent = NULL;
  } else {
    high = nRomCurves - 1;
    low = 0;
    while (low <= high) {
      mid = (high + low) >> 1;
      adjacent = romCurves[mid];
      if (adjacentId > adjacent->id) {
        low = mid + 1;
      } else if (adjacentId < adjacent->id) {
        high = mid - 1;
      } else {
        goto foundAdjacent;
      }
    }
    adjacent = NULL;
  }

foundAdjacent:
  if (adjacent == NULL) {
    return;
  }

  for (i = 0; i < ROMCURVE_LINK_COUNT; i++) {
    linkId = adjacent->linkIds[i];
    if (linkId != ROMCURVE_LINK_ID_NONE) {
      if ((adjacent->blockedLinkMask & (1 << i)) == 0) {
        outIds[3] = linkId;
      }
    }
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: RomCurve_getNearestAdjacentLink
 * EN v1.0 Address: 0x800E4A00
 * EN v1.0 Size: 484b
 * EN v1.1 Address: 0x800E4C84
 * EN v1.1 Size: 484b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int RomCurve_getNearestAdjacentLink(f32 x,f32 y,f32 z,RomCurveDef *curve,int excludeLinkId)
{
  f32 bestDistance[2];
  int bestLink[2];
  f32 segment[9];
  f32 dx;
  f32 dy;
  f32 dz;
  f32 distance;
  u32 linkId;
  int linkIndex;
  int slot;
  int low;
  int high;
  int mid;
  RomCurveDef *linkedCurve;

  bestLink[1] = ROMCURVE_LINK_ID_NONE;
  bestLink[0] = ROMCURVE_LINK_ID_NONE;
  bestDistance[1] = gFloatZero;
  bestDistance[0] = gFloatZero;
  segment[0] = curve->x;
  segment[1] = curve->y;
  segment[2] = curve->z;

  for (linkIndex = 0; linkIndex < ROMCURVE_LINK_COUNT; linkIndex++) {
    linkId = curve->linkIds[linkIndex];
    if ((s32)linkId > -1) {
      if ((s32)linkId < 0) {
        linkedCurve = NULL;
      } else {
        high = nRomCurves - 1;
        low = 0;
        while (low <= high) {
          mid = (high + low) >> 1;
          linkedCurve = romCurves[mid];
          if (linkId > linkedCurve->id) {
            low = mid + 1;
          } else if (linkId < linkedCurve->id) {
            high = mid - 1;
          } else {
            goto foundLinkedCurve;
          }
        }
        linkedCurve = NULL;
      }

foundLinkedCurve:
      if (linkedCurve != NULL) {
        segment[3] = linkedCurve->x;
        segment[4] = linkedCurve->y;
        segment[5] = linkedCurve->z;
        RomCurve_distanceToSegment(x,y,z,segment);
        dz = segment[8] - z;
        dx = segment[6] - x;
        dy = segment[7] - y;
        distance = dz * dz + dx * dx + dy * dy;
        slot = countLeadingZeros(excludeLinkId - linkId) >> 5;
        if (bestDistance[slot] < distance) {
          bestDistance[slot] = distance;
          bestLink[slot] = curve->linkIds[linkIndex];
        }
      }
    }
  }

  if ((bestLink[0] == ROMCURVE_LINK_ID_NONE) &&
      (bestLink[0] = bestLink[1], bestLink[1] == ROMCURVE_LINK_ID_NONE)) {
    bestLink[0] = ROMCURVE_LINK_ID_NONE;
  }
  return bestLink[0];
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: RomCurve_distanceToSegment
 * EN v1.0 Address: 0x800E4BE4
 * EN v1.0 Size: 324b
 * EN v1.1 Address: 0x800E4E68
 * EN v1.1 Size: 324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
f32 RomCurve_distanceToSegment(f32 x,f32 y,f32 z,float *segment)
{
  f32 startX;
  f32 startY;
  f32 startZ;
  f32 endX;
  f32 endY;
  f32 endZ;
  f32 deltaX;
  f32 deltaY;
  f32 deltaZ;
  f32 projection;
  f32 nearestX;
  f32 nearestY;
  f32 nearestZ;
  f32 diffX;
  f32 diffY;
  f32 diffZ;
  f32 distance;

  endX = segment[3];
  startX = segment[0];
  deltaX = endX - startX;
  endY = segment[4];
  startY = segment[1];
  deltaY = endY - startY;
  endZ = segment[5];
  startZ = segment[2];
  deltaZ = endZ - startZ;
  projection = gFloatZero;
  if (((projection != deltaX) || (projection != deltaY)) || (projection != deltaZ)) {
    projection = (deltaY * (y - startY) + deltaX * (x - startX) + deltaZ * (z - startZ)) /
                 (deltaY * deltaY + deltaX * deltaX + deltaZ * deltaZ);
  }
  if (projection < gFloatZero) {
    nearestX = startX;
    nearestY = startY;
    nearestZ = startZ;
    diffZ = startZ - z;
    diffX = startX - x;
    diffY = startY - y;
    distance = -(diffZ * diffZ + diffX * diffX + diffY * diffY);
  }
  else if (projection > gFloatOne) {
    nearestX = endX;
    nearestY = endY;
    nearestZ = endZ;
    diffZ = endZ - z;
    diffX = endX - x;
    diffY = endY - y;
    distance = -(diffZ * diffZ + diffX * diffX + diffY * diffY);
  }
  else {
    nearestX = projection * deltaX + startX;
    nearestY = projection * deltaY + startY;
    nearestZ = projection * deltaZ + startZ;
    diffZ = nearestZ - z;
    diffX = nearestX - x;
    diffY = nearestY - y;
    distance = diffZ * diffZ + diffX * diffX + diffY * diffY;
  }
  segment[6] = nearestX;
  segment[7] = nearestY;
  segment[8] = nearestZ;
  return distance;
}

/*
 * --INFO--
 *
 * Function: RomCurve_getRandomBlockedLink
 * EN v1.0 Address: 0x800E4D28
 * EN v1.0 Size: 316b
 * EN v1.1 Address: 0x800E4FAC
 * EN v1.1 Size: 472b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int RomCurve_getRandomBlockedLink(RomCurveDef *curve,int excludeLinkId)
{
  int link;
  int count;
  uint mask;
  int i;
  int result;
  int eligibleLinks[ROMCURVE_LINK_COUNT];

  count = 0;
  mask = 1;

  for (i = 0; i < ROMCURVE_LINK_COUNT; i = i + 1) {
    link = curve->linkIds[i];
    if ((-1 < link) && ((curve->blockedLinkMask & mask) != 0) && (link != excludeLinkId)) {
      eligibleLinks[count++] = link;
    }
    mask = mask << 1;
  }

  if (count != 0) {
    result = eligibleLinks[randomGetRange(0, count - 1)];
  } else {
    result = -1;
  }
  return result;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: RomCurve_getLinkIds
 * EN v1.0 Address: 0x800E4E64
 * EN v1.0 Size: 156b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int RomCurve_getLinkIds(RomCurveDef *curve,int excludeLinkId,int *outIds)
{
  int count;
  int linkId;

  count = 0;
  linkId = curve->linkIds[0];
  if (RomCurve_IsLinkIdValid(linkId) && linkId != excludeLinkId) {
    outIds[count++] = linkId;
  }
  linkId = curve->linkIds[1];
  if (RomCurve_IsLinkIdValid(linkId) && linkId != excludeLinkId) {
    outIds[count++] = linkId;
  }
  linkId = curve->linkIds[2];
  if (RomCurve_IsLinkIdValid(linkId) && linkId != excludeLinkId) {
    outIds[count++] = linkId;
  }
  linkId = curve->linkIds[3];
  if (RomCurve_IsLinkIdValid(linkId) && linkId != excludeLinkId) {
    outIds[count++] = linkId;
  }
  return count;
}

/*
 * --INFO--
 *
 * Function: RomCurve_getRandomUnblockedLink
 * EN v1.0 Address: 0x800E4F00
 * EN v1.0 Size: 316b
 * EN v1.1 Address: 0x800E5184
 * EN v1.1 Size: 428b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int RomCurve_getRandomUnblockedLink(RomCurveDef *curve,int excludeLinkId)
{
  int link;
  int count;
  uint mask;
  int i;
  int result;
  int eligibleLinks[ROMCURVE_LINK_COUNT];

  count = 0;
  mask = 1;

  for (i = 0; i < ROMCURVE_LINK_COUNT; i = i + 1) {
    link = curve->linkIds[i];
    if ((-1 < link) && ((curve->blockedLinkMask & mask) == 0) && (link != excludeLinkId)) {
      eligibleLinks[count++] = link;
    }
    mask = mask << 1;
  }

  if (count != 0) {
    result = eligibleLinks[randomGetRange(0, count - 1)];
  } else {
    result = -1;
  }
  return result;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: RomCurve_getById
 * EN v1.0 Address: 0x800E503C
 * EN v1.0 Size: 112b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
RomCurveDef *RomCurve_getById(uint curveId)
{
  int high;
  int low;
  int mid;

  if ((int)curveId < 0) {
    return 0;
  }
  high = nRomCurves - 1;
  low = 0;
  while (high >= low) {
    mid = (high + low) >> 1;
    if (curveId > RomCurve_GetId(romCurves[mid])) {
      low = mid + 1;
    }
    else if (curveId < RomCurve_GetId(romCurves[mid])) {
      high = mid - 1;
    }
    else {
      return (RomCurveDef *)romCurves[mid];
    }
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: RomCurve_find
 * EN v1.0 Address: 0x800E4628
 * EN v1.0 Size: 252b
 * EN v1.1 Address: 0x800E5330
 * EN v1.1 Size: 572b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int RomCurve_find(int *types,int typeCount,f32 x,f32 y,f32 z,int action)
{
  RomCurveDef *curve;
  RomCurveDef *bestCurve;
  RomCurveDef *bestActionCurve;
  f32 bestDistance;
  f32 bestActionDistance;
  f32 distance;
  f32 point[3];
  int curveIndex;
  int typeIndex;

  bestDistance = lbl_803E0664;
  bestCurve = NULL;
  bestActionDistance = bestDistance;
  bestActionCurve = NULL;
  point[0] = x;
  point[1] = y;
  point[2] = z;
  for (curveIndex = 0; curveIndex < nRomCurves; curveIndex++) {
    curve = romCurves[curveIndex];
    typeIndex = 0;
    do {
      if ((typeCount <= 0) || (curve->type == types[typeIndex])) {
        distance = vec3f_distanceSquared(point,&curve->x);
        if (distance < bestDistance) {
          bestDistance = distance;
          bestCurve = curve;
        }
        if ((curve->action == action) && (distance < bestActionDistance)) {
          bestActionDistance = distance;
          bestActionCurve = curve;
        }
        typeIndex = typeCount;
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
 * Function: curves_remove
 * EN v1.0 Address: 0x800E51EC
 * EN v1.0 Size: 252b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void curves_remove(RomCurveDef *curve)
{
  RomCurveDef **slot;
  int count;
  int index;
  u32 remaining;

  index = 0;
  slot = romCurves;
  count = nRomCurves;
  while ((index < count) &&
         (curve->id != (*slot)->id)) {
    slot = slot + 1;
    index = index + 1;
  }

  if (index >= count) {
    return;
  }

  count = nRomCurves - 1;
  nRomCurves = count;
  slot = romCurves + index;
  remaining = count - index;
  if (index >= count) {
    return;
  }
  for (; remaining != 0; remaining--) {
    slot[0] = slot[1];
    slot = slot + 1;
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: curves_addCurveDef
 * EN v1.0 Address: 0x800E52E8
 * EN v1.0 Size: 312b
 * EN v1.1 Address: 0x800E556C
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 *
 * Retail source-tag string: Hcurves.c: MAX_ROMCURVES exceeded!!
 */
void curves_addCurveDef(RomCurveDef *curve)
{
  RomCurveDef **slot;
  RomCurveDef **shiftSlot;
  int count;
  int insertIndex;

  count = nRomCurves;
  if (count == ROMCURVE_MAX_CURVES) {
    OSReport(sCurvesMaxRomCurvesExceeded);
    return;
  }

  insertIndex = 0;
  slot = romCurves;
  while ((insertIndex < count) && (curve->id > (*slot)->id)) {
    slot++;
    insertIndex++;
  }

  for (shiftSlot = romCurves + count; insertIndex < count; count--) {
    shiftSlot[0] = shiftSlot[-1];
    shiftSlot--;
  }

  nRomCurves++;
  romCurves[insertIndex] = curve;
}

/*
 * --INFO--
 *
 * Function: curves_countRandomPoints
 * EN v1.0 Address: 0x800E5434
 * EN v1.0 Size: 624b
 * EN v1.1 Address: 0x800E56B8
 * EN v1.1 Size: 624b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void curves_countRandomPoints(int obj,uint *curve)
{
  bool bVar1;
  int iVar2;
  int iVar3;
  float *pfVar4;
  uint *puVar5;
  undefined4 *puVar6;
  uint uVar7;
  int iVar8;
  float *pfVar9;
  uint *puVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  undefined4 *local_98;
  float local_94 [5];

  iVar2 = obj;
  puVar5 = curve;
  if ((int)(uint)*(byte *)(puVar5 + 0x97) >> 4 == 4) {
    dVar12 = (double)lbl_803E12E8;
    uVar7 = 0;
    pfVar9 = local_94;
    puVar10 = puVar5;
    dVar13 = dVar12;
    dVar14 = dVar12;
    dVar15 = dVar12;
    for (iVar8 = 0; dVar11 = DOUBLE_803e12f0, iVar8 < (int)(uint)*(byte *)(puVar5 + 0x97) >> 4;
        iVar8 = iVar8 + 1) {
      *pfVar9 = *(float *)(puVar10 + 3);
      iVar3 = hitDetectFn_80065e50(iVar2,*(float *)(puVar10 + 2),*(float *)(iVar2 + 0x1c),
                          *(float *)(puVar10 + 4),&local_98,-1,0);
      bVar1 = false;
      if ((iVar3 != 0) && (puVar6 = local_98, 0 < iVar3)) {
        do {
          if (!bVar1) {
            pfVar4 = (float *)*puVar6;
            dVar11 = (double)*pfVar4;
            if ((dVar11 < (double)(lbl_803E12EC + *(float *)(iVar2 + 0x1c))) &&
               (*(char *)(pfVar4 + 5) != '\x0e')) {
              *pfVar9 = *pfVar4;
              dVar15 = (double)(float)(dVar15 + (double)pfVar4[1]);
              dVar14 = (double)(float)(dVar14 + (double)pfVar4[2]);
              dVar13 = (double)(float)(dVar13 + (double)pfVar4[3]);
              dVar12 = (double)(float)(dVar12 + dVar11);
              uVar7 = uVar7 + 1;
              bVar1 = true;
            }
          }
          iVar3 = iVar3 + -1;
          puVar6 = puVar6 + 1;
        } while (iVar3 != 0);
      }
      *(float *)(puVar10 + 3) = *pfVar9;
      puVar10 = puVar10 + 3;
      pfVar9 = pfVar9 + 1;
    }
    if (uVar7 == 0) {
      *(undefined *)((int)puVar5 + 0x261) = 0;
    }
    else {
      *(f32 *)(iVar2 + 0x1c) = (f32)(dVar12 / (f64)(f32)(s32)uVar7);
      *(f32 *)(puVar5 + 0x68) = (f32)(dVar15 / (f64)(f32)(s32)uVar7);
      *(f32 *)(puVar5 + 0x69) = (f32)(dVar14 / (f64)(f32)(s32)uVar7);
      *(f32 *)(puVar5 + 0x6a) = (f32)(dVar13 / (f64)(f32)(s32)uVar7);
      *(u8 *)((int)puVar5 + 0x261) = 1;
    }
    dVar14 = (double)(*(float *)(puVar5[1] + 0x2c) - *(float *)(puVar5[1] + 8));
    dVar13 = (double)(local_94[3] - local_94[0]);
    getAngle((float)dVar13,(float)dVar14);
    iVar8 = getAngle((float)dVar13,(float)dVar14);
    *(short *)(iVar2 + 2) = -(short)iVar8;
    if ((*puVar5 & 0x400) != 0) {
      iVar8 = getAngle(local_94[1] - local_94[0],
                       *(float *)(puVar5[1] + 0xc) - *(float *)puVar5[1]);
      *(short *)(iVar2 + 4) = (short)iVar8;
    }
  }
}

/*
 * --INFO--
 *
 * Function: FUN_800e49c0
 * EN v1.0 Address: 0x800E49C0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800E5928
 * EN v1.1 Size: 600b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e49c0(int param_1,uint *param_2)
{
}

void fn_800E56A4(int obj,f32 *state)
{
  RomCurvePoint *point;
  RomCurvePoint *points;
  u32 hitCount;
  int pointIndex;
  f32 delta[3];
  CurvesHitScratch hitScratch;
  f32 startX;
  f32 startZ;

  startX = state[5];
  startZ = state[7];
  if ((*(s32 *)state & 0x100000) == 0) {
    *(f32 *)(obj + 0x18) = startX;
    *(f32 *)(obj + 0x20) = startZ;
    *(f32 *)(obj + 0x1c) = state[3];
  }

  points = curves_getCurves(state[5],state[7],obj,&hitCount,0);
  point = points;
  pointIndex = 0;
  while (pointIndex < (int)hitCount) {
    if (((s8)point->type != 0xe) && (point->z > lbl_803E0678) &&
        (point->x <= state[6]) && (point->x > state[3])) {
      state[0xe] = state[5];
      state[0xf] = state[6];
      state[0x10] = state[7];
      state[2] = state[5];
      state[3] = points[pointIndex].x;
      state[4] = state[7];
      hitDetectFn_80067958(obj,state + 0xe,state + 2,1,state + 0x1a,0);
      break;
    }
    point++;
    pointIndex++;
  }

  if (*(s16 *)(obj + 0x44) == 1) {
    state[0x14] = state[5];
    state[0x15] = state[6];
    state[0x16] = state[7];
    state[8] = state[5];
    state[9] = lbl_803E067C + state[6];
    state[10] = state[7];
    hitScratch.scale = lbl_803E0680;
    hitScratch.type = 3;
    hitDetectFn_80067958(obj,state + 0x14,state + 8,1,&hitScratch,0);
  }

  PSVECSubtract((f32 *)(state + 2),(f32 *)(state + 5),delta);
  if (((*(s32 *)state & 0x8000000) != 0) || (PSVECMag(delta) > lbl_803E0684)) {
    state[0xe] = state[5];
    state[0xf] = state[6];
    state[0x10] = state[7];
    state[2] = state[5];
    state[3] = state[6] - lbl_803E0688;
    state[4] = state[7];
    hitDetectFn_80067958(obj,state + 0xe,state + 2,1,state + 0x1a,0);
  }

  state[0x68] = state[0x1a];
  state[0x69] = state[0x1b];
  state[0x6a] = state[0x1c];
  ((u32 *)state)[0x36] = ((u32 *)state)[0x31];
  if (((u32 *)state)[0x36] != 0) {
    ObjHits_AddContactObject(((u32 *)state)[0x36],obj);
  }
}

/*
 * --INFO--
 *
 * Function: fn_800E58FC
 * EN v1.0 Address: 0x800E49C4
 * EN v1.0 Size: 672b
 * EN v1.1 Address: 0x800E5B80
 * EN v1.1 Size: 960b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_800E58FC(int obj,f32 *state)
{
  CurvesTransformScratch transform;
  f32 localX[4];
  f32 localY[4];
  f32 localZ[4];
  f32 matrix[16];
  f32 averageScale;
  f32 zero;
  u8 pointCount;
  s32 pointLimit;
  s16 pointIndex;
  s8 idx1;
  s8 idx2;
  s8 idx3;
  f32 *pointX;
  f32 *pointYZ;
  f32 *point;
  f32 *outZ;
  f32 *outY;
  f32 *outX;
  s16 angle;

  state[0x68] = state[0x1a];
  state[0x69] = state[0x1b];
  state[0x6a] = state[0x1c];
  pointCount = *(u8 *)((u8 *)state + 0x25c) >> 4;
  if ((pointCount == 2) || (pointCount == 4)) {
    zero = lbl_803E0668;
    *(f32 *)(obj + 0x18) = zero;
    *(f32 *)(obj + 0x1c) = zero;
    *(f32 *)(obj + 0x20) = zero;

    pointX = state;
    pointYZ = state;
    pointLimit = pointCount * 3;
    for (pointIndex = 0; pointIndex < pointLimit; pointIndex += 3) {
      *(f32 *)(obj + 0x18) += pointX[2];
      *(f32 *)(obj + 0x1c) += pointYZ[3];
      *(f32 *)(obj + 0x20) += pointYZ[4];
      pointX += 3;
      pointYZ += 3;
    }

    averageScale = lbl_803E068C / (f32)pointCount;
    *(f32 *)(obj + 0x18) *= averageScale;
    *(f32 *)(obj + 0x1c) *= averageScale;
    *(f32 *)(obj + 0x20) *= averageScale;

    if ((*(u32 *)state & 0x8600) != 0) {
      transform.angles[0] = -*(s16 *)obj;
      transform.angles[1] = -*(s16 *)(obj + 2);
      transform.angles[2] = -*(s16 *)(obj + 4);
      transform.scale = lbl_803E068C;
      transform.x = -*(f32 *)(obj + 0x18);
      transform.y = -*(f32 *)(obj + 0x1c);
      transform.z = -*(f32 *)(obj + 0x20);
      mtxRotateByVec3s(matrix,transform.angles);

      outZ = localZ;
      outY = localY;
      outX = localX;
      point = state;
      for (pointIndex = 0; pointIndex < (s32)pointCount; pointIndex++) {
        Matrix_TransformPoint(matrix,point[2],point[3],point[4],outX,outY,outZ);
        point += 3;
        outZ++;
        outY++;
        outX++;
      }

      idx1 = 1;
      idx2 = 2;
      idx3 = 3;
      if (pointCount == 2) {
        idx1 = 0;
        idx2 = 1;
        idx3 = 1;
      }
      if ((*(u32 *)state & 0x8000) != 0) {
        angle = getAngle((localX[0] + localX[idx1]) - (localX[idx2] + localX[idx3]),
                         (localZ[0] + localZ[idx1]) - (localZ[idx2] + localZ[idx3]));
        *(s16 *)obj += (s16)(angle - 0x8000) >> 2;
      }
      if ((*(u32 *)state & 0x200) != 0) {
        angle = getAngle(((localY[idx2] - localY[idx1]) + (localY[idx3] - localY[0])) *
                             lbl_803E0690,
                         ((localZ[idx2] - localZ[idx1]) + (localZ[idx3] - localZ[0])) *
                             lbl_803E0690);
        *(s16 *)((u8 *)state + 0x198) = -angle;
      }
      if ((pointCount == 4) && ((*(u32 *)state & 0x400) != 0)) {
        angle = getAngle(((localY[idx1] - localY[0]) + (localY[idx2] - localY[idx3])) *
                             lbl_803E0690,
                         ((localX[idx1] - localX[0]) + (localX[idx2] - localX[idx3])) *
                             lbl_803E0690);
        *(s16 *)((u8 *)state + 0x19a) = angle;
      }
    }
  }
  else {
    *(f32 *)(obj + 0x18) = state[2];
    *(f32 *)(obj + 0x1c) = state[3];
    *(f32 *)(obj + 0x20) = state[4];
  }
}

/*
 * --INFO--
 *
 * Function: fn_800E5CBC
 * EN v1.0 Address: 0x800E4C64
 * EN v1.0 Size: 336b
 * EN v1.1 Address: 0x800E5F40
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_800E5CBC(short *param_1,int param_2)
{
  float fVar1;
  short sVar2;
  int iVar3;
  float local_70;
  float local_74;
  float local_78;
  short local_6c [4];
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float afStack_54 [20];
  
  if ((*(char *)(param_2 + 0x260) & 0x10) != 0) {
    local_6c[0] = -*param_1;
    if (*(short **)(param_1 + 0x18) != (short *)0x0) {
      local_6c[0] = local_6c[0] - **(short **)(param_1 + 0x18);
    }
    local_6c[1] = 0;
    local_6c[2] = 0;
    local_64 = lbl_803E068C;
    local_60 = lbl_803E0668;
    local_5c = lbl_803E0668;
    local_58 = lbl_803E0668;
    mtxRotateByVec3s(afStack_54,local_6c);
    Matrix_TransformPoint(afStack_54,(double)*(float *)(param_2 + 0x1a0),
                 (double)*(float *)(param_2 + 0x1a4),(double)*(float *)(param_2 + 0x1a8),
                 &local_70,&local_74,&local_78);
    iVar3 = getAngle(local_74,local_78);
    sVar2 = 0x4000 - (short)iVar3;
    *(short *)(param_2 + 0x19c) = sVar2;
    *(short *)(param_2 + 0x198) =
         *(short *)(param_2 + 0x198) +
         ((int)((uint)framesThisStep * ((int)sVar2 - (int)*(short *)(param_2 + 0x198))) >> 3);
    iVar3 = getAngle(local_74,local_70);
    sVar2 = -(0x4000 - (short)iVar3);
    *(short *)(param_2 + 0x19e) = sVar2;
    *(short *)(param_2 + 0x19a) =
         *(short *)(param_2 + 0x19a) +
         ((int)((uint)framesThisStep * ((int)sVar2 - (int)*(short *)(param_2 + 0x19a))) >> 3);
  }
  else {
    *(short *)(param_2 + 0x198) =
         *(short *)(param_2 + 0x198) -
         ((int)((int)*(short *)(param_2 + 0x198) * (uint)framesThisStep) >> 3);
    *(short *)(param_2 + 0x19a) =
         *(short *)(param_2 + 0x19a) -
         ((int)((int)*(short *)(param_2 + 0x19a) * (uint)framesThisStep) >> 3);
    fVar1 = lbl_803E0668;
    *(float *)(param_2 + 0x1a0) = lbl_803E0668;
    *(float *)(param_2 + 0x1a4) = lbl_803E068C;
    *(float *)(param_2 + 0x1a8) = fVar1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: fn_800E5E38
 * EN v1.0 Address: 0x800E5E38
 * EN v1.0 Size: 228b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_800E5E38(int obj,f32 *state)
{
  u32 hitCount;
  int hitIndex;
  f32 currentY;
  f32 window;
  RomCurvePoint *point;

  point = curves_getCurves(state[2],state[4],obj,&hitCount,0);
  hitIndex = hitCount - 1;
  currentY = *(f32 *)(obj + 0x1c);
  window = lbl_803E06A0;
  point = point + hitIndex;
  while (hitIndex >= 0) {
    if ((s8)point->type != 0xe) {
      if ((currentY <= point->x) && (currentY >= (point->x - window))) {
        *(f32 *)(obj + 0x1c) = point->x;
        *(f32 *)((u8 *)state + 0x1a0) = point->y;
        *(f32 *)((u8 *)state + 0x1a4) = point->z;
        *(f32 *)((u8 *)state + 0x1a8) = point->w;
        *(s8 *)((u8 *)state + 0x260) = *(s8 *)((u8 *)state + 0x260) | 0x11;
        (*(u8 *)((u8 *)state + 0x261))++;
      }
      window = lbl_803E0688;
    }
    point--;
    hitIndex--;
  }
}

/*
 * --INFO--
 *
 * Function: fn_800E5F1C
 * EN v1.0 Address: 0x800E5F1C
 * EN v1.0 Size: 624b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_800E5F1C(int obj,f32 *state)
{
  u32 hitCount;
  int i;
  s8 foundBelow;
  RomCurvePoint *point;
  RomCurvePoint *points;
  f32 topSentinel;
  f32 floorSentinel;
  f32 zero;
  f32 one;

  topSentinel = lbl_803E06A4;
  floorSentinel = lbl_803E06A8;
  zero = lbl_803E0668;
  one = lbl_803E068C;
  foundBelow = 0;
  points = curves_getCurves(state[2],state[4],obj,&hitCount,0);
  *(f32 *)((u8 *)state + 0x200) = topSentinel;
  *(f32 *)((u8 *)state + 0x1f0) = topSentinel;
  *(f32 *)((u8 *)state + 0x1d0) = floorSentinel;
  *(f32 *)((u8 *)state + 0x1e0) = zero;
  *(f32 *)((u8 *)state + 0x1c0) = zero;
  *(f32 *)((u8 *)state + 0x210) = zero;
  *(f32 *)((u8 *)state + 0x220) = one;
  *(f32 *)((u8 *)state + 0x230) = zero;
  point = points;
  for (i = 0; i < (int)hitCount; i++) {
    if ((s8)point->type != 0xe) {
      if ((foundBelow == 0) && (point->x < (state[3] + lbl_803E06AC)) &&
          (point->z > lbl_803E0678)) {
        *(f32 *)((u8 *)state + 0x1f0) = point->x;
        *(f32 *)((u8 *)state + 0x1c0) = state[3] - point->x;
        if (*(s8 *)((u8 *)state + 0xb8) == -1) {
          *(u8 *)((u8 *)state + 0xb8) = point->type;
        }
        foundBelow = 1;
      }
      else if ((point->x >= (state[3] + lbl_803E06AC)) && (point->z < zero)) {
        *(f32 *)((u8 *)state + 0x1d0) = point->x;
      }
    }
    point++;
  }
  if (foundBelow == 0) {
    *(f32 *)((u8 *)state + 0x1c0) = lbl_803E06B0;
  }
  if (((s8)*(u8 *)((u8 *)state + 0x260) & 0x10) != 0) {
    *(f32 *)((u8 *)state + 0x1c0) = zero;
  }
  point = points;
  for (i = 0; i < (int)hitCount; i++) {
    if (((s8)point->type == 0xe) && (point->z > lbl_803E06B4) &&
        (point->x < *(f32 *)((u8 *)state + 0x1d0)) &&
        (point->x > *(f32 *)((u8 *)state + 0x1f0))) {
      *(f32 *)((u8 *)state + 0x200) = point->x;
      *(f32 *)((u8 *)state + 0x210) = point->y;
      *(f32 *)((u8 *)state + 0x220) = point->z;
      *(f32 *)((u8 *)state + 0x230) = point->w;
    }
    point++;
  }
  if (*(f32 *)((u8 *)state + 0x200) != topSentinel) {
    *(f32 *)((u8 *)state + 0x1e0) = *(f32 *)((u8 *)state + 0x200) - state[3];
  }
  *(f32 *)((u8 *)state + 0x1bc) = *(f32 *)((u8 *)state + 0x200);
  *(f32 *)((u8 *)state + 0x1b8) = *(f32 *)((u8 *)state + 0x1f0);
  *(f32 *)((u8 *)state + 0x1b0) = *(f32 *)((u8 *)state + 0x1d0);
  *(f32 *)((u8 *)state + 0x1b4) = *(f32 *)((u8 *)state + 0x1e0);
  *(f32 *)((u8 *)state + 0x1ac) = *(f32 *)((u8 *)state + 0x1c0);
}

/*
 * --INFO--
 *
 * Function: FUN_800e4db4
 * EN v1.0 Address: 0x800E4DB4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800E60BC
 * EN v1.1 Size: 228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e4db4(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800e4db8
 * EN v1.0 Address: 0x800E4DB8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800E61A0
 * EN v1.1 Size: 624b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e4db8(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: fn_800E618C
 * EN v1.0 Address: 0x800E4DBC
 * EN v1.0 Size: 912b
 * EN v1.1 Address: 0x800E6410
 * EN v1.1 Size: 872b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_800E618C(int obj,f32 *state)
{
  u8 pointCount;
  u8 *stateBytes;
  u32 flags;
  f32 *point;
  f32 *localPoint;
  u32 averageCount;
  u32 chunkCount;
  u32 pointTriples;
  u32 pointTripletDivisor;
  int pointIndex;
  int radiusOffset;
  int mode;
  int localOffset;
  f32 zero;
  f32 averageScale;
  f32 tempX;
  f32 tempZ;
  CurvesTransformScratch transform;
  f32 matrix[16];

  stateBytes = (u8 *)state;
  pointCount = stateBytes[0x25c] & 0xf;
  radiusOffset = 0;
  stateBytes[0x25e] = (u8)radiusOffset;
  pointIndex = 0;
  point = state;
  while (pointIndex < pointCount) {
    if ((s32)(*(u32 *)state & 0x200000) != 0) {
      mode = 2;
    }
    else {
      mode = 4;
    }
    stateBytes[0x25e] |= objBboxFn_800640cc(
        point + 0x45,point + 0x39,*(f32 *)(*(u32 *)(stateBytes + 0xe0) + radiusOffset),mode,
        state + 0x51,obj,stateBytes[0x25d],-1,0,(s8)stateBytes[0x264]) << pointIndex;
    flags = *(u32 *)state;
    if ((s32)(flags & 0x2000000) != 0) {
      if ((s32)(flags & 0x200000) != 0) {
        mode = 2;
      }
      else {
        mode = 4;
      }
      objBboxFn_800640cc(point + 0x45,point + 0x39,
                         *(f32 *)(*(u32 *)(stateBytes + 0xe0) + radiusOffset),mode,
                         state + 0x51,obj,stateBytes[0x263],-1,0,(s8)stateBytes[0x264]);
    }
    radiusOffset += sizeof(f32);
    point += 3;
    pointIndex++;
  }
  if (pointCount > 1) {
    if ((s32)(*(u32 *)state & 0x100000) != 0) {
      goto buildTransform;
    }
    zero = lbl_803E0668;
    *(f32 *)(obj + 0xc) = zero;
    *(f32 *)(obj + 0x14) = zero;
    pointTriples = pointCount * 3;
    pointTripletDivisor = 3;
    averageCount = (pointTriples + 2) / pointTripletDivisor;
    if (pointTriples != 0) {
      chunkCount = averageCount >> 2;
      point = state;
      if (chunkCount != 0) {
        do {
          *(f32 *)(obj + 0xc) += point[0x39];
          *(f32 *)(obj + 0x14) += point[0x3b];
          *(f32 *)(obj + 0xc) += point[0x3c];
          *(f32 *)(obj + 0x14) += point[0x3e];
          *(f32 *)(obj + 0xc) += point[0x3f];
          *(f32 *)(obj + 0x14) += point[0x41];
          *(f32 *)(obj + 0xc) += point[0x42];
          *(f32 *)(obj + 0x14) += point[0x44];
          point += 0xc;
          chunkCount--;
        } while (chunkCount != 0);
        averageCount &= 3;
        if (averageCount == 0) {
          goto scaleAverage;
        }
      }
      do {
        *(f32 *)(obj + 0xc) += point[0x39];
        *(f32 *)(obj + 0x14) += point[0x3b];
        averageCount--;
        point += 3;
      } while (averageCount != 0);
    }
scaleAverage:
    averageScale = lbl_803E068C / (f32)pointCount;
    *(f32 *)(obj + 0xc) *= averageScale;
    *(f32 *)(obj + 0x14) *= averageScale;
  }
  else if ((s32)(*(u32 *)state & 0x100000) == 0) {
    *(f32 *)(obj + 0xc) = state[0x39];
    *(f32 *)(obj + 0x14) = state[0x3b];
  }
buildTransform:
  transform.angles[0] = *(s16 *)obj;
  if ((s32)(*(u32 *)state & 0x20) != 0) {
    transform.angles[1] = 0;
    transform.angles[2] = 0;
  }
  else {
    transform.angles[1] = *(s16 *)(obj + 2);
    transform.angles[2] = *(s16 *)(obj + 4);
  }
  transform.scale = lbl_803E068C;
  transform.x = *(f32 *)(obj + 0xc);
  transform.y = *(f32 *)(obj + 0x10);
  transform.z = *(f32 *)(obj + 0x14);
  setMatrixFromObjectPos(matrix,&transform);
  localOffset = 0;
  point = state;
  for (pointIndex = 0; pointIndex < (pointCount * 3); pointIndex += 3) {
    point[0x45] = point[0x39];
    point[0x47] = point[0x3b];
    localPoint = (f32 *)(*(u32 *)(stateBytes + 0xdc) + localOffset);
    Matrix_TransformPoint(matrix,localPoint[0],localPoint[1],localPoint[2],&tempX,
                          state + pointIndex + 0x46,&tempZ);
    point += 3;
    localOffset += 0xc;
  }
}
/*
 * --INFO--
 *
 * Function: objFn_800e64f4
 * EN v1.0 Address: 0x800E514C
 * EN v1.0 Size: 732b
 * EN v1.1 Address: 0x800E6778
 * EN v1.1 Size: 696b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void objFn_800e64f4(int obj,u32 *state)
{
  u8 *stateBytes;
  u32 flags;
  int matrixSource;
  int pointIndex;
  int pointOffset;
  int pointWordIndex;
  f32 *localPoint;
  f32 *point;
  f32 *height;
  f32 raisedPointOffset;
  f32 resetRange;
  f32 resetMin;
  f32 resetZero;
  CurvesTransformScratch transform;
  f32 matrix[16];

  stateBytes = (u8 *)state;
  if ((s32)(*state & 0x4000000) != 0) {
    if (*(int *)(obj + 0x30) != 0) {
      if ((*(int *)(*(int *)(obj + 0x30) + 0x58) != 0) &&
          (ObjHits_IsObjectEnabled(*(int *)(obj + 0x30)) != 0)) {
        matrixSource = *(int *)(*(int *)(obj + 0x30) + 0x58);
        Matrix_TransformPoint((f32 *)(matrixSource + ((*(u8 *)(matrixSource + 0x10c) + 2) * 0x40)),
                              *(f32 *)(obj + 0xc),*(f32 *)(obj + 0x10),*(f32 *)(obj + 0x14),
                              (f32 *)(obj + 0x18),(f32 *)(obj + 0x1c),(f32 *)(obj + 0x20));
      }
      else {
        Obj_TransformLocalPointToWorld(*(f32 *)(obj + 0xc),*(f32 *)(obj + 0x10),
                                       *(f32 *)(obj + 0x14),(f32 *)(obj + 0x18),
                                       (f32 *)(obj + 0x1c),(f32 *)(obj + 0x20),
                                       *(u32 *)(obj + 0x30));
      }
    }
    else {
      *(f32 *)(obj + 0x18) = *(f32 *)(obj + 0xc);
      *(f32 *)(obj + 0x1c) = *(f32 *)(obj + 0x10);
      *(f32 *)(obj + 0x20) = *(f32 *)(obj + 0x14);
    }
    flags = *state;
    if ((s32)(flags & 0x2000) != 0) {
      transform.angles[0] = *(s16 *)obj;
      if ((s32)(flags & 0x20) != 0) {
        transform.angles[1] = 0;
        transform.angles[2] = 0;
      }
      else {
        transform.angles[1] = *(s16 *)(obj + 2);
        transform.angles[2] = *(s16 *)(obj + 4);
      }
      transform.scale = lbl_803E068C;
      transform.x = *(f32 *)(obj + 0x18);
      transform.y = *(f32 *)(obj + 0x1c);
      transform.z = *(f32 *)(obj + 0x20);
      setMatrixFromObjectPos(matrix,&transform);
      pointIndex = 0;
      pointOffset = 0;
      pointWordIndex = 0;
      while (pointIndex < ((s8)stateBytes[0x25c] >> 4)) {
        localPoint = (f32 *)(state[1] + pointOffset);
        Matrix_TransformPoint(matrix,localPoint[0],localPoint[1],localPoint[2],
                              (f32 *)(state + pointWordIndex + 2),
                              (f32 *)(state + pointWordIndex + 3),
                              (f32 *)(state + pointWordIndex + 4));
        *(s8 *)(stateBytes + pointIndex + 0xb8) = -1;
        pointOffset += 0xc;
        pointWordIndex += 3;
        pointIndex++;
      }
      point = (f32 *)state;
      height = (f32 *)state;
      raisedPointOffset = lbl_803E06B8;
      for (pointIndex = 0; pointIndex < ((s8)stateBytes[0x25c] >> 4); pointIndex++) {
        point[0xe] = point[2];
        point[0xf] = raisedPointOffset + (point[3] + height[0x2a]);
        point[0x10] = point[4];
        point += 3;
        height++;
      }
    }
    if (*(s16 *)(obj + 0x44) == 1) {
      state[8] = *(u32 *)(obj + 0x18);
      state[0x14] = *(u32 *)(obj + 0x18);
      *(f32 *)(state + 9) = lbl_803E06BC + *(f32 *)(obj + 0x1c);
      *(f32 *)(state + 0x15) = *(f32 *)(state + 9);
      state[10] = *(u32 *)(obj + 0x20);
      state[0x16] = *(u32 *)(obj + 0x20);
    }
    stateBytes[0x260] = 0;
    stateBytes[0x25f] = 0;
    resetRange = lbl_803E06A4;
    *(f32 *)(stateBytes + 0x1bc) = resetRange;
    *(f32 *)(stateBytes + 0x1b8) = resetRange;
    resetMin = lbl_803E06A8;
    *(f32 *)(stateBytes + 0x1b0) = resetMin;
    resetZero = lbl_803E0668;
    *(f32 *)(stateBytes + 0x1b4) = resetZero;
    *(f32 *)(stateBytes + 0x1ac) = resetZero;
    state[0x36] = 0;
    point = (f32 *)state;
    for (pointIndex = 0; pointIndex < ((s8)stateBytes[0x25c] >> 4); pointIndex++) {
      point[0x80] = resetRange;
      point[0x7c] = resetRange;
      point[0x74] = resetMin;
      point++;
    }
  }
}

/*
 * --INFO--
 *
 * Function: objFn_800e67ac
 * EN v1.0 Address: 0x800E5428
 * EN v1.0 Size: 328b
 * EN v1.1 Address: 0x800E6A30
 * EN v1.1 Size: 368b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void objFn_800e67ac(int obj,u32 *state)
{
  u8 *stateBytes;
  u32 flags;
  int pointIndex;
  int pointOffset;
  int pointWordIndex;
  f32 *localPoint;
  f32 *point;
  CurvesTransformScratch transform;
  f32 matrix[16];

  stateBytes = (u8 *)state;
  flags = *state;
  if (((s32)(flags & 0x4000000) != 0) && ((s32)(flags & 8) != 0)) {
    transform.angles[0] = *(s16 *)obj;
    if ((s32)(flags & 0x20) != 0) {
      transform.angles[1] = 0;
      transform.angles[2] = 0;
    }
    else {
      transform.angles[1] = *(s16 *)(obj + 2);
      transform.angles[2] = *(s16 *)(obj + 4);
    }
    transform.scale = lbl_803E068C;
    transform.x = *(f32 *)(obj + 0xc);
    transform.y = *(f32 *)(obj + 0x10);
    transform.z = *(f32 *)(obj + 0x14);
    setMatrixFromObjectPos(matrix,&transform);
    pointIndex = 0;
    pointOffset = 0;
    point = (f32 *)state;
    pointWordIndex = 0;
    while (pointIndex < (stateBytes[0x25c] & 0xf)) {
      localPoint = (f32 *)(*(u32 *)(stateBytes + 0xdc) + pointOffset);
      Matrix_TransformPoint(matrix,localPoint[0],localPoint[1],localPoint[2],
                            point + 0x39,(f32 *)(state + pointWordIndex + 0x3a),
                            (f32 *)(state + pointWordIndex + 0x3b));
      point += 3;
      pointOffset += 0xc;
      pointWordIndex += 3;
      pointIndex++;
    }
    point = (f32 *)state;
    for (pointIndex = 0; pointIndex < (stateBytes[0x25c] & 0xf); pointIndex++) {
      point[0x45] = point[0x39];
      point[0x46] = lbl_803E068C + point[0x3a];
      point[0x47] = point[0x3b];
      point += 3;
    }
    fn_80063368(obj);
  }
}

/*
 * --INFO--
 *
 * Function: dll_15_func0A
 * EN v1.0 Address: 0x800E5570
 * EN v1.0 Size: 332b
 * EN v1.1 Address: 0x800E6BA0
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_15_func0A(int obj,u32 *state)
{
  u8 *stateBytes;
  u32 flags;
  int pointIndex;
  int pointOffset;
  int pointWordIndex;
  f32 *localPoint;
  f32 *point;
  CurvesTransformScratch transform;
  f32 matrix[16];

  stateBytes = (u8 *)state;
  objFn_800e64f4(obj,state);
  flags = *state;
  if (((s32)(flags & 0x4000000) != 0) && ((s32)(flags & 8) != 0)) {
    transform.angles[0] = *(s16 *)obj;
    if ((s32)(flags & 0x20) != 0) {
      transform.angles[1] = 0;
      transform.angles[2] = 0;
    }
    else {
      transform.angles[1] = *(s16 *)(obj + 2);
      transform.angles[2] = *(s16 *)(obj + 4);
    }
    transform.scale = lbl_803E068C;
    transform.x = *(f32 *)(obj + 0xc);
    transform.y = *(f32 *)(obj + 0x10);
    transform.z = *(f32 *)(obj + 0x14);
    setMatrixFromObjectPos(matrix,&transform);
    pointIndex = 0;
    pointOffset = 0;
    point = (f32 *)state;
    pointWordIndex = 0;
    while (pointIndex < (stateBytes[0x25c] & 0xf)) {
      localPoint = (f32 *)(*(u32 *)(stateBytes + 0xdc) + pointOffset);
      Matrix_TransformPoint(matrix,localPoint[0],localPoint[1],localPoint[2],
                            point + 0x39,(f32 *)(state + pointWordIndex + 0x3a),
                            (f32 *)(state + pointWordIndex + 0x3b));
      point += 3;
      pointOffset += 0xc;
      pointWordIndex += 3;
      pointIndex++;
    }
    point = (f32 *)state;
    for (pointIndex = 0; pointIndex < (stateBytes[0x25c] & 0xf); pointIndex++) {
      point[0x45] = point[0x39];
      point[0x46] = lbl_803E068C + point[0x3a];
      point[0x47] = point[0x3b];
      point += 3;
    }
    fn_80063368(obj);
  }
}

/*
 * --INFO--
 *
 * Function: dll_15_func0B
 * EN v1.0 Address: 0x800E6A90
 * EN v1.0 Size: 168b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
f32 dll_15_func0B(int obj,f32 x,f32 baseY,f32 z,f32 height)
{
  u32 hitCount;
  int i;
  f32 maxY;
  RomCurvePoint *point;
  RomCurvePoint *points;

  points = curves_getCurves(x,z,obj,&hitCount,1);
  maxY = baseY + height;
  point = points;
  for (i = 0; i < (int)hitCount; i++) {
    if ((point->x < maxY) && (point->z > lbl_803E0668)) {
      return points[i].x;
    }
    point++;
  }
  return baseY;
}

/*
 * --INFO--
 *
 * Function: FUN_800e56bc
 * EN v1.0 Address: 0x800E56BC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800E6D14
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_800e56bc(undefined8 param_1,double param_2,double param_3,double param_4,int param_5)
{
    return 0.0;
}

/*
 * --INFO--
 *
 * Function: curves_getCurves
 * EN v1.0 Address: 0x800E6B38
 * EN v1.0 Size: 428b
 * EN v1.1 Address: 0x800E6DBC
 * EN v1.1 Size: 428b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
RomCurvePoint *
curves_getCurves(f32 x,f32 z,int obj,u32 *outCount,int queryAll)
{
  int queryMode;
  RomCurvePoint *outPoint;
  RomCurvePoint *point;
  uint remaining;
  uint pairCount;
  RomCurvePoint **hitPoints;
  RomCurvePoint **hitPointCursor;
  
  if ((u32)obj != sCurvesCachedHitObj) {
    sCurvesCachedHitObj = obj;
    if (queryAll != 0) {
      queryMode = 1;
    }
    else {
      queryMode = -2;
    }
    sCurvesCachedHitCount = hitDetectFn_80065e50(obj,x,*(float *)(obj + 0x1c),z,
                                                 &hitPoints,queryMode,0);
    if (ROMCURVE_GETCURVES_MAX_POINTS < (int)sCurvesCachedHitCount) {
      sCurvesCachedHitCount = ROMCURVE_GETCURVES_MAX_POINTS;
    }
    remaining = sCurvesCachedHitCount;
    outPoint = sCurvesHitPoints;
    hitPointCursor = hitPoints;
    if (0 < (int)sCurvesCachedHitCount) {
      pairCount = sCurvesCachedHitCount >> 1;
      if (pairCount != 0) {
        do {
          point = *hitPointCursor;
          outPoint->x = point->x;
          outPoint->y = point->y;
          outPoint->z = point->z;
          outPoint->w = point->w;
          outPoint->flags = point->flags;
          outPoint->type = point->type;
          outPoint = outPoint + 1;
          point = hitPointCursor[1];
          outPoint->x = point->x;
          outPoint->y = point->y;
          outPoint->z = point->z;
          outPoint->w = point->w;
          outPoint->flags = point->flags;
          outPoint->type = point->type;
          hitPointCursor = hitPointCursor + 2;
          outPoint = outPoint + 1;
          pairCount = pairCount - 1;
        } while (pairCount != 0);
        remaining = remaining & 1;
        if (remaining == 0) goto LAB_800e6f44;
      }
      do {
        point = *hitPointCursor;
        outPoint->x = point->x;
        outPoint->y = point->y;
        outPoint->z = point->z;
        outPoint->w = point->w;
        outPoint->flags = point->flags;
        outPoint->type = point->type;
        hitPointCursor = hitPointCursor + 1;
        outPoint = outPoint + 1;
        remaining = remaining - 1;
      } while (remaining != 0);
    }
  }
LAB_800e6f44:
  *outCount = sCurvesCachedHitCount;
  return sCurvesHitPoints;
}

/*
 * --INFO--
 *
 * Function: dll_15_func08
 * EN v1.0 Address: 0x800E58B8
 * EN v1.0 Size: 2184b
 * EN v1.1 Address: 0x800E6F68
 * EN v1.1 Size: 2472b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_15_func08(ushort *curveObj,uint *state,uint updateValue,f32 step)
{
  byte bVar1;
  float fVar2;
  float fVar3;
  ushort *puVar4;
  ushort uVar6;
  undefined uVar7;
  uint uVar5;
  uint *puVar8;
  float *pfVar9;
  uint *puVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  double dVar14;
  ushort local_1e8;
  ushort local_1e6;
  ushort local_1e4;
  float local_1e0;
  undefined4 local_1dc;
  undefined4 local_1d8;
  undefined4 local_1d4;
  ushort local_1d0;
  ushort local_1ce;
  ushort local_1cc;
  float local_1c8;
  undefined4 local_1c4;
  undefined4 local_1c0;
  undefined4 local_1bc;
  ushort local_1b8;
  ushort local_1b6;
  ushort local_1b4;
  float local_1b0;
  undefined4 local_1ac;
  undefined4 local_1a8;
  undefined4 local_1a4;
  ushort local_1a0;
  ushort local_19e;
  ushort local_19c;
  float local_198;
  undefined4 local_194;
  undefined4 local_190;
  undefined4 local_18c;
  ushort local_188;
  ushort local_186;
  ushort local_184;
  float local_180;
  undefined4 local_17c;
  undefined4 local_178;
  undefined4 local_174;
  float afStack_170 [16];
  float afStack_130 [16];
  float afStack_f0 [16];
  float afStack_b0 [16];
  float afStack_70 [26];

  fVar3 = lbl_803E130C;
  puVar4 = curveObj;
  puVar8 = state;
  if ((*puVar8 & 0x4000000) == 0) goto LAB_800e78f0;
  dVar14 = (double)(float)((double)lbl_803E130C / step);
  puVar8[0x36] = updateValue;
  fVar2 = lbl_803E12E8;
  if (*(char *)((int)puVar8 + 0x25b) == '\x01') {
    sCurvesCachedHitObj = 0;
    sCurvesCachedHitCount = 0;
    *(f32 *)(puVar8 + 0x68) = lbl_803E12E8;
    *(f32 *)(puVar8 + 0x69) = fVar3;
    *(f32 *)(puVar8 + 0x6a) = fVar2;
    if (((*puVar8 & 8) != 0) && ((*(byte *)(puVar8 + 0x97) & 0xf) != 0)) {
      local_188 = *puVar4;
      if ((*puVar8 & 0x20) == 0) {
        local_186 = puVar4[1];
        local_184 = puVar4[2];
      }
      else {
        local_186 = 0;
        local_184 = 0;
      }
      local_180 = lbl_803E130C;
      local_17c = *(undefined4 *)(puVar4 + 6);
      local_178 = *(undefined4 *)(puVar4 + 8);
      local_174 = *(undefined4 *)(puVar4 + 10);
      setMatrixFromObjectPos(afStack_70,&local_188);
      iVar13 = 0;
      iVar11 = 0;
      puVar10 = puVar8;
      for (iVar12 = 0; iVar12 < (int)(*(byte *)(puVar8 + 0x97) & 0xf); iVar12 = iVar12 + 1) {
        pfVar9 = (float *)(puVar8[0x37] + iVar11);
        Matrix_TransformPoint(afStack_70,(double)*pfVar9,(double)pfVar9[1],
                              (double)pfVar9[2],(float *)(puVar10 + 0x39),
                              (float *)(puVar8 + iVar13 + 0x3a),
                              (float *)(puVar8 + iVar13 + 0x3b));
        puVar10 = puVar10 + 3;
        iVar11 = iVar11 + 0xc;
        iVar13 = iVar13 + 3;
      }
      fn_800E618C((int)puVar4,(f32 *)puVar8);
      iVar11 = *(int *)(puVar4 + 0x18);
      if (iVar11 == 0) {
        *(undefined4 *)(puVar4 + 0xc) = *(undefined4 *)(puVar4 + 6);
        *(undefined4 *)(puVar4 + 0xe) = *(undefined4 *)(puVar4 + 8);
        *(undefined4 *)(puVar4 + 0x10) = *(undefined4 *)(puVar4 + 10);
      }
      else if ((*(int *)(iVar11 + 0x58) == 0) || (uVar6 = ObjHits_IsObjectEnabled(iVar11), uVar6 == 0)) {
        FUN_800068f8((double)*(float *)(puVar4 + 6),(double)*(float *)(puVar4 + 8),
                     (double)*(float *)(puVar4 + 10),(float *)(puVar4 + 0xc),(float *)(puVar4 + 0xe)
                     ,(float *)(puVar4 + 0x10),*(int *)(puVar4 + 0x18));
      }
      else {
        Matrix_TransformPoint((float *)(*(int *)(*(int *)(puVar4 + 0x18) + 0x58) +
                                         (*(byte *)(*(int *)(*(int *)(puVar4 + 0x18) +
                                                            0x58) +
                                                   0x10c) +
                                          2) *
                                             0x40),
                              (double)*(float *)(puVar4 + 6),
                              (double)*(float *)(puVar4 + 8),
                              (double)*(float *)(puVar4 + 10),(float *)(puVar4 + 0xc),
                              (float *)(puVar4 + 0xe),(float *)(puVar4 + 0x10));
      }
    }
    if (((*puVar8 & 0x2000) != 0) && ((*(byte *)(puVar8 + 0x97) & 0xf0) != 0)) {
      local_1a0 = *puVar4;
      if ((*puVar8 & 0x20) == 0) {
        local_19e = puVar4[1];
        local_19c = puVar4[2];
      }
      else {
        local_19e = 0;
        local_19c = 0;
      }
      local_198 = lbl_803E130C;
      local_194 = *(undefined4 *)(puVar4 + 0xc);
      local_190 = *(undefined4 *)(puVar4 + 0xe);
      local_18c = *(undefined4 *)(puVar4 + 0x10);
      setMatrixFromObjectPos(afStack_b0,&local_1a0);
      iVar12 = 0;
      iVar11 = 0;
      puVar10 = puVar8;
      for (iVar13 = 0; iVar13 < (int)(uint)*(byte *)(puVar8 + 0x97) >> 4; iVar13 = iVar13 + 1) {
        pfVar9 = (float *)(puVar8[1] + iVar11);
        Matrix_TransformPoint(afStack_b0,(double)*pfVar9,(double)pfVar9[1],
                              (double)pfVar9[2],(float *)(puVar10 + 2),
                              (float *)(puVar8 + iVar12 + 3),
                              (float *)(puVar8 + iVar12 + 4));
        *(undefined *)((int)puVar8 + iVar13 + 0xb8) = 0xff;
        puVar10 = puVar10 + 3;
        iVar11 = iVar11 + 0xc;
        iVar12 = iVar12 + 3;
      }
      if ((*puVar8 & 2) != 0) {
        uVar7 = FUN_80063a68();
        *(undefined *)(puVar8 + 0x98) = uVar7;
        *(char *)((int)puVar8 + 0x261) = (char)*(undefined2 *)(puVar8 + 0x35);
        *(undefined *)((int)puVar8 + 0x25f) = 0;
      }
      bVar1 = *(byte *)((int)puVar8 + 0x262);
      if (bVar1 == 3) {
          curves_countRandomPoints((int)puVar4,puVar8);
      }
      else if (bVar1 < 3) {
        if (bVar1 == 1) {
          fn_800E56A4((int)puVar4,(f32 *)puVar8);
        }
        else {
LAB_800e7350:
          fn_800E58FC((int)puVar4,(f32 *)puVar8);
        }
      }
      else {
        if (4 < bVar1) goto LAB_800e7350;
        *(f32 *)(puVar8 + 0x68) = *(f32 *)(puVar8 + 0x1a);
        *(f32 *)(puVar8 + 0x69) = *(f32 *)(puVar8 + 0x1b);
        *(f32 *)(puVar8 + 0x6a) = *(f32 *)(puVar8 + 0x1c);
        if (((*(byte *)(puVar8 + 0x98) & 1) != 0) && (*(char *)(puVar8 + 0x2e) == '!')) {
          *(uint *)(puVar4 + 0xc) = puVar8[2];
          *(uint *)(puVar4 + 0xe) = puVar8[3];
          *(uint *)(puVar4 + 0x10) = puVar8[4];
        }
      }
      if ((*puVar8 & 0x100) != 0) {
        fn_800E5E38((int)puVar4,(f32 *)puVar8);
      }
      if ((*puVar8 & 0x80) != 0) {
        fn_800E5CBC((short *)puVar4,(int)puVar8);
      }
      if ((*puVar8 & 1) != 0) {
        fn_800E5F1C((int)puVar4,(f32 *)puVar8);
      }
      FUN_80003494((uint)(puVar8 + 0xe),(uint)(puVar8 + 2),
                   ((int)(uint)*(byte *)(puVar8 + 0x97) >> 4) * 0xc);
    }
    if ((*puVar8 & 0x800) != 0) {
      if (0x3400 < (short)puVar4[1]) {
        puVar4[1] = 0x3400;
      }
      if ((short)puVar4[1] < -0x3400) {
        puVar4[1] = 0xcc00;
      }
    }
    if ((*puVar8 & 0x1000) != 0) {
      if (0x3400 < (short)puVar4[2]) {
        puVar4[2] = 0x3400;
      }
      if ((short)puVar4[2] < -0x3400) {
        puVar4[2] = 0xcc00;
      }
    }
    if ((*puVar8 & 0x40000) == 0) {
      iVar11 = *(int *)(puVar4 + 0x2a);
      if ((iVar11 == 0) || ((*(ushort *)(iVar11 + 0x60) & 1) == 0)) {
        *(float *)(puVar4 + 0x14) =
             (float)(dVar14 * (double)(*(float *)(puVar4 + 0xe) - *(float *)(puVar4 + 0x48)));
      }
      else {
        *(float *)(puVar4 + 0x14) =
             (float)(dVar14 * (double)(*(float *)(puVar4 + 0xe) - *(float *)(iVar11 + 0x20)));
        if (*(float *)(*(int *)(puVar4 + 0x2a) + 0x20) < *(float *)(puVar4 + 0xe)) {
          *(float *)(puVar4 + 0x14) = lbl_803E12E8;
        }
      }
    }
  }
  else if (*(char *)((int)puVar8 + 0x25b) == '\x02') {
    objFn_800e64f4((int)puVar4,puVar8);
    uVar5 = *puVar8;
    if (((uVar5 & 0x4000000) != 0) && ((uVar5 & 8) != 0)) {
      local_1d0 = *puVar4;
      if ((uVar5 & 0x20) == 0) {
        local_1ce = puVar4[1];
        local_1cc = puVar4[2];
      }
      else {
        local_1ce = 0;
        local_1cc = 0;
      }
      local_1c8 = lbl_803E130C;
      local_1c4 = *(undefined4 *)(puVar4 + 6);
      local_1c0 = *(undefined4 *)(puVar4 + 8);
      local_1bc = *(undefined4 *)(puVar4 + 10);
      setMatrixFromObjectPos(afStack_130,&local_1d0);
      iVar12 = 0;
      iVar11 = 0;
      puVar10 = puVar8;
      for (iVar13 = 0; fVar3 = lbl_803E130C, iVar13 < (int)(*(byte *)(puVar8 + 0x97) & 0xf);
          iVar13 = iVar13 + 1) {
        pfVar9 = (float *)(puVar8[0x37] + iVar11);
        Matrix_TransformPoint(afStack_130,(double)*pfVar9,(double)pfVar9[1],
                              (double)pfVar9[2],(float *)(puVar10 + 0x39),
                              (float *)(puVar8 + iVar12 + 0x3a),
                              (float *)(puVar8 + iVar12 + 0x3b));
        puVar10 = puVar10 + 3;
        iVar11 = iVar11 + 0xc;
        iVar12 = iVar12 + 3;
      }
      puVar10 = puVar8;
      for (iVar11 = 0; iVar11 < (int)(*(byte *)(puVar8 + 0x97) & 0xf); iVar11 = iVar11 + 1) {
        *(f32 *)(puVar10 + 0x45) = *(f32 *)(puVar10 + 0x39);
        *(f32 *)(puVar10 + 0x46) = fVar3 + *(f32 *)(puVar10 + 0x3a);
        *(f32 *)(puVar10 + 0x47) = *(f32 *)(puVar10 + 0x3b);
        puVar10 = puVar10 + 3;
      }
      FUN_80061fc8((int)puVar4);
    }
    if ((*puVar8 & 0x2000) != 0) {
      local_1b8 = *puVar4;
      if ((*puVar8 & 0x20) == 0) {
        local_1b6 = puVar4[1];
        local_1b4 = puVar4[2];
      }
      else {
        local_1b6 = 0;
        local_1b4 = 0;
      }
      local_1b0 = lbl_803E130C;
      local_1ac = *(undefined4 *)(puVar4 + 0xc);
      local_1a8 = *(undefined4 *)(puVar4 + 0xe);
      local_1a4 = *(undefined4 *)(puVar4 + 0x10);
      setMatrixFromObjectPos(afStack_f0,&local_1b8);
      iVar12 = 0;
      iVar11 = 0;
      puVar10 = puVar8;
      for (iVar13 = 0; iVar13 < (int)(uint)*(byte *)(puVar8 + 0x97) >> 4; iVar13 = iVar13 + 1) {
        pfVar9 = (float *)(puVar8[1] + iVar11);
        Matrix_TransformPoint(afStack_f0,(double)*pfVar9,(double)pfVar9[1],
                              (double)pfVar9[2],(float *)(puVar10 + 2),
                              (float *)(puVar8 + iVar12 + 3),
                              (float *)(puVar8 + iVar12 + 4));
        *(undefined *)((int)puVar8 + iVar13 + 0xb8) = 0xff;
        puVar10 = puVar10 + 3;
        iVar11 = iVar11 + 0xc;
        iVar12 = iVar12 + 3;
      }
      FUN_80003494((uint)(puVar8 + 0xe),(uint)(puVar8 + 2),
                   ((int)(uint)*(byte *)(puVar8 + 0x97) >> 4) * 0xc);
      if ((*puVar8 & 1) != 0) {
        fn_800E5F1C((int)puVar4,(f32 *)puVar8);
      }
    }
  }
  else {
    objFn_800e64f4((int)puVar4,puVar8);
    uVar5 = *puVar8;
    if (((uVar5 & 0x4000000) != 0) && ((uVar5 & 8) != 0)) {
      local_1e8 = *puVar4;
      if ((uVar5 & 0x20) == 0) {
        local_1e6 = puVar4[1];
        local_1e4 = puVar4[2];
      }
      else {
        local_1e6 = 0;
        local_1e4 = 0;
      }
      local_1e0 = lbl_803E130C;
      local_1dc = *(undefined4 *)(puVar4 + 6);
      local_1d8 = *(undefined4 *)(puVar4 + 8);
      local_1d4 = *(undefined4 *)(puVar4 + 10);
      setMatrixFromObjectPos(afStack_170,&local_1e8);
      iVar12 = 0;
      iVar11 = 0;
      puVar10 = puVar8;
      for (iVar13 = 0; fVar3 = lbl_803E130C, iVar13 < (int)(*(byte *)(puVar8 + 0x97) & 0xf);
          iVar13 = iVar13 + 1) {
        pfVar9 = (float *)(puVar8[0x37] + iVar11);
        Matrix_TransformPoint(afStack_170,(double)*pfVar9,(double)pfVar9[1],
                              (double)pfVar9[2],(float *)(puVar10 + 0x39),
                              (float *)(puVar8 + iVar12 + 0x3a),
                              (float *)(puVar8 + iVar12 + 0x3b));
        puVar10 = puVar10 + 3;
        iVar11 = iVar11 + 0xc;
        iVar12 = iVar12 + 3;
      }
      puVar10 = puVar8;
      for (iVar11 = 0; iVar11 < (int)(*(byte *)(puVar8 + 0x97) & 0xf); iVar11 = iVar11 + 1) {
        *(f32 *)(puVar10 + 0x45) = *(f32 *)(puVar10 + 0x39);
        *(f32 *)(puVar10 + 0x46) = fVar3 + *(f32 *)(puVar10 + 0x3a);
        *(f32 *)(puVar10 + 0x47) = *(f32 *)(puVar10 + 0x3b);
        puVar10 = puVar10 + 3;
      }
      FUN_80061fc8((int)puVar4);
    }
  }
  iVar11 = *(int *)(puVar4 + 0x18);
  if (iVar11 == 0) {
    *(undefined4 *)(puVar4 + 6) = *(undefined4 *)(puVar4 + 0xc);
    *(undefined4 *)(puVar4 + 8) = *(undefined4 *)(puVar4 + 0xe);
    *(undefined4 *)(puVar4 + 10) = *(undefined4 *)(puVar4 + 0x10);
  }
  else if ((*(int *)(iVar11 + 0x58) == 0) || (uVar6 = ObjHits_IsObjectEnabled(iVar11), uVar6 == 0)) {
    FUN_800068f4((double)*(float *)(puVar4 + 0xc),(double)*(float *)(puVar4 + 0xe),
                 (double)*(float *)(puVar4 + 0x10),(float *)(puVar4 + 6),(float *)(puVar4 + 8),
                 (float *)(puVar4 + 10),*(int *)(puVar4 + 0x18));
  }
  else {
    Matrix_TransformPoint((float *)(*(int *)(*(int *)(puVar4 + 0x18) + 0x58) +
                                     (uint)*(byte *)(*(int *)(*(int *)(puVar4 + 0x18) +
                                                        0x58) +
                                               0x10c) *
                                         0x40),
                          (double)*(float *)(puVar4 + 0xc),
                          (double)*(float *)(puVar4 + 0xe),
                          (double)*(float *)(puVar4 + 0x10),(float *)(puVar4 + 6),
                          (float *)(puVar4 + 8),(float *)(puVar4 + 10));
  }
LAB_800e78f0:
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800e6140
 * EN v1.0 Address: 0x800E6140
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x800E7910
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e6140(undefined4 param_1,uint *param_2)
{
  uint uVar1;
  uint uVar2;
  
  uVar2 = *param_2;
  if ((((uVar2 & 0x4000000) != 0) && ((uVar2 & 0x2000) != 0)) &&
     ((*(char *)((int)param_2 + 0x25b) == '\x01' || (*(char *)((int)param_2 + 0x25b) == '\x02')))) {
    uVar1 = (uint)((uVar2 & 4) != 0);
    if ((uVar2 & 0x1000000) != 0) {
      uVar1 = uVar1 | 0x20;
    }
    FUN_80063a74(param_1,param_2 + 0x90,uVar1,'\x01');
  }
  return;
}

/*
 * --INFO--
 *
 * Function: dll_15_func06
 * EN v1.0 Address: 0x800E61A4
 * EN v1.0 Size: 1060b
 * EN v1.1 Address: 0x800E79A0
 * EN v1.1 Size: 1384b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_15_func06(ushort *curveObj,uint *state)
{
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  uint *puVar10;
  int iVar11;
  ushort *puVar12;
  int iVar13;
  ushort uVar14;
  uint *puVar15;
  float *pfVar16;
  int iVar17;
  float *pfVar18;
  float *pfVar19;
  float *pfVar20;
  uint *puVar21;
  int iVar22;
  float *pfVar23;
  double dVar24;
  double dVar25;
  float local_118 [4];
  ushort local_108;
  ushort local_106;
  ushort local_104;
  float local_100;
  undefined4 local_fc;
  undefined4 local_f8;
  undefined4 local_f4;
  float local_f0 [12];
  float afStack_c0 [16];

  puVar12 = curveObj;
  puVar15 = state;
  if (((*(char *)((int)puVar15 + 0x25b) != '\0') && ((*puVar15 & 0x4000000) != 0)) &&
     ((*puVar15 & 0x2000) != 0)) {
    iVar13 = *(int *)(puVar12 + 0x18);
    if (iVar13 == 0) {
      *(undefined4 *)(puVar12 + 0xc) = *(undefined4 *)(puVar12 + 6);
      *(undefined4 *)(puVar12 + 0xe) = *(undefined4 *)(puVar12 + 8);
      *(undefined4 *)(puVar12 + 0x10) = *(undefined4 *)(puVar12 + 10);
    }
    else if ((*(int *)(iVar13 + 0x58) == 0) || (uVar14 = ObjHits_IsObjectEnabled(iVar13), uVar14 == 0)) {
      FUN_800068f8((double)*(float *)(puVar12 + 6),(double)*(float *)(puVar12 + 8),
                   (double)*(float *)(puVar12 + 10),(float *)(puVar12 + 0xc),
                   (float *)(puVar12 + 0xe),(float *)(puVar12 + 0x10),*(int *)(puVar12 + 0x18));
    }
    else {
      Matrix_TransformPoint((float *)(*(int *)(*(int *)(puVar12 + 0x18) + 0x58) +
                                       (*(byte *)(*(int *)(*(int *)(puVar12 + 0x18) +
                                                          0x58) +
                                                 0x10c) +
                                        2) *
                                           0x40),
                            (double)*(float *)(puVar12 + 6),
                            (double)*(float *)(puVar12 + 8),
                            (double)*(float *)(puVar12 + 10),(float *)(puVar12 + 0xc),
                            (float *)(puVar12 + 0xe),(float *)(puVar12 + 0x10));
    }
    local_108 = *puVar12;
    if ((*puVar15 & 0x20) == 0) {
      local_106 = puVar12[1];
      local_104 = puVar12[2];
    }
    else {
      local_106 = 0;
      local_104 = 0;
    }
    local_100 = lbl_803E130C;
    local_fc = *(undefined4 *)(puVar12 + 0xc);
    local_f8 = *(undefined4 *)(puVar12 + 0xe);
    local_f4 = *(undefined4 *)(puVar12 + 0x10);
    setMatrixFromObjectPos(afStack_c0,&local_108);
    iVar13 = 0;
    pfVar18 = local_f0;
    iVar22 = 0;
    pfVar19 = local_118;
    dVar25 = (double)lbl_803E1340;
    pfVar20 = pfVar19;
    puVar21 = puVar15;
    pfVar23 = pfVar18;
    for (iVar17 = 0; iVar11 = (int)(uint)*(byte *)(puVar15 + 0x97) >> 4, puVar10 = puVar15,
        fVar3 = lbl_803E1324, fVar4 = lbl_803E1324, fVar5 = lbl_803E1324,
        fVar6 = lbl_803E1328, fVar7 = lbl_803E1328, fVar8 = lbl_803E1328, iVar17 < iVar11;
        iVar17 = iVar17 + 1) {
      pfVar16 = (float *)(puVar15[1] + iVar22);
      Matrix_TransformPoint(afStack_c0,(double)*pfVar16,(double)pfVar16[1],
                            (double)pfVar16[2],pfVar23,local_f0 + iVar13 + 1,
                            local_f0 + iVar13 + 2);
      *pfVar20 = *(f32 *)(puVar21 + 0x2a);
      dVar24 = FUN_80293900((double)(float)((double)(float)(dVar25 * (double)*pfVar20) *
                                           (double)*pfVar20));
      *pfVar20 = (float)dVar24;
      pfVar23 = pfVar23 + 3;
      iVar22 = iVar22 + 0xc;
      iVar13 = iVar13 + 3;
      puVar21 = puVar21 + 1;
      pfVar20 = pfVar20 + 1;
    }
    for (; iVar11 != 0; iVar11 = iVar11 + -1) {
      fVar2 = *pfVar19;
      fVar9 = *pfVar18 + fVar2;
      if (fVar3 < fVar9) {
        fVar3 = fVar9;
      }
      fVar9 = *pfVar18 - fVar2;
      if (fVar9 < fVar6) {
        fVar6 = fVar9;
      }
      fVar9 = pfVar18[1] + fVar2;
      if (fVar5 < fVar9) {
        fVar5 = fVar9;
      }
      fVar9 = pfVar18[1] - fVar2;
      if (fVar9 < fVar8) {
        fVar8 = fVar9;
      }
      fVar9 = pfVar18[2] + fVar2;
      if (fVar4 < fVar9) {
        fVar4 = fVar9;
      }
      fVar9 = pfVar18[2] - fVar2;
      if (fVar9 < fVar7) {
        fVar7 = fVar9;
      }
      fVar9 = *(f32 *)(puVar10 + 0xe) + fVar2;
      if (fVar3 < fVar9) {
        fVar3 = fVar9;
      }
      fVar9 = *(f32 *)(puVar10 + 0xe) - fVar2;
      if (fVar9 < fVar6) {
        fVar6 = fVar9;
      }
      fVar9 = *(f32 *)(puVar10 + 0xf) + fVar2;
      if (fVar5 < fVar9) {
        fVar5 = fVar9;
      }
      fVar9 = *(f32 *)(puVar10 + 0xf) - fVar2;
      if (fVar9 < fVar8) {
        fVar8 = fVar9;
      }
      fVar9 = *(f32 *)(puVar10 + 0x10) + fVar2;
      if (fVar4 < fVar9) {
        fVar4 = fVar9;
      }
      fVar2 = *(f32 *)(puVar10 + 0x10) - fVar2;
      if (fVar2 < fVar7) {
        fVar7 = fVar2;
      }
      pfVar18 = pfVar18 + 3;
      pfVar19 = pfVar19 + 1;
      puVar10 = puVar10 + 3;
    }
    *(f32 *)(puVar15 + 0x90) = fVar6;
    *(f32 *)(puVar15 + 0x93) = fVar3;
    *(f32 *)(puVar15 + 0x91) = fVar8 - (f32)(u32)*(byte *)(puVar15 + 0x96);
    *(f32 *)(puVar15 + 0x94) = fVar5 + (f32)(u32)*(byte *)(puVar15 + 0x96);
    *(f32 *)(puVar15 + 0x92) = fVar7;
    *(f32 *)(puVar15 + 0x95) = fVar4;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: dll_15_func05
 * EN v1.0 Address: 0x800E7AE8
 * EN v1.0 Size: 412b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_15_func05(u32 *state,int count,u32 source,f32 *radii,s8 *types)
{
  u8 *stateBytes;
  int i;

  stateBytes = (u8 *)state;
  stateBytes[0x25c] &= 0xf;
  stateBytes[0x25c] |= (count & 0xf) << 4;
  state[1] = source;
  for (i = 0; i < count; i++) {
    stateBytes[0xbc + i] = types[i];
    stateBytes[0xb8 + i] = 0xff;
    *(f32 *)(stateBytes + 0xa8 + i * sizeof(f32)) = radii[i];
  }
  *state |= 0x2000;
}

/*
 * --INFO--
 *
 * Function: FUN_800e65c8
 * EN v1.0 Address: 0x800E65C8
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x800E7F08
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e65c8(uint *param_1,byte param_2,uint param_3,uint param_4,undefined param_5,
                 undefined param_6)
{
  *(byte *)(param_1 + 0x97) = *(byte *)(param_1 + 0x97) & 0xf0;
  *(byte *)(param_1 + 0x97) = *(byte *)(param_1 + 0x97) | param_2 & 0xf;
  *(undefined *)((int)param_1 + 0x25d) = param_5;
  *(undefined *)((int)param_1 + 0x263) = param_6;
  param_1[0x37] = param_3;
  param_1[0x38] = param_4;
  *param_1 = *param_1 | 0x2000008;
  *(undefined *)(param_1 + 0x99) = 10;
  return;
}

/* dll_15_func07: early-out unless flags bits 0x04000000 and 0x00002000 are
 * set; bail if obj[0x25b] isn't 1 or 2; otherwise OR-in 0x01 (when bit 0x4)
 * and 0x20 (when bit 0x01000000) into the mask, then forward to
 * hitDetectFn_800691c0(arg1, obj+0x240, mask, 1). */
extern void hitDetectFn_800691c0(void* a, void* b, u8 mask, int e);
#pragma scheduling off
#pragma peephole off
void dll_15_func07(void* arg1, u8* obj)
{
    u32 flags;
    s8 type;
    u8 mask;
    mask = 0;
    flags = *(u32*)obj;
    if ((s32)(flags & 0x04000000) == 0) return;
    if ((s32)(flags & 0x00002000) != 0) {
        type = *(s8*)(obj + 0x25b);
        if (type != 1 && type != 2) return;
        if ((s32)(flags & 0x00000004) != 0) mask = (u8)(mask | 0x1);
        if ((s32)(flags & 0x01000000) != 0) mask = (u8)(mask | 0x20);
        hitDetectFn_800691c0(arg1, obj + 0x240, mask, 1);
    }
}
#pragma peephole reset
#pragma scheduling reset

/* fn_800E7C84: extended dll_15_func04 — same fields plus a second signed
 * byte at obj[0x263] and OR-in 0x02000008 on the flags word at obj[0]. */
#pragma scheduling off
#pragma peephole off
void fn_800E7C84(u8* obj, int a, u32 b, u32 c, int d, int e)
{
    obj[0x25c] &= 0xf0;
    obj[0x25c] = (u8)(obj[0x25c] | (a & 0xf));
    *(s8*)(obj + 0x25d) = (s8)d;
    *(s8*)(obj + 0x263) = (s8)e;
    *(u32*)(obj + 0xdc) = b;
    *(u32*)(obj + 0xe0) = c;
    *(u32*)obj |= 0x02000008;
    obj[0x264] = 0xa;
}
#pragma peephole reset
#pragma scheduling reset

/* dll_15_func04: write the per-slot config block on obj+0x25c..+0x264:
 * replace low 4 bits of obj[0x25c] with (a & 0xf), set obj[0x25d] = (s8)d,
 * stash two u32s at +0xdc/+0xe0, OR-in bit 3 of obj[0], and set obj[0x264]=10. */
#pragma scheduling off
#pragma peephole off
void dll_15_func04(u8* obj, int a, u32 b, u32 c, int d)
{
    obj[0x25c] &= 0xf0;
    obj[0x25c] = (u8)(obj[0x25c] | (a & 0xf));
    *(s8*)(obj + 0x25d) = (s8)d;
    *(u32*)(obj + 0xdc) = b;
    *(u32*)(obj + 0xe0) = c;
    *(u32*)obj |= 0x8;
    obj[0x264] = 0xa;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: curves_clear
 * EN v1.0 Address: 0x800E7D20
 * EN v1.0 Size: 120b
 * EN v1.1 Address: 0x800E7FA4
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void curves_clear(uint *param_1,int param_2,uint param_3,int param_4)
{
  uint *curve;
  int flagsByte;
  uint flags;
  int subtype;

  curve = param_1;
  flagsByte = param_2;
  flags = param_3;
  subtype = param_4;
  memset(curve,0,0x268);
  *(s8 *)((int)curve + 0x25b) = (s8)subtype;
  *curve = flags | 0x4000000;
  *(u8 *)((int)curve + 0x262) = (u8)flagsByte;
  *(u8 *)(curve + 0x96) = 5;
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: playerHasKrazoaSpirit
 * EN v1.0 Address: 0x800E6680
 * EN v1.0 Size: 180b
 * EN v1.1 Address: 0x800E8024
 * EN v1.1 Size: 160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint playerHasKrazoaSpirit(u8 checkStoryBits,uint bit)
{
  if (checkStoryBits == 0) {
    return GameBit_Get(bit);
  }
  if ((GameBit_Get(0xbfd) != 0) || (GameBit_Get(0xff) != 0) ||
      (GameBit_Get(0xba8) != 0) || (GameBit_Get(0xc85) != 0) ||
      (GameBit_Get(0xc6e) != 0) || (GameBit_Get(0x174) != 0)) {
    return 1;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: saveFileStruct_setCheatActive
 * EN v1.0 Address: 0x800E6734
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x800E80C4
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
typedef struct SaveData {
  u8 pad00[2];
  u8 subtitlesEnabled;
  u8 gameUiSetting;
  u8 cameraSetting;
  u8 pad05;
  u8 widescreenEnabled;
  u8 pad07;
  u8 rumbleEnabled;
  u8 soundMode;
  u8 musicVolume;
  u8 sfxVolume;
  u8 speechVolume;
  u8 pad0D[3];
  u32 registeredDebugOptions;
  u32 enabledDebugOptions;
} SaveData;

extern SaveData saveData;
void saveFileStruct_setCheatActive(uint optionIndex, u8 active)
{
  volatile SaveData *save;
  u32 registeredDebugOptions;
  u32 enabledDebugOptions;
  u32 mask;

  save = &saveData;
  registeredDebugOptions = save->registeredDebugOptions;
  mask = 1 << (u8)optionIndex;
  if ((registeredDebugOptions & mask) == 0) {
    return;
  }
  if (active != 0) {
    save->enabledDebugOptions |= mask;
  }
  else {
    enabledDebugOptions = save->enabledDebugOptions;
    mask = ~mask;
    save->enabledDebugOptions = enabledDebugOptions & mask;
  }
}


/* Trivial 4b 0-arg blr leaves. */
void curves_release(void) {}
void RomCurve_initialise(void) {}
void dll_15_release_nop(void) {}
void dll_15_initialise_nop(void) {}

/*
 * --INFO--
 *
 * Function: loadSaveSettings
 * EN v1.0 Address: 0x800E7F44
 * EN v1.0 Size: 256b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void setWidescreen(u8 enabled);
extern void setSubtitlesEnabled(u8 enabled);
extern void setRumbleEnabled(u8 value);
extern void audioSetSoundMode(u8 mode, u8 secondary);
extern void audioSetVolumes(u8 volume, int p1, int p2, int p3, int p4);
extern void **gGameUIInterface;
extern void **gCameraInterface;

#pragma scheduling off
#pragma peephole off
void loadSaveSettings(void)
{
  setWidescreen(saveData.widescreenEnabled);
  setSubtitlesEnabled(saveData.subtitlesEnabled);
  setRumbleEnabled(saveData.rumbleEnabled);
  audioSetSoundMode(saveData.soundMode, 0);
  (*(void (**)(u8))((char *)*gGameUIInterface + 0x50))(saveData.gameUiSetting);
  (*(void (**)(u8))((char *)*gCameraInterface + 0x6c))(saveData.cameraSetting);
  audioSetVolumes(saveData.sfxVolume, 10, 0, 1, 0);
  audioSetVolumes(saveData.musicVolume, 10, 1, 0, 0);
  audioSetVolumes(saveData.speechVolume, 10, 0, 0, 1);
}
#pragma peephole reset
#pragma scheduling reset

/* Pattern wrappers. */
void curves_initialise(void) { nRomCurves = 0x0; }

void RomCurve_func0D(RomCurveDef **p1, RomCurveDef **p2) { *p1 = lbl_803DD474; *p2 = lbl_803DD470; }

/* getSaveFileStruct: return &saveData (lis/addi). */
void* getSaveFileStruct(void) { return &saveData; }

/* getLastSavedGameTexts: return (u8*)&lbl_803A32A8 + 0x558. Array form forces lis/addi. */
extern u8 lbl_803A32A8[];
void* getLastSavedGameTexts(void) { return lbl_803A32A8 + 0x558; }

#define SAVEGAME_OBJECT_POSITION_COUNT 0x3f
#define SAVEGAME_OBJECT_POSITION_OFFSET 0x168

typedef struct CurvesSaveGameObjectPosition {
  u32 objectId;
  f32 x;
  f32 y;
  f32 z;
} CurvesSaveGameObjectPosition;

int pushable_savePos(int obj)
{
  int i;
  CurvesSaveGameObjectPosition *position;
  u32 objectId;

  for (i = 0; i < SAVEGAME_OBJECT_POSITION_COUNT; i++) {
    position = (CurvesSaveGameObjectPosition *)(lbl_803A32A8 + SAVEGAME_OBJECT_POSITION_OFFSET +
                                                i * sizeof(CurvesSaveGameObjectPosition));
    objectId = *(u32 *)(*(u32 *)(obj + 0x4c) + 0x14);
    if (objectId == position->objectId) {
      if ((*(f32 *)(obj + 0xc) == position->x) && (*(f32 *)(obj + 0x10) == position->y) &&
          (*(f32 *)(obj + 0x14) == position->z)) {
        return 0;
      }
      *(f32 *)(obj + 0xc) = position->x;
      *(f32 *)(obj + 0x10) = position->y;
      *(f32 *)(obj + 0x14) = position->z;
      return 1;
    }
  }
  return 0;
}

/* RomCurve_getCurves: *outCount = nRomCurves; return romCurves. */
#pragma scheduling off
#pragma peephole off
void* RomCurve_getCurves(int *outCount) {
    *outCount = nRomCurves;
    return romCurves;
}
#pragma peephole reset
#pragma scheduling reset

void saveFileStruct_resetVolumes(void)
{
  saveData.musicVolume = 0x7f;
  saveData.sfxVolume = 0x7f;
  saveData.speechVolume = 0x7f;
}

/* isCheatUnlocked: return registeredDebugOptions & (1 << (idx & 0xff)). */
#pragma scheduling off
#pragma peephole off
int isCheatUnlocked(u8 idx) {
    SaveData *p = &saveData;
    u32 reg = p->registeredDebugOptions;
    u32 mask = 1 << idx;
    return reg & mask;
}
#pragma peephole reset
#pragma scheduling reset

/* saveFileStruct_unlockCheat: set bit (1 << (idx & 0xff)) in registeredDebugOptions. */
#pragma scheduling off
#pragma peephole off
void saveFileStruct_unlockCheat(u8 idx) {
    SaveData *p = &saveData;
    u32 reg = p->registeredDebugOptions;
    u32 mask = 1 << idx;
    p->registeredDebugOptions = reg | mask;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int saveFileStruct_isCheatActive(u8 idx)
{
  volatile SaveData *save;
  u32 registeredDebugOptions;
  u32 mask;
  u32 enabledDebugOptions;

  save = &saveData;
  registeredDebugOptions = save->registeredDebugOptions;
  mask = 1 << idx;
  if ((registeredDebugOptions & mask) != 0) {
    enabledDebugOptions = save->enabledDebugOptions;
    if ((enabledDebugOptions & mask) != 0) {
      return 1;
    }
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

/* curves_findByAction: scan romCurves for matching action curves, return curve id. */
#pragma scheduling off
#pragma peephole off
int curves_findByAction(int act) {
    int i;

    for (i = 0; i < nRomCurves; i++) {
        RomCurveDef *c = romCurves[i];
        if (c->type == ROMCURVE_TYPE_ACTION) {
            if (c->action == act) {
                return c->id;
            }
        }
    }
    return -1;
}
#pragma peephole reset
#pragma scheduling reset

/* RomCurve_segmentIntersectsOriginRayXZ: 2D segment-intersection predicate.
 * Returns 1 if the segment between (x, z) and the origin in the xz-plane
 * crosses the segment between a and b. */
#pragma scheduling off
#pragma peephole off
int RomCurve_segmentIntersectsOriginRayXZ(RomCurveDef *a, RomCurveDef *b, f32 x, f32 unusedY,
                                          f32 z, f32 unusedW) {
    f32 ax = a->x;
    f32 az = a->z;
    f32 bx = b->x;
    f32 bz = b->z;
    f32 cross1 = bx * az - ax * bz;
    f32 sum1 = cross1 + (x * (bz - az) + z * (ax - bx));
    if (!((sum1 <= gFloatZero && cross1 >= gFloatZero) ||
          (sum1 >= gFloatZero && cross1 < gFloatZero))) {
        return 0;
    }
    {
        f32 cross_a = -z * ax + x * az;
        f32 cross_b = -z * bx + x * bz;
        if ((cross_a <= gFloatZero && cross_b >= gFloatZero) ||
            (cross_a >= gFloatZero && cross_b < gFloatZero)) {
            return 1;
        }
        return 0;
    }
}
#pragma peephole reset
#pragma scheduling reset
