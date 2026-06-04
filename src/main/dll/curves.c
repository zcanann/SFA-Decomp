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
extern f32 lbl_803E066C;
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
extern void fn_80063368(short *obj);
extern int hitDetectFn_80065e50(int obj,f32 x,f32 y,f32 z,void *out,int p5,int p6);
extern undefined FUN_80063a68();
extern undefined4 FUN_80063a74();
extern int hitDetectFn_80067958(int obj,void *startPoints,void *endPoints,int pointCount,
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

/* Hcurves keeps the ROM curve definitions sorted by id for binary searches. */
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
#define SQ(v) ((v) * (v))

int RomCurve_func13(uint curveId,int typeFilter,uint param_3,int *param_4)
{
  int done;
  int found;
  int li;
  RomCurveDef *start;
  RomCurveDef *node;
  RomCurveDef *cand;
  f32 newDist;
  f32 *probe;
  int count;
  int pos;
  int k;
  int m;
  int j;
  int best;
  f32 *distRead;
  f32 *distWrite;
  u32 *idRead;
  u32 *idWrite;
  char *pc;
  char *pu;
  int rem;
  int off;
  char zval;
  f64 curDist;
  char visited[ROMCURVE_MAX_CURVES];
  int queueIds[ROMCURVE_LINK_SEARCH_QUEUE_CAPACITY];
  f32 queueDist[ROMCURVE_LINK_SEARCH_QUEUE_CAPACITY];
  u32 resultIds[4];
  f32 bestDists[4];
  int idx;
  int startIdx;
  char resultLinks[4];

  start = RomCurve_findByIdWithIndex(curveId, &startIdx);
  if (start == NULL) {
    return -1;
  }
  found = 0;
  distRead = bestDists;
  idRead = resultIds;
  distWrite = distRead;
  for (li = 0; li < 4; li++) {
    if (-1 < (int)start->linkIds[li]) {
      pc = visited;
      zval = 0;
      off = 0;
      for (rem = 0x1b; rem != 0; rem--) {
          pc[0] = zval;
          pc[1] = zval;
          pc[2] = zval;
          pc[3] = zval;
          pc[4] = zval;
          pc[5] = zval;
          pc[6] = zval;
          pc[7] = zval;
          pc[8] = zval;
          pc[9] = zval;
          pc[10] = zval;
          pc[11] = zval;
          pc[12] = zval;
          pc[13] = zval;
          pc[14] = zval;
          pc[15] = zval;
          pc[16] = zval;
          pc[17] = zval;
          pc[18] = zval;
          pc[19] = zval;
          pc[20] = zval;
          pc[21] = zval;
          pc[22] = zval;
          pc[23] = zval;
          pc[24] = zval;
          pc[25] = zval;
          pc[26] = zval;
          pc[27] = zval;
          pc[28] = zval;
          pc[29] = zval;
          pc[30] = zval;
          pc[31] = zval;
          pc[32] = zval;
          pc[33] = zval;
          pc[34] = zval;
          pc[35] = zval;
          pc[36] = zval;
          pc[37] = zval;
          pc[38] = zval;
          pc[39] = zval;
          pc[40] = zval;
          pc[41] = zval;
          pc[42] = zval;
          pc[43] = zval;
          pc[44] = zval;
          pc[45] = zval;
          pc[46] = zval;
          pc[47] = zval;
          pc = pc + 0x30;
          off = off + 0x30;
      }
      pu = visited + off;
      rem = 0x514 - off;
      if (off < 0x514) {
        do {
          *pu = 0;
          pu++;
          off++;
          rem--;
        } while (rem != 0);
      }
      visited[startIdx] = 1;
      node = RomCurve_findByIdWithIndex(start->linkIds[li], &idx);
      if (node != NULL) {
        queueDist[0] = SQ(node->z - start->z) + (SQ(node->x - start->x) + SQ(node->y - start->y));
        pos = 0;
        count = 1;
        queueIds[pos] = idx;
        visited[idx] = 1;
        done = 0;
        idWrite = idRead;
        do {
          if (count > 0) {
            count--;
            idx = queueIds[count];
            node = romCurves[queueIds[count]];
            curDist = queueDist[count];
            if ((((int)node->type == typeFilter) || (typeFilter == -1)) &&
                ((*(u8 *)((u8 *)node + 0x31) == param_3 ||
                  ((*(u8 *)((u8 *)node + 0x32) == param_3 || (*(u8 *)((u8 *)node + 0x33) == param_3)))))) {
              done = 1;
              *distWrite = queueDist[count];
              if (found < 4) {
                *idWrite = node->id;
                distWrite++;
                idWrite++;
                resultLinks[found] = (char)li;
                found++;
              }
            }
            else {
              for (k = 0; k < 4; k++) {
                if (((-1 < (int)node->linkIds[k]) &&
                     ((cand = RomCurve_findByIdWithIndex(node->linkIds[k], &idx)) != NULL)) &&
                    (visited[idx] == 0) && (count < ROMCURVE_LINK_SEARCH_QUEUE_CAPACITY)) {
                  newDist = SQ(node->z - cand->z) + (f32)(curDist + (f64)SQ(node->x - cand->x)) +
                            SQ(node->y - cand->y);
                  pos = 0;
                  for (probe = queueDist; (pos < count) && (newDist < *probe); probe++) {
                    pos++;
                  }
                  for (m = count; m > pos; m--) {
                    queueIds[m] = queueIds[m - 1];
                    queueDist[m] = queueDist[m - 1];
                  }
                  count++;
                  queueDist[pos] = newDist;
                  queueIds[pos] = idx;
                  visited[idx] = 1;
                }
              }
            }
          }
          else {
            done = 1;
          }
        } while (!done);
      }
    }
  }
  if (found < 1) {
    return -1;
  }
  best = 0;
  j = 0;
  if (found >= 1) {
    do {
      if (*distRead < bestDists[best]) {
        best = j;
      }
      distRead++;
      j++;
      found--;
    } while (found != 0);
  }
  if (param_4 != NULL) {
    *param_4 = resultLinks[best];
  }
  return resultIds[best];
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
#pragma fp_contract off
int RomCurve_func11(RomCurveDef *curve,int typeFilter,int actionFilter,int *outCurveId)
{
  f32 zd;
  f32 xd;
  f32 yd;
  int done;
  int found;
  int li;
  RomCurveDef *node;
  RomCurveDef *cand;
  f32 newDist;
  f32 *probe;
  int count;
  int pos;
  int k;
  int m;
  int j;
  int best;
  f32 *distRead;
  f32 *distWrite;
  int linkWord;
  char *pc;
  char *pu;
  int rem;
  int off;
  char zval;
  f64 curDist;
  char visited[ROMCURVE_MAX_CURVES];
  int queueIds[ROMCURVE_LINK_SEARCH_QUEUE_CAPACITY];
  f32 queueDist[ROMCURVE_LINK_SEARCH_QUEUE_CAPACITY];
  int results[4];
  f32 bestDists[4];
  int idx;
  int startIdx;

  if (curve == NULL) {
    return -1;
  }
  if (RomCurve_findByIdWithIndex(curve->id, &startIdx) == NULL) {
    return -1;
  }
  found = 0;
  distRead = bestDists;
  distWrite = distRead;
  for (li = 0; li < 4; li++) {
    if (-1 < (int)curve->linkIds[li]) {
      pc = visited;
      zval = 0;
      off = 0;
      for (rem = 0x1b; rem != 0; rem--) {
          pc[0] = zval;
          pc[1] = zval;
          pc[2] = zval;
          pc[3] = zval;
          pc[4] = zval;
          pc[5] = zval;
          pc[6] = zval;
          pc[7] = zval;
          pc[8] = zval;
          pc[9] = zval;
          pc[10] = zval;
          pc[11] = zval;
          pc[12] = zval;
          pc[13] = zval;
          pc[14] = zval;
          pc[15] = zval;
          pc[16] = zval;
          pc[17] = zval;
          pc[18] = zval;
          pc[19] = zval;
          pc[20] = zval;
          pc[21] = zval;
          pc[22] = zval;
          pc[23] = zval;
          pc[24] = zval;
          pc[25] = zval;
          pc[26] = zval;
          pc[27] = zval;
          pc[28] = zval;
          pc[29] = zval;
          pc[30] = zval;
          pc[31] = zval;
          pc[32] = zval;
          pc[33] = zval;
          pc[34] = zval;
          pc[35] = zval;
          pc[36] = zval;
          pc[37] = zval;
          pc[38] = zval;
          pc[39] = zval;
          pc[40] = zval;
          pc[41] = zval;
          pc[42] = zval;
          pc[43] = zval;
          pc[44] = zval;
          pc[45] = zval;
          pc[46] = zval;
          pc[47] = zval;
          pc = pc + 0x30;
          off = off + 0x30;
      }
      pu = visited + off;
      rem = 0x514 - off;
      if (off < 0x514) {
        do {
          *pu = 0;
          pu++;
          off++;
          rem--;
        } while (rem != 0);
      }
      visited[startIdx] = 1;
      node = RomCurve_findByIdWithIndex(curve->linkIds[li], &idx);
      if (node != NULL) {
        queueDist[0] = SQ(node->z - curve->z) + (SQ(node->x - curve->x) + SQ(node->y - curve->y));
        pos = 0;
        count = 1;
        queueIds[pos] = idx;
        visited[idx] = 1;
        done = 0;
        do {
          if (count > 0) {
            count--;
            idx = queueIds[count];
            node = romCurves[queueIds[count]];
            curDist = queueDist[count];
            if (((int)node->type == typeFilter) &&
                ((actionFilter == -1) || (actionFilter == node->action))) {
              done = 1;
              *distWrite = queueDist[count];
              distWrite++;
              results[found] = curve->linkIds[li];
              found++;
            }
            else {
              for (k = 0; k < 4; k++) {
                if (((-1 < (int)node->linkIds[k]) &&
                     ((cand = RomCurve_findByIdWithIndex(node->linkIds[k], &idx)) != NULL)) &&
                    (visited[idx] == 0) && (count < ROMCURVE_LINK_SEARCH_QUEUE_CAPACITY)) {
                  zd = node->z - cand->z;
                  xd = node->x - cand->x;
                  yd = node->y - cand->y;
                  newDist = zd * zd + (f32)(curDist + (f64)(xd * xd)) + yd * yd;
                  pos = 0;
                  for (probe = queueDist; (pos < count) && (newDist < *probe); probe++) {
                    pos++;
                  }
                  for (m = count; m > pos; m--) {
                    queueIds[m] = queueIds[m - 1];
                    queueDist[m] = queueDist[m - 1];
                  }
                  count++;
                  queueDist[pos] = newDist;
                  queueIds[pos] = idx;
                  visited[idx] = 1;
                }
              }
            }
          }
          else {
            done = 1;
          }
        } while (!done);
      }
    }
  }
  if (found == 0) {
    return -1;
  }
  if (found == 1) {
    *outCurveId = curve->id;
    return results[0];
  }
  if (found < 2) {
    return -1;
  }
  for (j = 0; j < found; j++) {
    if (*outCurveId == results[j]) {
      for (; j < found - 1; j++) {
        results[j] = results[j + 1];
        bestDists[j] = bestDists[j + 1];
      }
      found--;
    }
  }
  *outCurveId = curve->id;
  best = 0;
  j = 0;
  if (0 < found) {
    do {
      if (*distRead < bestDists[best]) {
        best = j;
      }
      distRead++;
      j++;
      found--;
    } while (found != 0);
  }
  return results[best];
}
#pragma fp_contract reset

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
  int candidateCount;
  int linkIndex;
  int typeIndex;
  int low;
  int high;
  int mid;
  int top;
  int j;
  int linkId;
  RomCurveDef *linkedCurve;
  int candidates[7];

  if (curve == NULL) {
    return -1;
  }
  candidateCount = 0;
  top = nRomCurves - 1;
  for (linkIndex = 0; linkIndex < ROMCURVE_LINK_COUNT; linkIndex++) {
    linkId = curve->linkIds[linkIndex];
    if (linkId > -1) {
      if (linkId < 0) {
        linkedCurve = NULL;
      } else {
        high = top;
        low = 0;
        while (high >= low) {
          mid = (high + low) >> 1;
          linkedCurve = romCurves[mid];
          if ((u32)linkId > linkedCurve->id) {
            low = mid + 1;
          } else if ((u32)linkId < linkedCurve->id) {
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
    return -1;
  }
  if (candidateCount == 1) {
    *previousLinkId = curve->id;
    return candidates[0];
  }
  if (candidateCount < 2) {
    return -1;
  }
  for (j = 0; j < candidateCount; j++) {
    if (*previousLinkId == candidates[j]) {
      for (; j < candidateCount - 1; j++) {
        candidates[j] = candidates[j + 1];
      }
      candidateCount--;
    }
  }
  *previousLinkId = curve->id;
  return candidates[randomGetRange(0, candidateCount - 1)];
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
RomCurveDef *RomCurve_findByIdWithIndex(uint curveId,int *outIndex)
{
  int high;
  int low;
  int mid;

  *outIndex = -1;
  if ((int)curveId < 0) {
    return NULL;
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
      return romCurves[mid];
    }
  }
  *outIndex = -1;
  return NULL;
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
extern f32 lbl_803E0610;
extern f32 lbl_803E0614;
extern f32 lbl_803E0618;
extern f32 fn_80293E80(f32);
extern f32 sin(f32);

#define ROMCURVE_PLACEMENT_ANGLE(v) ((lbl_803E0614 * (f32)((s32)(v) << 8)) / lbl_803E0618)

static inline int RomCurve_noUnblockedLinks(RomCurvePlacementDef *curve) {
  int bit;

  for (bit = 0; bit < ROMCURVE_LINK_COUNT; bit++) {
    if ((s32)curve->base.linkIds[bit] != -1 && (curve->base.blockedLinkMask & (1 << bit)) == 0) {
      return 0;
    }
  }
  return 1;
}

static inline int RomCurve_noBlockedLinks(RomCurvePlacementDef *curve) {
  int bit;

  for (bit = 0; bit < ROMCURVE_LINK_COUNT; bit++) {
    if ((s32)curve->base.linkIds[bit] != -1 && (curve->base.blockedLinkMask & (1 << bit)) != 0) {
      return 0;
    }
  }
  return 1;
}

int RomCurve_func20(RomCurvePlacementDef *curve, f32 *outX, f32 *outY, f32 *outZ, s8 *outTypes)
{
  RomCurvePlacementDef *next;
  int done;
  int n;
  int mA;
  int mB;
  int count;
  int link;
  int id;
  uint mask;
  int i;
  int idsB[ROMCURVE_LINK_COUNT];
  int idsA[ROMCURVE_LINK_COUNT];

  done = RomCurve_noUnblockedLinks(curve) ? 1 : 0;
  n = 0;
  mA = 0;
  mB = 0;
  if (!done) {
    while (curve != NULL && !RomCurve_noUnblockedLinks(curve)) {
      count = 0;
      mask = 1;
      for (i = 0; i < ROMCURVE_LINK_COUNT; i++) {
        link = curve->base.linkIds[i];
        if ((-1 < link) && ((curve->base.blockedLinkMask & mask) == 0) && (link != 0)) {
          idsB[count++] = link;
        }
        mask = mask << 1;
      }
      if (count != 0) {
        id = idsB[randomGetRange(0, count - 1)];
      } else {
        id = -1;
      }
      next = (RomCurvePlacementDef *)RomCurve_FindByIdInline(id);
      if (next != NULL) {
        if (outTypes != NULL) {
          outTypes[n >> 2] = curve->base.type;
        }
        outX[mB] = curve->base.x;
        outY[mB] = curve->base.y;
        outZ[mB] = curve->base.z;
        mB++;
        outX[mB] = next->base.x;
        outY[mB] = next->base.y;
        outZ[mB] = next->base.z;
        mB++;
        n += 2;
        outX[mB] = lbl_803E0610 * ((f32)curve->rotX * fn_80293E80(ROMCURVE_PLACEMENT_ANGLE(curve->rotZ)));
        outY[mB] = lbl_803E0610 * ((f32)curve->rotX * fn_80293E80(ROMCURVE_PLACEMENT_ANGLE(curve->rotY)));
        outZ[n] = lbl_803E0610 * ((f32)curve->rotX * sin(ROMCURVE_PLACEMENT_ANGLE(curve->rotZ)));
        n++;
        mB++;
        outX[mB] = lbl_803E0610 * ((f32)next->rotX * fn_80293E80(ROMCURVE_PLACEMENT_ANGLE(next->rotZ)));
        outY[mB] = lbl_803E0610 * ((f32)next->rotX * fn_80293E80(ROMCURVE_PLACEMENT_ANGLE(next->rotY)));
        outZ[n] = lbl_803E0610 * ((f32)next->rotX * sin(ROMCURVE_PLACEMENT_ANGLE(next->rotZ)));
        n++;
        mB++;
      }
      curve = next;
    }
  } else {
    while (curve != NULL && !RomCurve_noBlockedLinks(curve)) {
      count = 0;
      mask = 1;
      for (i = 0; i < ROMCURVE_LINK_COUNT; i++) {
        link = curve->base.linkIds[i];
        if ((-1 < link) && ((curve->base.blockedLinkMask & mask) != 0) && (link != 0)) {
          idsA[count++] = link;
        }
        mask = mask << 1;
      }
      if (count != 0) {
        id = idsA[randomGetRange(0, count - 1)];
      } else {
        id = -1;
      }
      next = (RomCurvePlacementDef *)RomCurve_FindByIdInline(id);
      if (next != NULL) {
        if (outTypes != NULL) {
          outTypes[n >> 2] = curve->base.type;
        }
        outX[mA] = curve->base.x;
        outY[mA] = curve->base.y;
        outZ[mA] = curve->base.z;
        mA++;
        outX[mA] = next->base.x;
        outY[mA] = next->base.y;
        outZ[mA] = next->base.z;
        mA++;
        n += 2;
        outX[mA] = lbl_803E0610 * ((f32)curve->rotX * fn_80293E80(ROMCURVE_PLACEMENT_ANGLE(curve->rotZ)));
        outY[mA] = lbl_803E0610 * ((f32)curve->rotX * fn_80293E80(ROMCURVE_PLACEMENT_ANGLE(curve->rotY)));
        outZ[n] = lbl_803E0610 * ((f32)curve->rotX * sin(ROMCURVE_PLACEMENT_ANGLE(curve->rotZ)));
        n++;
        mA++;
        outX[mA] = lbl_803E0610 * ((f32)next->rotX * fn_80293E80(ROMCURVE_PLACEMENT_ANGLE(next->rotZ)));
        outY[mA] = lbl_803E0610 * ((f32)next->rotX * fn_80293E80(ROMCURVE_PLACEMENT_ANGLE(next->rotY)));
        outZ[n] = lbl_803E0610 * ((f32)next->rotX * sin(ROMCURVE_PLACEMENT_ANGLE(next->rotZ)));
        n++;
        mA++;
      }
      curve = next;
    }
  }
  return n;
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
  int count;
  int linkCount;
  int link;
  int id;
  uint mask;
  int i;
  int ids[ROMCURVE_LINK_COUNT];

  count = 1;
  while (curve != NULL && !RomCurve_noUnblockedLinks((RomCurvePlacementDef *)curve)) {
    linkCount = 0;
    mask = 1;
    for (i = 0; i < ROMCURVE_LINK_COUNT; i++) {
      link = curve->linkIds[i];
      if ((-1 < link) && ((curve->blockedLinkMask & mask) == 0) && (link != 0)) {
        ids[linkCount++] = link;
      }
      mask = mask << 1;
    }
    if (linkCount != 0) {
      id = ids[randomGetRange(0, linkCount - 1)];
    } else {
      id = -1;
    }
    curve = RomCurve_FindByIdInline(id);
    if (curve != NULL) {
      count++;
    }
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
void RomCurve_func1E(uint *curveIds,float *outX,float *outY,float *outZ)
{
  uint *puVar1;
  float *pfVar2;
  float *outXCursor;
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
  int local_28 [10];
  
  puVar1 = curveIds;
  pfVar2 = outX;
  outXCursor = outX;
  iVar4 = 0;
  piVar3 = local_28;
  iVar13 = 4;
  pfVar9 = outZ;
  pfVar10 = outY;
  piVar11 = piVar3;
  do {
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
      *outXCursor = *(float *)(iVar5 + 8);
      *pfVar10 = *(float *)(iVar5 + 0xc);
      *pfVar9 = *(float *)(iVar5 + 0x10);
      iVar4 = iVar4 + 1;
    }
    piVar11 = piVar11 + 1;
    puVar1++;
    outXCursor++;
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
              *outY = *(float *)(local_28[1] + 0xc) +
                      (*(float *)(local_28[1] + 0xc) - *(float *)(local_28[2] + 0xc));
              *outZ = *(float *)(local_28[1] + 0x10) +
                      (*(float *)(local_28[1] + 0x10) - *(float *)(local_28[2] + 0x10));
            }
            else if (iVar4 == 3) {
              *pfVar2 = *(float *)(local_28[2] + 8) +
                        (*(float *)(local_28[2] + 8) - *(float *)(local_28[1] + 8));
              *outY = *(float *)(local_28[2] + 0xc) +
                      (*(float *)(local_28[2] + 0xc) - *(float *)(local_28[1] + 0xc));
              *outZ = *(float *)(local_28[2] + 0x10) +
                      (*(float *)(local_28[2] + 0x10) - *(float *)(local_28[1] + 0x10));
            }
          }
          piVar3 = piVar3 + 1;
          pfVar2 = pfVar2 + 1;
          outY = outY + 1;
          outZ = outZ + 1;
          iVar4 = iVar4 + 1;
          iVar13 = iVar13 + -1;
        } while (iVar13 != 0);
      }
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
  if (((gFloatZero != deltaX) || (gFloatZero != deltaY)) || (gFloatZero != deltaZ)) {
    projection = (deltaY * (y - startY) + deltaX * (x - startX) + deltaZ * (z - startZ)) /
                 (deltaY * deltaY + deltaX * deltaX + deltaZ * deltaZ);
  }
  else {
    projection = gFloatZero;
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
  int curveCount;
  RomCurveDef **tableSlot;
  int removeIndex;
  u32 remaining;

  removeIndex = 0;
  tableSlot = romCurves;
  curveCount = nRomCurves;
  while ((removeIndex < curveCount) &&
         (curve->id != (*tableSlot)->id)) {
    tableSlot = tableSlot + 1;
    removeIndex = removeIndex + 1;
  }

  if (removeIndex >= curveCount) {
    return;
  }

  curveCount = nRomCurves - 1;
  nRomCurves = curveCount;
  tableSlot = romCurves + removeIndex;
  remaining = curveCount - removeIndex;
  if (removeIndex >= curveCount) {
    return;
  }
  for (; remaining != 0; remaining--) {
    tableSlot[0] = tableSlot[1];
    tableSlot = tableSlot + 1;
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
  int curveCount;
  RomCurveDef **scanSlot;
  RomCurveDef **shiftSlot;
  int insertIndex;

  curveCount = nRomCurves;
  if (curveCount == ROMCURVE_MAX_CURVES) {
    OSReport(sCurvesMaxRomCurvesExceeded);
    return;
  }

  insertIndex = 0;
  scanSlot = romCurves;
  while ((insertIndex < curveCount) && (curve->id > (*scanSlot)->id)) {
    scanSlot++;
    insertIndex++;
  }

  for (shiftSlot = romCurves + curveCount; insertIndex < curveCount; curveCount--) {
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
  int found1;
  int hits;
  f32 *pt;
  f32 w;
  f32 dx;
  f32 dz;
  s16 ang;
  uint count;
  int i;
  f32 *pf;
  uint *walk;
  f32 **list;
  f32 sum0;
  f32 sum1;
  f32 sum2;
  f32 sum3;
  f32 **hitOut;
  f32 heights[5];

  if ((int)(uint)*(byte *)(curve + 0x97) >> 4 == 4) {
    sum0 = lbl_803E0668;
    count = 0;
    sum1 = sum0;
    sum2 = sum0;
    sum3 = sum0;
    pf = heights;
    walk = curve;
    for (i = 0; i < (int)(uint)*(byte *)(curve + 0x97) >> 4; i++) {
      *pf = *(f32 *)(walk + 3);
      hits = hitDetectFn_80065e50(obj, *(f32 *)(walk + 2), *(f32 *)(obj + 0x1c),
                                  *(f32 *)(walk + 4), &hitOut, -1, 0);
      found1 = 0;
      if ((hits != 0) && (list = hitOut, 0 < hits)) {
        do {
          if (!found1) {
            pt = *list;
            w = pt[0];
            if ((w < lbl_803E066C + *(f32 *)(obj + 0x1c)) && (*(char *)(pt + 5) != 0xe)) {
              *pf = pt[0];
              sum1 = sum1 + pt[1];
              sum2 = sum2 + pt[2];
              sum3 = sum3 + pt[3];
              sum0 = sum0 + w;
              count = count + 1;
              found1 = 1;
            }
          }
          list = list + 1;
        } while (--hits != 0);
      }
      *(f32 *)(walk + 3) = *pf;
      walk = walk + 3;
      pf = pf + 1;
    }
    if (count != 0) {
      *(f32 *)(obj + 0x1c) = sum0 / (f32)(s32)count;
      *(f32 *)(curve + 0x68) = sum1 / (f32)(s32)count;
      *(f32 *)(curve + 0x69) = sum2 / (f32)(s32)count;
      *(f32 *)(curve + 0x6a) = sum3 / (f32)(s32)count;
      *(u8 *)((u8 *)curve + 0x261) = 1;
    }
    else {
      *(u8 *)((u8 *)curve + 0x261) = 0;
    }
    dz = *(f32 *)(curve[1] + 0x2c) - *(f32 *)(curve[1] + 8);
    dx = heights[3] - heights[0];
    getAngle(dx, dz);
    ang = getAngle(dx, dz);
    *(s16 *)(obj + 2) = -ang;
    if ((*curve & 0x400) != 0) {
      *(s16 *)(obj + 4) = getAngle(heights[1] - heights[0],
                                   *(f32 *)(curve[1] + 0xc) - *(f32 *)curve[1]);
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
#pragma dont_inline on
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
#pragma dont_inline reset

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
#pragma dont_inline on
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
#pragma dont_inline reset

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
 * Function: curves_updateLocalPointCollision
 * EN v1.0 Address: 0x800E4DBC
 * EN v1.0 Size: 912b
 * EN v1.1 Address: 0x800E6410
 * EN v1.1 Size: 872b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void curves_updateLocalPointCollision(int obj,f32 *state)
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
 * Function: curves_preparePointCollisionFrame
 * EN v1.0 Address: 0x800E514C
 * EN v1.0 Size: 732b
 * EN v1.1 Address: 0x800E6778
 * EN v1.1 Size: 696b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void curves_preparePointCollisionFrame(int obj,u32 *state)
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
 * Function: curves_updateLocalPointTransforms
 * EN v1.0 Address: 0x800E5428
 * EN v1.0 Size: 328b
 * EN v1.1 Address: 0x800E6A30
 * EN v1.1 Size: 368b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void curves_updateLocalPointTransforms(int obj,u32 *state)
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
    fn_80063368((short *)obj);
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
  curves_preparePointCollisionFrame(obj,state);
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
    fn_80063368((short *)obj);
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
extern f32 lbl_803E0668;
extern f32 lbl_803E066C;
extern f32 lbl_803E068C;
extern void Obj_TransformWorldPointToLocal(f32 x,f32 y,f32 z,f32 *outX,f32 *outY,f32 *outZ,u32 obj);

void dll_15_func08(short *curveObj,int *state,uint updateValue,f32 step)
{
  int flags;
  f32 *pf;
  int *walk;
  int byteOff;
  int outOff;
  int i;
  int linked;
  f32 invStep;
  f32 one;
  f32 zero;
  f32 m1a[16];
  f32 m1b[16];
  f32 m2b[16];
  f32 m2a[16];
  f32 mE[16];
  CurvesTransformScratch s1a;
  CurvesTransformScratch s1b;
  CurvesTransformScratch s2b;
  CurvesTransformScratch s2a;
  CurvesTransformScratch sE;

  if ((*state & 0x4000000) == 0) {
    return;
  }
  one = lbl_803E068C;
  invStep = one / step;
  state[0x36] = 0;
  if (*(char *)((u8 *)state + 0x25b) == 1) {
    sCurvesCachedHitObj = 0;
    sCurvesCachedHitCount = 0;
    zero = lbl_803E0668;
    *(f32 *)(state + 0x68) = zero;
    *(f32 *)(state + 0x69) = one;
    *(f32 *)(state + 0x6a) = zero;
    if (((*state & 8) != 0) && ((*(byte *)(state + 0x97) & 0xf) != 0)) {
      s1a.angles[0] = curveObj[0];
      if ((*state & 0x20) != 0) {
        s1a.angles[1] = 0;
        s1a.angles[2] = 0;
        }
        else {
        s1a.angles[1] = curveObj[1];
        s1a.angles[2] = curveObj[2];
        }
      s1a.scale = lbl_803E068C;
      s1a.x = *(f32 *)(curveObj + 6);
      s1a.y = *(f32 *)(curveObj + 8);
      s1a.z = *(f32 *)(curveObj + 10);
      setMatrixFromObjectPos(m1a, &s1a);
      outOff = 0;
      i = 0;
      walk = state;
      byteOff = 0;
      for (; i < (int)(*(byte *)(state + 0x97) & 0xf); i++) {
        pf = (f32 *)(state[0x37] + byteOff);
        Matrix_TransformPoint(m1a, pf[0], pf[1], pf[2], (f32 *)(walk + 0x39),
                              (f32 *)(state + (outOff + 1) + 0x39), (f32 *)(state + (outOff + 2) + 0x39));
        walk = walk + 3;
        byteOff = byteOff + 0xc;
        outOff = outOff + 3;
      }
      curves_updateLocalPointCollision((int)curveObj, (f32 *)state);
      if (*(void **)(curveObj + 0x18) != NULL) {
        if ((*(void **)(*(int *)(curveObj + 0x18) + 0x58) != NULL) &&
            (ObjHits_IsObjectEnabled(*(int *)(curveObj + 0x18)) != 0)) {
          Matrix_TransformPoint((f32 *)(*(int *)(*(int *)(curveObj + 0x18) + 0x58)) +
                                    (*(byte *)(*(int *)(*(int *)(curveObj + 0x18) + 0x58) + 0x10c) + 2) * 0x10,
                                *(f32 *)(curveObj + 6), *(f32 *)(curveObj + 8), *(f32 *)(curveObj + 10),
                                (f32 *)(curveObj + 0xc), (f32 *)(curveObj + 0xe), (f32 *)(curveObj + 0x10));
        }
        else {
          Obj_TransformLocalPointToWorld(*(f32 *)(curveObj + 6), *(f32 *)(curveObj + 8),
                                         *(f32 *)(curveObj + 10), (f32 *)(curveObj + 0xc),
                                         (f32 *)(curveObj + 0xe), (f32 *)(curveObj + 0x10),
                                         *(u32 *)(curveObj + 0x18));
        }
      }
      else {
        *(f32 *)(curveObj + 0xc) = *(f32 *)(curveObj + 6);
        *(f32 *)(curveObj + 0xe) = *(f32 *)(curveObj + 8);
        *(f32 *)(curveObj + 0x10) = *(f32 *)(curveObj + 10);
      }
    }
    if (((*state & 0x2000) != 0) && ((*(byte *)(state + 0x97) & 0xf0) != 0)) {
      s1b.angles[0] = curveObj[0];
      if ((*state & 0x20) != 0) {
        s1b.angles[1] = 0;
        s1b.angles[2] = 0;
        }
        else {
        s1b.angles[1] = curveObj[1];
        s1b.angles[2] = curveObj[2];
        }
      s1b.scale = lbl_803E068C;
      s1b.x = *(f32 *)(curveObj + 0xc);
      s1b.y = *(f32 *)(curveObj + 0xe);
      s1b.z = *(f32 *)(curveObj + 0x10);
      setMatrixFromObjectPos(m1b, &s1b);
      outOff = 0;
      i = 0;
      walk = state;
      byteOff = 0;
      for (; i < (int)(uint)*(byte *)(state + 0x97) >> 4; i++) {
        pf = (f32 *)(state[1] + byteOff);
        Matrix_TransformPoint(m1b, pf[0], pf[1], pf[2], (f32 *)(walk + 2),
                              (f32 *)(state + (outOff + 1) + 2), (f32 *)(state + (outOff + 2) + 2));
        *(char *)((i + 0xb8) + (int)state) = -1;
        walk = walk + 3;
        byteOff = byteOff + 0xc;
        outOff = outOff + 3;
      }
      if ((*state & 2) != 0) {
        *(char *)(state + 0x98) = hitDetectFn_80067958((int)curveObj, state + 0xe, state + 2,
                                                       (int)(uint)*(byte *)(state + 0x97) >> 4,
                                                       state + 0x1a, 0);
        *(char *)((u8 *)state + 0x261) = *(s16 *)((u8 *)state + 0xd4);
        *(u8 *)((u8 *)state + 0x25f) = 0;
      }
      switch (*(byte *)((u8 *)state + 0x262)) {
      case 3:
        curves_countRandomPoints((int)curveObj, (uint *)state);
        break;
      case 1:
        fn_800E56A4((int)curveObj, (f32 *)state);
        break;
      case 4:
        *(f32 *)(state + 0x68) = *(f32 *)(state + 0x1a);
        *(f32 *)(state + 0x69) = *(f32 *)(state + 0x1b);
        *(f32 *)(state + 0x6a) = *(f32 *)(state + 0x1c);
        if (((*(char *)(state + 0x98) & 1) != 0) && (*(char *)(state + 0x2e) == 0x21)) {
          *(f32 *)(curveObj + 0xc) = *(f32 *)(state + 2);
          *(f32 *)(curveObj + 0xe) = *(f32 *)(state + 3);
          *(f32 *)(curveObj + 0x10) = *(f32 *)(state + 4);
        }
        break;
      default:
        fn_800E58FC((int)curveObj, (f32 *)state);
        break;
      }
      if ((*state & 0x100) != 0) {
        fn_800E5E38((int)curveObj, (f32 *)state);
      }
      if ((*state & 0x80) != 0) {
        fn_800E5CBC((short *)curveObj, (int)state);
      }
      if ((*state & 1) != 0) {
        fn_800E5F1C((int)curveObj, (f32 *)state);
      }
      memcpy(state + 0xe, state + 2, ((int)(uint)*(byte *)(state + 0x97) >> 4) * 0xc);
    }
    if ((*state & 0x800) != 0) {
      if (0x3400 < curveObj[1]) {
        curveObj[1] = 0x3400;
      }
      if (curveObj[1] < -0x3400) {
        curveObj[1] = -0x3400;
      }
    }
    if ((*state & 0x1000) != 0) {
      if (0x3400 < curveObj[2]) {
        curveObj[2] = 0x3400;
      }
      if (curveObj[2] < -0x3400) {
        curveObj[2] = -0x3400;
      }
    }
    if ((*state & 0x40000) == 0) {
      linked = *(int *)(curveObj + 0x2a);
      if ((linked == 0) || ((*(ushort *)(linked + 0x60) & 1) == 0)) {
        *(f32 *)(curveObj + 0x14) =
            (f32)((f64)invStep * (f64)(*(f32 *)(curveObj + 0xe) - *(f32 *)(curveObj + 0x48)));
      }
      else {
        *(f32 *)(curveObj + 0x14) =
            (f32)((f64)invStep * (f64)(*(f32 *)(curveObj + 0xe) - *(f32 *)(linked + 0x20)));
        if (*(f32 *)(*(int *)(curveObj + 0x2a) + 0x20) < *(f32 *)(curveObj + 0xe)) {
          *(f32 *)(curveObj + 0x14) = lbl_803E0668;
        }
      }
    }
  }
  else if (*(char *)((u8 *)state + 0x25b) == 2) {
    curves_preparePointCollisionFrame((int)curveObj, (u32 *)state);
    flags = *state;
    if (((flags & 0x4000000) != 0) && ((flags & 8) != 0)) {
      s2a.angles[0] = curveObj[0];
      if ((flags & 0x20) != 0) {
        s2a.angles[1] = 0;
        s2a.angles[2] = 0;
        }
        else {
        s2a.angles[1] = curveObj[1];
        s2a.angles[2] = curveObj[2];
        }
      s2a.scale = lbl_803E068C;
      s2a.x = *(f32 *)(curveObj + 6);
      s2a.y = *(f32 *)(curveObj + 8);
      s2a.z = *(f32 *)(curveObj + 10);
      setMatrixFromObjectPos(m2a, &s2a);
      outOff = 0;
      i = 0;
      walk = state;
      byteOff = 0;
      for (; i < (int)(*(byte *)(state + 0x97) & 0xf); i++) {
        pf = (f32 *)(state[0x37] + byteOff);
        Matrix_TransformPoint(m2a, pf[0], pf[1], pf[2], (f32 *)(walk + 0x39),
                              (f32 *)(state + (outOff + 1) + 0x39), (f32 *)(state + (outOff + 2) + 0x39));
        walk = walk + 3;
        byteOff = byteOff + 0xc;
        outOff = outOff + 3;
      }
      walk = state;
      for (i = 0; i < (int)(*(byte *)(state + 0x97) & 0xf); i++) {
        walk[0x45] = walk[0x39];
        *(f32 *)(walk + 0x46) = lbl_803E068C + *(f32 *)(walk + 0x3a);
        walk[0x47] = walk[0x3b];
        walk = walk + 3;
      }
      fn_80063368(curveObj);
    }
    if ((*state & 0x2000) != 0) {
      s2b.angles[0] = curveObj[0];
      if ((*state & 0x20) != 0) {
        s2b.angles[1] = 0;
        s2b.angles[2] = 0;
        }
        else {
        s2b.angles[1] = curveObj[1];
        s2b.angles[2] = curveObj[2];
        }
      s2b.scale = lbl_803E068C;
      s2b.x = *(f32 *)(curveObj + 0xc);
      s2b.y = *(f32 *)(curveObj + 0xe);
      s2b.z = *(f32 *)(curveObj + 0x10);
      setMatrixFromObjectPos(m2b, &s2b);
      outOff = 0;
      i = 0;
      walk = state;
      byteOff = 0;
      for (; i < (int)(uint)*(byte *)(state + 0x97) >> 4; i++) {
        pf = (f32 *)(state[1] + byteOff);
        Matrix_TransformPoint(m2b, pf[0], pf[1], pf[2], (f32 *)(walk + 2),
                              (f32 *)(state + (outOff + 1) + 2), (f32 *)(state + (outOff + 2) + 2));
        *(char *)((i + 0xb8) + (int)state) = -1;
        walk = walk + 3;
        byteOff = byteOff + 0xc;
        outOff = outOff + 3;
      }
      memcpy(state + 0xe, state + 2, ((int)(uint)*(byte *)(state + 0x97) >> 4) * 0xc);
      if ((*state & 1) != 0) {
        fn_800E5F1C((int)curveObj, (f32 *)state);
      }
    }
  }
  else {
    curves_preparePointCollisionFrame((int)curveObj, (u32 *)state);
    flags = *state;
    if (((flags & 0x4000000) != 0) && ((flags & 8) != 0)) {
      sE.angles[0] = curveObj[0];
      if ((flags & 0x20) != 0) {
        sE.angles[1] = 0;
        sE.angles[2] = 0;
        }
        else {
        sE.angles[1] = curveObj[1];
        sE.angles[2] = curveObj[2];
        }
      sE.scale = lbl_803E068C;
      sE.x = *(f32 *)(curveObj + 6);
      sE.y = *(f32 *)(curveObj + 8);
      sE.z = *(f32 *)(curveObj + 10);
      setMatrixFromObjectPos(mE, &sE);
      outOff = 0;
      i = 0;
      walk = state;
      byteOff = 0;
      for (; i < (int)(*(byte *)(state + 0x97) & 0xf); i++) {
        pf = (f32 *)(state[0x37] + byteOff);
        Matrix_TransformPoint(mE, pf[0], pf[1], pf[2], (f32 *)(walk + 0x39),
                              (f32 *)(state + (outOff + 1) + 0x39), (f32 *)(state + (outOff + 2) + 0x39));
        walk = walk + 3;
        byteOff = byteOff + 0xc;
        outOff = outOff + 3;
      }
      walk = state;
      for (i = 0; i < (int)(*(byte *)(state + 0x97) & 0xf); i++) {
        walk[0x45] = walk[0x39];
        *(f32 *)(walk + 0x46) = lbl_803E068C + *(f32 *)(walk + 0x3a);
        walk[0x47] = walk[0x3b];
        walk = walk + 3;
      }
      fn_80063368(curveObj);
    }
  }
  if (*(void **)(curveObj + 0x18) != NULL) {
    if ((*(void **)(*(int *)(curveObj + 0x18) + 0x58) != NULL) &&
        (ObjHits_IsObjectEnabled(*(int *)(curveObj + 0x18)) != 0)) {
      outOff = (uint)*(byte *)(*(int *)(*(int *)(curveObj + 0x18) + 0x58) + 0x10c) * 0x10;
      Matrix_TransformPoint((f32 *)(*(int *)(*(int *)(curveObj + 0x18) + 0x58)) + outOff,
                            *(f32 *)(curveObj + 0xc), *(f32 *)(curveObj + 0xe), *(f32 *)(curveObj + 0x10),
                            (f32 *)(curveObj + 6), (f32 *)(curveObj + 8), (f32 *)(curveObj + 10));
    }
    else {
      Obj_TransformWorldPointToLocal(*(f32 *)(curveObj + 0xc), *(f32 *)(curveObj + 0xe),
                                     *(f32 *)(curveObj + 0x10), (f32 *)(curveObj + 6),
                                     (f32 *)(curveObj + 8), (f32 *)(curveObj + 10),
                                     *(u32 *)(curveObj + 0x18));
    }
  }
  else {
    *(f32 *)(curveObj + 6) = *(f32 *)(curveObj + 0xc);
    *(f32 *)(curveObj + 8) = *(f32 *)(curveObj + 0xe);
    *(f32 *)(curveObj + 10) = *(f32 *)(curveObj + 0x10);
  }
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
extern f32 lbl_803E06C0;

void dll_15_func06(short *curveObj,int *state)
{
  f32 r;
  f32 v;
  f32 maxX;
  f32 maxZ;
  f32 maxY;
  f32 minX;
  f32 minZ;
  f32 minY;
  f32 *pin;
  int idx3;
  int byteOff;
  int i;
  int n;
  int count;
  f64 c;
  f32 *ptsWalk;
  f32 *radWalk;
  f32 *radWrite;
  f32 *ptsRead;
  int *walk;
  int *walk2;
  f32 m[16];
  f32 pts[12];
  CurvesTransformScratch s;
  f32 radii[4];

  if ((*(char *)((u8 *)state + 0x25b) != 0) && ((*state & 0x4000000) != 0) &&
      ((*state & 0x2000) != 0)) {
    if (*(void **)(curveObj + 0x18) != NULL) {
      if ((*(void **)(*(int *)(curveObj + 0x18) + 0x58) != NULL) &&
          (ObjHits_IsObjectEnabled(*(int *)(curveObj + 0x18)) != 0)) {
        idx3 = (*(byte *)(*(int *)(*(int *)(curveObj + 0x18) + 0x58) + 0x10c) + 2) * 0x10;
        Matrix_TransformPoint((f32 *)(*(int *)(*(int *)(curveObj + 0x18) + 0x58)) + idx3,
                              *(f32 *)(curveObj + 6), *(f32 *)(curveObj + 8), *(f32 *)(curveObj + 10),
                              (f32 *)(curveObj + 0xc), (f32 *)(curveObj + 0xe), (f32 *)(curveObj + 0x10));
      }
      else {
        Obj_TransformLocalPointToWorld(*(f32 *)(curveObj + 6), *(f32 *)(curveObj + 8),
                                       *(f32 *)(curveObj + 10), (f32 *)(curveObj + 0xc),
                                       (f32 *)(curveObj + 0xe), (f32 *)(curveObj + 0x10),
                                       *(u32 *)(curveObj + 0x18));
      }
    }
    else {
      *(f32 *)(curveObj + 0xc) = *(f32 *)(curveObj + 6);
      *(f32 *)(curveObj + 0xe) = *(f32 *)(curveObj + 8);
      *(f32 *)(curveObj + 0x10) = *(f32 *)(curveObj + 10);
    }
    s.angles[0] = curveObj[0];
    if ((*state & 0x20) != 0) {
      s.angles[1] = 0;
      s.angles[2] = 0;
    }
    else {
      s.angles[1] = curveObj[1];
      s.angles[2] = curveObj[2];
    }
    s.scale = lbl_803E068C;
    s.x = *(f32 *)(curveObj + 0xc);
    s.y = *(f32 *)(curveObj + 0xe);
    s.z = *(f32 *)(curveObj + 0x10);
    setMatrixFromObjectPos(m, &s);
    idx3 = 0;
    byteOff = 0;
    ptsWalk = pts;
    ptsRead = ptsWalk;
    walk2 = state;
    radWrite = radii;
    radWalk = radWrite;
    c = lbl_803E06C0;
    for (i = 0; i < (int)(uint)*(byte *)(state + 0x97) >> 4; i++) {
      pin = (f32 *)(state[1] + byteOff);
      Matrix_TransformPoint(m, pin[0], pin[1], pin[2], ptsWalk,
                            pts + (idx3 + 1), pts + (idx3 + 2));
      *radWalk = *(f32 *)(walk2 + 0x2a);
      *radWalk = sqrtf((f32)((f64)(f32)(c * (f64)*radWalk) * (f64)*radWalk));
      ptsWalk = ptsWalk + 3;
      byteOff = byteOff + 0xc;
      idx3 = idx3 + 3;
      walk2 = walk2 + 1;
      radWalk = radWalk + 1;
    }
    maxX = lbl_803E06A4;
    maxZ = lbl_803E06A4;
    maxY = lbl_803E06A4;
    minX = lbl_803E06A8;
    minZ = lbl_803E06A8;
    minY = lbl_803E06A8;
    walk = state;
    for (n = (int)(uint)*(byte *)(state + 0x97) >> 4; n != 0; n--) {
      r = *radWrite;
      v = *ptsRead + r;
      if (maxX < v) {
        maxX = v;
      }
      v = *ptsRead - r;
      if (v < minX) {
        minX = v;
      }
      v = ptsRead[1] + r;
      if (maxY < v) {
        maxY = v;
      }
      v = ptsRead[1] - r;
      if (v < minY) {
        minY = v;
      }
      v = ptsRead[2] + r;
      if (maxZ < v) {
        maxZ = v;
      }
      v = ptsRead[2] - r;
      if (v < minZ) {
        minZ = v;
      }
      v = *(f32 *)(walk + 0xe) + r;
      if (maxX < v) {
        maxX = v;
      }
      v = *(f32 *)(walk + 0xe) - r;
      if (v < minX) {
        minX = v;
      }
      v = *(f32 *)(walk + 0xf) + r;
      if (maxY < v) {
        maxY = v;
      }
      v = *(f32 *)(walk + 0xf) - r;
      if (v < minY) {
        minY = v;
      }
      v = *(f32 *)(walk + 0x10) + r;
      if (maxZ < v) {
        maxZ = v;
      }
      r = *(f32 *)(walk + 0x10) - r;
      if (r < minZ) {
        minZ = r;
      }
      ptsRead = ptsRead + 3;
      radWrite = radWrite + 1;
      walk = walk + 3;
    }
    state[0x90] = (int)minX;
    state[0x93] = (int)maxX;
    state[0x91] = (int)(minY - (f32)*(u8 *)((u8 *)state + 0x258));
    state[0x94] = (int)(maxY + (f32)*(u8 *)((u8 *)state + 0x258));
    state[0x92] = (int)minZ;
    state[0x95] = (int)maxZ;
  }
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

/* curves_setLocalPointCollisionEx: extended dll_15_func04 - same fields plus a second signed
 * byte at obj[0x263] and OR-in 0x02000008 on the flags word at obj[0]. */
#pragma scheduling off
#pragma peephole off
void curves_setLocalPointCollisionEx(u8* obj, int a, u32 b, u32 c, int d, int e)
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
