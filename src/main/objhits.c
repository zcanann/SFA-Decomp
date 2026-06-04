#include "ghidra_import.h"
#include "main/objhits.h"


#pragma peephole off
#pragma scheduling off
extern undefined8 memcpy();
extern void Obj_TransformWorldVectorToLocal(f32 x, f32 y, f32 z, f32 *outX, f32 *outY, f32 *outZ, int obj);
extern undefined4 Obj_TransformWorldPointToLocal();
extern void Obj_TransformLocalPointToWorld(f32 x, f32 y, f32 z, f32 *outX, f32 *outY, f32 *outZ, int obj);
extern uint getAngle(f32 a, f32 b);
extern undefined4 mtxRotateByVec3s();
extern undefined4 setMatrixFromObjectPos();
extern int ObjModel_GetJointMatrix(int *model,int jointIndex);
extern int *ObjList_GetObjects(int *startIndex,int *objectCount);
extern int ObjHits_RecordObjectHit(int obj,int hitObj,char priority,u8 hitVolume,u8 sphereIndex);
extern int ObjHits_RecordPositionHit(f32 hitPosX,f32 hitPosY,f32 hitPosZ,int obj,int hitObj,char priority,
                                     u8 hitVolume,u8 sphereIndex);
extern void ObjContact_DispatchCallbacks(int objA,int objB);
extern byte hitDetectFn_80067958(int obj,float *startPoints,float *endPoints,int pointCount,
                                 void *outHits,int flags);
extern void hitDetectFn_800691c0(int obj,void *bounds,uint mask,int flags);
extern void hitDetect_calcSweptSphereBounds(uint *boundsOut,float *startPoints,float *endPoints,float *radii,
                        int pointCount);
extern void debugPrintf(char *message,...);
extern undefined8 __save_gpr();
extern undefined8 _savegpr_17();
extern int _savegpr_19();
extern undefined8 _savegpr_21();
extern undefined8 _savegpr_23();
extern undefined8 _savegpr_24();
extern undefined8 _savegpr_27();
extern undefined4 __restore_gpr();
extern undefined4 _restgpr_17();
extern undefined4 _restgpr_19();
extern undefined4 _restgpr_21();
extern undefined4 _restgpr_23();
extern undefined4 _restgpr_24();
extern undefined4 _restgpr_27();
extern f32 sqrtf(f32 v);
extern f32 sin(f32 v);

extern ObjHitsSweepEntry *gObjHitsSweepEntryPtrs[OBJHITS_SWEEP_ENTRY_CAPACITY];
extern ObjHitsSweepEntry gObjHitsSweepEntries[OBJHITS_SWEEP_ENTRY_CAPACITY];
extern undefined4 DAT_80341b9c;
extern u8 *gObjHitsPriorityHitStates;
extern f64 DOUBLE_803df5a8;
extern f64 DOUBLE_803df5c0;
extern f64 DOUBLE_803df5d0;
extern f32 timeDelta;
extern f32 oneOverTimeDelta;
extern f32 lbl_803DE960;
extern f32 lbl_803DE91C;
extern f32 lbl_803DE958;
extern f32 lbl_803DE95C;
extern f32 lbl_803DE920;
extern f32 lbl_803DE930;
extern f32 lbl_803DE934;
extern f32 lbl_803DE938;
extern f32 lbl_803DE948;
extern f32 lbl_803DE94C;
extern f32 lbl_803DB450;

typedef struct ObjHitsVec3 {
  f32 x;
  f32 y;
  f32 z;
} ObjHitsVec3;
extern f32 lbl_803DC074;
extern f32 lbl_803DC078;
extern f32 lbl_803DC0B0;
extern f32 gObjHitsPriorityHitTickDelta;
extern f32 gObjHitsScalarZero;
extern f32 gObjHitsScalarOne;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803DF590;
extern f32 lbl_803DF598;
extern void Vec3_Normalize();
extern void Vec3_ScaleAdd();
extern void Vec3_Cross();
extern f32 Vec3_Length();
extern void Vec3_ReflectAgainstNormal();
extern f32 lbl_803DF59C;
extern f32 lbl_803DF5A0;
extern f32 lbl_803DF5B0;
extern f32 lbl_803DF5B4;
extern f32 lbl_803DF5B8;
extern f32 lbl_803DF5D8;
extern f32 lbl_803DF5DC;
extern f32 lbl_803DF5E0;

/*
 * --INFO--
 *
 * Function: ObjHits_CollectSkeletonHitsXZ
 * EN v1.0 Address: 0x80030688
 * EN v1.0 Size: 1124b
 * EN v1.1 Address: 0x80030780
 * EN v1.1 Size: 1124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int ObjHits_CollectSkeletonHitsXZ(f32 *point,f32 radius,int jointData,int *model,int *hits,
                                  int *outBest,f32 yMax,f32 yMin,f32 *outAccum)
{
  float dVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int iVar6;
  int iVar7;
  uint uVar8;
  int iVar10;
  int iVar11;
  int iVar12;
  uint uVar13;
  int iVar14;
  float *pfVar15;
  int iVar16;
  float dVar17;
  float dVar18;
  float dVar19;
  float in_f25;
  float dVar20;
  float in_f26;
  float in_f27;
  float in_f28;
  float in_f29;
  float dVar21;
  float in_f30;
  float dVar22;
  float in_f31;
  float dVar23;
  float local_e8;
  float local_e4;
  float local_e0;
  float local_dc;
  float local_d8;
  float local_d4;
  float local_d0;
  float local_cc;
  float local_c8;
  float local_c4;
  float local_c0;
  float local_bc;
  
  iVar11 = 0;
  if (jointData != 0) {
    iVar10 = *model;
    iVar14 = *(int *)(jointData + 4);
    dVar21 = (float)(radius + radius);
    *outBest = (int)hits;
    *outAccum = gObjHitsScalarZero;
    dVar20 = radius;
    iVar6 = ObjModel_GetJointMatrix(model,0);
    local_c4 = *(float *)(iVar6 + 0xc);
    local_c0 = *(float *)(iVar6 + 0x1c);
    local_bc = *(float *)(iVar6 + 0x2c);
    dVar17 = sqrtf(((local_bc - point[2]) * (local_bc - point[2]) +
                                  (local_c4 - *point) * (local_c4 - *point) + gObjHitsScalarZero));
    dVar17 = (float)(dVar17 - dVar20);
    dVar23 = (*point + *point);
    dVar22 = (point[2] + point[2]);
    uVar13 = (uint)*(byte *)(iVar10 + 0xf3);
    iVar6 = uVar13 * 4;
    iVar16 = uVar13 * 0x1c;
    pfVar15 = (float *)(iVar14 + iVar6);
    while( true ) {
      iVar6 = iVar6 + -4;
      iVar16 = iVar16 + -0x1c;
      pfVar15 = pfVar15 + -1;
      uVar13 = uVar13 - 1;
      if (uVar13 == 0) break;
      if (dVar17 < *(float *)(*(int *)(jointData + 0x10) + iVar6)) {
        iVar12 = (int)*(char *)(*(int *)(iVar10 + 0x3c) + iVar16);
        iVar7 = ObjModel_GetJointMatrix(model,uVar13);
        local_c4 = *(float *)(iVar7 + 0xc);
        local_c0 = *(float *)(iVar7 + 0x1c);
        local_bc = *(float *)(iVar7 + 0x2c);
        iVar7 = ObjModel_GetJointMatrix(model,iVar12);
        local_d0 = *(float *)(iVar7 + 0xc);
        local_cc = *(float *)(iVar7 + 0x1c);
        local_c8 = *(float *)(iVar7 + 0x2c);
        *(undefined *)(*(int *)(jointData + 0x18) + uVar13) = 1;
        *(undefined *)(*(int *)(jointData + 0x18) + iVar12) = 1;
        dVar18 = *pfVar15;
        dVar19 = *(float *)(iVar14 + iVar12 * 4);
        if ((((float)(local_c0 - dVar18) <= yMax) ||
            ((float)(local_cc - dVar19) <= yMax)) &&
           ((yMin <= (float)(local_c0 + dVar18) ||
            (yMin <= (float)(local_cc + dVar19))))) {
          fVar3 = (float)((local_d0 + local_c4) - dVar23);
          fVar4 = (float)((local_c8 + local_bc) - dVar22);
          if (dVar18 <= dVar19) {
            dVar1 = dVar19 + dVar19;
          }
          else {
            dVar1 = dVar18 + dVar18;
          }
          fVar2 = (float)(dVar21 + (*(float *)(*(int *)(jointData + 0xc) + iVar6) + (float)dVar1
                                           ));
          if (fVar4 * fVar4 + fVar3 * fVar3 + gObjHitsScalarZero < fVar2 * fVar2) {
            local_dc = local_d0 - local_c4;
            local_d8 = local_cc - local_c0;
            local_d4 = local_c8 - local_bc;
            fVar3 = *(float *)(*(int *)(jointData + 0xc) + iVar6);
            if (fVar3 != gObjHitsScalarZero) {
              fVar3 = gObjHitsScalarOne / fVar3;
              local_dc = local_dc * fVar3;
              local_d8 = local_d8 * fVar3;
              local_d4 = local_d4 * fVar3;
            }
            *(undefined *)(*(int *)(jointData + 0x18) + uVar13) = 0;
            *(undefined *)(*(int *)(jointData + 0x18) + iVar12) = 0;
            uVar8 = ObjHits_TestTaperedCapsuleXZ(dVar20,dVar18,dVar19,
                                                 *(float *)(*(int *)(jointData + 0xc) + iVar6),
                                                 point,&local_c4,&local_dc,&local_d0,&local_e0,
                                                 &local_e4,&local_e8);
            if (uVar8 != 0) {
              *(undefined *)(*(int *)(jointData + 0x18) + uVar13) = 1;
              *(undefined *)(*(int *)(jointData + 0x18) + iVar12) = 1;
              dVar18 = sqrtf(local_e4);
              *(float *)(hits + 0xc) = (float)(dVar20 + (float)(dVar18 - local_e8));
              if (gObjHitsScalarZero == *(float *)(hits + 0xc)) {
                *(float *)(hits + 0xc) = lbl_803DE920;
              }
              fVar3 = *(float *)(hits + 0xc);
              if (fVar3 <= gObjHitsScalarZero) {
                fVar3 = -fVar3;
              }
              *(float *)(hits + 0xf) = (gObjHitsScalarOne / fVar3);
              *outAccum = *outAccum + *(float *)(hits + 0xf);
              if (*(float *)(hits + 0xc) < *(float *)(*outBest + 0x30)) {
                *outBest = (int)hits;
              }
              *hits = (int)&local_c4;
              hits[1] = (int)&local_d0;
              *(float *)(hits + 2) = local_c4;
              *(float *)(hits + 3) = local_c0;
              *(float *)(hits + 4) = local_bc;
              *(float *)(hits + 5) = local_d0;
              *(float *)(hits + 6) = local_cc;
              *(float *)(hits + 7) = local_c8;
              *(float *)(hits + 0xb) = local_e0;
              *(float *)(hits + 0xe) = local_e8;
              dVar18 = sqrtf(local_e4);
              *(float *)(hits + 0xd) = (float)dVar18;
              *(float *)(hits + 8) = local_dc;
              *(float *)(hits + 9) = local_d8;
              *(float *)(hits + 10) = local_d4;
              hits[OBJHITS_SKELETON_HIT_POINT_INDEX_A_WORD] = uVar13;
              hits[OBJHITS_SKELETON_HIT_POINT_INDEX_B_WORD] = iVar12;
              if (iVar11 < OBJHITS_SKELETON_HIT_CAPACITY) {
                hits = hits + OBJHITS_SKELETON_HIT_WORD_COUNT;
                iVar11 = iVar11 + 1;
              }
            }
          }
        }
      }
    }
    hits[OBJHITS_SKELETON_HIT_POINT_INDEX_A_WORD] = OBJHITS_SKELETON_HIT_SENTINEL;
  }
  return iVar11;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
/*
 * --INFO--
 *
 * Function: ObjHits_CollectSkeletonHits3D
 * EN v1.0 Address: 0x80030AEC
 * EN v1.0 Size: 988b
 * EN v1.1 Address: 0x80030BE4
 * EN v1.1 Size: 988b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int ObjHits_CollectSkeletonHits3D(f32 *point,f32 radius,int jointData,int *model,int *hits,
                                  int *outBest,f32 *outAccum)
{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar5;
  int iVar6;
  uint uVar7;
  int iVar9;
  int iVar10;
  int iVar11;
  uint uVar12;
  int iVar13;
  float *pfVar14;
  int iVar15;
  float dVar16;
  float dVar17;
  float dVar18;
  float dVar19;
  float in_f27;
  float dVar20;
  float in_f28;
  float in_f29;
  float dVar21;
  float in_f30;
  float dVar22;
  float in_f31;
  float dVar23;
  float local_c8;
  float local_c4;
  float local_c0;
  float local_bc;
  float local_b8;
  float local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  
  iVar10 = 0;
  if (jointData != 0) {
    iVar9 = *model;
    iVar13 = *(int *)(jointData + 4);
    dVar21 = (float)(radius + radius);
    *outBest = (int)hits;
    *outAccum = gObjHitsScalarZero;
    dVar20 = radius;
    iVar5 = ObjModel_GetJointMatrix(model,0);
    local_a4 = *(float *)(iVar5 + 0xc);
    local_a0 = *(float *)(iVar5 + 0x1c);
    local_9c = *(float *)(iVar5 + 0x2c);
    dVar16 = sqrtf(((local_9c - point[2]) * (local_9c - point[2]) +
                                  (local_a4 - *point) * (local_a4 - *point) + gObjHitsScalarZero));
    dVar16 = (float)(dVar16 - dVar20);
    dVar23 = (*point + *point);
    dVar22 = (point[2] + point[2]);
    uVar12 = (uint)*(byte *)(iVar9 + 0xf3);
    iVar5 = uVar12 * 4;
    iVar15 = uVar12 * 0x1c;
    pfVar14 = (float *)(iVar13 + iVar5);
    while( true ) {
      iVar5 = iVar5 + -4;
      iVar15 = iVar15 + -0x1c;
      pfVar14 = pfVar14 + -1;
      uVar12 = uVar12 - 1;
      if (uVar12 == 0) break;
      if (dVar16 < *(float *)(*(int *)(jointData + 0x10) + iVar5)) {
        iVar11 = (int)*(char *)(*(int *)(iVar9 + 0x3c) + iVar15);
        iVar6 = ObjModel_GetJointMatrix(model,uVar12);
        local_a4 = *(float *)(iVar6 + 0xc);
        local_a0 = *(float *)(iVar6 + 0x1c);
        local_9c = *(float *)(iVar6 + 0x2c);
        iVar6 = ObjModel_GetJointMatrix(model,iVar11);
        local_b0 = *(float *)(iVar6 + 0xc);
        local_ac = *(float *)(iVar6 + 0x1c);
        local_a8 = *(float *)(iVar6 + 0x2c);
        dVar17 = *pfVar14;
        dVar18 = *(float *)(iVar13 + iVar11 * 4);
        *(undefined *)(*(int *)(jointData + 0x18) + uVar12) = 1;
        *(undefined *)(*(int *)(jointData + 0x18) + iVar11) = 1;
        fVar2 = (float)((local_b0 + local_a4) - dVar23);
        fVar3 = (float)((local_a8 + local_9c) - dVar22);
        if (dVar17 <= dVar18) {
          dVar19 = dVar18 + dVar18;
        }
        else {
          dVar19 = dVar17 + dVar17;
        }
        fVar1 = (float)(dVar21 + (*(float *)(*(int *)(jointData + 0xc) + iVar5) + (float)dVar19)
                       );
        if (fVar3 * fVar3 + fVar2 * fVar2 + gObjHitsScalarZero < fVar1 * fVar1) {
          dVar19 = *(float *)(*(int *)(jointData + 0xc) + iVar5);
          local_b4 = (float)(gObjHitsScalarOne / dVar19);
          local_bc = (local_b0 - local_a4) * local_b4;
          local_b8 = (local_ac - local_a0) * local_b4;
          local_b4 = (local_a8 - local_9c) * local_b4;
          uVar7 = ObjHits_TestTaperedCapsule3D(dVar20,dVar17,dVar18,dVar19,point,&local_a4,
                                               &local_bc,&local_b0,&local_c0,&local_c4,&local_c8);
          if (uVar7 != 0) {
            *(undefined *)(*(int *)(jointData + 0x18) + uVar12) = 1;
            *(undefined *)(*(int *)(jointData + 0x18) + iVar11) = 1;
            dVar17 = sqrtf(local_c4);
            *(float *)(hits + 0xc) = (float)(dVar20 + (float)(dVar17 - local_c8));
            if (gObjHitsScalarZero == *(float *)(hits + 0xc)) {
              *(float *)(hits + 0xc) = lbl_803DE920;
            }
            fVar2 = *(float *)(hits + 0xc);
            if (fVar2 <= gObjHitsScalarZero) {
              fVar2 = -fVar2;
            }
            *(float *)(hits + 0xf) = (gObjHitsScalarOne / fVar2);
            *outAccum = *outAccum + *(float *)(hits + 0xf);
            if (*(float *)(hits + 0xc) < *(float *)(*outBest + 0x30)) {
              *outBest = (int)hits;
            }
            *hits = (int)&local_a4;
            hits[1] = (int)&local_b0;
            *(float *)(hits + 2) = local_a4;
            *(float *)(hits + 3) = local_a0;
            *(float *)(hits + 4) = local_9c;
            *(float *)(hits + 5) = local_b0;
            *(float *)(hits + 6) = local_ac;
            *(float *)(hits + 7) = local_a8;
            *(float *)(hits + 0xb) = local_c0;
            *(float *)(hits + 0xe) = local_c8;
            dVar17 = sqrtf(local_c4);
            *(float *)(hits + 0xd) = (float)dVar17;
            *(float *)(hits + 8) = local_bc;
            *(float *)(hits + 9) = local_b8;
            *(float *)(hits + 10) = local_b4;
            hits[OBJHITS_SKELETON_HIT_POINT_INDEX_A_WORD] = uVar12;
            hits[OBJHITS_SKELETON_HIT_POINT_INDEX_B_WORD] = iVar11;
            if (iVar10 < OBJHITS_SKELETON_HIT_CAPACITY) {
              iVar10 = iVar10 + 1;
              hits = hits + OBJHITS_SKELETON_HIT_WORD_COUNT;
            }
          }
        }
      }
    }
    hits[OBJHITS_SKELETON_HIT_POINT_INDEX_A_WORD] = OBJHITS_SKELETON_HIT_SENTINEL;
  }
  return iVar10;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjHits_CalcSkeletonResponseXZ
 * EN v1.0 Address: 0x80030EC8
 * EN v1.0 Size: 1248b
 * EN v1.1 Address: 0x80030FC0
 * EN v1.1 Size: 1248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void ObjHits_CalcSkeletonResponseXZ(f32 *pos,f32 radius,int obj,int hits,int jointPoints,
                                    int jointModel,int bestHit,f32 t,f32 axial,f32 *out)
{
  int iVar5;
  int iVar1;
  float fVar2;
  float *pfVar4;
  float dVar6;
  float in_f27;
  float dVar7;
  float in_f28;
  float in_f29;
  float in_f30;
  float in_f31;
  float dVar8;
  float local_e8;
  float local_e4;
  float local_e0;
  float local_dc;
  float local_d8;
  float local_d4;
  float local_d0;
  float local_cc;
  float local_c8;
  float local_c4;
  float local_c0;
  float local_bc;
  float afStack_b8 [3];
  float local_ac;
  float local_a8;
  float local_a4;
  float afStack_a0 [9];
  float local_7c;
  float local_78;
  float local_74;
  
  local_dc = *(float *)(obj + 0x18) - *(float *)(obj + 0x8c);
  local_d8 = *(float *)(obj + 0x10) - *(float *)(obj + 0x90);
  local_d4 = *(float *)(obj + 0x20) - *(float *)(obj + 0x94);
  dVar7 = radius;
  dVar6 = Vec3_Length(&local_dc);
  local_dc = (float)(local_dc * t);
  local_d8 = (float)(local_d8 * t);
  local_d4 = (float)(local_d4 * t);
  local_e8 = *pos - local_dc;
  local_e4 = pos[1] - local_d8;
  local_e0 = pos[2] - local_d4;
  local_7c = gObjHitsScalarZero;
  local_78 = gObjHitsScalarZero;
  local_74 = gObjHitsScalarZero;
  local_c4 = gObjHitsScalarZero;
  local_c0 = gObjHitsScalarZero;
  local_bc = gObjHitsScalarZero;
  iVar5 = *(int *)(bestHit + OBJHITS_SKELETON_HIT_POINT_INDEX_A_OFFSET) * 4;
  pfVar4 = ObjHits_CalcTaperedCapsuleNormal(
      *(float *)(bestHit + OBJHITS_SKELETON_HIT_AXIAL_OFFSET),
      *(float *)(*(int *)(jointPoints + 4) + iVar5),
      *(float *)(*(int *)(jointPoints + 4) +
                         *(int *)(bestHit + OBJHITS_SKELETON_HIT_POINT_INDEX_B_OFFSET) * 4),
      *(float *)(*(int *)(jointPoints + 0xc) + iVar5),&local_e8,(float *)(bestHit + 8),
      (float *)(bestHit + 0x14),afStack_b8);
  Vec3_Normalize(pfVar4);
  dVar8 = gObjHitsScalarZero;
  for (iVar5 = hits;
       *(int *)(iVar5 + OBJHITS_SKELETON_HIT_POINT_INDEX_A_OFFSET) != OBJHITS_SKELETON_HIT_SENTINEL;
       iVar5 = iVar5 + OBJHITS_SKELETON_HIT_SIZE) {
    iVar1 = *(int *)(iVar5 + OBJHITS_SKELETON_HIT_POINT_INDEX_A_OFFSET) * 4;
    pfVar4 = ObjHits_ProjectPointToTaperedCapsuleXZ(
        dVar7,*(float *)(iVar5 + OBJHITS_SKELETON_HIT_AXIAL_OFFSET),
        *(float *)(*(int *)(jointPoints + 4) + iVar1),
        *(float *)(*(int *)(jointPoints + 4) +
                           *(int *)(iVar5 + OBJHITS_SKELETON_HIT_POINT_INDEX_B_OFFSET) * 4),
        *(float *)(*(int *)(jointPoints + 0xc) + iVar1),&local_e8,(float *)(iVar5 + 8),
        (float *)(iVar5 + 0x14),afStack_a0);
    if (axial <= dVar8) {
      *(float *)(iVar5 + 0x3c) = (float)dVar8;
    }
    else {
      *(float *)(iVar5 + 0x3c) = (float)(*(float *)(iVar5 + 0x3c) / axial);
    }
    *pfVar4 = *pfVar4 * *(float *)(iVar5 + OBJHITS_SKELETON_HIT_INVERSE_DISTANCE_OFFSET);
    pfVar4[1] = pfVar4[1] * *(float *)(iVar5 + OBJHITS_SKELETON_HIT_INVERSE_DISTANCE_OFFSET);
    pfVar4[2] = pfVar4[2] * *(float *)(iVar5 + OBJHITS_SKELETON_HIT_INVERSE_DISTANCE_OFFSET);
    local_7c = local_7c + *pfVar4;
    local_78 = local_78 + pfVar4[1];
    local_74 = local_74 + pfVar4[2];
    iVar1 = *(int *)(iVar5 + OBJHITS_SKELETON_HIT_POINT_INDEX_A_OFFSET) * 4;
    pfVar4 = ObjHits_CalcTaperedCapsuleNormal(
        *(float *)(iVar5 + OBJHITS_SKELETON_HIT_AXIAL_OFFSET),
        *(float *)(*(int *)(jointPoints + 4) + iVar1),
        *(float *)(*(int *)(jointPoints + 4) +
                           *(int *)(iVar5 + OBJHITS_SKELETON_HIT_POINT_INDEX_B_OFFSET) * 4),
        *(float *)(*(int *)(jointPoints + 0xc) + iVar1),pos,(float *)(iVar5 + 8),
        (float *)(iVar5 + 0x14),afStack_b8);
    Vec3_Normalize(pfVar4);
    local_c4 = local_c4 + *pfVar4;
    local_c0 = local_c0 + pfVar4[1];
    local_bc = local_bc + pfVar4[2];
  }
  Vec3_Normalize(&local_c4);
  local_d0 = local_7c - local_e8;
  local_cc = gObjHitsScalarZero;
  local_c8 = local_74 - local_e0;
  dVar8 = Vec3_Length(&local_d0);
  local_d0 = local_7c - *pos;
  local_cc = gObjHitsScalarZero;
  local_c8 = local_74 - pos[2];
  Vec3_Normalize(&local_dc);
  if (dVar6 <= dVar8) {
    local_ac = gObjHitsScalarZero;
    local_a8 = gObjHitsScalarZero;
    local_a4 = gObjHitsScalarZero;
  }
  else {
    fVar2 = (float)(DOUBLE_803df5a8 +
                   ((float)(gObjHitsScalarOne - t) * lbl_803DE930)) *
            (float)(dVar6 - dVar8);
    local_dc = local_dc * fVar2;
    local_d8 = local_d8 * fVar2;
    local_d4 = local_d4 * fVar2;
    Vec3_ReflectAgainstNormal(&local_c4,&local_dc,&local_ac);
  }
  local_7c = local_7c + local_ac;
  local_78 = local_78 + local_a8;
  local_74 = local_74 + local_a4;
  local_ac = gObjHitsScalarZero;
  local_a8 = gObjHitsScalarZero;
  local_a4 = gObjHitsScalarZero;
  for (; *(int *)(hits + OBJHITS_SKELETON_HIT_POINT_INDEX_A_OFFSET) !=
         OBJHITS_SKELETON_HIT_SENTINEL;
       hits = hits + OBJHITS_SKELETON_HIT_SIZE) {
    iVar5 = *(int *)(hits + OBJHITS_SKELETON_HIT_POINT_INDEX_A_OFFSET) * 4;
    pfVar4 = ObjHits_ProjectPointToTaperedCapsuleXZ(
        dVar7,*(float *)(hits + OBJHITS_SKELETON_HIT_AXIAL_OFFSET),
        *(float *)(*(int *)(jointPoints + 4) + iVar5),
        *(float *)(*(int *)(jointPoints + 4) +
                           *(int *)(hits + OBJHITS_SKELETON_HIT_POINT_INDEX_B_OFFSET) * 4),
        *(float *)(*(int *)(jointPoints + 0xc) + iVar5),&local_7c,(float *)(hits + 8),
        (float *)(hits + 0x14),afStack_a0);
    *pfVar4 = *pfVar4 * *(float *)(hits + OBJHITS_SKELETON_HIT_INVERSE_DISTANCE_OFFSET);
    pfVar4[1] = pfVar4[1] * *(float *)(hits + OBJHITS_SKELETON_HIT_INVERSE_DISTANCE_OFFSET);
    pfVar4[2] = pfVar4[2] * *(float *)(hits + OBJHITS_SKELETON_HIT_INVERSE_DISTANCE_OFFSET);
    local_ac = local_ac + *pfVar4;
    local_a8 = local_a8 + pfVar4[1];
    local_a4 = local_a4 + pfVar4[2];
  }
  *out = local_ac - *pos;
  out[1] = gObjHitsScalarZero;
  out[2] = local_a4 - pos[2];
  return;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
/*
 * --INFO--
 *
 * Function: ObjHits_CalcSkeletonResponse3D
 * EN v1.0 Address: 0x800313A8
 * EN v1.0 Size: 1196b
 * EN v1.1 Address: 0x800314A0
 * EN v1.1 Size: 1196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_CalcSkeletonResponse3D(f32 *pos,f32 radius,int obj,int hits,int jointPoints,
                                    int jointModel,int bestHit,f32 t,f32 axial,f32 *out)
{
  float local_68;
  int iVar5;
  float fVar1;
  int iVar2;
  float *pfVar4;
  float dVar6;
  float in_f28;
  float dVar7;
  float in_f29;
  float in_f30;
  float in_f31;
  float dVar8;
  float local_d8;
  float local_d4;
  float local_d0;
  float local_cc;
  float local_c8;
  float local_c4;
  float local_c0;
  float local_bc;
  float local_b8;
  float local_b4;
  float local_b0;
  float local_ac;
  float afStack_a8 [3];
  float local_9c;
  float local_98;
  float local_94;
  float afStack_90 [9];
  float local_6c;
  float local_64;
  
  local_cc = *(float *)(iVar5 + 0xc) - *(float *)(iVar5 + 0x80);
  local_c8 = *(float *)(iVar5 + 0x10) - *(float *)(iVar5 + 0x84);
  local_c4 = *(float *)(iVar5 + 0x14) - *(float *)(iVar5 + 0x88);
  dVar7 = radius;
  dVar6 = Vec3_Length(&local_cc);
  local_d8 = *pos - local_cc;
  local_d4 = pos[1] - local_c8;
  local_d0 = pos[2] - local_c4;
  local_6c = gObjHitsScalarZero;
  local_68 = gObjHitsScalarZero;
  local_64 = gObjHitsScalarZero;
  local_b4 = gObjHitsScalarZero;
  local_b0 = gObjHitsScalarZero;
  local_ac = gObjHitsScalarZero;
  iVar5 = *(int *)(bestHit + OBJHITS_SKELETON_HIT_POINT_INDEX_A_OFFSET) * 4;
  pfVar4 = ObjHits_CalcTaperedCapsuleNormal(
      *(float *)(bestHit + OBJHITS_SKELETON_HIT_AXIAL_OFFSET),
      *(float *)(*(int *)(jointPoints + 4) + iVar5),
      *(float *)(*(int *)(jointPoints + 4) +
                         *(int *)(bestHit + OBJHITS_SKELETON_HIT_POINT_INDEX_B_OFFSET) * 4),
      *(float *)(*(int *)(jointPoints + 0xc) + iVar5),&local_d8,(float *)(bestHit + 8),
      (float *)(bestHit + 0x14),afStack_a8);
  Vec3_Normalize(pfVar4);
  dVar8 = gObjHitsScalarZero;
  for (iVar5 = hits;
       *(int *)(iVar5 + OBJHITS_SKELETON_HIT_POINT_INDEX_A_OFFSET) != OBJHITS_SKELETON_HIT_SENTINEL;
       iVar5 = iVar5 + OBJHITS_SKELETON_HIT_SIZE) {
    iVar2 = *(int *)(iVar5 + OBJHITS_SKELETON_HIT_POINT_INDEX_A_OFFSET) * 4;
    pfVar4 = ObjHits_ProjectPointToTaperedCapsule3D(
        dVar7,*(float *)(iVar5 + OBJHITS_SKELETON_HIT_AXIAL_OFFSET),
        *(float *)(*(int *)(jointPoints + 4) + iVar2),
        *(float *)(*(int *)(jointPoints + 4) +
                           *(int *)(iVar5 + OBJHITS_SKELETON_HIT_POINT_INDEX_B_OFFSET) * 4),
        *(float *)(*(int *)(jointPoints + 0xc) + iVar2),&local_d8,(float *)(iVar5 + 8),
        (float *)(iVar5 + 0x14),afStack_90);
    if (axial <= dVar8) {
      *(float *)(iVar5 + 0x3c) = (float)dVar8;
    }
    else {
      *(float *)(iVar5 + 0x3c) = (float)(*(float *)(iVar5 + 0x3c) / axial);
    }
    *pfVar4 = *pfVar4 * *(float *)(iVar5 + OBJHITS_SKELETON_HIT_INVERSE_DISTANCE_OFFSET);
    pfVar4[1] = pfVar4[1] * *(float *)(iVar5 + OBJHITS_SKELETON_HIT_INVERSE_DISTANCE_OFFSET);
    pfVar4[2] = pfVar4[2] * *(float *)(iVar5 + OBJHITS_SKELETON_HIT_INVERSE_DISTANCE_OFFSET);
    local_6c = local_6c + *pfVar4;
    local_68 = local_68 + pfVar4[1];
    local_64 = local_64 + pfVar4[2];
    iVar2 = *(int *)(iVar5 + OBJHITS_SKELETON_HIT_POINT_INDEX_A_OFFSET) * 4;
    pfVar4 = ObjHits_CalcTaperedCapsuleNormal(
        *(float *)(iVar5 + OBJHITS_SKELETON_HIT_AXIAL_OFFSET),
        *(float *)(*(int *)(jointPoints + 4) + iVar2),
        *(float *)(*(int *)(jointPoints + 4) +
                           *(int *)(iVar5 + OBJHITS_SKELETON_HIT_POINT_INDEX_B_OFFSET) * 4),
        *(float *)(*(int *)(jointPoints + 0xc) + iVar2),pos,(float *)(iVar5 + 8),
        (float *)(iVar5 + 0x14),afStack_a8);
    Vec3_Normalize(pfVar4);
    local_b4 = local_b4 + *pfVar4;
    local_b0 = local_b0 + pfVar4[1];
    local_ac = local_ac + pfVar4[2];
  }
  Vec3_Normalize(&local_b4);
  local_c0 = local_6c - local_d8;
  local_bc = local_68 - local_d4;
  local_b8 = local_64 - local_d0;
  dVar8 = Vec3_Length(&local_c0);
  local_c0 = local_6c - *pos;
  local_bc = local_68 - pos[1];
  local_b8 = local_64 - pos[2];
  Vec3_Normalize(&local_cc);
  if (dVar6 <= dVar8) {
    local_9c = gObjHitsScalarZero;
    local_98 = gObjHitsScalarZero;
    local_94 = gObjHitsScalarZero;
  }
  else {
    fVar1 = (float)(dVar6 - dVar8);
    local_cc = local_cc * fVar1;
    local_c8 = local_c8 * fVar1;
    local_c4 = local_c4 * fVar1;
    Vec3_ReflectAgainstNormal(&local_b4,&local_cc,&local_9c);
  }
  local_6c = local_6c + local_9c;
  local_68 = local_68 + local_98;
  local_64 = local_64 + local_94;
  local_9c = gObjHitsScalarZero;
  local_98 = gObjHitsScalarZero;
  local_94 = gObjHitsScalarZero;
  for (; *(int *)(hits + OBJHITS_SKELETON_HIT_POINT_INDEX_A_OFFSET) !=
         OBJHITS_SKELETON_HIT_SENTINEL;
       hits = hits + OBJHITS_SKELETON_HIT_SIZE) {
    iVar5 = *(int *)(hits + OBJHITS_SKELETON_HIT_POINT_INDEX_A_OFFSET) * 4;
    pfVar4 = ObjHits_ProjectPointToTaperedCapsule3D(
        dVar7,*(float *)(hits + OBJHITS_SKELETON_HIT_AXIAL_OFFSET),
        *(float *)(*(int *)(jointPoints + 4) + iVar5),
        *(float *)(*(int *)(jointPoints + 4) +
                           *(int *)(hits + OBJHITS_SKELETON_HIT_POINT_INDEX_B_OFFSET) * 4),
        *(float *)(*(int *)(jointPoints + 0xc) + iVar5),&local_6c,(float *)(hits + 8),
        (float *)(hits + 0x14),afStack_90);
    *pfVar4 = *pfVar4 * *(float *)(hits + OBJHITS_SKELETON_HIT_INVERSE_DISTANCE_OFFSET);
    pfVar4[1] = pfVar4[1] * *(float *)(hits + OBJHITS_SKELETON_HIT_INVERSE_DISTANCE_OFFSET);
    pfVar4[2] = pfVar4[2] * *(float *)(hits + OBJHITS_SKELETON_HIT_INVERSE_DISTANCE_OFFSET);
    local_9c = local_9c + *pfVar4;
    local_98 = local_98 + pfVar4[1];
    local_94 = local_94 + pfVar4[2];
  }
  *out = local_9c - *pos;
  out[1] = local_98 - pos[1];
  out[2] = local_94 - pos[2];
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjHits_ProjectPointToTaperedCapsuleXZ
 * EN v1.0 Address: 0x80031854
 * EN v1.0 Size: 732b
 * EN v1.1 Address: 0x8003194C
 * EN v1.1 Size: 732b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
float *ObjHits_ProjectPointToTaperedCapsuleXZ(float pointRadius, float axial, float baseRadius,
                                              float tipRadius, float length, float *point,
                                              float *base, float *tip, float *out)
{
    float invLength;
    float axisDir[3];
    float surfacePoint[3];

    if (axial < gObjHitsScalarZero) {
        out[0] = point[0] - base[0];
        out[1] = gObjHitsScalarZero;
        out[2] = point[2] - base[2];
        Vec3_Normalize(out);
        pointRadius = pointRadius + baseRadius;
        out[0] = out[0] * pointRadius;
        out[1] = out[1] * pointRadius;
        out[2] = out[2] * pointRadius;
        out[0] = out[0] + base[0];
        out[1] = out[1] + base[1];
        out[2] = out[2] + base[2];
        return out;
    }
    if (axial > length) {
        out[0] = point[0] - tip[0];
        out[1] = gObjHitsScalarZero;
        out[2] = point[2] - tip[2];
        Vec3_Normalize(out);
        pointRadius = pointRadius + tipRadius;
        out[0] = out[0] * pointRadius;
        out[1] = out[1] * pointRadius;
        out[2] = out[2] * pointRadius;
        out[0] = out[0] + tip[0];
        out[1] = out[1] + tip[1];
        out[2] = out[2] + tip[2];
        return out;
    }
    axisDir[0] = tip[0] - base[0];
    axisDir[1] = tip[1] - base[1];
    axisDir[2] = tip[2] - base[2];
    invLength = gObjHitsScalarOne / length;
    axisDir[0] = axisDir[0] * invLength;
    axisDir[1] = axisDir[1] * invLength;
    axisDir[2] = axisDir[2] * invLength;
    Vec3_ScaleAdd(axial, base, axisDir, surfacePoint);
    out[0] = point[0] - surfacePoint[0];
    out[1] = gObjHitsScalarZero;
    out[2] = point[2] - surfacePoint[2];
    Vec3_Normalize(out);
    invLength = (tipRadius - baseRadius) * (axial / length);
    pointRadius = invLength + (baseRadius + pointRadius);
    out[0] = out[0] * pointRadius;
    out[1] = out[1] * pointRadius;
    out[2] = out[2] * pointRadius;
    out[0] = out[0] + surfacePoint[0];
    out[1] = out[1] + surfacePoint[1];
    out[2] = out[2] + surfacePoint[2];
    return out;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjHits_ProjectPointToTaperedCapsule3D
 * EN v1.0 Address: 0x80031B30
 * EN v1.0 Size: 764b
 * EN v1.1 Address: 0x80031C28
 * EN v1.1 Size: 764b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
float *ObjHits_ProjectPointToTaperedCapsule3D(float pointRadius, float axial, float baseRadius,
                                              float tipRadius, float length, float *point,
                                              float *base, float *tip, float *out)
{
    float invLength;
    float axisDir[3];
    float surfacePoint[3];

    if (axial < gObjHitsScalarZero) {
        out[0] = point[0] - base[0];
        out[1] = point[1] - base[1];
        out[2] = point[2] - base[2];
        Vec3_Normalize(out);
        pointRadius = pointRadius + baseRadius;
        out[0] = out[0] * pointRadius;
        out[1] = out[1] * pointRadius;
        out[2] = out[2] * pointRadius;
        out[0] = out[0] + base[0];
        out[1] = out[1] + base[1];
        out[2] = out[2] + base[2];
        return out;
    }
    if (axial > length) {
        out[0] = point[0] - tip[0];
        out[1] = point[1] - tip[1];
        out[2] = point[2] - tip[2];
        Vec3_Normalize(out);
        pointRadius = pointRadius + tipRadius;
        out[0] = out[0] * pointRadius;
        out[1] = out[1] * pointRadius;
        out[2] = out[2] * pointRadius;
        out[0] = out[0] + tip[0];
        out[1] = out[1] + tip[1];
        out[2] = out[2] + tip[2];
        return out;
    }
    axisDir[0] = tip[0] - base[0];
    axisDir[1] = tip[1] - base[1];
    axisDir[2] = tip[2] - base[2];
    invLength = gObjHitsScalarOne / length;
    axisDir[0] = axisDir[0] * invLength;
    axisDir[1] = axisDir[1] * invLength;
    axisDir[2] = axisDir[2] * invLength;
    Vec3_ScaleAdd(axial, base, axisDir, surfacePoint);
    out[0] = point[0] - surfacePoint[0];
    out[1] = point[1] - surfacePoint[1];
    out[2] = point[2] - surfacePoint[2];
    Vec3_Normalize(out);
    invLength = (tipRadius - baseRadius) * (axial / length);
    pointRadius = invLength + (baseRadius + pointRadius);
    out[0] = out[0] * pointRadius;
    out[1] = out[1] * pointRadius;
    out[2] = out[2] * pointRadius;
    out[0] = out[0] + surfacePoint[0];
    out[1] = out[1] + surfacePoint[1];
    out[2] = out[2] + surfacePoint[2];
    return out;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjHits_CalcTaperedCapsuleNormal
 * EN v1.0 Address: 0x80031E2C
 * EN v1.0 Size: 612b
 * EN v1.1 Address: 0x80031F24
 * EN v1.1 Size: 612b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
float *ObjHits_CalcTaperedCapsuleNormal(float axial,float baseRadius,float tipRadius,
                                        float length,float *point,float *base,float *tip,
                                        float *out)
{
  float invAxial;
  float radiusDelta;
  float radiusOffset;
  float axisDir[3];
  float normal[3];
  float blended[3];
  float cross[3];
  float surface[3];

  if (axial <= gObjHitsScalarZero) {
    *out = *point - *tip;
    out[1] = point[1] - tip[1];
    out[2] = point[2] - tip[2];
    Vec3_Normalize(out);
    return out;
  }
  else if (axial >= length) {
    *out = *point - *tip;
    out[1] = point[1] - tip[1];
    out[2] = point[2] - tip[2];
    Vec3_Normalize(out);
    return out;
  }
  else {
    radiusDelta = tipRadius - baseRadius;
    radiusOffset = radiusDelta * (axial / length);
    axisDir[0] = tip[0] - base[0];
    axisDir[1] = tip[1] - base[1];
    axisDir[2] = tip[2] - base[2];
    Vec3_Normalize(axisDir);
    Vec3_ScaleAdd(base,axisDir,axial,surface);
    normal[0] = point[0] - surface[0];
    normal[1] = point[1] - surface[1];
    normal[2] = point[2] - surface[2];
    Vec3_Normalize(normal);
    if (radiusDelta == gObjHitsScalarZero) {
      out[0] = normal[0];
      out[1] = normal[1];
      out[2] = normal[2];
      return out;
    }
    else {
      axisDir[0] = axisDir[0] * axial;
      axisDir[1] = axisDir[1] * axial;
      axisDir[2] = axisDir[2] * axial;
      Vec3_ScaleAdd(axisDir,normal,radiusOffset,blended);
      Vec3_Normalize(blended);
      axisDir[0] = axisDir[0] * (gObjHitsScalarOne / axial);
      invAxial = gObjHitsScalarOne / axial;
      axisDir[1] = axisDir[1] * invAxial;
      axisDir[2] = axisDir[2] * invAxial;
      Vec3_Cross(normal,axisDir,cross);
      Vec3_Normalize(cross);
      Vec3_Cross(cross,blended,out);
    }
  }
  return out;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjHits_TestTaperedCapsuleXZ
 * EN v1.0 Address: 0x80032090
 * EN v1.0 Size: 276b
 * EN v1.1 Address: 0x80032188
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
uint ObjHits_TestTaperedCapsuleXZ(float pointRadius, float baseRadius, float tipRadius, float length,
                                  float *point, float *base, float *axis, float *tip,
                                  float *axial, float *dist2, float *sumR)
{
    float deltaX, deltaZ;
    float radialX, radialZ;
    float tipDeltaX, tipDeltaZ;
    float projection;
    float radiusSum;

    deltaX = point[0] - base[0];
    deltaZ = point[2] - base[2];
    *axial = deltaX * axis[0] + deltaZ * axis[2];
    if (*axial > length) {
        tipDeltaX = tip[0] - point[0];
        tipDeltaX *= tipDeltaX;
        tipDeltaZ = tip[2] - point[2];
        tipDeltaZ *= tipDeltaZ;
        *dist2 = tipDeltaX + tipDeltaZ;
        radiusSum = pointRadius + tipRadius;
        *sumR = radiusSum;
        return *dist2 <= radiusSum * radiusSum;
    }
    if (*axial < gObjHitsScalarZero) {
        *dist2 = deltaX * deltaX + deltaZ * deltaZ;
        radiusSum = pointRadius + baseRadius;
        *sumR = radiusSum;
        return *dist2 <= radiusSum * radiusSum;
    }
    radialX = axis[0] * (projection = -*axial) + deltaX;
    radialZ = axis[2] * projection + deltaZ;
    *dist2 = radialX * radialX + radialZ * radialZ;
    radiusSum = (*axial / length) * (tipRadius - baseRadius) + (pointRadius + baseRadius);
    *sumR = radiusSum;
    return *dist2 <= radiusSum * radiusSum;
}
#pragma scheduling reset

#pragma scheduling off
#pragma peephole on
/*
 * --INFO--
 *
 * Function: ObjHits_TestTaperedCapsule3D
 * EN v1.0 Address: 0x800321A4
 * EN v1.0 Size: 324b
 * EN v1.1 Address: 0x8003229C
 * EN v1.1 Size: 324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint ObjHits_TestTaperedCapsule3D(float pointRadius, float baseRadius, float tipRadius, float length,
                                  float *point, float *base, float *axis, float *tip,
                                  float *axial, float *dist2, float *sumR)
{
    float deltaX, deltaY, deltaZ;
    float radialX, radialY, radialZ;
    float tipDeltaX, tipDeltaY, tipDeltaZ;
    float radiusSum;

    deltaX = point[0] - base[0];
    deltaY = point[1] - base[1];
    deltaZ = point[2] - base[2];
    *axial = deltaZ * axis[2] + (deltaX * axis[0] + deltaY * axis[1]);
    if (*axial > length) {
        tipDeltaX = tip[0] - point[0];
        tipDeltaY = tip[1] - point[1];
        tipDeltaZ = tip[2] - point[2];
        *dist2 = tipDeltaZ * tipDeltaZ + (tipDeltaX * tipDeltaX + tipDeltaY * tipDeltaY);
        radiusSum = pointRadius + tipRadius;
        *sumR = radiusSum;
        return *dist2 <= radiusSum * radiusSum;
    }
    if (*axial < gObjHitsScalarZero) {
        *dist2 = deltaZ * deltaZ + (deltaX * deltaX + deltaY * deltaY);
        radiusSum = pointRadius + baseRadius;
        *sumR = radiusSum;
        return *dist2 <= radiusSum * radiusSum;
    }
    radialX = axis[0] * -*axial + deltaX;
    radialY = axis[1] * -*axial + deltaY;
    radialZ = axis[2] * -*axial + deltaZ;
    *dist2 = radialZ * radialZ + (radialX * radialX + radialY * radialY);
    radiusSum = (*axial / length) * (tipRadius - baseRadius) + (pointRadius + baseRadius);
    *sumR = radiusSum;
    return *dist2 <= radiusSum * radiusSum;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjHits_SortSweepEntries
 * EN v1.0 Address: 0x800322E8
 * EN v1.0 Size: 232b
 * EN v1.1 Address: 0x800323E0
 * EN v1.1 Size: 232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void ObjHits_SortSweepEntries(ObjHitsSweepEntry **sweepPtrs,int entryCount)
{
  int gap;
  int maxGap;
  int index;
  int insertIndex;
  ObjHitsSweepEntry **entrySlot;
  ObjHitsSweepEntry **insertSlot;
  ObjHitsSweepEntry *entry;
  ObjHitsSweepEntry *prevEntry;

  gap = 1;
  maxGap = (entryCount - 1) / 9;
  for (; gap <= maxGap; gap = gap * 3 + 1) {
  }
  for (; gap > 0; gap = gap / 3) {
    index = gap + 1;
    entrySlot = sweepPtrs + index;
    if (index < entryCount) {
      do {
        entry = *entrySlot;
        insertSlot = sweepPtrs + index;
        insertIndex = index;
        while ((gap < insertIndex) &&
               (prevEntry = sweepPtrs[insertIndex - gap], prevEntry->minX > entry->minX)) {
          *insertSlot = prevEntry;
          insertSlot -= gap;
          insertIndex -= gap;
        }
        sweepPtrs[insertIndex] = entry;
        entrySlot++;
        index++;
      } while (index < entryCount);
    }
  }
  return;
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjHits_TickPriorityHitCooldowns
 * EN v1.0 Address: 0x800323D0
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x800324C8
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void ObjHits_TickPriorityHitCooldowns(void)
{
  int iVar1;
  short sVar2;
  u8 *base;
  ObjHitsPriorityWorkSlot *workSlot;

  sVar2 = 0;
  iVar1 = 0;
  do {
    base = gObjHitsPriorityHitStates;
    workSlot = (ObjHitsPriorityWorkSlot *)(base + iVar1);
    if (workSlot->active != 0) {
      workSlot->active--;
    }
    iVar1 = iVar1 + OBJHITS_PRIORITY_WORK_SLOT_SIZE;
    sVar2++;
  } while (sVar2 < OBJHITS_PRIORITY_WORK_SLOT_COUNT);
  gObjHitsPriorityHitTickDelta = timeDelta;
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjHitbox_UpdateRotatedBounds
 * EN v1.0 Address: 0x80032410
 * EN v1.0 Size: 432b
 * EN v1.1 Address: 0x80032508
 * EN v1.1 Size: 432b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHitbox_UpdateRotatedBounds(ObjHitbox *hitbox,int advanceMatrix)
{
  typedef struct HitboxTransform {
    short x;
    short y;
    short z;
    float scale;
    float radiusX;
    float radiusY;
    float radiusZ;
  } HitboxTransform;
  ObjHitboxTransformState *transformState;
  int matrixBase;
  int matrixFloatOffset;
  HitboxTransform local_28;
  
  transformState = hitbox->transformState;
  if (transformState != 0) {
    if (advanceMatrix != 0) {
      transformState->activeMatrixIndex = (transformState->activeMatrixIndex + 1) & 1;
    }
    matrixFloatOffset = transformState->activeMatrixIndex * OBJHITBOX_STATE_MATRIX_FLOAT_COUNT;
    matrixBase = (int)((float *)transformState->matrices + matrixFloatOffset);
    local_28.x = -hitbox->rotationX;
    if ((hitbox->def->flags & OBJHITBOX_DEF_CLAMP_Y) != 0) {
      local_28.y = 0;
    }
    else {
      local_28.y = -hitbox->rotationY;
    }
    if ((hitbox->def->flags & OBJHITBOX_DEF_CLAMP_Z) != 0) {
      local_28.z = 0;
    }
    else {
      local_28.z = -hitbox->rotationZ;
    }
    local_28.scale = gObjHitsScalarOne;
    local_28.radiusX = -hitbox->radiusX;
    local_28.radiusY = -hitbox->radiusY;
    local_28.radiusZ = -hitbox->radiusZ;
    mtxRotateByVec3s((float *)matrixBase,&local_28);
    local_28.x = hitbox->rotationX;
    if ((hitbox->def->flags & OBJHITBOX_DEF_CLAMP_Y) != 0) {
      local_28.y = 0;
    }
    else {
      local_28.y = hitbox->rotationY;
    }
    if ((hitbox->def->flags & OBJHITBOX_DEF_CLAMP_Z) != 0) {
      local_28.z = 0;
    }
    else {
      local_28.z = hitbox->rotationZ;
    }
    local_28.scale = gObjHitsScalarOne;
    local_28.radiusX = hitbox->radiusX;
    local_28.radiusY = hitbox->radiusY;
    local_28.radiusZ = hitbox->radiusZ;
    matrixFloatOffset = (transformState->activeMatrixIndex + 2) * OBJHITBOX_STATE_MATRIX_FLOAT_COUNT;
    setMatrixFromObjectPos((float *)transformState->matrices + matrixFloatOffset,&local_28);
    if (transformState->resetFrames != 0) {
      transformState->resetFrames--;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: ObjHits_CheckHitVolumes
 * EN v1.0 Address: 0x800325C0
 * EN v1.0 Size: 3592b
 * EN v1.1 Address: 0x800326B8
 * EN v1.1 Size: 3592b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
u8 ObjHits_CheckHitVolumes(int objA,int objB,int srcObj,char checkA,char checkB,uint mask,
                           uint volMask)
{
  bool bVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  bool bVar6;
  bool bVar7;
  bool bVar8;
  bool bVar9;
  uint uVar10;
  int *piVar11;
  undefined *puVar12;
  uint uVar13;
  int iVar16;
  uint uVar17;
  uint uVar20;
  uint uVar21;
  uint uVar22;
  uint uVar23;
  int iVar24;
  int iVar25;
  float *pfVar26;
  int iVar27;
  uint unaff_r26;
  uint unaff_r27;
  int iVar28;
  float *pfVar29;
  float *pfVar30;
  uint uVar31;
  float dVar32;
  float dVar33;
  float dVar34;
  float in_f14;
  float dVar35;
  float in_f15;
  float dVar36;
  float in_f16;
  float dVar37;
  float in_f17;
  float dVar38;
  float in_f18;
  float in_f19;
  float in_f20;
  float in_f21;
  float in_f22;
  float in_f23;
  float in_f24;
  float in_f25;
  float in_f26;
  float in_f27;
  float dVar39;
  float in_f28;
  float dVar40;
  float in_f29;
  float dVar41;
  float in_f30;
  float dVar42;
  float dVar43;
  float in_f31;
  float dVar44;
  float dVar45;
  undefined auStack_248 [20];
  undefined2 local_234;
  undefined local_232;
  undefined local_231;
  undefined auStack_230 [20];
  undefined2 local_21c;
  undefined local_21a;
  undefined local_219;
  float local_218;
  float local_214;
  undefined4 local_210;
  float local_20c;
  float local_208;
  float local_204;
  undefined4 local_200;
  float local_1fc;
  float local_1f8;
  float local_1f4;
  undefined4 local_1f0;
  float local_1ec;
  float local_1e8;
  float local_1e4;
  undefined4 local_1e0;
  float local_1dc;
  float local_1c8;
  float local_1c4;
  float local_1c0;
  float local_1bc;
  float local_1b8;
  float local_1b4;
  float local_1b0;
  float local_1ac;
  int local_1a8;
  float *local_1a4;
  uint local_1a0;
  uint local_19c;
  int local_198;
  undefined *local_194;
  undefined *local_190;
  float *local_18c;
  float *local_188;
  float *local_184;
  float *local_180;
  float *local_17c;
  uint local_178;
  uint local_174;
  
  local_1a8 = 0;
  iVar25 = *(int *)(objA + 0x54);
  iVar24 = *(int *)(objB + 0x54);
  local_198 = *(int *)(srcObj + 0x54);
  if ((((*(byte *)(local_198 + 0xb6) & 0x10) == 0) ||
      ((*(char *)(local_198 + 0xaf) == '\0' && (*(char *)(local_198 + 0xae) == '\0')))) &&
     (((*(byte *)(iVar24 + 0xb6) & 0x10) == 0 ||
      ((*(char *)(iVar24 + 0xaf) == '\0' && (*(char *)(iVar24 + 0xae) == '\0')))))) {
    bVar6 = false;
    bVar7 = false;
        if (((checkA == '\0') || ((*(byte *)(iVar25 + 0xb6) & 0x10) == 0)) &&
       ((checkB == '\0' || (*(char *)(iVar25 + 0x62) != '\x10')))) {
      local_174 = 1;
      local_184 = &local_218;
      local_18c = &local_1f8;
      local_190 = auStack_248;
      bVar6 = (*(byte *)(iVar25 + 0xb6) & 2) != 0;
      fVar2 = (f32)*(s16 *)(iVar25 + 100);
      local_214 = (float)(*(float *)(objA + 0x18) - playerMapOffsetX);
      local_210 = *(undefined4 *)(objA + 0x1c);
      local_20c = (float)(*(float *)(objA + 0x20) - playerMapOffsetZ);
      local_1f4 = (float)(*(float *)(iVar25 + 0x1c) - playerMapOffsetX);
      local_1f0 = *(undefined4 *)(iVar25 + 0x20);
      local_1ec = (float)(*(float *)(iVar25 + 0x24) - playerMapOffsetZ);
      local_232 = 0;
      local_231 = 0;
      local_234 = 0;
      iVar16 = objB;
      local_218 = fVar2;
      local_1f8 = fVar2;
    }
    else {
      piVar11 = *(int **)(*(int *)(objA + 0x7c) + *(char *)(objA + 0xad) * 4);
      iVar16 = *piVar11;
      local_174 = (uint)*(byte *)(iVar16 + 0xf7);
      local_184 = (float *)piVar11[0x14];
      local_18c = (float *)piVar11[(*(ushort *)(piVar11 + 6) >> 2 & 1 ^ 1) + 0x12];
      local_190 = *(undefined **)(iVar16 + 0x58);
      if ((uint)srcObj != (uint)objA) {
        fVar2 = *(float *)(local_198 + 0x34);
      } else {
        fVar2 = *(float *)(iVar25 + 0x34);
      }
      if ((*(ushort *)(objA + 6) & 0x4000) != 0) goto LAB_80033418;
    }
    dVar44 = fVar2;
    if (((checkA == '\0') || ((*(byte *)(iVar24 + 0xb6) & 0x10) == 0)) &&
       ((checkB == '\0' || (*(char *)(iVar24 + 0x62) != '\x10')))) {
      local_178 = 1;
      local_188 = &local_208;
      local_194 = auStack_230;
      bVar7 = (*(byte *)(iVar24 + 0xb6) & 2) != 0;
      fVar2 = (f32)*(s16 *)(iVar24 + 100);
      local_204 = (float)(*(float *)(objB + 0x18) - playerMapOffsetX);
      local_200 = *(undefined4 *)(objB + 0x1c);
      local_1fc = (float)(*(float *)(objB + 0x20) - playerMapOffsetZ);
      local_1e8 = local_218;
      local_1e4 = (float)(*(float *)(iVar25 + 0x1c) - playerMapOffsetX);
      local_1e0 = *(undefined4 *)(iVar25 + 0x20);
      local_1dc = (float)(*(float *)(iVar25 + 0x24) - playerMapOffsetZ);
      local_21a = 0;
      local_219 = 0;
      local_21c = 0;
      local_208 = fVar2;
    }
    else {
      piVar11 = *(int **)(*(int *)(objB + 0x7c) + *(char *)(objB + 0xad) * 4);
      iVar16 = *piVar11;
      local_178 = (uint)*(byte *)(iVar16 + 0xf7);
      local_188 = (float *)piVar11[0x14];
      local_194 = *(undefined **)(iVar16 + 0x58);
      fVar2 = *(float *)(iVar24 + 0x34);
      if ((*(ushort *)(objB + 6) & 0x4000) != 0) goto LAB_80033418;
    }
    dVar42 = fVar2;
    if ((0x40 < local_174) || (0x40 < local_178)) {
      debugPrintf(sObjHitsTooManyHitSpheresWarning);
    }
    dVar41 = (*(float *)(objA + 0x18) - *(float *)(objB + 0x18));
    dVar40 = (*(float *)(objA + 0x1c) - *(float *)(objB + 0x1c));
    dVar39 = (*(float *)(objA + 0x20) - *(float *)(objB + 0x20));
    dVar32 = sqrtf((float)(dVar39 * dVar39 +
                                         (float)(dVar41 * dVar41 +
                                                        (float)(dVar40 * dVar40))));
    if (dVar32 <= (lbl_803DE934 + (float)(dVar44 + dVar42))) {
      uVar22 = 0;
      uVar23 = 0;
      uVar20 = 0;
      uVar21 = 0;
      local_19c = 0;
      local_1a0 = 0;
      iVar16 = 0;
      puVar12 = local_190;
      uVar31 = local_174;
      if (0 < (int)local_174) {
        do {
          if (iVar16 == (char)puVar12[0x16]) {
            if ((mask & 1 << (int)(char)puVar12[0x17]) != 0) {
              uVar22 = uVar22 | 1 << iVar16;
              uVar23 = uVar23 | (1 << iVar16) >> 0x1f;
            }
            if ((volMask & 1 << (int)(char)puVar12[0x17]) != 0) {
              local_19c = local_19c | 1 << iVar16;
              local_1a0 = local_1a0 | (1 << iVar16) >> 0x1f;
            }
          }
          puVar12 = puVar12 + 0x18;
          iVar16 = iVar16 + 1;
          uVar31 = uVar31 - 1;
        } while (uVar31 != 0);
      }
      iVar16 = 0;
      puVar12 = local_194;
      uVar31 = local_178;
      if (0 < (int)local_178) {
        do {
          if (iVar16 == (char)puVar12[0x16]) {
            uVar20 = uVar20 | 1 << iVar16;
            uVar21 = uVar21 | (1 << iVar16) >> 0x1f;
          }
          puVar12 = puVar12 + 0x18;
          iVar16 = iVar16 + 1;
          uVar31 = uVar31 - 1;
        } while (uVar31 != 0);
      }
      local_1a4 = gObjHitsContactScratch;
      local_1c4 = lbl_803DE938;
      iVar16 = 1;
      while (iVar16 != 0) {
        iVar16 = 0;
        local_17c = local_184;
        local_180 = local_18c;
        pfVar26 = local_1a4;
        for (iVar28 = 0; iVar28 < (int)local_174; iVar28 = iVar28 + 1) {
          uVar31 = 1 << iVar28;
          if ((uVar22 & uVar31) != 0 || (uVar23 & (int)uVar31 >> 0x1f) != 0) {
            dVar43 = *local_17c;
            dVar45 = local_17c[1];
            dVar42 = local_17c[2];
            dVar44 = local_17c[3];
            bVar8 = (local_19c & uVar31) == 0;
            bVar9 = (local_1a0 & (int)uVar31 >> 0x1f) == 0;
            bVar1 = bVar8 && bVar9;
            if (!bVar8 || !bVar9) {
              local_1b4 = local_180[1];
              local_1b8 = local_180[2];
              in_f23 = local_180[3];
              in_f21 = (float)(dVar45 - local_1b4);
              in_f20 = (float)(dVar42 - local_1b8);
              in_f19 = (float)(dVar44 - in_f23);
              in_f18 = (float)(in_f19 * in_f19 +
                                      (float)(in_f21 * in_f21 +
                                                     (float)(in_f20 * in_f20)));
              if (in_f18 <= gObjHitsScalarZero) {
                bVar1 = true;
              }
              else {
                local_1c8 = (float)(gObjHitsScalarOne / in_f18);
              }
            }
            local_1ac = (float)(dVar42 - dVar43);
            local_1b0 = (float)(dVar42 + dVar43);
            pfVar29 = pfVar26;
            pfVar30 = local_188;
            for (iVar27 = 0; iVar27 < (int)local_178; iVar27 = iVar27 + 1) {
              if ((uVar20 & 1 << iVar27) != 0 || (uVar21 & (1 << iVar27) >> 0x1f) != 0) {
                unaff_r26 = 0;
                if (((iVar28 == 0) && (bVar6)) || ((iVar27 == 0 && (bVar7)))) {
                  if (bVar6) {
                                                            fVar5 = pfVar30[2] - *pfVar30;
                    fVar3 = pfVar30[2] + *pfVar30;
                    fVar2 = (float)(dVar42 + (f32)*(s16 *)(iVar25 + 0x66));
                    fVar4 = (float)(dVar42 + (f32)*(s16 *)(iVar25 + 0x68));
                  }
                  else {
                    fVar5 = (f32)*(s16 *)(iVar24 + 0x66) + pfVar30[2];
                    fVar3 = (f32)*(s16 *)(iVar24 + 0x68) + pfVar30[2];
                    fVar2 = local_1ac;
                    fVar4 = local_1b0;
                  }
                  if (((fVar2 <= fVar5) || (fVar2 <= fVar3)) &&
                     ((fVar5 <= fVar4 || (fVar3 <= fVar4)))) {
                    in_f22 = ((float)(dVar43 + *pfVar30) *
                                     (float)(dVar43 + *pfVar30));
                    dVar41 = (float)(dVar45 - pfVar30[1]);
                    dVar32 = (float)(dVar41 * dVar41);
                    if (dVar32 < in_f22) {
                      dVar39 = (float)(dVar44 - pfVar30[3]);
                      dVar32 = (float)(dVar39 * dVar39 + dVar32);
                      if (dVar32 < in_f22) {
                        dVar40 = gObjHitsScalarZero;
                        unaff_r26 = 1;
                      }
                    }
                  }
                }
                else {
                  in_f22 = ((float)(dVar43 + *pfVar30) *
                                   (float)(dVar43 + *pfVar30));
                  if (bVar1) {
                    dVar41 = (float)(dVar45 - pfVar30[1]);
                    dVar32 = (float)(dVar41 * dVar41);
                    if (dVar32 < in_f22) {
                      dVar40 = (float)(dVar42 - pfVar30[2]);
                      dVar32 = (float)(dVar40 * dVar40 + dVar32);
                      if (dVar32 < in_f22) {
                        dVar39 = (float)(dVar44 - pfVar30[3]);
                        dVar32 = (float)(dVar39 * dVar39 + dVar32);
                        if (dVar32 < in_f22) {
                          unaff_r26 = 1;
                        }
                      }
                    }
                  }
                  else {
                    dVar38 = (local_1b4 - pfVar30[1]);
                    dVar37 = (local_1b8 - pfVar30[2]);
                    dVar36 = (float)(in_f23 - pfVar30[3]);
                    dVar33 = (float)((float)(dVar36 * dVar36 +
                                                            (float)(dVar38 * dVar38 +
                                                                           (float)(dVar37 * 
                                                  dVar37))) - in_f22);
                    dVar35 = (float)(dVar36 * in_f19 +
                                            (float)(dVar38 * in_f21 +
                                                           (float)(dVar37 * in_f20)));
                    if ((dVar35 <= gObjHitsScalarZero) || (dVar33 <= gObjHitsScalarZero)) {
                      dVar33 = (float)(dVar35 * dVar35 - (float)(in_f18 * dVar33));
                      if ((gObjHitsScalarZero <= dVar33) &&
                         ((dVar34 = (float)(in_f18 + dVar35),
                          gObjHitsScalarZero <= dVar34 ||
                          ((float)(dVar34 * dVar34) <= dVar33)))) {
                        unaff_r26 = 1;
                        dVar32 = sqrtf(dVar33);
                        dVar32 = (local_1c8 * -(float)(dVar35 + dVar32));
                        dVar41 = (float)(in_f21 * dVar32 + dVar38);
                        dVar40 = (float)(in_f20 * dVar32 + dVar37);
                        dVar39 = (float)(in_f19 * dVar32 + dVar36);
                        dVar32 = (float)(dVar39 * dVar39 +
                                                (float)(dVar41 * dVar41 +
                                                               (float)(dVar40 * dVar40)));
                      }
                    }
                  }
                }
                if ((unaff_r26 != 0) && (iVar16 < 0x40)) {
                  if (checkB == '\0') {
                    in_f22 = sqrtf((float)(dVar39 * dVar39 +
                                                         (float)(dVar41 * dVar41 +
                                                                        (float)(dVar40 * 
                                                  dVar40))));
                    if (gObjHitsScalarZero < in_f22) {
                      dVar41 = (float)(dVar41 / in_f22);
                      dVar40 = (float)(dVar40 / in_f22);
                      dVar39 = (float)(dVar39 / in_f22);
                    }
                    dVar33 = *pfVar30;
                    pfVar29[2] = (float)(dVar41 * dVar33);
                    pfVar29[3] = (float)(dVar40 * dVar33);
                    pfVar29[4] = (float)(dVar39 * dVar33);
                  }
                  else if (gObjHitsScalarZero < dVar32) {
                    dVar33 = sqrtf(in_f22);
                    dVar32 = sqrtf(dVar32);
                    in_f22 = gObjHitsScalarZero;
                    if (in_f22 < dVar33) {
                      in_f22 = (float)((float)(dVar33 - dVar32) / dVar33);
                    }
                    pfVar29[5] = (float)in_f22;
                    *pfVar29 = (float)(dVar41 * in_f22);
                    pfVar29[1] = (float)(dVar39 * in_f22);
                  }
                  *(char *)(pfVar29 + 6) = (char)iVar28;
                  *(char *)((int)pfVar29 + 0x19) = (char)iVar27;
                  pfVar29 = pfVar29 + 7;
                  pfVar26 = pfVar26 + 7;
                  iVar16 = iVar16 + 1;
                }
              }
              pfVar30 = pfVar30 + 4;
            }
          }
          local_17c = local_17c + 4;
          local_180 = local_180 + 4;
        }
        uVar22 = 0;
        uVar23 = 0;
        uVar20 = 0;
        uVar21 = 0;
        pfVar26 = local_1a4;
        for (iVar28 = 0; iVar28 < iVar16; iVar28 = iVar28 + 1) {
          unaff_r27 = (uint)*(byte *)(pfVar26 + 6);
          unaff_r26 = (uint)*(byte *)((int)pfVar26 + 0x19);
          uVar13 = (uint)*(ushort *)(local_194 + unaff_r26 * 0x18 + 0x14);
          uVar10 = (uint)*(ushort *)(local_190 + unaff_r27 * 0x18 + 0x14);
          for (uVar31 = uVar10; uVar17 = uVar13, uVar31 != 0; uVar31 = (uVar31 & 0xfff) << 4) {
            uVar17 = 1 << unaff_r27 + ((int)(uVar31 & 0xf000) >> 0xc);
            uVar22 = uVar22 | uVar17;
            uVar23 = uVar23 | (int)uVar17 >> 0x1f;
          }
          for (; uVar17 != 0; uVar17 = (uVar17 & 0xfff) << 4) {
            uVar31 = 1 << unaff_r26 + ((int)(uVar17 & 0xf000) >> 0xc);
            uVar20 = uVar20 | uVar31;
            uVar21 = uVar21 | (int)uVar31 >> 0x1f;
          }
          if ((uVar10 == 0) && (uVar13 == 0)) {
            if (checkA == '\0') {
              if ((checkB != '\0') && (local_1c4 < pfVar26[5])) {
                local_1bc = *pfVar26;
                local_1c0 = pfVar26[1];
                local_1c4 = pfVar26[5];
              }
            }
            else {
              if (bVar7) {
                fVar2 = local_184[unaff_r27 * 4 + 2];
              }
              else {
                fVar2 = local_188[unaff_r26 * 4 + 2] + pfVar26[3];
              }
              ObjHits_RecordPositionHit((local_188[unaff_r26 * 4 + 1] + pfVar26[2]),fVar2,
                           (local_188[unaff_r26 * 4 + 3] + pfVar26[4]),objB,objA,
                           ((ObjHitsPriorityState *)local_198)->hitVolumePriority,
                           ((ObjHitsPriorityState *)local_198)->hitVolumeId,
                           *(byte *)((int)pfVar26 + 0x19));
              local_1a8 = 1;
            }
          }
          else if (uVar10 == 0) {
            uVar22 = uVar22 | 1 << unaff_r27;
            uVar23 = uVar23 | (1 << unaff_r27) >> 0x1f;
          }
          else if (uVar13 == 0) {
            uVar20 = uVar20 | 1 << unaff_r26;
            uVar21 = uVar21 | (1 << unaff_r26) >> 0x1f;
          }
          pfVar26 = pfVar26 + 7;
        }
      }
      if ((checkA == '\0') || (local_1a8 == 0)) {
        if ((checkB != '\0') && ((gObjHitsScalarZero < local_1c4 && (objA == srcObj)))) {
          ObjHits_RecordObjectHit(objB,objA,((ObjHitsPriorityState *)local_198)->objectPairPriority,
                       ((ObjHitsPriorityState *)local_198)->objectPairHitVolume,
                       (char)unaff_r26);
          ObjHits_RecordObjectHit(objA,objB,((ObjHitsPriorityState *)iVar24)->objectPairPriority,
                       ((ObjHitsPriorityState *)iVar24)->objectPairHitVolume,
                       (char)unaff_r27);
          ObjHits_ApplyPairResponse(-local_1bc,gObjHitsScalarZero,-local_1c0,
                                    objA,objB,0);
        }
      }
      else {
        if (((*(ushort *)(iVar25 + 0x60) & 0x80) != 0) &&
           (objA = *(int *)(objA + 0x54), objA != 0)) {
          *(ushort *)(objA + 0x60) = *(ushort *)(objA + 0x60) & ~1;
        }
        if (((*(ushort *)(iVar24 + 0x60) & 0x80) != 0) &&
           (objA = *(int *)(objB + 0x54), objA != 0)) {
          *(ushort *)(objA + 0x60) = *(ushort *)(objA + 0x60) & ~1;
        }
      }
    }
  }
LAB_80033418:
  __restore_gpr();
  return (u8)local_1a8;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: doNothing_800333C8
 * EN v1.0 Address: 0x800333C8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800334C0
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma dont_inline on
void doNothing_800333C8(int objA,int objB,int att,void *state,void *attState,f32 dt)
{
}
#pragma dont_inline reset

/*
 * --INFO--
 *
 * Function: ObjHits_CheckObjectHitVolumes
 * EN v1.0 Address: 0x800333CC
 * EN v1.0 Size: 1392b
 * EN v1.1 Address: 0x800334C4
 * EN v1.1 Size: 1392b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void ObjHits_CheckObjectHitVolumes(int objA,int objB,int attA,int attB,f32 dt)
{
  ObjHitsPriorityState *stateA;
  ObjHitsPriorityState *stateB;
  ObjHitsPriorityState *attStateA;
  ObjHitsPriorityState *attStateB;
  int *hitboxBuf;
  uint bufIndex;
  uint mask;
  u8 result;

  stateA = *(ObjHitsPriorityState **)(objA + 0x54);
  stateB = *(ObjHitsPriorityState **)(objB + 0x54);
  if (attA != 0) {
    attStateA = *(ObjHitsPriorityState **)(attA + 0x54);
  } else {
    attStateA = NULL;
  }
  if (attB != 0) {
    attStateB = *(ObjHitsPriorityState **)(attB + 0x54);
  } else {
    attStateB = NULL;
  }
  result = 0;
  if ((*(uint *)((int)stateA + 0x48) != 0) && (*(s8 *)((int)stateA + 0x70) == 0)) {
    if (*(s16 *)(objA + 0x44) == 1) {
      hitboxBuf = *(int **)(*(int *)(objA + 0x7c) + *(s8 *)(objA + 0xad) * 4);
      bufIndex = (*(u16 *)((int)hitboxBuf + 0x18) >> 2) & 1;
      if ((stateA->flags & 0x2000) != 0) {
        memcpy((void *)hitboxBuf[bufIndex + 0x12], gObjHitsPrimaryHitboxBufferScratch0,
               (uint)*(u8 *)(*hitboxBuf + 0xf7) << 4);
        memcpy((void *)hitboxBuf[(bufIndex ^ 1) + 0x12], gObjHitsPrimaryHitboxBufferScratch1,
               (uint)*(u8 *)(*hitboxBuf + 0xf7) << 4);
      } else {
        memcpy(gObjHitsPrimaryHitboxBufferScratch0, (void *)hitboxBuf[bufIndex + 0x12],
               (uint)*(u8 *)(*hitboxBuf + 0xf7) << 4);
        memcpy(gObjHitsPrimaryHitboxBufferScratch1, (void *)hitboxBuf[(bufIndex ^ 1) + 0x12],
               (uint)*(u8 *)(*hitboxBuf + 0xf7) << 4);
      }
      if (attA != 0) {
        hitboxBuf = *(int **)(*(int *)(attA + 0x7c) + *(s8 *)(attA + 0xad) * 4);
        bufIndex = (*(u16 *)((int)hitboxBuf + 0x18) >> 2) & 1;
        if ((stateA->flags & 0x2000) != 0) {
          memcpy((void *)hitboxBuf[bufIndex + 0x12], gObjHitsSecondaryHitboxBufferScratch0,
                 (uint)*(u8 *)(*hitboxBuf + 0xf7) << 4);
          memcpy((void *)hitboxBuf[(bufIndex ^ 1) + 0x12], gObjHitsSecondaryHitboxBufferScratch1,
                 (uint)*(u8 *)(*hitboxBuf + 0xf7) << 4);
        } else {
          memcpy(gObjHitsSecondaryHitboxBufferScratch0, (void *)hitboxBuf[bufIndex + 0x12],
                 (uint)*(u8 *)(*hitboxBuf + 0xf7) << 4);
          memcpy(gObjHitsSecondaryHitboxBufferScratch1, (void *)hitboxBuf[(bufIndex ^ 1) + 0x12],
                 (uint)*(u8 *)(*hitboxBuf + 0xf7) << 4);
          stateA->flags = stateA->flags | 0x2000;
        }
      }
    }
    mask = *(uint *)((int)stateA + 0x48) >> 4;
    if (mask != 0) {
      result = ObjHits_CheckHitVolumes(objA, objB, objA, 1, 0, mask, *(uint *)((int)stateA + 0x4c) >> 4);
    }
    if (((attA != 0) && (result == 0)) &&
        (mask = *(uint *)((int)stateA + 0x48) & 0xf, mask != 0)) {
      result = ObjHits_CheckHitVolumes(attA, objB, objA, 1, 0, mask, *(uint *)((int)stateA + 0x4c) & 0xf);
    }
    if ((result == 0) && (*(s16 *)(objA + 0x44) == 1)) {
      doNothing_800333C8(objA, objB, attA, stateA, attStateA, dt);
    }
  }
  result = 0;
  if (((*(u8 *)((int)stateB + 0xb4) & 0x80) == 0) && (*(uint *)((int)stateB + 0x48) != 0) &&
      (*(s8 *)((int)stateB + 0x70) == 0)) {
    if (*(s16 *)(objB + 0x44) == 1) {
      hitboxBuf = *(int **)(*(int *)(objB + 0x7c) + *(s8 *)(objB + 0xad) * 4);
      bufIndex = (*(u16 *)((int)hitboxBuf + 0x18) >> 2) & 1;
      if ((stateB->flags & 0x2000) != 0) {
        memcpy((void *)hitboxBuf[bufIndex + 0x12], gObjHitsPrimaryHitboxBufferScratch0,
               (uint)*(u8 *)(*hitboxBuf + 0xf7) << 4);
        memcpy((void *)hitboxBuf[(bufIndex ^ 1) + 0x12], gObjHitsPrimaryHitboxBufferScratch1,
               (uint)*(u8 *)(*hitboxBuf + 0xf7) << 4);
      } else {
        memcpy(gObjHitsPrimaryHitboxBufferScratch0, (void *)hitboxBuf[bufIndex + 0x12],
               (uint)*(u8 *)(*hitboxBuf + 0xf7) << 4);
        memcpy(gObjHitsPrimaryHitboxBufferScratch1, (void *)hitboxBuf[(bufIndex ^ 1) + 0x12],
               (uint)*(u8 *)(*hitboxBuf + 0xf7) << 4);
      }
      if (attB != 0) {
        hitboxBuf = *(int **)(*(int *)(attB + 0x7c) + *(s8 *)(attB + 0xad) * 4);
        bufIndex = (*(u16 *)((int)hitboxBuf + 0x18) >> 2) & 1;
        if ((stateB->flags & 0x2000) != 0) {
          memcpy((void *)hitboxBuf[bufIndex + 0x12], gObjHitsSecondaryHitboxBufferScratch0,
                 (uint)*(u8 *)(*hitboxBuf + 0xf7) << 4);
          memcpy((void *)hitboxBuf[(bufIndex ^ 1) + 0x12], gObjHitsSecondaryHitboxBufferScratch1,
                 (uint)*(u8 *)(*hitboxBuf + 0xf7) << 4);
        } else {
          memcpy(gObjHitsSecondaryHitboxBufferScratch0, (void *)hitboxBuf[bufIndex + 0x12],
                 (uint)*(u8 *)(*hitboxBuf + 0xf7) << 4);
          memcpy(gObjHitsSecondaryHitboxBufferScratch1, (void *)hitboxBuf[(bufIndex ^ 1) + 0x12],
                 (uint)*(u8 *)(*hitboxBuf + 0xf7) << 4);
          stateB->flags = stateB->flags | 0x2000;
        }
      }
    }
    mask = *(uint *)((int)stateB + 0x48) >> 4;
    if (mask != 0) {
      result = ObjHits_CheckHitVolumes(objB, objA, objB, 1, 0, mask, *(uint *)((int)stateB + 0x4c) >> 4);
    }
    if (((attB != 0) && (result == 0)) &&
        (mask = *(uint *)((int)stateB + 0x48) & 0xf, mask != 0)) {
      result = ObjHits_CheckHitVolumes(attB, objA, objB, 1, 0, mask, *(uint *)((int)stateB + 0x4c) & 0xf);
    }
    if ((result == 0) && (*(s16 *)(objB + 0x44) == 1)) {
      doNothing_800333C8(objB, objA, attB, stateB, attStateB, dt);
    }
  }
}

#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjHits_RegisterActiveHitVolumeObject
 * EN v1.0 Address: 0x8003393C
 * EN v1.0 Size: 88b
 * EN v1.1 Address: 0x80033A34
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void ObjHits_RegisterActiveHitVolumeObject(int obj)
{
  int index;

  index = 0;
  while (index < OBJHITS_ACTIVE_HIT_VOLUME_OBJECT_COUNT &&
         (uint)gObjHitsActiveHitVolumeObjects[index] != 0) {
    index = index + 1;
  }
  if (index == OBJHITS_ACTIVE_HIT_VOLUME_OBJECT_COUNT) {
    gObjHitsActiveHitVolumeObjects[0] = obj;
    return;
  }
  gObjHitsActiveHitVolumeObjects[index] = obj;
  return;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjHits_ApplyPairResponse
 * EN v1.0 Address: 0x80033994
 * EN v1.0 Size: 1520b
 * EN v1.1 Address: 0x80033A8C
 * EN v1.1 Size: 1520b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void ObjHits_ApplyPairResponse(int objA,int objB,f32 x,f32 y,f32 z,int flag)
{
  ObjHitsPriorityState *stateA;
  ObjHitsPriorityState *stateB;
  f32 localAx;
  f32 localAy;
  f32 localAz;
  f32 localBx;
  f32 localBy;
  f32 localBz;
  uint angle;
  int angleA;
  int angleB;
  f32 sinVal;
  f32 sinSq;
  f32 weightA;
  f32 weightB;
  f32 sum;
  f32 blend;
  f32 invBlend;

  ObjContact_DispatchCallbacks(objA, objB);
  stateA = *(ObjHitsPriorityState **)(objA + 0x54);
  stateB = *(ObjHitsPriorityState **)(objB + 0x54);
  stateA->flags = stateA->flags | 8;
  stateB->flags = stateB->flags | 8;
  *(int *)stateA = objB;
  *(int *)stateB = objA;
  if (*(int *)(objA + 0x30) != 0) {
    Obj_TransformWorldVectorToLocal(x, y, z, &localAx, &localAy, &localAz, *(int *)(objA + 0x30));
  } else {
    localAx = x;
    localAy = y;
    localAz = z;
  }
  if (*(int *)(objB + 0x30) != 0) {
    Obj_TransformWorldVectorToLocal(x, y, z, &localBx, &localBy, &localBz, *(int *)(objB + 0x30));
  } else {
    localBx = x;
    localBy = y;
    localBz = z;
  }
  if ((*(s16 *)(objA + 0x44) == 1) && (*(u8 *)((int)stateA + 0x6a) != 0) &&
      ((stateB->flags & 0x400) == 0)) {
    *(f32 *)(objA + 0xc) = *(f32 *)(objA + 0xc) - localAx;
    *(f32 *)(objA + 0x10) = *(f32 *)(objA + 0x10) - localAy;
    *(f32 *)(objA + 0x14) = *(f32 *)(objA + 0x14) - localAz;
    if (flag != 0) {
      *(f32 *)(objA + 0x18) = *(f32 *)(objA + 0x18) - x;
      *(f32 *)(objA + 0x1c) = *(f32 *)(objA + 0x1c) - y;
      *(f32 *)(objA + 0x20) = *(f32 *)(objA + 0x20) - z;
    } else {
      Obj_TransformLocalPointToWorld(*(f32 *)(objA + 0xc), *(f32 *)(objA + 0x10),
                                     *(f32 *)(objA + 0x14), (f32 *)(objA + 0x18),
                                     (f32 *)(objA + 0x1c), (f32 *)(objA + 0x20),
                                     *(int *)(objA + 0x30));
    }
  } else if ((*(s16 *)(objB + 0x44) == 1) && (*(u8 *)((int)stateB + 0x6a) != 0) &&
             ((stateA->flags & 0x400) == 0)) {
    *(f32 *)(objB + 0xc) = *(f32 *)(objB + 0xc) + localBx;
    *(f32 *)(objB + 0x10) = *(f32 *)(objB + 0x10) + localBy;
    *(f32 *)(objB + 0x14) = *(f32 *)(objB + 0x14) + localBz;
    if (flag != 0) {
      *(f32 *)(objB + 0x18) = *(f32 *)(objB + 0x18) + x;
      *(f32 *)(objB + 0x1c) = *(f32 *)(objB + 0x1c) + y;
      *(f32 *)(objB + 0x20) = *(f32 *)(objB + 0x20) + z;
    } else {
      Obj_TransformLocalPointToWorld(*(f32 *)(objB + 0xc), *(f32 *)(objB + 0x10),
                                     *(f32 *)(objB + 0x14), (f32 *)(objB + 0x18),
                                     (f32 *)(objB + 0x1c), (f32 *)(objB + 0x20),
                                     *(int *)(objB + 0x30));
    }
  } else if (*(u8 *)((int)stateB + 0x6a) == 0) {
    if (*(u8 *)((int)stateA + 0x6a) != 0) {
      *(f32 *)(objA + 0xc) = *(f32 *)(objA + 0xc) - localAx;
      *(f32 *)(objA + 0x10) = *(f32 *)(objA + 0x10) - localAy;
      *(f32 *)(objA + 0x14) = *(f32 *)(objA + 0x14) - localAz;
      if (flag != 0) {
        *(f32 *)(objA + 0x18) = *(f32 *)(objA + 0x18) - x;
        *(f32 *)(objA + 0x1c) = *(f32 *)(objA + 0x1c) - y;
        *(f32 *)(objA + 0x20) = *(f32 *)(objA + 0x20) - z;
      } else {
        Obj_TransformLocalPointToWorld(*(f32 *)(objA + 0xc), *(f32 *)(objA + 0x10),
                                       *(f32 *)(objA + 0x14), (f32 *)(objA + 0x18),
                                       (f32 *)(objA + 0x1c), (f32 *)(objA + 0x20),
                                       *(int *)(objA + 0x30));
      }
    }
  } else if (*(u8 *)((int)stateA + 0x6a) == 0) {
    if (*(u8 *)((int)stateB + 0x6a) != 0) {
      *(f32 *)(objB + 0xc) = *(f32 *)(objB + 0xc) + localBx;
      *(f32 *)(objB + 0x10) = *(f32 *)(objB + 0x10) + localBy;
      *(f32 *)(objB + 0x14) = *(f32 *)(objB + 0x14) + localBz;
      if (flag != 0) {
        *(f32 *)(objB + 0x18) = *(f32 *)(objB + 0x18) + x;
        *(f32 *)(objB + 0x1c) = *(f32 *)(objB + 0x1c) + y;
        *(f32 *)(objB + 0x20) = *(f32 *)(objB + 0x20) + z;
      } else {
        Obj_TransformLocalPointToWorld(*(f32 *)(objB + 0xc), *(f32 *)(objB + 0x10),
                                       *(f32 *)(objB + 0x14), (f32 *)(objB + 0x18),
                                       (f32 *)(objB + 0x1c), (f32 *)(objB + 0x20),
                                       *(int *)(objB + 0x30));
      }
    }
  } else {
    angle = getAngle(-x, -z);
    angleA = *(s16 *)objA - (int)(angle & 0xffff);
    if (angleA > 0x8000) {
      angleA -= 0xffff;
    }
    if (angleA < -0x8000) {
      angleA += 0xffff;
    }
    angleB = *(s16 *)objB - (int)(((angle & 0xffff) + 0x8000) & 0xffff);
    if (angleB > 0x8000) {
      angleB -= 0xffff;
    }
    if (angleB < -0x8000) {
      angleB += 0xffff;
    }
    sinVal = sin((lbl_803DE948 * (f32)angleA) / lbl_803DE94C);
    sinSq = sinVal * sinVal;
    weightA = (f32)*(u8 *)((int)stateA + 0x6a) * sinSq +
              (f32)*(u8 *)((int)stateA + 0x6b) * (gObjHitsScalarOne - sinSq);
    sinVal = sin((lbl_803DE948 * (f32)angleB) / lbl_803DE94C);
    sinSq = sinVal * sinVal;
    weightB = (f32)*(u8 *)((int)stateB + 0x6a) * sinSq +
              (f32)*(u8 *)((int)stateB + 0x6b) * (gObjHitsScalarOne - sinSq);
    if (weightA >= weightB * lbl_803DB450) {
      if (weightB < weightA * lbl_803DB450) {
        weightB = gObjHitsScalarZero;
      }
    } else {
      weightA = gObjHitsScalarZero;
    }
    sum = weightA + weightB;
    blend = (sum > gObjHitsScalarZero) ? weightB / sum : gObjHitsScalarZero;
    *(f32 *)(objA + 0xc) = *(f32 *)(objA + 0xc) - localAx * blend;
    *(f32 *)(objA + 0x10) = *(f32 *)(objA + 0x10) - localAy * blend;
    *(f32 *)(objA + 0x14) = *(f32 *)(objA + 0x14) - localAz * blend;
    Obj_TransformLocalPointToWorld(*(f32 *)(objA + 0xc), *(f32 *)(objA + 0x10),
                                   *(f32 *)(objA + 0x14), (f32 *)(objA + 0x18),
                                   (f32 *)(objA + 0x1c), (f32 *)(objA + 0x20),
                                   *(int *)(objA + 0x30));
    invBlend = gObjHitsScalarOne - blend;
    *(f32 *)(objB + 0xc) = localBx * invBlend + *(f32 *)(objB + 0xc);
    *(f32 *)(objB + 0x10) = localBy * invBlend + *(f32 *)(objB + 0x10);
    *(f32 *)(objB + 0x14) = localBz * invBlend + *(f32 *)(objB + 0x14);
    Obj_TransformLocalPointToWorld(*(f32 *)(objB + 0xc), *(f32 *)(objB + 0x10),
                                   *(f32 *)(objB + 0x14), (f32 *)(objB + 0x18),
                                   (f32 *)(objB + 0x1c), (f32 *)(objB + 0x20),
                                   *(int *)(objB + 0x30));
  }
}

#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
/*
 * --INFO--
 *
 * Function: ObjHits_DetectObjectPair
 * EN v1.0 Address: 0x80033F84
 * EN v1.0 Size: 1232b
 * EN v1.1 Address: 0x8003407C
 * EN v1.1 Size: 1232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_DetectObjectPair(int objA,int objB)
{
  ObjHitsPriorityState *stateA;
  ObjHitsPriorityState *stateB;
  u8 shapeB;
  int vertical;
  int distInt;
  int distClamped;
  f32 dx;
  f32 dy;
  f32 dz;
  f32 yA;
  f32 yB;
  f32 radiusA;
  f32 radiusB;
  f32 span;
  f32 dist;
  f32 sumRadius;
  f32 bx;
  f32 by;
  f32 bz;
  f32 sx;
  f32 sy;
  f32 sz;
  f32 segSq;
  f32 t;
  f32 cx;
  f32 cy;
  f32 cz;
  f32 nx;
  f32 ny;
  f32 nz;
  f32 len;
  f32 diff;

  stateA = *(ObjHitsPriorityState **)(objA + 0x54);
  stateB = *(ObjHitsPriorityState **)(objB + 0x54);
  if ((*(u8 *)((int)stateA + 0xae) != 0) || (*(u8 *)((int)stateB + 0xae) != 0)) goto end;
  dx = *(f32 *)(objB + 0x18) - *(f32 *)(objA + 0x18);
  yB = *(f32 *)(objB + 0x1c);
  yA = *(f32 *)(objA + 0x1c);
  dy = yB - yA;
  dz = *(f32 *)(objB + 0x20) - *(f32 *)(objA + 0x20);
  radiusA = (f32)*(s16 *)((int)stateA + 0x5a);
  radiusB = (f32)*(s16 *)((int)stateB + 0x5a);
  vertical = 0;
  shapeB = stateB->shapeFlags;
  if (((shapeB & 2) != 0) || ((stateA->shapeFlags & 2) != 0)) {
    if (dy <= gObjHitsScalarZero) {
      span = radiusB;
      if ((shapeB & 2) != 0) {
        span = (f32)*(s16 *)((int)stateB + 0x5e);
      }
      if ((stateA->shapeFlags & 2) == 0) {
        yA = yA - radiusA;
      } else {
        yA = yA + (f32)*(s16 *)((int)stateA + 0x5c);
      }
      if (yB + span < yA) goto end;
    } else {
      span = radiusA;
      if ((stateA->shapeFlags & 2) != 0) {
        span = (f32)*(s16 *)((int)stateA + 0x5e);
      }
      if ((shapeB & 2) == 0) {
        yB = yB - radiusB;
      } else {
        yB = yB + (f32)*(s16 *)((int)stateB + 0x5c);
      }
      if (yA + span < yB) goto end;
    }
    dy = gObjHitsScalarZero;
    vertical = 1;
  }
  dist = dz * dz + (dx * dx + dy * dy);
  if (dist != gObjHitsScalarZero) {
    dist = sqrtf(dist);
  }
  distInt = (int)dist;
  distClamped = distInt;
  if (distInt > 0x400) {
    distClamped = 0x400;
  }
  if (distClamped <= *(s16 *)((int)stateA + 0x58)) {
    *(s16 *)((int)stateA + 0x58) = distClamped;
  }
  if (distInt > 0x400) {
    distInt = 0x400;
  }
  if (distInt <= *(s16 *)((int)stateB + 0x58)) {
    *(s16 *)((int)stateB + 0x58) = distInt;
  }
  if ((stateB->flags & 1) != 0) {
    sumRadius = radiusB + radiusA;
    bx = *(f32 *)((int)stateA + 0x1c);
    sx = *(f32 *)(objA + 0x18) - bx;
    by = *(f32 *)((int)stateA + 0x20);
    bz = *(f32 *)((int)stateA + 0x24);
    sz = *(f32 *)(objA + 0x20) - bz;
    sy = *(f32 *)(objA + 0x1c) - by;
    if (vertical) {
      sy = gObjHitsScalarZero;
    }
    segSq = sz * sz + sx * sx + sy * sy;
    if (segSq > gObjHitsScalarOne) {
      t = (sz * (*(f32 *)(objB + 0x20) - bz) + sx * (*(f32 *)(objB + 0x18) - bx) +
           sy * (*(f32 *)(objB + 0x1c) - by)) / segSq;
      if ((t >= gObjHitsScalarZero) && (t <= gObjHitsScalarOne)) {
        cz = (t * sz + bz) - *(f32 *)(objB + 0x20);
        cx = (t * sx + bx) - *(f32 *)(objB + 0x18);
        cy = (t * sy + by) - *(f32 *)(objB + 0x1c);
        dist = sqrtf(cz * cz + cx * cx + cy * cy);
      }
    }
    if ((dist < sumRadius) && (dist > gObjHitsScalarZero)) {
      ObjHits_RecordObjectHit(objB, objA, *(s8 *)((int)stateA + 0x6c),
                              *(u8 *)((int)stateA + 0x6d), 0);
      ObjHits_RecordObjectHit(objA, objB, *(s8 *)((int)stateB + 0x6c),
                              *(u8 *)((int)stateB + 0x6d), 0);
      if (((stateB->flags & 2) == 0) && ((stateA->flags & 2) == 0)) {
        nx = *(f32 *)((int)stateB + 0x1c) - *(f32 *)((int)stateA + 0x1c);
        nz = *(f32 *)((int)stateB + 0x24) - *(f32 *)((int)stateA + 0x24);
        ny = *(f32 *)((int)stateB + 0x20) - *(f32 *)((int)stateA + 0x20);
        if (vertical) {
          ny = gObjHitsScalarZero;
        }
        len = sqrtf(nz * nz + (nx * nx + ny * ny));
        if (len > gObjHitsScalarZero) {
          nx = nx / len;
          ny = ny / len;
          nz = nz / len;
        } else {
          nx = dx / dist;
          ny = dy / dist;
          nz = dz / dist;
        }
        diff = sumRadius - dist;
        nx = nx * diff;
        ny = ny * diff;
        nz = nz * diff;
        ObjHits_ApplyPairResponse(objA, objB, nx, ny, nz, 0);
      }
    }
  }
end:;
}

#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjHits_CheckSkeletonPair
 * EN v1.0 Address: 0x80034454
 * EN v1.0 Size: 1116b
 * EN v1.1 Address: 0x8003454C
 * EN v1.1 Size: 1116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_CheckSkeletonPair(int objA,int objB,void *hits,void *scratchB,void *scratchC,
                               void *scratchD,void *scratchE,int depth)
{
  ObjHitsPriorityState *objAState;
  ObjHitsPriorityState *objBState;
  int *hitboxBuf;
  u8 shapeFlags;
  int hitCount;
  f32 ratio;
  f32 clamped;
  f32 fVar2;
  f32 fVar3;
  f32 fVar4;
  f32 outAxial;
  int outCount;
  ObjHitsVec3 point;
  f32 response[3];
  ObjHitsVec3 point3D;
  ObjHitsVec3 pointXZ;

  objBState = *(ObjHitsPriorityState **)(objB + 0x54);
  objAState = *(ObjHitsPriorityState **)(objA + 0x54);
  if (((*(s8 *)((int)objAState + 0xaf) == 0) && (*(s8 *)((int)objBState + 0xaf) == 0)) &&
      (*(u8 *)((int)objBState + 0xae) == 0) && (*(u8 *)((int)objAState + 0xae) == 0)) {
    hitboxBuf = *(int **)(*(int *)(objA + 0x7c) + *(s8 *)(objA + 0xad) * 4);
    shapeFlags = objBState->shapeFlags;
    if ((shapeFlags & 1) != 0) {
      point.x = *(f32 *)(objB + 0x18) - playerMapOffsetX;
      point.y = *(f32 *)(objB + 0x1c);
      point.z = *(f32 *)(objB + 0x20) - playerMapOffsetZ;
      point3D = point;
      hitCount = ObjHits_CollectSkeletonHits3D(&point3D.x, (f32)*(s16 *)((int)objBState + 0x5a),
                                               hitboxBuf[5], hitboxBuf, (int *)hits, &outCount,
                                               &outAxial);
      if (hitCount != 0) {
        ratio = (*(f32 *)(objB + 0xa8) * *(f32 *)(objB + 8)) /
                (*(f32 *)(objA + 0xa8) * *(f32 *)(objA + 8));

        clamped = gObjHitsScalarZero;
        if (ratio < clamped) {
        } else {
          clamped = gObjHitsScalarOne;
          if (ratio > clamped) {
          } else {
            clamped = ratio;
          }
        }
        ObjHits_CalcSkeletonResponse3D(&point.x, (f32)*(s16 *)((int)objBState + 0x5a), objB,
                                       (int)hits, hitboxBuf[5], *hitboxBuf, outCount, clamped,
                                       outAxial, response);
        fVar2 = lbl_803DE958;
        if (response[0] < fVar2) {
        } else {
          fVar2 = lbl_803DE95C;
          if (response[0] > fVar2) {
          } else {
            fVar2 = response[0];
          }
        }
        response[0] = fVar2;
        fVar3 = lbl_803DE958;
        if (response[1] < fVar3) {
        } else {
          fVar3 = lbl_803DE95C;
          if (response[1] > fVar3) {
          } else {
            fVar3 = response[1];
          }
        }
        response[1] = fVar3;
        fVar4 = lbl_803DE958;
        if (response[2] < fVar4) {
        } else {
          fVar4 = lbl_803DE95C;
          if (response[2] > fVar4) {
          } else {
            fVar4 = response[2];
          }
        }
        response[2] = fVar4;
        ObjHits_ApplyPairResponse(objA, objB, response[0], response[1], fVar4, 0);
      }
    } else if ((shapeFlags & 2) != 0) {
      point.x = *(f32 *)(objB + 0x18) - playerMapOffsetX;
      point.y = *(f32 *)(objB + 0x1c);
      point.z = *(f32 *)(objB + 0x20) - playerMapOffsetZ;
      pointXZ = point;
      hitCount = ObjHits_CollectSkeletonHitsXZ(&pointXZ.x, (f32)*(s16 *)((int)objBState + 0x5a),
                                               hitboxBuf[5], hitboxBuf, (int *)hits, &outCount,
                                               point.y + (f32)*(s16 *)((int)objBState + 0x5e),
                                               point.y + (f32)*(s16 *)((int)objBState + 0x5c),
                                               &outAxial);
      if (hitCount != 0) {
        ratio = (*(f32 *)(objB + 0xa8) * *(f32 *)(objB + 8)) /
                (*(f32 *)(objA + 0xa8) * *(f32 *)(objB + 8));

        clamped = gObjHitsScalarZero;
        if (ratio < clamped) {
        } else {
          clamped = gObjHitsScalarOne;
          if (ratio > clamped) {
          } else {
            clamped = ratio;
          }
        }
        ObjHits_CalcSkeletonResponseXZ(&point.x, (f32)*(s16 *)((int)objBState + 0x5a), objB,
                                       (int)hits, hitboxBuf[5], *hitboxBuf, outCount, clamped,
                                       outAxial, response);
        fVar2 = lbl_803DE958;
        if (response[0] < fVar2) {
        } else {
          fVar2 = lbl_803DE95C;
          if (response[0] > fVar2) {
          } else {
            fVar2 = response[0];
          }
        }
        response[0] = fVar2;
        fVar3 = lbl_803DE958;
        if (response[1] < fVar3) {
        } else {
          fVar3 = lbl_803DE95C;
          if (response[1] > fVar3) {
          } else {
            fVar3 = response[1];
          }
        }
        response[1] = fVar3;
        fVar4 = lbl_803DE958;
        if (response[2] < fVar4) {
        } else {
          fVar4 = lbl_803DE95C;
          if (response[2] > fVar4) {
          } else {
            fVar4 = response[2];
          }
        }
        response[2] = fVar4;
        ObjHits_ApplyPairResponse(objA, objB, response[0], response[1], fVar4, 0);
      }
    } else if (((shapeFlags & 0x20) != 0) && (depth < 1)) {
      ObjHits_CheckSkeletonPair(objB, objA, hits, scratchB, scratchC, scratchD, scratchE,
                                depth + 1);
    }
  }
}


/*
 * --INFO--
 *
 * Function: ObjHits_CheckTrackContact
 * EN v1.0 Address: 0x800348B0
 * EN v1.0 Size: 1068b
 * EN v1.1 Address: 0x800349A8
 * EN v1.1 Size: 1068b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void ObjHits_CheckTrackContact(int objA,int objB)
{
  uint uVar1;
  int mask2;
  int iVar3;
  byte bVar4;
  int iVar6;
  uint uVar7;
  float *puVar8;
  int *piVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  float *puVar13;
  int iVar14;
  int iVar15;
  int iVar16;
  float *puVar17;
  int iVar18;
  undefined *puVar19;
  undefined *puVar20;
  float *pfVar21;
  float *pfVar22;
  int iVar23;
  uint auStack_148 [6];
  float local_130 [18];
  float local_e8 [18];
  undefined auStack_a0 [64];
  float local_60 [4];
  undefined local_50 [12];
  int local_44 [5];
  f32 fConv;

  iVar6 = *(int *)(objA + 0x54);
  if ((uint)objB == (uint)objA) {
    mask2 = *(uint *)(iVar6 + 0x48) >> 4;
  }
  else {
    mask2 = *(uint *)(iVar6 + 0x48) & 0xf;
  }
  if ((mask2 != 0) && (*(char *)(iVar6 + 0x70) == '\0')) {
    iVar6 = *(int *)(objB + 0x54);
    if ((*(byte *)(iVar6 + 0xb6) & 0x10) != 0) {
      piVar9 = *(int **)(*(int *)(objB + 0x7c) + *(char *)(objB + 0xad) * 4);
      iVar12 = *piVar9;
      uVar7 = *(ushort *)(piVar9 + 6) >> 2 & 1;
      puVar13 = (float *)piVar9[uVar7 + 0x12];
      iVar14 = piVar9[(uVar7 ^ 1) + 0x12];
      iVar23 = 0;
      iVar15 = 0;
      iVar16 = 0;
      iVar3 = 0;
      puVar8 = puVar13;
      iVar10 = iVar14;
      for (iVar11 = 0; iVar11 < (int)(uint)*(byte *)(iVar12 + 0xf7); iVar11 = iVar11 + 1) {
        iVar18 = *(int *)(iVar12 + 0x58) + iVar3;
        if ((iVar11 == *(char *)(iVar18 + 0x16)) &&
           ((mask2 & 1 << (int)*(char *)(iVar18 + 0x17)) != 0)) {
          uVar7 = (uint)*(ushort *)(iVar18 + 0x14);
          if (uVar7 != 0) {
            pfVar22 = (float *)((int)local_e8 + iVar16);
            pfVar21 = (float *)((int)local_130 + iVar16);
            puVar20 = auStack_a0 + iVar15;
            puVar19 = auStack_a0 + iVar23;
            for (; uVar7 != 0; uVar7 = (uVar7 & 0xfff) << 4) {
              uVar1 = ((int)(uVar7 & 0xf000) >> 0xc) + iVar11 & 0xffff;
              if (iVar23 < 4) {
                puVar17 = puVar13 + uVar1 * 4;
                *pfVar22 = playerMapOffsetX + puVar17[1];
                pfVar22[1] = puVar17[2];
                pfVar22[2] = playerMapOffsetZ + puVar17[3];
                iVar18 = iVar14 + uVar1 * 0x10;
                *pfVar21 = playerMapOffsetX + *(float *)(iVar18 + 4);
                pfVar21[1] = *(float *)(iVar18 + 8);
                pfVar21[2] = playerMapOffsetZ + *(float *)(iVar18 + 0xc);
                *(float *)(puVar20 + 0x40) = *puVar17;
                *(s8 *)&puVar19[0x50] = -1;
                puVar19[0x54] = 7;
                pfVar22 = pfVar22 + 3;
                pfVar21 = pfVar21 + 3;
                puVar20 = puVar20 + 4;
                puVar19 = puVar19 + 1;
                iVar23 = iVar23 + 1;
                iVar15 = iVar15 + 4;
                iVar16 = iVar16 + 0xc;
              }
            }
          }
          else {
            if (iVar23 < 4) {
              *(float *)((int)local_e8 + iVar16) = playerMapOffsetX + puVar8[1];
              *(float *)((int)local_e8 + iVar16 + 4) = puVar8[2];
              *(float *)((int)local_e8 + iVar16 + 8) = playerMapOffsetZ + puVar8[3];
              *(float *)((int)local_130 + iVar16) = playerMapOffsetX + *(float *)(iVar10 + 4);
              *(undefined4 *)((int)local_130 + iVar16 + 4) = *(undefined4 *)(iVar10 + 8);
              *(float *)((int)local_130 + iVar16 + 8) = playerMapOffsetZ + *(float *)(iVar10 + 0xc);
              *(float *)(auStack_a0 + iVar15 + 0x40) = *puVar8;
              *(s8 *)&local_50[iVar23] = -1;
              local_50[iVar23 + 4] = 7;
              iVar23 = iVar23 + 1;
              iVar15 = iVar15 + 4;
              iVar16 = iVar16 + 0xc;
            }
          }
        }
        iVar3 = iVar3 + 0x18;
        puVar8 = puVar8 + 4;
        iVar10 = iVar10 + 0x10;
      }
    }
    else {
      local_e8[0] = *(float *)(objA + 0x18);
      local_e8[1] = *(float *)(objA + 0x1c);
      local_e8[2] = *(float *)(objA + 0x20);
      local_130[0] = *(float *)(objA + 0x8c);
      local_130[1] = *(float *)(objA + 0x90);
      local_130[2] = *(float *)(objA + 0x94);
      fConv = (f32)(u32)*(u8 *)(*(int *)(objA + 0x50) + 0x8f);
      if (fConv < lbl_803DE91C) {
        fConv = lbl_803DE91C;
      }
      local_60[0] = fConv;
      *(s8 *)&local_50[0] = -1;
      local_50[4] = 7;
      iVar23 = 1;
    }
    if (iVar23 != 0) {
      hitDetect_calcSweptSphereBounds(auStack_148,local_130,local_e8,local_60,iVar23);
      hitDetectFn_800691c0(objB,auStack_148,(uint)*(ushort *)(iVar6 + 0xb2),1);
      bVar4 = hitDetectFn_80067958(objB,local_130,local_e8,iVar23,auStack_a0,0);
      if (bVar4 != 0) {
        if ((bVar4 & 1) == 0) {
          if ((bVar4 & 2) == 0) {
            if ((bVar4 & 4) == 0) {
              iVar23 = 3;
            }
            else {
              iVar23 = 2;
            }
          }
          else {
            iVar23 = 1;
          }
        }
        else {
          iVar23 = 0;
        }
        ((ObjHitsPriorityState *)iVar6)->contactHitVolume = local_50[iVar23];
        *(float *)(iVar6 + 0x3c) = local_e8[iVar23 * 3];
        *(float *)(iVar6 + 0x40) = local_e8[iVar23 * 3 + 1];
        *(float *)(iVar6 + 0x44) = local_e8[iVar23 * 3 + 2];
        if (local_44[iVar23] == 0) {
          ((ObjHitsPriorityState *)iVar6)->contactFlags = ((ObjHitsPriorityState *)iVar6)->contactFlags | 1;
        }
        else {
          ((ObjHitsPriorityState *)iVar6)->contactFlags = ((ObjHitsPriorityState *)iVar6)->contactFlags | 2;
        }
      }
    }
  }
  _restgpr_23();
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: ObjHits_Update
 * EN v1.0 Address: 0x80034CDC
 * EN v1.0 Size: 1736b
 * EN v1.1 Address: 0x80034DD4
 * EN v1.1 Size: 1736b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjHits_Update(int objectCount)
{
  u8 skeletonScratchB[1052];
  u8 skeletonScratchC[1040];
  u8 skeletonHits[1512];
  u8 skeletonScratchD[100];
  u8 skeletonScratchE[100];
  int listCount;
  int startIndex;
  int *objectList;
  ObjHitsSweepEntry *sweepEntries;
  ObjHitsSweepEntry *nextEntry;
  ObjHitsSweepEntry **entrySlotBase;
  ObjHitsSweepEntry **entrySlot;
  ObjHitsSweepEntry *entry;
  ObjHitsSweepEntry *candidateEntry;
  int obj;
  int candObj;
  uint attachedObj;
  uint candAttachedObj;
  ObjHitsPriorityState *objState;
  ObjHitsPriorityState *candState;
  int slotCount;
  int slotIndex;
  int currentIndex;
  int candidateIndex;
  f32 axisDiff;
  f32 diff;

  objectList = ObjList_GetObjects(&startIndex, &listCount);
  sweepEntries = gObjHitsSweepEntries;
  sweepEntries->minX = lbl_803DE960;
  sweepEntries->maxX = lbl_803DE960;
  gObjHitsSweepEntryPtrs[0] = sweepEntries;
  slotCount = 1;
  nextEntry = &sweepEntries[1];
  entrySlotBase = &gObjHitsSweepEntryPtrs[1];
  entrySlot = entrySlotBase;
  for (; objectCount > 0; objectCount--) {
    {
      obj = *objectList;
      objState = *(ObjHitsPriorityState **)(obj + 0x54);
      if (objState != NULL) {
        if (((objState->flags & 3) != 0) && (objState->shapeFlags != 8) && (slotCount < 400)) {
          *entrySlot = nextEntry;
          (*entrySlot)->obj = obj;
          (*entrySlot)->minX = *(f32 *)(obj + 0x18) - objState->sweepRadiusX;
          nextEntry++;
          entrySlot++;
          gObjHitsSweepEntryPtrs[slotCount++]->maxX = *(f32 *)(obj + 0x18) + objState->sweepRadiusX;
        }
        objState->flags = objState->flags & ~0x8;
        objState->contactFlags = 0;
        *(s8 *)&objState->contactHitVolume = -1;
        *(int *)objState = 0;
        attachedObj = *(uint *)(obj + 0xc8);
        if ((attachedObj != 0) && (*(s16 *)(attachedObj + 0x44) == 0x2d)) {
          objState = *(ObjHitsPriorityState **)(attachedObj + 0x54);
          objState->flags = objState->flags & ~0x8;
          objState->contactFlags = 0;
          *(s8 *)&objState->contactHitVolume = -1;
          *(int *)objState = 0;
        }
      }
      objectList++;
    }
  }
  ObjHits_SortSweepEntries(gObjHitsSweepEntryPtrs, slotCount);
  currentIndex = 1;
  slotIndex = 1;
  entrySlot = entrySlotBase;
  for (; slotIndex < slotCount; slotIndex++, entrySlot++) {
    entry = *entrySlot;
    obj = entry->obj;
    objState = *(ObjHitsPriorityState **)(obj + 0x54);
    attachedObj = *(uint *)(obj + 0xc8);
    if ((attachedObj != 0) &&
        ((*(void **)(attachedObj + 0x54) == NULL) ||
         (((*(ObjHitsPriorityState **)(attachedObj + 0x54))->flags & 1) == 0))) {
      attachedObj = 0;
    }
    if ((objState->flags & 4) != 0) {
      ObjHitsSweepEntry **skipSlot;
      ObjHitsSweepEntry **ptrSlot;
      int scaled;
      candidateIndex = currentIndex;
      skipSlot = &gObjHitsSweepEntryPtrs[currentIndex];
      for (; (entry->minX > (*skipSlot)->maxX) && (candidateIndex < slotCount); candidateIndex++) {
        skipSlot++;
      }
      currentIndex = candidateIndex;
      ptrSlot = gObjHitsSweepEntryPtrs;
      scaled = candidateIndex << 2;
      for (; (candidateIndex < slotCount) &&
             ((*entrySlot)->maxX > (*(ObjHitsSweepEntry **)((int)ptrSlot + scaled))->minX);
           candidateIndex++, scaled += 4) {
        candidateEntry = *(ObjHitsSweepEntry **)((int)ptrSlot + scaled);
        if ((*entrySlot)->minX > candidateEntry->maxX) {
          continue;
        }
        {
          candObj = candidateEntry->obj;
          candState = *(ObjHitsPriorityState **)(candObj + 0x54);
          if ((slotIndex != candidateIndex) && (*(uint *)(obj + 0x30) != (uint)candObj)) {
            axisDiff = *(f32 *)(obj + 0x20) - *(f32 *)(candObj + 0x20);
            if (axisDiff > gObjHitsScalarZero) {
              diff = axisDiff;
            } else {
              diff = -axisDiff;
            }
            if (diff < objState->primaryRadiusXZ + candState->primaryRadiusXZ) {
              diff = *(f32 *)(obj + 0x1c) - *(f32 *)(candObj + 0x1c);
              if (diff > gObjHitsScalarZero) {
              } else {
                diff = -diff;
              }
              if ((diff < objState->primaryRadiusY + candState->primaryRadiusY) &&
                  ((objState->flags & 0x40) == 0) && ((candState->flags & 0x40) == 0) &&
                  (((candState->flags & 4) == 0) || (slotIndex >= candidateIndex)) &&
                  ((*(u8 *)(*(int *)(obj + 0x50) + 0x71) & candState->targetMask) != 0) &&
                  ((*(u8 *)(*(int *)(candObj + 0x50) + 0x71) & objState->targetMask) != 0)) {
                if ((candState->shapeFlags & 0x20) != 0) {
                  ((void (*)(int, int, void *, void *, void *, void *, void *, int))
                       ObjHits_CheckSkeletonPair)(candObj, obj, skeletonHits, skeletonScratchB,
                                                  skeletonScratchC, skeletonScratchD,
                                                  skeletonScratchE, 0);
                } else if ((objState->shapeFlags & 0x20) != 0) {
                  ((void (*)(int, int, void *, void *, void *, void *, void *, int))
                       ObjHits_CheckSkeletonPair)(obj, candObj, skeletonHits, skeletonScratchB,
                                                  skeletonScratchC, skeletonScratchD,
                                                  skeletonScratchE, 0);
                } else if ((objState->shapeFlags == 0x10) || (candState->shapeFlags == 0x10)) {
                  if ((*(u8 *)((int)objState + 0x6a) != 0) ||
                      (*(u8 *)((int)candState + 0x6a) != 0)) {
                    ObjHits_CheckHitVolumes(obj, candObj, obj, 0, 1, 0xffffffff, 0);
                  }
                } else if ((*(u8 *)((int)objState + 0x6a) != 0) ||
                           (*(u8 *)((int)candState + 0x6a) != 0)) {
                  ObjHits_DetectObjectPair(obj, candObj);
                }
              }
            }
            if (diff < objState->secondaryRadiusXZ + candState->secondaryRadiusXZ) {
              axisDiff = *(f32 *)(obj + 0x1c) - *(f32 *)(candObj + 0x1c);
              if (axisDiff > gObjHitsScalarZero) {
              } else {
                axisDiff = -axisDiff;
              }
              if ((axisDiff < objState->secondaryRadiusY + candState->secondaryRadiusY) &&
                  ((objState->flags & 0x100) == 0) && ((candState->flags & 0x100) == 0) &&
                  ((objState->sourceMask & candState->targetMask) != 0) &&
                  (((candState->sourceMask & 0x80) != 0) ||
                   ((candState->sourceMask & objState->targetMask) != 0))) {
                candAttachedObj = *(uint *)(candObj + 0xc8);
                if ((candAttachedObj != 0) &&
                    ((*(void **)(candAttachedObj + 0x54) == NULL) ||
                     (((*(ObjHitsPriorityState **)(candAttachedObj + 0x54))->flags & 1) == 0))) {
                  candAttachedObj = 0;
                }
                ObjHits_CheckObjectHitVolumes(obj, candObj, attachedObj, candAttachedObj,
                                              timeDelta);
              }
            }
          }
        }
      }
    }
  }
  entrySlot = entrySlotBase;
  for (slotIndex = 1; slotIndex < slotCount; slotIndex++, entrySlot++) {
    obj = (*entrySlot)->obj;
    if (((*(ObjHitsPriorityState **)(obj + 0x54))->flags & 0x200) != 0) {
      ObjHits_CheckTrackContact(obj, obj);
      attachedObj = *(uint *)(obj + 0xc8);
      if (attachedObj != 0) {
        ObjHits_CheckTrackContact(obj, attachedObj);
      }
    }
  }
  for (slotIndex = 1; slotIndex < slotCount; slotIndex++, entrySlotBase++) {
    obj = (*entrySlotBase)->obj;
    objState = *(ObjHitsPriorityState **)(obj + 0x54);
    objState->localPosX = *(f32 *)(obj + 0xc);
    objState->localPosY = *(f32 *)(obj + 0x10);
    objState->localPosZ = *(f32 *)(obj + 0x14);
    if (*(int *)(obj + 0x30) != 0) {
      Obj_TransformLocalPointToWorld(objState->localPosX, objState->localPosY, objState->localPosZ,
                                     &objState->worldPosX, &objState->worldPosY,
                                     &objState->worldPosZ, *(int *)(obj + 0x30));
    } else {
      objState->worldPosX = *(f32 *)(obj + 0xc);
      objState->worldPosY = *(f32 *)(obj + 0x10);
      objState->worldPosZ = *(f32 *)(obj + 0x14);
    }
    objState->activeHitboxMode = 0;
    objState->flags = objState->flags & ~0x2000;
    if (((objState->priorityHitCount != 0) || ((objState->flags & 8) != 0)) &&
        ((objState->flags & 0x40) == 0) && ((objState->flags & 0x4000) == 0)) {
      *(f32 *)(obj + 0x24) = oneOverTimeDelta * (*(f32 *)(obj + 0xc) - *(f32 *)(obj + 0x80));
      *(f32 *)(obj + 0x2c) = oneOverTimeDelta * (*(f32 *)(obj + 0x14) - *(f32 *)(obj + 0x88));
    }
  }
  for (slotIndex = 0; slotIndex < 5; slotIndex++) {
    gObjHitsActiveHitVolumeObjects[slotIndex] = 0;
  }
}
