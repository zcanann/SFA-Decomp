#include "ghidra_import.h"
#include "main/objhits.h"

extern undefined8 memcpy();
extern undefined4 Obj_TransformWorldPointToLocal();
extern undefined4 Obj_TransformLocalPointToWorld();
extern uint getAngle();
extern undefined4 FUN_8001774c();
extern undefined4 FUN_80017754();
extern int FUN_80017970();
extern undefined4 ObjList_GetObjects();
extern undefined4 ObjHits_RecordObjectHit();
extern undefined4 ObjHits_RecordPositionHit();
extern undefined4 ObjContact_DispatchCallbacks();
extern byte FUN_80063a68();
extern undefined4 FUN_80063a74();
extern void trackDolphin_buildSweptBounds(uint *boundsOut,float *startPoints,float *endPoints,
                                          float *radii,int pointCount);
extern undefined4 FUN_80135810();
extern undefined8 FUN_8028680c();
extern undefined8 FUN_80286818();
extern int FUN_80286820();
extern undefined8 FUN_80286828();
extern undefined8 FUN_80286830();
extern undefined8 FUN_80286834();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286858();
extern undefined4 FUN_80286864();
extern undefined4 FUN_8028686c();
extern undefined4 FUN_80286874();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_8028688c();
extern double sqrtf();
extern undefined4 sin();

extern undefined4* DAT_80341558;
extern int DAT_8034155c;
extern undefined4 DAT_80341b98;
extern undefined4 DAT_80341b9c;
extern undefined4 DAT_80341ba4;
extern undefined4 DAT_80342e58;
extern undefined4 DAT_803dd848;
extern undefined4 DAT_803dd850;
extern int *lbl_803DCBDC;
extern f64 DOUBLE_803df5a8;
extern f64 DOUBLE_803df5c0;
extern f64 DOUBLE_803df5d0;
extern f32 timeDelta;
extern f32 lbl_803DC074;
extern f32 lbl_803DC078;
extern f32 lbl_803DC0B0;
extern f32 lbl_803DCBE8;
extern f32 lbl_803DE910;
extern f32 lbl_803DE918;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803DF590;
extern f32 lbl_803DF598;
extern void Vec3_Normalize();
extern void Vec3_ScaleAdd();
extern void Vec3_Cross();
extern f32 Vec3_Length();
extern void fn_8002273C();
extern f32 lbl_803DF59C;
extern f32 lbl_803DF5A0;
extern f32 lbl_803DF5B0;
extern f32 lbl_803DF5B4;
extern f32 lbl_803DF5B8;
extern f32 lbl_803DF5D8;
extern f32 lbl_803DF5DC;
extern f32 lbl_803DF5E0;
extern char s_HIT_VOLUMES__an_object_has_too_m_802cb98c[];
extern undefined4 uRam803dd84c;
extern undefined4 uRam803dd854;

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
void ObjHits_CollectSkeletonHitsXZ(undefined8 param_1,double param_2,double param_3,
                                   undefined4 param_4,undefined4 param_5,int *param_6,
                                   int *param_7,int *param_8,float *param_9)
{
  double dVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float *pfVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  uint uVar13;
  int iVar14;
  float *pfVar15;
  int iVar16;
  double extraout_f1;
  double dVar17;
  double dVar18;
  double dVar19;
  double in_f25;
  double dVar20;
  double in_f26;
  double in_f27;
  double in_f28;
  double in_f29;
  double dVar21;
  double in_f30;
  double dVar22;
  double in_f31;
  double dVar23;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar24;
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
  float local_68;
  float fStack_64;
  float local_58;
  float fStack_54;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  local_68 = (float)in_f25;
  fStack_64 = (float)in_ps25_1;
  uVar24 = FUN_80286818();
  pfVar5 = (float *)((ulonglong)uVar24 >> 0x20);
  iVar9 = (int)uVar24;
  iVar11 = 0;
  if (iVar9 != 0) {
    iVar10 = *param_6;
    iVar14 = *(int *)(iVar9 + 4);
    dVar21 = (double)(float)(extraout_f1 + extraout_f1);
    *param_8 = (int)param_7;
    *param_9 = lbl_803DF590;
    dVar20 = extraout_f1;
    iVar6 = FUN_80017970(param_6,0);
    local_c4 = *(float *)(iVar6 + 0xc);
    local_c0 = *(float *)(iVar6 + 0x1c);
    local_bc = *(float *)(iVar6 + 0x2c);
    dVar17 = sqrtf((double)((local_bc - pfVar5[2]) * (local_bc - pfVar5[2]) +
                                  (local_c4 - *pfVar5) * (local_c4 - *pfVar5) + lbl_803DF590));
    dVar17 = (double)(float)(dVar17 - dVar20);
    dVar23 = (double)(*pfVar5 + *pfVar5);
    dVar22 = (double)(pfVar5[2] + pfVar5[2]);
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
      if (dVar17 < (double)*(float *)(*(int *)(iVar9 + 0x10) + iVar6)) {
        iVar12 = (int)*(char *)(*(int *)(iVar10 + 0x3c) + iVar16);
        iVar7 = FUN_80017970(param_6,uVar13);
        local_c4 = *(float *)(iVar7 + 0xc);
        local_c0 = *(float *)(iVar7 + 0x1c);
        local_bc = *(float *)(iVar7 + 0x2c);
        iVar7 = FUN_80017970(param_6,iVar12);
        local_d0 = *(float *)(iVar7 + 0xc);
        local_cc = *(float *)(iVar7 + 0x1c);
        local_c8 = *(float *)(iVar7 + 0x2c);
        *(undefined *)(*(int *)(iVar9 + 0x18) + uVar13) = 1;
        *(undefined *)(*(int *)(iVar9 + 0x18) + iVar12) = 1;
        dVar18 = (double)*pfVar15;
        dVar19 = (double)*(float *)(iVar14 + iVar12 * 4);
        if ((((double)(float)((double)local_c0 - dVar18) <= param_2) ||
            ((double)(float)((double)local_cc - dVar19) <= param_2)) &&
           ((param_3 <= (double)(float)((double)local_c0 + dVar18) ||
            (param_3 <= (double)(float)((double)local_cc + dVar19))))) {
          fVar3 = (float)((double)(local_d0 + local_c4) - dVar23);
          fVar4 = (float)((double)(local_c8 + local_bc) - dVar22);
          if (dVar18 <= dVar19) {
            dVar1 = dVar19 + dVar19;
          }
          else {
            dVar1 = dVar18 + dVar18;
          }
          fVar2 = (float)(dVar21 + (double)(*(float *)(*(int *)(iVar9 + 0xc) + iVar6) + (float)dVar1
                                           ));
          if (fVar4 * fVar4 + fVar3 * fVar3 + lbl_803DF590 < fVar2 * fVar2) {
            local_dc = local_d0 - local_c4;
            local_d8 = local_cc - local_c0;
            local_d4 = local_c8 - local_bc;
            fVar3 = *(float *)(*(int *)(iVar9 + 0xc) + iVar6);
            if (fVar3 != lbl_803DF590) {
              fVar3 = lbl_803DF598 / fVar3;
              local_dc = local_dc * fVar3;
              local_d8 = local_d8 * fVar3;
              local_d4 = local_d4 * fVar3;
            }
            *(undefined *)(*(int *)(iVar9 + 0x18) + uVar13) = 0;
            *(undefined *)(*(int *)(iVar9 + 0x18) + iVar12) = 0;
            uVar8 = ObjHits_TestTaperedCapsuleXZ(dVar20,dVar18,dVar19,
                                                 (double)*(float *)(*(int *)(iVar9 + 0xc) + iVar6),
                                                 pfVar5,&local_c4,&local_dc,&local_d0,&local_e0,
                                                 &local_e4,&local_e8);
            if (uVar8 != 0) {
              *(undefined *)(*(int *)(iVar9 + 0x18) + uVar13) = 1;
              *(undefined *)(*(int *)(iVar9 + 0x18) + iVar12) = 1;
              dVar18 = sqrtf((double)local_e4);
              param_7[0xc] = (int)(float)(dVar20 + (double)(float)(dVar18 - (double)local_e8));
              if (lbl_803DF590 == (float)param_7[0xc]) {
                param_7[0xc] = (int)lbl_803DF5A0;
              }
              fVar3 = (float)param_7[0xc];
              if (fVar3 <= lbl_803DF590) {
                fVar3 = -fVar3;
              }
              param_7[0xf] = (int)(lbl_803DF598 / fVar3);
              *param_9 = *param_9 + (float)param_7[0xf];
              if ((float)param_7[0xc] < *(float *)(*param_8 + 0x30)) {
                *param_8 = (int)param_7;
              }
              *param_7 = (int)&local_c4;
              param_7[1] = (int)&local_d0;
              param_7[2] = (int)local_c4;
              param_7[3] = (int)local_c0;
              param_7[4] = (int)local_bc;
              param_7[5] = (int)local_d0;
              param_7[6] = (int)local_cc;
              param_7[7] = (int)local_c8;
              param_7[0xb] = (int)local_e0;
              param_7[0xe] = (int)local_e8;
              dVar18 = sqrtf((double)local_e4);
              param_7[0xd] = (int)(float)dVar18;
              param_7[8] = (int)local_dc;
              param_7[9] = (int)local_d8;
              param_7[10] = (int)local_d4;
              param_7[0x10] = uVar13;
              param_7[0x11] = iVar12;
              if (iVar11 < 0x13) {
                param_7 = param_7 + 0x12;
                iVar11 = iVar11 + 1;
              }
            }
          }
        }
      }
    }
    param_7[0x10] = -1;
  }
  FUN_80286864();
  return;
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
void ObjHits_CollectSkeletonHits3D(undefined4 param_1,undefined4 param_2,int *param_3,
                                   int *param_4,int *param_5,float *param_6)
{
  float fVar1;
  float fVar2;
  float fVar3;
  float *pfVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  uint uVar12;
  int iVar13;
  float *pfVar14;
  int iVar15;
  double extraout_f1;
  double dVar16;
  double dVar17;
  double dVar18;
  double dVar19;
  double in_f27;
  double dVar20;
  double in_f28;
  double in_f29;
  double dVar21;
  double in_f30;
  double dVar22;
  double in_f31;
  double dVar23;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar24;
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
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  uVar24 = FUN_80286818();
  pfVar4 = (float *)((ulonglong)uVar24 >> 0x20);
  iVar8 = (int)uVar24;
  iVar10 = 0;
  if (iVar8 != 0) {
    iVar9 = *param_3;
    iVar13 = *(int *)(iVar8 + 4);
    dVar21 = (double)(float)(extraout_f1 + extraout_f1);
    *param_5 = (int)param_4;
    *param_6 = lbl_803DF590;
    dVar20 = extraout_f1;
    iVar5 = FUN_80017970(param_3,0);
    local_a4 = *(float *)(iVar5 + 0xc);
    local_a0 = *(float *)(iVar5 + 0x1c);
    local_9c = *(float *)(iVar5 + 0x2c);
    dVar16 = sqrtf((double)((local_9c - pfVar4[2]) * (local_9c - pfVar4[2]) +
                                  (local_a4 - *pfVar4) * (local_a4 - *pfVar4) + lbl_803DF590));
    dVar16 = (double)(float)(dVar16 - dVar20);
    dVar23 = (double)(*pfVar4 + *pfVar4);
    dVar22 = (double)(pfVar4[2] + pfVar4[2]);
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
      if (dVar16 < (double)*(float *)(*(int *)(iVar8 + 0x10) + iVar5)) {
        iVar11 = (int)*(char *)(*(int *)(iVar9 + 0x3c) + iVar15);
        iVar6 = FUN_80017970(param_3,uVar12);
        local_a4 = *(float *)(iVar6 + 0xc);
        local_a0 = *(float *)(iVar6 + 0x1c);
        local_9c = *(float *)(iVar6 + 0x2c);
        iVar6 = FUN_80017970(param_3,iVar11);
        local_b0 = *(float *)(iVar6 + 0xc);
        local_ac = *(float *)(iVar6 + 0x1c);
        local_a8 = *(float *)(iVar6 + 0x2c);
        dVar17 = (double)*pfVar14;
        dVar18 = (double)*(float *)(iVar13 + iVar11 * 4);
        *(undefined *)(*(int *)(iVar8 + 0x18) + uVar12) = 1;
        *(undefined *)(*(int *)(iVar8 + 0x18) + iVar11) = 1;
        fVar2 = (float)((double)(local_b0 + local_a4) - dVar23);
        fVar3 = (float)((double)(local_a8 + local_9c) - dVar22);
        if (dVar17 <= dVar18) {
          dVar19 = dVar18 + dVar18;
        }
        else {
          dVar19 = dVar17 + dVar17;
        }
        fVar1 = (float)(dVar21 + (double)(*(float *)(*(int *)(iVar8 + 0xc) + iVar5) + (float)dVar19)
                       );
        if (fVar3 * fVar3 + fVar2 * fVar2 + lbl_803DF590 < fVar1 * fVar1) {
          dVar19 = (double)*(float *)(*(int *)(iVar8 + 0xc) + iVar5);
          local_b4 = (float)((double)lbl_803DF598 / dVar19);
          local_bc = (local_b0 - local_a4) * local_b4;
          local_b8 = (local_ac - local_a0) * local_b4;
          local_b4 = (local_a8 - local_9c) * local_b4;
          uVar7 = ObjHits_TestTaperedCapsule3D(dVar20,dVar17,dVar18,dVar19,pfVar4,&local_a4,
                                               &local_bc,&local_b0,&local_c0,&local_c4,&local_c8);
          if (uVar7 != 0) {
            *(undefined *)(*(int *)(iVar8 + 0x18) + uVar12) = 1;
            *(undefined *)(*(int *)(iVar8 + 0x18) + iVar11) = 1;
            dVar17 = sqrtf((double)local_c4);
            param_4[0xc] = (int)(float)(dVar20 + (double)(float)(dVar17 - (double)local_c8));
            if (lbl_803DF590 == (float)param_4[0xc]) {
              param_4[0xc] = (int)lbl_803DF5A0;
            }
            fVar2 = (float)param_4[0xc];
            if (fVar2 <= lbl_803DF590) {
              fVar2 = -fVar2;
            }
            param_4[0xf] = (int)(lbl_803DF598 / fVar2);
            *param_6 = *param_6 + (float)param_4[0xf];
            if ((float)param_4[0xc] < *(float *)(*param_5 + 0x30)) {
              *param_5 = (int)param_4;
            }
            *param_4 = (int)&local_a4;
            param_4[1] = (int)&local_b0;
            param_4[2] = (int)local_a4;
            param_4[3] = (int)local_a0;
            param_4[4] = (int)local_9c;
            param_4[5] = (int)local_b0;
            param_4[6] = (int)local_ac;
            param_4[7] = (int)local_a8;
            param_4[0xb] = (int)local_c0;
            param_4[0xe] = (int)local_c8;
            dVar17 = sqrtf((double)local_c4);
            param_4[0xd] = (int)(float)dVar17;
            param_4[8] = (int)local_bc;
            param_4[9] = (int)local_b8;
            param_4[10] = (int)local_b4;
            param_4[0x10] = uVar12;
            param_4[0x11] = iVar11;
            if (iVar10 < 0x13) {
              iVar10 = iVar10 + 1;
              param_4 = param_4 + 0x12;
            }
          }
        }
      }
    }
    param_4[0x10] = -1;
  }
  FUN_80286864();
  return;
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
void ObjHits_CalcSkeletonResponseXZ(undefined8 param_1,double param_2,double param_3,
                                    undefined4 param_4,undefined4 param_5,int param_6,
                                    int param_7,undefined4 param_8,int param_9,float *param_10)
{
  int iVar1;
  float fVar2;
  float *pfVar3;
  float *pfVar4;
  int iVar5;
  double extraout_f1;
  double dVar6;
  double in_f27;
  double dVar7;
  double in_f28;
  double in_f29;
  double in_f30;
  double in_f31;
  double dVar8;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar9;
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
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  uVar9 = FUN_80286834();
  pfVar3 = (float *)((ulonglong)uVar9 >> 0x20);
  iVar5 = (int)uVar9;
  local_dc = *(float *)(iVar5 + 0x18) - *(float *)(iVar5 + 0x8c);
  local_d8 = *(float *)(iVar5 + 0x10) - *(float *)(iVar5 + 0x90);
  local_d4 = *(float *)(iVar5 + 0x20) - *(float *)(iVar5 + 0x94);
  dVar7 = extraout_f1;
  dVar6 = (double)Vec3_Length(&local_dc);
  local_dc = (float)((double)local_dc * param_2);
  local_d8 = (float)((double)local_d8 * param_2);
  local_d4 = (float)((double)local_d4 * param_2);
  local_e8 = *pfVar3 - local_dc;
  local_e4 = pfVar3[1] - local_d8;
  local_e0 = pfVar3[2] - local_d4;
  local_7c = lbl_803DF590;
  local_78 = lbl_803DF590;
  local_74 = lbl_803DF590;
  local_c4 = lbl_803DF590;
  local_c0 = lbl_803DF590;
  local_bc = lbl_803DF590;
  iVar5 = *(int *)(param_9 + 0x40) * 4;
  pfVar4 = ObjHits_CalcTaperedCapsuleNormal(
      (double)*(float *)(param_9 + 0x2c),(double)*(float *)(*(int *)(param_7 + 4) + iVar5),
      (double)*(float *)(*(int *)(param_7 + 4) + *(int *)(param_9 + 0x44) * 4),
      (double)*(float *)(*(int *)(param_7 + 0xc) + iVar5),&local_e8,(float *)(param_9 + 8),
      (float *)(param_9 + 0x14),afStack_b8);
  Vec3_Normalize(pfVar4);
  dVar8 = (double)lbl_803DF590;
  for (iVar5 = param_6; *(int *)(iVar5 + 0x40) != -1; iVar5 = iVar5 + 0x48) {
    iVar1 = *(int *)(iVar5 + 0x40) * 4;
    pfVar4 = ObjHits_ProjectPointToTaperedCapsuleXZ(
        dVar7,(double)*(float *)(iVar5 + 0x2c),(double)*(float *)(*(int *)(param_7 + 4) + iVar1),
        (double)*(float *)(*(int *)(param_7 + 4) + *(int *)(iVar5 + 0x44) * 4),
        (double)*(float *)(*(int *)(param_7 + 0xc) + iVar1),&local_e8,(float *)(iVar5 + 8),
        (float *)(iVar5 + 0x14),afStack_a0);
    if (param_3 <= dVar8) {
      *(float *)(iVar5 + 0x3c) = (float)dVar8;
    }
    else {
      *(float *)(iVar5 + 0x3c) = (float)((double)*(float *)(iVar5 + 0x3c) / param_3);
    }
    *pfVar4 = *pfVar4 * *(float *)(iVar5 + 0x3c);
    pfVar4[1] = pfVar4[1] * *(float *)(iVar5 + 0x3c);
    pfVar4[2] = pfVar4[2] * *(float *)(iVar5 + 0x3c);
    local_7c = local_7c + *pfVar4;
    local_78 = local_78 + pfVar4[1];
    local_74 = local_74 + pfVar4[2];
    iVar1 = *(int *)(iVar5 + 0x40) * 4;
    pfVar4 = ObjHits_CalcTaperedCapsuleNormal(
        (double)*(float *)(iVar5 + 0x2c),(double)*(float *)(*(int *)(param_7 + 4) + iVar1),
        (double)*(float *)(*(int *)(param_7 + 4) + *(int *)(iVar5 + 0x44) * 4),
        (double)*(float *)(*(int *)(param_7 + 0xc) + iVar1),pfVar3,(float *)(iVar5 + 8),
        (float *)(iVar5 + 0x14),afStack_b8);
    Vec3_Normalize(pfVar4);
    local_c4 = local_c4 + *pfVar4;
    local_c0 = local_c0 + pfVar4[1];
    local_bc = local_bc + pfVar4[2];
  }
  Vec3_Normalize(&local_c4);
  local_d0 = local_7c - local_e8;
  local_cc = lbl_803DF590;
  local_c8 = local_74 - local_e0;
  dVar8 = (double)Vec3_Length(&local_d0);
  local_d0 = local_7c - *pfVar3;
  local_cc = lbl_803DF590;
  local_c8 = local_74 - pfVar3[2];
  Vec3_Normalize(&local_dc);
  if (dVar6 <= dVar8) {
    local_ac = lbl_803DF590;
    local_a8 = lbl_803DF590;
    local_a4 = lbl_803DF590;
  }
  else {
    fVar2 = (float)(DOUBLE_803df5a8 +
                   (double)((float)((double)lbl_803DF598 - param_2) * lbl_803DF5B0)) *
            (float)(dVar6 - dVar8);
    local_dc = local_dc * fVar2;
    local_d8 = local_d8 * fVar2;
    local_d4 = local_d4 * fVar2;
    fn_8002273C(&local_c4,&local_dc,&local_ac);
  }
  local_7c = local_7c + local_ac;
  local_78 = local_78 + local_a8;
  local_74 = local_74 + local_a4;
  local_ac = lbl_803DF590;
  local_a8 = lbl_803DF590;
  local_a4 = lbl_803DF590;
  for (; *(int *)(param_6 + 0x40) != -1; param_6 = param_6 + 0x48) {
    iVar5 = *(int *)(param_6 + 0x40) * 4;
    pfVar4 = ObjHits_ProjectPointToTaperedCapsuleXZ(
        dVar7,(double)*(float *)(param_6 + 0x2c),(double)*(float *)(*(int *)(param_7 + 4) + iVar5),
        (double)*(float *)(*(int *)(param_7 + 4) + *(int *)(param_6 + 0x44) * 4),
        (double)*(float *)(*(int *)(param_7 + 0xc) + iVar5),&local_7c,(float *)(param_6 + 8),
        (float *)(param_6 + 0x14),afStack_a0);
    *pfVar4 = *pfVar4 * *(float *)(param_6 + 0x3c);
    pfVar4[1] = pfVar4[1] * *(float *)(param_6 + 0x3c);
    pfVar4[2] = pfVar4[2] * *(float *)(param_6 + 0x3c);
    local_ac = local_ac + *pfVar4;
    local_a8 = local_a8 + pfVar4[1];
    local_a4 = local_a4 + pfVar4[2];
  }
  *param_10 = local_ac - *pfVar3;
  param_10[1] = lbl_803DF590;
  param_10[2] = local_a4 - pfVar3[2];
  FUN_80286880();
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
void ObjHits_CalcSkeletonResponse3D(undefined8 param_1,undefined8 param_2,double param_3,
                                    undefined4 param_4,undefined4 param_5,int param_6,
                                    int param_7,undefined4 param_8,int param_9,float *param_10)
{
  float fVar1;
  int iVar2;
  float *pfVar3;
  float *pfVar4;
  int iVar5;
  double extraout_f1;
  double dVar6;
  double in_f28;
  double dVar7;
  double in_f29;
  double in_f30;
  double in_f31;
  double dVar8;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar9;
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
  float local_68;
  float local_64;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  uVar9 = FUN_80286834();
  pfVar3 = (float *)((ulonglong)uVar9 >> 0x20);
  iVar5 = (int)uVar9;
  local_cc = *(float *)(iVar5 + 0xc) - *(float *)(iVar5 + 0x80);
  local_c8 = *(float *)(iVar5 + 0x10) - *(float *)(iVar5 + 0x84);
  local_c4 = *(float *)(iVar5 + 0x14) - *(float *)(iVar5 + 0x88);
  dVar7 = extraout_f1;
  dVar6 = (double)Vec3_Length(&local_cc);
  local_d8 = *pfVar3 - local_cc;
  local_d4 = pfVar3[1] - local_c8;
  local_d0 = pfVar3[2] - local_c4;
  local_6c = lbl_803DF590;
  local_68 = lbl_803DF590;
  local_64 = lbl_803DF590;
  local_b4 = lbl_803DF590;
  local_b0 = lbl_803DF590;
  local_ac = lbl_803DF590;
  iVar5 = *(int *)(param_9 + 0x40) * 4;
  pfVar4 = ObjHits_CalcTaperedCapsuleNormal(
      (double)*(float *)(param_9 + 0x2c),(double)*(float *)(*(int *)(param_7 + 4) + iVar5),
      (double)*(float *)(*(int *)(param_7 + 4) + *(int *)(param_9 + 0x44) * 4),
      (double)*(float *)(*(int *)(param_7 + 0xc) + iVar5),&local_d8,(float *)(param_9 + 8),
      (float *)(param_9 + 0x14),afStack_a8);
  Vec3_Normalize(pfVar4);
  dVar8 = (double)lbl_803DF590;
  for (iVar5 = param_6; *(int *)(iVar5 + 0x40) != -1; iVar5 = iVar5 + 0x48) {
    iVar2 = *(int *)(iVar5 + 0x40) * 4;
    pfVar4 = ObjHits_ProjectPointToTaperedCapsule3D(
        dVar7,(double)*(float *)(iVar5 + 0x2c),(double)*(float *)(*(int *)(param_7 + 4) + iVar2),
        (double)*(float *)(*(int *)(param_7 + 4) + *(int *)(iVar5 + 0x44) * 4),
        (double)*(float *)(*(int *)(param_7 + 0xc) + iVar2),&local_d8,(float *)(iVar5 + 8),
        (float *)(iVar5 + 0x14),afStack_90);
    if (param_3 <= dVar8) {
      *(float *)(iVar5 + 0x3c) = (float)dVar8;
    }
    else {
      *(float *)(iVar5 + 0x3c) = (float)((double)*(float *)(iVar5 + 0x3c) / param_3);
    }
    *pfVar4 = *pfVar4 * *(float *)(iVar5 + 0x3c);
    pfVar4[1] = pfVar4[1] * *(float *)(iVar5 + 0x3c);
    pfVar4[2] = pfVar4[2] * *(float *)(iVar5 + 0x3c);
    local_6c = local_6c + *pfVar4;
    local_68 = local_68 + pfVar4[1];
    local_64 = local_64 + pfVar4[2];
    iVar2 = *(int *)(iVar5 + 0x40) * 4;
    pfVar4 = ObjHits_CalcTaperedCapsuleNormal(
        (double)*(float *)(iVar5 + 0x2c),(double)*(float *)(*(int *)(param_7 + 4) + iVar2),
        (double)*(float *)(*(int *)(param_7 + 4) + *(int *)(iVar5 + 0x44) * 4),
        (double)*(float *)(*(int *)(param_7 + 0xc) + iVar2),pfVar3,(float *)(iVar5 + 8),
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
  dVar8 = (double)Vec3_Length(&local_c0);
  local_c0 = local_6c - *pfVar3;
  local_bc = local_68 - pfVar3[1];
  local_b8 = local_64 - pfVar3[2];
  Vec3_Normalize(&local_cc);
  if (dVar6 <= dVar8) {
    local_9c = lbl_803DF590;
    local_98 = lbl_803DF590;
    local_94 = lbl_803DF590;
  }
  else {
    fVar1 = (float)(dVar6 - dVar8);
    local_cc = local_cc * fVar1;
    local_c8 = local_c8 * fVar1;
    local_c4 = local_c4 * fVar1;
    fn_8002273C(&local_b4,&local_cc,&local_9c);
  }
  local_6c = local_6c + local_9c;
  local_68 = local_68 + local_98;
  local_64 = local_64 + local_94;
  local_9c = lbl_803DF590;
  local_98 = lbl_803DF590;
  local_94 = lbl_803DF590;
  for (; *(int *)(param_6 + 0x40) != -1; param_6 = param_6 + 0x48) {
    iVar5 = *(int *)(param_6 + 0x40) * 4;
    pfVar4 = ObjHits_ProjectPointToTaperedCapsule3D(
        dVar7,(double)*(float *)(param_6 + 0x2c),(double)*(float *)(*(int *)(param_7 + 4) + iVar5),
        (double)*(float *)(*(int *)(param_7 + 4) + *(int *)(param_6 + 0x44) * 4),
        (double)*(float *)(*(int *)(param_7 + 0xc) + iVar5),&local_6c,(float *)(param_6 + 8),
        (float *)(param_6 + 0x14),afStack_90);
    *pfVar4 = *pfVar4 * *(float *)(param_6 + 0x3c);
    pfVar4[1] = pfVar4[1] * *(float *)(param_6 + 0x3c);
    pfVar4[2] = pfVar4[2] * *(float *)(param_6 + 0x3c);
    local_9c = local_9c + *pfVar4;
    local_98 = local_98 + pfVar4[1];
    local_94 = local_94 + pfVar4[2];
  }
  *param_10 = local_9c - *pfVar3;
  param_10[1] = local_98 - pfVar3[1];
  param_10[2] = local_94 - pfVar3[2];
  FUN_80286880();
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
float *ObjHits_ProjectPointToTaperedCapsuleXZ(float radiusA, float axial, float radiusB,
                                              float radiusC, float halfLength, float *p,
                                              float *p0, float *p1, float *out)
{
    float invHalfLength;
    float surface[3];
    float dir[3];

    if (axial < lbl_803DE910) {
        out[0] = p[0] - p0[0];
        out[1] = lbl_803DE910;
        out[2] = p[2] - p0[2];
        Vec3_Normalize(out);
        radiusA = radiusA + radiusB;
        out[0] = out[0] * radiusA;
        out[1] = out[1] * radiusA;
        out[2] = out[2] * radiusA;
        out[0] = out[0] + p0[0];
        out[1] = out[1] + p0[1];
        out[2] = out[2] + p0[2];
        return out;
    }
    if (axial > halfLength) {
        out[0] = p[0] - p1[0];
        out[1] = lbl_803DE910;
        out[2] = p[2] - p1[2];
        Vec3_Normalize(out);
        radiusA = radiusA + radiusC;
        out[0] = out[0] * radiusA;
        out[1] = out[1] * radiusA;
        out[2] = out[2] * radiusA;
        out[0] = out[0] + p1[0];
        out[1] = out[1] + p1[1];
        out[2] = out[2] + p1[2];
        return out;
    }
    dir[0] = p1[0] - p0[0];
    dir[1] = p1[1] - p0[1];
    dir[2] = p1[2] - p0[2];
    invHalfLength = lbl_803DE918 / halfLength;
    dir[0] = dir[0] * invHalfLength;
    dir[1] = dir[1] * invHalfLength;
    dir[2] = dir[2] * invHalfLength;
    Vec3_ScaleAdd(axial, p0, dir, surface);
    out[0] = p[0] - surface[0];
    out[1] = lbl_803DE910;
    out[2] = p[2] - surface[2];
    Vec3_Normalize(out);
    radiusA = (radiusC - radiusB) * (axial / halfLength) + (radiusB + radiusA);
    out[0] = out[0] * radiusA;
    out[1] = out[1] * radiusA;
    out[2] = out[2] * radiusA;
    out[0] = out[0] + surface[0];
    out[1] = out[1] + surface[1];
    out[2] = out[2] + surface[2];
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
float *ObjHits_ProjectPointToTaperedCapsule3D(float radiusA, float axial, float radiusB,
                                              float radiusC, float halfLength, float *p,
                                              float *p0, float *p1, float *out)
{
    float invHalfLength;
    float dir[3];
    float surface[3];

    if (axial < lbl_803DE910) {
        out[0] = p[0] - p0[0];
        out[1] = p[1] - p0[1];
        out[2] = p[2] - p0[2];
        Vec3_Normalize(out);
        radiusA = radiusA + radiusB;
        out[0] = out[0] * radiusA;
        out[1] = out[1] * radiusA;
        out[2] = out[2] * radiusA;
        out[0] = out[0] + p0[0];
        out[1] = out[1] + p0[1];
        out[2] = out[2] + p0[2];
        return out;
    }
    if (axial > halfLength) {
        out[0] = p[0] - p1[0];
        out[1] = p[1] - p1[1];
        out[2] = p[2] - p1[2];
        Vec3_Normalize(out);
        radiusA = radiusA + radiusC;
        out[0] = out[0] * radiusA;
        out[1] = out[1] * radiusA;
        out[2] = out[2] * radiusA;
        out[0] = out[0] + p1[0];
        out[1] = out[1] + p1[1];
        out[2] = out[2] + p1[2];
        return out;
    }
    dir[0] = p1[0] - p0[0];
    dir[1] = p1[1] - p0[1];
    dir[2] = p1[2] - p0[2];
    invHalfLength = lbl_803DE918 / halfLength;
    dir[0] = dir[0] * invHalfLength;
    dir[1] = dir[1] * invHalfLength;
    dir[2] = dir[2] * invHalfLength;
    Vec3_ScaleAdd(axial, p0, dir, surface);
    out[0] = p[0] - surface[0];
    out[1] = p[1] - surface[1];
    out[2] = p[2] - surface[2];
    Vec3_Normalize(out);
    invHalfLength = (radiusC - radiusB) * (axial / halfLength);
    radiusA = invHalfLength + (radiusB + radiusA);
    out[0] = out[0] * radiusA;
    out[1] = out[1] * radiusA;
    out[2] = out[2] * radiusA;
    out[0] = out[0] + surface[0];
    out[1] = out[1] + surface[1];
    out[2] = out[2] + surface[2];
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
float *ObjHits_CalcTaperedCapsuleNormal(float param_1,float param_2,float param_3,
                                        float param_4,float *param_5,float *param_6,
                                        float *param_7,float *param_8)
{
  float fVar1;
  float dVar2;
  float dVar3;
  float axisDir[3];
  float normal[3];
  float blended[3];
  float cross[3];
  float surface[3];

  if (param_1 <= lbl_803DE910) {
    *param_8 = *param_5 - *param_7;
    param_8[1] = param_5[1] - param_7[1];
    param_8[2] = param_5[2] - param_7[2];
    Vec3_Normalize(param_8);
  }
  else if (param_1 >= param_4) {
    *param_8 = *param_5 - *param_7;
    param_8[1] = param_5[1] - param_7[1];
    param_8[2] = param_5[2] - param_7[2];
    Vec3_Normalize(param_8);
  }
  else {
    dVar3 = param_3 - param_2;
    dVar2 = dVar3 * (param_1 / param_4);
    axisDir[0] = param_7[0] - param_6[0];
    axisDir[1] = param_7[1] - param_6[1];
    axisDir[2] = param_7[2] - param_6[2];
    Vec3_Normalize(axisDir);
    Vec3_ScaleAdd(param_6,axisDir,param_1,surface);
    normal[0] = param_5[0] - surface[0];
    normal[1] = param_5[1] - surface[1];
    normal[2] = param_5[2] - surface[2];
    Vec3_Normalize(normal);
    if (dVar3 == lbl_803DE910) {
      param_8[0] = normal[0];
      param_8[1] = normal[1];
      param_8[2] = normal[2];
    }
    else {
      axisDir[0] = axisDir[0] * param_1;
      axisDir[1] = axisDir[1] * param_1;
      axisDir[2] = axisDir[2] * param_1;
      Vec3_ScaleAdd(axisDir,normal,dVar2,blended);
      Vec3_Normalize(blended);
      fVar1 = lbl_803DE918 / param_1;
      axisDir[0] = axisDir[0] * fVar1;
      axisDir[1] = axisDir[1] * fVar1;
      axisDir[2] = axisDir[2] * fVar1;
      Vec3_Cross(normal,axisDir,cross);
      Vec3_Normalize(cross);
      Vec3_Cross(cross,blended,param_8);
    }
  }
  return param_8;
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
uint ObjHits_TestTaperedCapsuleXZ(float radiusA, float radiusB, float radiusC, float halfLength,
                                  float *p0, float *p1, float *axis, float *hit,
                                  float *axial, float *dist2, float *sumR)
{
    float dx, dz;
    float ex, ey;
    float fa, fc;
    float t;
    float r;

    dx = p0[0] - p1[0];
    dz = p0[2] - p1[2];
    *axial = dx * axis[0] + dz * axis[2];
    if (*axial > halfLength) {
        fa = hit[0] - p0[0];
        fa *= fa;
        fc = hit[2] - p0[2];
        fc *= fc;
        *dist2 = fa + fc;
        r = radiusA + radiusC;
        *sumR = r;
        return *dist2 <= r * r;
    }
    if (*axial < lbl_803DE910) {
        *dist2 = dx * dx + dz * dz;
        r = radiusA + radiusB;
        *sumR = r;
        return *dist2 <= r * r;
    }
    ex = axis[0] * (t = -*axial) + dx;
    ey = axis[2] * t + dz;
    *dist2 = ex * ex + ey * ey;
    r = (*axial / halfLength) * (radiusC - radiusB) + (radiusA + radiusB);
    *sumR = r;
    return *dist2 <= r * r;
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
uint ObjHits_TestTaperedCapsule3D(float radiusA, float radiusB, float radiusC, float halfLength,
                                  float *p0, float *p1, float *axis, float *hit,
                                  float *axial, float *dist2, float *sumR)
{
    float dx, dy, dz;
    float ex, ey, ez;
    float fa, fb, fc;
    float t;
    float r;

    dx = p0[0] - p1[0];
    dy = p0[1] - p1[1];
    dz = p0[2] - p1[2];
    *axial = dz * axis[2] + (dx * axis[0] + dy * axis[1]);
    if (*axial > halfLength) {
        fa = hit[0] - p0[0];
        fb = hit[1] - p0[1];
        fc = hit[2] - p0[2];
        *dist2 = fc * fc + (fa * fa + fb * fb);
        r = radiusA + radiusC;
        *sumR = r;
        return *dist2 <= r * r;
    }
    if (*axial < lbl_803DE910) {
        *dist2 = dz * dz + (dx * dx + dy * dy);
        r = radiusA + radiusB;
        *sumR = r;
        return *dist2 <= r * r;
    }
    ex = axis[0] * -*axial + dx;
    ey = axis[1] * -*axial + dy;
    ez = axis[2] * -*axial + dz;
    *dist2 = ez * ez + (ex * ex + ey * ey);
    r = (*axial / halfLength) * (radiusC - radiusB) + (radiusA + radiusB);
    *sumR = r;
    return *dist2 <= r * r;
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
void ObjHits_SortSweepEntries(int sweepPtrs,int entryCount)
{
  int iVar1;
  int iVar2;
  int *piVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;

  iVar1 = (entryCount + -1) / 9;
  for (iVar9 = 1; iVar9 <= iVar1; iVar9 = iVar9 * 3 + 1) {
  }
  for (; 0 < iVar9; iVar9 = iVar9 / 3) {
    iVar6 = iVar9 + 1;
    iVar1 = iVar6 * 4;
    piVar4 = (int *)(sweepPtrs + iVar1);
    iVar2 = entryCount - iVar6;
    if (iVar6 < entryCount) {
      do {
        iVar8 = *piVar4;
        piVar3 = (int *)(sweepPtrs + iVar1);
        iVar7 = iVar6;
        while ((iVar9 < iVar7 &&
               (iVar5 = *(int *)(sweepPtrs + (iVar7 - iVar9) * 4),
               *(float *)(iVar8 + 4) < *(float *)(iVar5 + 4)))) {
          *piVar3 = iVar5;
          piVar3 = piVar3 + -iVar9;
          iVar7 = iVar7 - iVar9;
        }
        *(int *)(sweepPtrs + iVar7 * 4) = iVar8;
        piVar4 = piVar4 + 1;
        iVar6 = iVar6 + 1;
        iVar1 = iVar1 + 4;
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
    }
  }
  return;
}
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
  int *base;

  sVar2 = 0;
  iVar1 = 0;
  do {
    base = lbl_803DCBDC;
    if (*(int *)((int)base + iVar1) != 0) {
      *(int *)((int)base + iVar1) = *(int *)((int)base + iVar1) + -1;
    }
    iVar1 = iVar1 + 0x3c;
    sVar2++;
  } while (sVar2 < 0x32);
  lbl_803DCBE8 = timeDelta;
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
void ObjHitbox_UpdateRotatedBounds(ushort *param_1,int param_2)
{
  int iVar1;
  ushort local_28;
  ushort local_26;
  ushort local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  iVar1 = *(int *)(param_1 + 0x2c);
  if (iVar1 != 0) {
    if (param_2 != 0) {
      *(byte *)(iVar1 + 0x10c) = *(char *)(iVar1 + 0x10c) + 1U & 1;
    }
    local_28 = -*param_1;
    if ((*(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 0x800) == 0) {
      local_26 = -param_1[1];
    }
    else {
      local_26 = 0;
    }
    if ((*(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 0x1000) == 0) {
      local_24 = -param_1[2];
    }
    else {
      local_24 = 0;
    }
    local_20 = lbl_803DF598;
    local_1c = -*(float *)(param_1 + 0xc);
    local_18 = -*(float *)(param_1 + 0xe);
    local_14 = -*(float *)(param_1 + 0x10);
    FUN_8001774c((float *)(iVar1 + (uint)*(byte *)(iVar1 + 0x10c) * 0x40),(int)&local_28);
    local_28 = *param_1;
    if ((*(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 0x800) == 0) {
      local_26 = param_1[1];
    }
    else {
      local_26 = 0;
    }
    if ((*(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 0x1000) == 0) {
      local_24 = param_1[2];
    }
    else {
      local_24 = 0;
    }
    local_20 = lbl_803DF598;
    local_1c = *(float *)(param_1 + 0xc);
    local_18 = *(float *)(param_1 + 0xe);
    local_14 = *(float *)(param_1 + 0x10);
    FUN_80017754((float *)(iVar1 + (*(byte *)(iVar1 + 0x10c) + 2) * 0x40),&local_28);
    if (*(char *)(iVar1 + 0x10d) != '\0') {
      *(char *)(iVar1 + 0x10d) = *(char *)(iVar1 + 0x10d) + -1;
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
u8 ObjHits_CheckHitVolumes(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                           undefined8 param_5,undefined8 param_6,undefined8 param_7,
                           undefined8 param_8,undefined4 param_9,undefined4 param_10,
                           int param_11,undefined4 param_12,undefined4 param_13,uint param_14,
                           uint param_15,undefined4 param_16)
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
  int iVar14;
  int iVar15;
  int iVar16;
  uint uVar17;
  char cVar18;
  char cVar19;
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
  double extraout_f1;
  double dVar32;
  double dVar33;
  double dVar34;
  double in_f14;
  double dVar35;
  double in_f15;
  double dVar36;
  double in_f16;
  double dVar37;
  double in_f17;
  double dVar38;
  double in_f18;
  double in_f19;
  double in_f20;
  double in_f21;
  double in_f22;
  double in_f23;
  double in_f24;
  double in_f25;
  double in_f26;
  double in_f27;
  double dVar39;
  double in_f28;
  double dVar40;
  double in_f29;
  double dVar41;
  double in_f30;
  double dVar42;
  double dVar43;
  double in_f31;
  double dVar44;
  double dVar45;
  double in_ps14_1;
  double in_ps15_1;
  double in_ps16_1;
  double in_ps17_1;
  double in_ps18_1;
  double in_ps19_1;
  double in_ps20_1;
  double in_ps21_1;
  double in_ps22_1;
  double in_ps23_1;
  double in_ps24_1;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar46;
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
  undefined4 local_1d8;
  uint uStack_1d4;
  undefined4 local_1d0;
  uint uStack_1cc;
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
  float local_118;
  float fStack_114;
  float local_108;
  float fStack_104;
  float local_f8;
  float fStack_f4;
  float local_e8;
  float fStack_e4;
  float local_d8;
  float fStack_d4;
  float local_c8;
  float fStack_c4;
  float local_b8;
  float fStack_b4;
  float local_a8;
  float fStack_a4;
  float local_98;
  float fStack_94;
  float local_88;
  float fStack_84;
  float local_78;
  float fStack_74;
  float local_68;
  float fStack_64;
  float local_58;
  float fStack_54;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  local_68 = (float)in_f25;
  fStack_64 = (float)in_ps25_1;
  local_78 = (float)in_f24;
  fStack_74 = (float)in_ps24_1;
  local_88 = (float)in_f23;
  fStack_84 = (float)in_ps23_1;
  local_98 = (float)in_f22;
  fStack_94 = (float)in_ps22_1;
  local_a8 = (float)in_f21;
  fStack_a4 = (float)in_ps21_1;
  local_b8 = (float)in_f20;
  fStack_b4 = (float)in_ps20_1;
  local_c8 = (float)in_f19;
  fStack_c4 = (float)in_ps19_1;
  local_d8 = (float)in_f18;
  fStack_d4 = (float)in_ps18_1;
  local_e8 = (float)in_f17;
  fStack_e4 = (float)in_ps17_1;
  local_f8 = (float)in_f16;
  fStack_f4 = (float)in_ps16_1;
  local_108 = (float)in_f15;
  fStack_104 = (float)in_ps15_1;
  local_118 = (float)in_f14;
  fStack_114 = (float)in_ps14_1;
  uVar46 = FUN_8028680c();
  iVar14 = (int)((ulonglong)uVar46 >> 0x20);
  iVar15 = (int)uVar46;
  cVar18 = (char)param_12;
  local_1a8 = 0;
  iVar25 = *(int *)(iVar14 + 0x54);
  iVar24 = *(int *)(iVar15 + 0x54);
  local_198 = *(int *)(param_11 + 0x54);
  if ((((*(byte *)(local_198 + 0xb6) & 0x10) == 0) ||
      ((*(char *)(local_198 + 0xaf) == '\0' && (*(char *)(local_198 + 0xae) == '\0')))) &&
     (((*(byte *)(iVar24 + 0xb6) & 0x10) == 0 ||
      ((*(char *)(iVar24 + 0xaf) == '\0' && (*(char *)(iVar24 + 0xae) == '\0')))))) {
    bVar6 = false;
    bVar7 = false;
    cVar19 = (char)param_13;
    if (((cVar18 == '\0') || ((*(byte *)(iVar25 + 0xb6) & 0x10) == 0)) &&
       ((cVar19 == '\0' || (*(char *)(iVar25 + 0x62) != '\x10')))) {
      local_174 = 1;
      local_184 = &local_218;
      local_18c = &local_1f8;
      local_190 = auStack_248;
      bVar6 = (*(byte *)(iVar25 + 0xb6) & 2) != 0;
      uStack_1d4 = (int)*(short *)(iVar25 + 100) ^ 0x80000000;
      local_1d8 = 0x43300000;
      fVar2 = (float)((double)CONCAT44(0x43300000,uStack_1d4) - DOUBLE_803df5c0);
      dVar32 = (double)playerMapOffsetX;
      local_214 = (float)((double)*(float *)(iVar14 + 0x18) - dVar32);
      local_210 = *(undefined4 *)(iVar14 + 0x1c);
      param_2 = (double)playerMapOffsetZ;
      local_20c = (float)((double)*(float *)(iVar14 + 0x20) - param_2);
      local_1f4 = (float)((double)*(float *)(iVar25 + 0x1c) - dVar32);
      local_1f0 = *(undefined4 *)(iVar25 + 0x20);
      local_1ec = (float)((double)*(float *)(iVar25 + 0x24) - param_2);
      local_232 = 0;
      local_231 = 0;
      local_234 = 0;
      iVar16 = iVar15;
      local_218 = fVar2;
      local_1f8 = fVar2;
    }
    else {
      piVar11 = *(int **)(*(int *)(iVar14 + 0x7c) + *(char *)(iVar14 + 0xad) * 4);
      iVar16 = *piVar11;
      local_174 = (uint)*(byte *)(iVar16 + 0xf7);
      local_184 = (float *)piVar11[0x14];
      local_18c = (float *)piVar11[(*(ushort *)(piVar11 + 6) >> 2 & 1 ^ 1) + 0x12];
      local_190 = *(undefined **)(iVar16 + 0x58);
      if (param_11 == iVar14) {
        fVar2 = *(float *)(iVar25 + 0x34);
      }
      else {
        fVar2 = *(float *)(local_198 + 0x34);
      }
      dVar32 = extraout_f1;
      if ((*(ushort *)(iVar14 + 6) & 0x4000) != 0) goto LAB_80033418;
    }
    dVar44 = (double)fVar2;
    if (((cVar18 == '\0') || ((*(byte *)(iVar24 + 0xb6) & 0x10) == 0)) &&
       ((cVar19 == '\0' || (*(char *)(iVar24 + 0x62) != '\x10')))) {
      local_178 = 1;
      local_188 = &local_208;
      local_194 = auStack_230;
      bVar7 = (*(byte *)(iVar24 + 0xb6) & 2) != 0;
      uStack_1d4 = (int)*(short *)(iVar24 + 100) ^ 0x80000000;
      local_1d8 = 0x43300000;
      fVar2 = (float)((double)CONCAT44(0x43300000,uStack_1d4) - DOUBLE_803df5c0);
      dVar32 = (double)playerMapOffsetX;
      local_204 = (float)((double)*(float *)(iVar15 + 0x18) - dVar32);
      local_200 = *(undefined4 *)(iVar15 + 0x1c);
      param_2 = (double)playerMapOffsetZ;
      local_1fc = (float)((double)*(float *)(iVar15 + 0x20) - param_2);
      local_1e8 = local_218;
      local_1e4 = (float)((double)*(float *)(iVar25 + 0x1c) - dVar32);
      local_1e0 = *(undefined4 *)(iVar25 + 0x20);
      local_1dc = (float)((double)*(float *)(iVar25 + 0x24) - param_2);
      local_21a = 0;
      local_219 = 0;
      local_21c = 0;
      local_208 = fVar2;
    }
    else {
      piVar11 = *(int **)(*(int *)(iVar15 + 0x7c) + *(char *)(iVar15 + 0xad) * 4);
      iVar16 = *piVar11;
      local_178 = (uint)*(byte *)(iVar16 + 0xf7);
      local_188 = (float *)piVar11[0x14];
      local_194 = *(undefined **)(iVar16 + 0x58);
      fVar2 = *(float *)(iVar24 + 0x34);
      if ((*(ushort *)(iVar15 + 6) & 0x4000) != 0) goto LAB_80033418;
    }
    dVar42 = (double)fVar2;
    if ((0x40 < local_174) || (0x40 < local_178)) {
      FUN_80135810(dVar32,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   s_HIT_VOLUMES__an_object_has_too_m_802cb98c,iVar16,param_11,param_12,param_13,
                   param_14,param_15,param_16);
    }
    dVar41 = (double)(*(float *)(iVar14 + 0x18) - *(float *)(iVar15 + 0x18));
    dVar40 = (double)(*(float *)(iVar14 + 0x1c) - *(float *)(iVar15 + 0x1c));
    dVar39 = (double)(*(float *)(iVar14 + 0x20) - *(float *)(iVar15 + 0x20));
    dVar32 = sqrtf((double)(float)(dVar39 * dVar39 +
                                         (double)(float)(dVar41 * dVar41 +
                                                        (double)(float)(dVar40 * dVar40))));
    if (dVar32 <= (double)(lbl_803DF5B4 + (float)(dVar44 + dVar42))) {
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
            if ((param_14 & 1 << (int)(char)puVar12[0x17]) != 0) {
              uVar22 = uVar22 | 1 << iVar16;
              uVar23 = uVar23 | (1 << iVar16) >> 0x1f;
            }
            if ((param_15 & 1 << (int)(char)puVar12[0x17]) != 0) {
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
      local_1a4 = (float *)&DAT_80342e58;
      local_1c4 = lbl_803DF5B8;
      iVar16 = 1;
      while (iVar16 != 0) {
        iVar16 = 0;
        local_17c = local_184;
        local_180 = local_18c;
        pfVar26 = local_1a4;
        for (iVar28 = 0; iVar28 < (int)local_174; iVar28 = iVar28 + 1) {
          uVar31 = 1 << iVar28;
          if ((uVar22 & uVar31) != 0 || (uVar23 & (int)uVar31 >> 0x1f) != 0) {
            dVar43 = (double)*local_17c;
            dVar45 = (double)local_17c[1];
            dVar42 = (double)local_17c[2];
            dVar44 = (double)local_17c[3];
            bVar8 = (local_19c & uVar31) == 0;
            bVar9 = (local_1a0 & (int)uVar31 >> 0x1f) == 0;
            bVar1 = bVar8 && bVar9;
            if (!bVar8 || !bVar9) {
              local_1b4 = local_180[1];
              local_1b8 = local_180[2];
              in_f23 = (double)local_180[3];
              in_f21 = (double)(float)(dVar45 - (double)local_1b4);
              in_f20 = (double)(float)(dVar42 - (double)local_1b8);
              in_f19 = (double)(float)(dVar44 - in_f23);
              in_f18 = (double)(float)(in_f19 * in_f19 +
                                      (double)(float)(in_f21 * in_f21 +
                                                     (double)(float)(in_f20 * in_f20)));
              if (in_f18 <= (double)lbl_803DF590) {
                bVar1 = true;
              }
              else {
                local_1c8 = (float)((double)lbl_803DF598 / in_f18);
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
                    uStack_1d4 = (int)*(short *)(iVar25 + 0x66) ^ 0x80000000;
                    uStack_1cc = (int)*(short *)(iVar25 + 0x68) ^ 0x80000000;
                    fVar5 = pfVar30[2] - *pfVar30;
                    fVar3 = pfVar30[2] + *pfVar30;
                    fVar2 = (float)(dVar42 + (double)(float)((double)CONCAT44(0x43300000,uStack_1d4)
                                                            - DOUBLE_803df5c0));
                    fVar4 = (float)(dVar42 + (double)(float)((double)CONCAT44(0x43300000,uStack_1cc)
                                                            - DOUBLE_803df5c0));
                  }
                  else {
                    uStack_1cc = (int)*(short *)(iVar24 + 0x66) ^ 0x80000000;
                    fVar5 = (float)((double)CONCAT44(0x43300000,uStack_1cc) - DOUBLE_803df5c0) +
                            pfVar30[2];
                    uStack_1d4 = (int)*(short *)(iVar24 + 0x68) ^ 0x80000000;
                    fVar3 = (float)((double)CONCAT44(0x43300000,uStack_1d4) - DOUBLE_803df5c0) +
                            pfVar30[2];
                    fVar2 = local_1ac;
                    fVar4 = local_1b0;
                  }
                  local_1d0 = 0x43300000;
                  local_1d8 = 0x43300000;
                  if (((fVar2 <= fVar5) || (fVar2 <= fVar3)) &&
                     ((fVar5 <= fVar4 || (fVar3 <= fVar4)))) {
                    in_f22 = (double)((float)(dVar43 + (double)*pfVar30) *
                                     (float)(dVar43 + (double)*pfVar30));
                    dVar41 = (double)(float)(dVar45 - (double)pfVar30[1]);
                    dVar32 = (double)(float)(dVar41 * dVar41);
                    if (dVar32 < in_f22) {
                      dVar39 = (double)(float)(dVar44 - (double)pfVar30[3]);
                      dVar32 = (double)(float)(dVar39 * dVar39 + dVar32);
                      if (dVar32 < in_f22) {
                        dVar40 = (double)lbl_803DF590;
                        unaff_r26 = 1;
                      }
                    }
                  }
                }
                else {
                  in_f22 = (double)((float)(dVar43 + (double)*pfVar30) *
                                   (float)(dVar43 + (double)*pfVar30));
                  if (bVar1) {
                    dVar41 = (double)(float)(dVar45 - (double)pfVar30[1]);
                    dVar32 = (double)(float)(dVar41 * dVar41);
                    if (dVar32 < in_f22) {
                      dVar40 = (double)(float)(dVar42 - (double)pfVar30[2]);
                      dVar32 = (double)(float)(dVar40 * dVar40 + dVar32);
                      if (dVar32 < in_f22) {
                        dVar39 = (double)(float)(dVar44 - (double)pfVar30[3]);
                        dVar32 = (double)(float)(dVar39 * dVar39 + dVar32);
                        if (dVar32 < in_f22) {
                          unaff_r26 = 1;
                        }
                      }
                    }
                  }
                  else {
                    dVar38 = (double)(local_1b4 - pfVar30[1]);
                    dVar37 = (double)(local_1b8 - pfVar30[2]);
                    dVar36 = (double)(float)(in_f23 - (double)pfVar30[3]);
                    dVar33 = (double)(float)((double)(float)(dVar36 * dVar36 +
                                                            (double)(float)(dVar38 * dVar38 +
                                                                           (double)(float)(dVar37 * 
                                                  dVar37))) - in_f22);
                    dVar35 = (double)(float)(dVar36 * in_f19 +
                                            (double)(float)(dVar38 * in_f21 +
                                                           (double)(float)(dVar37 * in_f20)));
                    if ((dVar35 <= (double)lbl_803DF590) || (dVar33 <= (double)lbl_803DF590)) {
                      dVar33 = (double)(float)(dVar35 * dVar35 - (double)(float)(in_f18 * dVar33));
                      if (((double)lbl_803DF590 <= dVar33) &&
                         ((dVar34 = (double)(float)(in_f18 + dVar35),
                          (double)lbl_803DF590 <= dVar34 ||
                          ((double)(float)(dVar34 * dVar34) <= dVar33)))) {
                        unaff_r26 = 1;
                        dVar32 = sqrtf(dVar33);
                        dVar32 = (double)(local_1c8 * -(float)(dVar35 + dVar32));
                        dVar41 = (double)(float)(in_f21 * dVar32 + dVar38);
                        dVar40 = (double)(float)(in_f20 * dVar32 + dVar37);
                        dVar39 = (double)(float)(in_f19 * dVar32 + dVar36);
                        dVar32 = (double)(float)(dVar39 * dVar39 +
                                                (double)(float)(dVar41 * dVar41 +
                                                               (double)(float)(dVar40 * dVar40)));
                      }
                    }
                  }
                }
                if ((unaff_r26 != 0) && (iVar16 < 0x40)) {
                  if (cVar19 == '\0') {
                    in_f22 = sqrtf((double)(float)(dVar39 * dVar39 +
                                                         (double)(float)(dVar41 * dVar41 +
                                                                        (double)(float)(dVar40 * 
                                                  dVar40))));
                    if ((double)lbl_803DF590 < in_f22) {
                      dVar41 = (double)(float)(dVar41 / in_f22);
                      dVar40 = (double)(float)(dVar40 / in_f22);
                      dVar39 = (double)(float)(dVar39 / in_f22);
                    }
                    dVar33 = (double)*pfVar30;
                    pfVar29[2] = (float)(dVar41 * dVar33);
                    pfVar29[3] = (float)(dVar40 * dVar33);
                    pfVar29[4] = (float)(dVar39 * dVar33);
                  }
                  else if ((double)lbl_803DF590 < dVar32) {
                    dVar33 = sqrtf(in_f22);
                    dVar32 = sqrtf(dVar32);
                    in_f22 = (double)lbl_803DF590;
                    if (in_f22 < dVar33) {
                      in_f22 = (double)(float)((double)(float)(dVar33 - dVar32) / dVar33);
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
            if (cVar18 == '\0') {
              if ((cVar19 != '\0') && (local_1c4 < pfVar26[5])) {
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
              ObjHits_RecordPositionHit((double)(local_188[unaff_r26 * 4 + 1] + pfVar26[2]),(double)fVar2,
                           (double)(local_188[unaff_r26 * 4 + 3] + pfVar26[4]),iVar15,iVar14,
                           *(char *)(local_198 + 0x6e),*(undefined *)(local_198 + 0x6f),
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
      if ((cVar18 == '\0') || (local_1a8 == 0)) {
        if ((cVar19 != '\0') && ((lbl_803DF590 < local_1c4 && (iVar14 == param_11)))) {
          ObjHits_RecordObjectHit(iVar15,iVar14,*(char *)(local_198 + 0x6c),*(undefined *)(local_198 + 0x6d),
                       (char)unaff_r26);
          ObjHits_RecordObjectHit(iVar14,iVar15,*(char *)(iVar24 + 0x6c),*(undefined *)(iVar24 + 0x6d),
                       (char)unaff_r27);
          ObjHits_ApplyPairResponse(-(double)local_1bc,(double)lbl_803DF590,-(double)local_1c0,
                                    iVar14,iVar15,0);
        }
      }
      else {
        if (((*(ushort *)(iVar25 + 0x60) & 0x80) != 0) &&
           (iVar14 = *(int *)(iVar14 + 0x54), iVar14 != 0)) {
          *(ushort *)(iVar14 + 0x60) = *(ushort *)(iVar14 + 0x60) & 0xfffe;
        }
        if (((*(ushort *)(iVar24 + 0x60) & 0x80) != 0) &&
           (iVar14 = *(int *)(iVar15 + 0x54), iVar14 != 0)) {
          *(ushort *)(iVar14 + 0x60) = *(ushort *)(iVar14 + 0x60) & 0xfffe;
        }
      }
    }
  }
LAB_80033418:
  FUN_80286858();
  return (u8)local_1a8;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: fn_800333C8
 * EN v1.0 Address: 0x800333C8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800334C0
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_800333C8(void)
{
  return;
}

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
void ObjHits_CheckObjectHitVolumes(undefined8 param_1,double param_2,undefined8 param_3,
                                   undefined8 param_4,undefined8 param_5,undefined8 param_6,
                                   undefined8 param_7,undefined8 param_8,undefined4 param_9,
                                   undefined4 param_10,int param_11,int param_12)
{
  int iVar1;
  char cVar2;
  int iVar3;
  undefined4 in_r10;
  int iVar4;
  int iVar5;
  uint uVar6;
  int *piVar7;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  undefined8 extraout_f1_01;
  undefined8 extraout_f1_02;
  undefined8 uVar8;

  uVar8 = FUN_80286828();
  iVar1 = (int)((ulonglong)uVar8 >> 0x20);
  iVar3 = (int)uVar8;
  iVar5 = *(int *)(iVar1 + 0x54);
  iVar4 = *(int *)(iVar3 + 0x54);
  cVar2 = '\0';
  uVar8 = extraout_f1;
  if ((*(int *)(iVar5 + 0x48) != 0) && (*(char *)(iVar5 + 0x70) == '\0')) {
    if (*(short *)(iVar1 + 0x44) == 1) {
      piVar7 = *(int **)(*(int *)(iVar1 + 0x7c) + *(char *)(iVar1 + 0xad) * 4);
      uVar6 = *(ushort *)(piVar7 + 6) >> 2 & 1;
      if ((*(ushort *)(iVar5 + 0x60) & 0x2000) == 0) {
        memcpy(DAT_803dd850,piVar7[uVar6 + 0x12],(uint)*(byte *)(*piVar7 + 0xf7) << 4);
        uVar8 = memcpy(uRam803dd854,piVar7[(uVar6 ^ 1) + 0x12],
                             (uint)*(byte *)(*piVar7 + 0xf7) << 4);
      }
      else {
        memcpy(piVar7[uVar6 + 0x12],DAT_803dd850,(uint)*(byte *)(*piVar7 + 0xf7) << 4);
        uVar8 = memcpy(piVar7[(uVar6 ^ 1) + 0x12],uRam803dd854,
                             (uint)*(byte *)(*piVar7 + 0xf7) << 4);
      }
      if (param_11 != 0) {
        piVar7 = *(int **)(*(int *)(param_11 + 0x7c) + *(char *)(param_11 + 0xad) * 4);
        uVar6 = *(ushort *)(piVar7 + 6) >> 2 & 1;
        if ((*(ushort *)(iVar5 + 0x60) & 0x2000) == 0) {
          memcpy(DAT_803dd848,piVar7[uVar6 + 0x12],(uint)*(byte *)(*piVar7 + 0xf7) << 4);
          uVar8 = memcpy(uRam803dd84c,piVar7[(uVar6 ^ 1) + 0x12],
                               (uint)*(byte *)(*piVar7 + 0xf7) << 4);
          *(ushort *)(iVar5 + 0x60) = *(ushort *)(iVar5 + 0x60) | 0x2000;
        }
        else {
          memcpy(piVar7[uVar6 + 0x12],DAT_803dd848,(uint)*(byte *)(*piVar7 + 0xf7) << 4);
          uVar8 = memcpy(piVar7[(uVar6 ^ 1) + 0x12],uRam803dd84c,
                               (uint)*(byte *)(*piVar7 + 0xf7) << 4);
        }
      }
    }
    uVar6 = *(uint *)(iVar5 + 0x48) >> 4;
    if (uVar6 != 0) {
      cVar2 = ObjHits_CheckHitVolumes(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                      iVar1,iVar3,iVar1,1,0,uVar6,
                                      *(uint *)(iVar5 + 0x4c) >> 4,in_r10);
      uVar8 = extraout_f1_00;
    }
    if (((param_11 != 0) && (cVar2 == '\0')) && (uVar6 = *(uint *)(iVar5 + 0x48) & 0xf, uVar6 != 0))
    {
      cVar2 = ObjHits_CheckHitVolumes(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                      param_11,iVar3,iVar1,1,0,uVar6,
                                      *(uint *)(iVar5 + 0x4c) & 0xf,in_r10);
      uVar8 = extraout_f1_01;
    }
    if ((cVar2 == '\0') && (*(short *)(iVar1 + 0x44) == 1)) {
      fn_800333C8();
    }
  }
  cVar2 = '\0';
  if ((((*(byte *)(iVar4 + 0xb4) & 0x80) == 0) && (*(int *)(iVar4 + 0x48) != 0)) &&
     (*(char *)(iVar4 + 0x70) == '\0')) {
    if (*(short *)(iVar3 + 0x44) == 1) {
      piVar7 = *(int **)(*(int *)(iVar3 + 0x7c) + *(char *)(iVar3 + 0xad) * 4);
      uVar6 = *(ushort *)(piVar7 + 6) >> 2 & 1;
      if ((*(ushort *)(iVar4 + 0x60) & 0x2000) == 0) {
        memcpy(DAT_803dd850,piVar7[uVar6 + 0x12],(uint)*(byte *)(*piVar7 + 0xf7) << 4);
        uVar8 = memcpy(uRam803dd854,piVar7[(uVar6 ^ 1) + 0x12],
                             (uint)*(byte *)(*piVar7 + 0xf7) << 4);
      }
      else {
        memcpy(piVar7[uVar6 + 0x12],DAT_803dd850,(uint)*(byte *)(*piVar7 + 0xf7) << 4);
        uVar8 = memcpy(piVar7[(uVar6 ^ 1) + 0x12],uRam803dd854,
                             (uint)*(byte *)(*piVar7 + 0xf7) << 4);
      }
      if (param_12 != 0) {
        piVar7 = *(int **)(*(int *)(param_12 + 0x7c) + *(char *)(param_12 + 0xad) * 4);
        uVar6 = *(ushort *)(piVar7 + 6) >> 2 & 1;
        if ((*(ushort *)(iVar4 + 0x60) & 0x2000) == 0) {
          memcpy(DAT_803dd848,piVar7[uVar6 + 0x12],(uint)*(byte *)(*piVar7 + 0xf7) << 4);
          uVar8 = memcpy(uRam803dd84c,piVar7[(uVar6 ^ 1) + 0x12],
                               (uint)*(byte *)(*piVar7 + 0xf7) << 4);
          *(ushort *)(iVar4 + 0x60) = *(ushort *)(iVar4 + 0x60) | 0x2000;
        }
        else {
          memcpy(piVar7[uVar6 + 0x12],DAT_803dd848,(uint)*(byte *)(*piVar7 + 0xf7) << 4);
          uVar8 = memcpy(piVar7[(uVar6 ^ 1) + 0x12],uRam803dd84c,
                               (uint)*(byte *)(*piVar7 + 0xf7) << 4);
        }
      }
    }
    uVar6 = *(uint *)(iVar4 + 0x48) >> 4;
    if (uVar6 != 0) {
      cVar2 = ObjHits_CheckHitVolumes(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                      iVar3,iVar1,iVar3,1,0,uVar6,
                                      *(uint *)(iVar4 + 0x4c) >> 4,in_r10);
      uVar8 = extraout_f1_02;
    }
    if (((param_12 != 0) && (cVar2 == '\0')) && (uVar6 = *(uint *)(iVar4 + 0x48) & 0xf, uVar6 != 0))
    {
      cVar2 = ObjHits_CheckHitVolumes(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                      param_12,iVar1,iVar3,1,0,uVar6,
                                      *(uint *)(iVar4 + 0x4c) & 0xf,in_r10);
    }
    if ((cVar2 == '\0') && (*(short *)(iVar3 + 0x44) == 1)) {
      fn_800333C8();
    }
  }
  FUN_80286874();
  return;
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
#pragma peephole off
void ObjHits_RegisterActiveHitVolumeObject(int obj)
{
  u32 *piVar1;
  int iVar2;

  iVar2 = 0;
  piVar1 = (u32 *)gObjHitsActiveHitVolumeObjects;
  while (iVar2 < OBJHITS_ACTIVE_HIT_VOLUME_OBJECT_COUNT && *piVar1 != 0) {
    piVar1 = piVar1 + 1;
    iVar2 = iVar2 + 1;
  }
  if (iVar2 == OBJHITS_ACTIVE_HIT_VOLUME_OBJECT_COUNT) {
    gObjHitsActiveHitVolumeObjects[0] = obj;
    return;
  }
  gObjHitsActiveHitVolumeObjects[iVar2] = obj;
  return;
}
#pragma peephole reset
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
void ObjHits_ApplyPairResponse(undefined8 param_1,double param_2,double param_3,undefined4 param_4,
                               undefined4 param_5,int param_6)
{
  float fVar1;
  short *psVar2;
  uint uVar3;
  short *psVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  double dVar7;
  double extraout_f1;
  double dVar8;
  double in_f29;
  double in_f30;
  double in_f31;
  double dVar9;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar10;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84 [2];
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
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;

  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  uVar10 = FUN_80286840();
  psVar2 = (short *)((ulonglong)uVar10 >> 0x20);
  psVar4 = (short *)uVar10;
  dVar8 = extraout_f1;
  ObjContact_DispatchCallbacks();
  puVar6 = *(undefined4 **)(psVar2 + 0x2a);
  puVar5 = *(undefined4 **)(psVar4 + 0x2a);
  *(ushort *)(puVar6 + 0x18) = *(ushort *)(puVar6 + 0x18) | 8;
  *(ushort *)(puVar5 + 0x18) = *(ushort *)(puVar5 + 0x18) | 8;
  *puVar6 = (undefined4)psVar4;
  *puVar5 = (undefined4)psVar2;
  if (*(int *)(psVar2 + 0x18) == 0) {
    local_84[0] = (float)dVar8;
    local_88 = (float)param_2;
    local_8c = (float)param_3;
  }
  else {
    Obj_TransformWorldPointToLocal(dVar8,param_2,param_3,local_84,&local_88,&local_8c,*(int *)(psVar2 + 0x18));
  }
  if (*(int *)(psVar4 + 0x18) == 0) {
    local_90 = (float)dVar8;
    local_94 = (float)param_2;
    local_98 = (float)param_3;
  }
  else {
    Obj_TransformWorldPointToLocal(dVar8,param_2,param_3,&local_90,&local_94,&local_98,*(int *)(psVar4 + 0x18));
  }
  if (((psVar2[0x22] == 1) && (*(char *)((int)puVar6 + 0x6a) != '\0')) &&
     ((*(ushort *)(puVar5 + 0x18) & 0x400) == 0)) {
    *(float *)(psVar2 + 6) = *(float *)(psVar2 + 6) - local_84[0];
    *(float *)(psVar2 + 8) = *(float *)(psVar2 + 8) - local_88;
    *(float *)(psVar2 + 10) = *(float *)(psVar2 + 10) - local_8c;
    if (param_6 == 0) {
      Obj_TransformLocalPointToWorld((double)*(float *)(psVar2 + 6),(double)*(float *)(psVar2 + 8),
                   (double)*(float *)(psVar2 + 10),(float *)(psVar2 + 0xc),(float *)(psVar2 + 0xe),
                   (float *)(psVar2 + 0x10),*(int *)(psVar2 + 0x18));
    }
    else {
      *(float *)(psVar2 + 0xc) = (float)((double)*(float *)(psVar2 + 0xc) - dVar8);
      *(float *)(psVar2 + 0xe) = (float)((double)*(float *)(psVar2 + 0xe) - param_2);
      *(float *)(psVar2 + 0x10) = (float)((double)*(float *)(psVar2 + 0x10) - param_3);
    }
  }
  else if (((psVar4[0x22] == 1) && (*(char *)((int)puVar5 + 0x6a) != '\0')) &&
          ((*(ushort *)(puVar6 + 0x18) & 0x400) == 0)) {
    *(float *)(psVar4 + 6) = *(float *)(psVar4 + 6) + local_90;
    *(float *)(psVar4 + 8) = *(float *)(psVar4 + 8) + local_94;
    *(float *)(psVar4 + 10) = *(float *)(psVar4 + 10) + local_98;
    if (param_6 == 0) {
      Obj_TransformLocalPointToWorld((double)*(float *)(psVar4 + 6),(double)*(float *)(psVar4 + 8),
                   (double)*(float *)(psVar4 + 10),(float *)(psVar4 + 0xc),(float *)(psVar4 + 0xe),
                   (float *)(psVar4 + 0x10),*(int *)(psVar4 + 0x18));
    }
    else {
      *(float *)(psVar4 + 0xc) = (float)((double)*(float *)(psVar4 + 0xc) + dVar8);
      *(float *)(psVar4 + 0xe) = (float)((double)*(float *)(psVar4 + 0xe) + param_2);
      *(float *)(psVar4 + 0x10) = (float)((double)*(float *)(psVar4 + 0x10) + param_3);
    }
  }
  else if (*(char *)((int)puVar5 + 0x6a) == '\0') {
    if (*(char *)((int)puVar6 + 0x6a) != '\0') {
      *(float *)(psVar2 + 6) = *(float *)(psVar2 + 6) - local_84[0];
      *(float *)(psVar2 + 8) = *(float *)(psVar2 + 8) - local_88;
      *(float *)(psVar2 + 10) = *(float *)(psVar2 + 10) - local_8c;
      if (param_6 == 0) {
        Obj_TransformLocalPointToWorld((double)*(float *)(psVar2 + 6),(double)*(float *)(psVar2 + 8),
                     (double)*(float *)(psVar2 + 10),(float *)(psVar2 + 0xc),(float *)(psVar2 + 0xe),
                     (float *)(psVar2 + 0x10),*(int *)(psVar2 + 0x18));
      }
      else {
        *(float *)(psVar2 + 0xc) = (float)((double)*(float *)(psVar2 + 0xc) - dVar8);
        *(float *)(psVar2 + 0xe) = (float)((double)*(float *)(psVar2 + 0xe) - param_2);
        *(float *)(psVar2 + 0x10) = (float)((double)*(float *)(psVar2 + 0x10) - param_3);
      }
    }
  }
  else if (*(char *)((int)puVar6 + 0x6a) == '\0') {
    if (*(char *)((int)puVar5 + 0x6a) != '\0') {
      *(float *)(psVar4 + 6) = *(float *)(psVar4 + 6) + local_90;
      *(float *)(psVar4 + 8) = *(float *)(psVar4 + 8) + local_94;
      *(float *)(psVar4 + 10) = *(float *)(psVar4 + 10) + local_98;
      if (param_6 == 0) {
        Obj_TransformLocalPointToWorld((double)*(float *)(psVar4 + 6),(double)*(float *)(psVar4 + 8),
                     (double)*(float *)(psVar4 + 10),(float *)(psVar4 + 0xc),(float *)(psVar4 + 0xe),
                     (float *)(psVar4 + 0x10),*(int *)(psVar4 + 0x18));
      }
      else {
        *(float *)(psVar4 + 0xc) = (float)((double)*(float *)(psVar4 + 0xc) + dVar8);
        *(float *)(psVar4 + 0xe) = (float)((double)*(float *)(psVar4 + 0xe) + param_2);
        *(float *)(psVar4 + 0x10) = (float)((double)*(float *)(psVar4 + 0x10) + param_3);
      }
    }
  }
  else {
    uVar3 = getAngle();
    uStack_7c = (int)*psVar2 - (uVar3 & 0xffff);
    if (0x8000 < (int)uStack_7c) {
      uStack_7c = uStack_7c - 0xffff;
    }
    if ((int)uStack_7c < -0x8000) {
      uStack_7c = uStack_7c + 0xffff;
    }
    uVar3 = (int)*psVar4 - ((uVar3 & 0xffff) + 0x8000 & 0xffff);
    if (0x8000 < (int)uVar3) {
      uVar3 = uVar3 - 0xffff;
    }
    if ((int)uVar3 < -0x8000) {
      uVar3 = uVar3 + 0xffff;
    }
    uStack_7c = uStack_7c ^ 0x80000000;
    local_84[1] = 176.0f;
    dVar8 = (double)sin();
    uStack_74 = (uint)*(byte *)((int)puVar6 + 0x6a);
    local_78 = 0x43300000;
    uStack_6c = (uint)*(byte *)((int)puVar6 + 0x6b);
    local_70 = 0x43300000;
    dVar9 = (double)((float)((double)CONCAT44(0x43300000,uStack_74) - DOUBLE_803df5d0) *
                     (float)(dVar8 * dVar8) +
                    (float)((double)CONCAT44(0x43300000,uStack_6c) - DOUBLE_803df5d0) *
                    (lbl_803DF598 - (float)(dVar8 * dVar8)));
    uStack_64 = uVar3 ^ 0x80000000;
    local_68 = 0x43300000;
    dVar8 = (double)sin();
    uStack_5c = (uint)*(byte *)((int)puVar5 + 0x6a);
    local_60 = 0x43300000;
    uStack_54 = (uint)*(byte *)((int)puVar5 + 0x6b);
    local_58 = 0x43300000;
    dVar8 = (double)((float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803df5d0) *
                     (float)(dVar8 * dVar8) +
                    (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803df5d0) *
                    (lbl_803DF598 - (float)(dVar8 * dVar8)));
    if ((double)(float)(dVar8 * (double)lbl_803DC0B0) <= dVar9) {
      if (dVar8 < (double)(float)(dVar9 * (double)lbl_803DC0B0)) {
        dVar8 = (double)lbl_803DF590;
      }
    }
    else {
      dVar9 = (double)lbl_803DF590;
    }
    dVar7 = (double)lbl_803DF590;
    if (dVar7 < (double)(float)(dVar9 + dVar8)) {
      dVar7 = (double)(float)(dVar8 / (double)(float)(dVar9 + dVar8));
    }
    *(float *)(psVar2 + 6) = -(float)((double)local_84[0] * dVar7 - (double)*(float *)(psVar2 + 6));
    *(float *)(psVar2 + 8) = -(float)((double)local_88 * dVar7 - (double)*(float *)(psVar2 + 8));
    *(float *)(psVar2 + 10) = -(float)((double)local_8c * dVar7 - (double)*(float *)(psVar2 + 10));
    Obj_TransformLocalPointToWorld((double)*(float *)(psVar2 + 6),(double)*(float *)(psVar2 + 8),
                 (double)*(float *)(psVar2 + 10),(float *)(psVar2 + 0xc),(float *)(psVar2 + 0xe),
                 (float *)(psVar2 + 0x10),*(int *)(psVar2 + 0x18));
    fVar1 = (float)((double)lbl_803DF598 - dVar7);
    *(float *)(psVar4 + 6) = local_90 * fVar1 + *(float *)(psVar4 + 6);
    *(float *)(psVar4 + 8) = local_94 * fVar1 + *(float *)(psVar4 + 8);
    *(float *)(psVar4 + 10) = local_98 * fVar1 + *(float *)(psVar4 + 10);
    Obj_TransformLocalPointToWorld((double)*(float *)(psVar4 + 6),(double)*(float *)(psVar4 + 8),
                 (double)*(float *)(psVar4 + 10),(float *)(psVar4 + 0xc),(float *)(psVar4 + 0xe),
                 (float *)(psVar4 + 0x10),*(int *)(psVar4 + 0x18));
  }
  FUN_8028688c();
  return;
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
void ObjHits_DetectObjectPair(void)
{
  byte bVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  bool bVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  int iVar15;
  double dVar16;
  double dVar17;
  double dVar18;
  double dVar19;
  double dVar20;
  double dVar21;
  double dVar22;
  double dVar23;
  double dVar24;
  undefined8 uVar25;
  undefined8 local_b0;
  
  uVar25 = FUN_80286840();
  iVar10 = (int)((ulonglong)uVar25 >> 0x20);
  iVar12 = (int)uVar25;
  iVar15 = *(int *)(iVar10 + 0x54);
  iVar14 = *(int *)(iVar12 + 0x54);
  if ((*(char *)(iVar15 + 0xae) != '\0') || (*(char *)(iVar14 + 0xae) != '\0')) goto LAB_800344f4;
  dVar23 = (double)(*(float *)(iVar12 + 0x18) - *(float *)(iVar10 + 0x18));
  dVar18 = (double)*(float *)(iVar12 + 0x1c);
  dVar17 = (double)*(float *)(iVar10 + 0x1c);
  dVar22 = (double)(float)(dVar18 - dVar17);
  dVar21 = (double)(*(float *)(iVar12 + 0x20) - *(float *)(iVar10 + 0x20));
  dVar24 = (double)(float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar15 + 0x5a) ^ 0x80000000)
                          - DOUBLE_803df5c0);
  local_b0 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar14 + 0x5a) ^ 0x80000000);
  dVar20 = (double)(float)(local_b0 - DOUBLE_803df5c0);
  bVar9 = false;
  bVar1 = *(byte *)(iVar14 + 0x62);
  if (((bVar1 & 2) != 0) || ((*(byte *)(iVar15 + 0x62) & 2) != 0)) {
    if (dVar22 <= (double)lbl_803DF590) {
      dVar22 = dVar20;
      if ((bVar1 & 2) != 0) {
        local_b0 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar14 + 0x5e) ^ 0x80000000);
        dVar22 = (double)(float)(local_b0 - DOUBLE_803df5c0);
      }
      if ((*(byte *)(iVar15 + 0x62) & 2) == 0) {
        dVar17 = dVar17 - dVar24;
      }
      else {
        dVar17 = dVar17 + (double)(float)((double)CONCAT44(0x43300000,
                                                           (int)*(short *)(iVar15 + 0x5c) ^
                                                           0x80000000) - DOUBLE_803df5c0);
      }
      if ((float)(dVar18 + dVar22) < (float)dVar17) goto LAB_800344f4;
    }
    else {
      dVar22 = dVar24;
      if ((*(byte *)(iVar15 + 0x62) & 2) != 0) {
        local_b0 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar15 + 0x5e) ^ 0x80000000);
        dVar22 = (double)(float)(local_b0 - DOUBLE_803df5c0);
      }
      if ((bVar1 & 2) == 0) {
        dVar18 = dVar18 - dVar20;
      }
      else {
        dVar18 = dVar18 + (double)(float)((double)CONCAT44(0x43300000,
                                                           (int)*(short *)(iVar14 + 0x5c) ^
                                                           0x80000000) - DOUBLE_803df5c0);
      }
      if ((float)(dVar17 + dVar22) < (float)dVar18) goto LAB_800344f4;
    }
    dVar22 = (double)lbl_803DF590;
    bVar9 = true;
  }
  dVar18 = (double)(float)(dVar21 * dVar21 +
                          (double)(float)(dVar23 * dVar23 + (double)(float)(dVar22 * dVar22)));
  if (dVar18 != (double)lbl_803DF590) {
    dVar18 = sqrtf(dVar18);
  }
  iVar11 = (int)((double)CONCAT44(0x43300000,(int)dVar18 ^ 0x80000000) - DOUBLE_803df5c0);
  iVar13 = iVar11;
  if (0x400 < iVar11) {
    iVar13 = 0x400;
  }
  if (iVar13 <= *(short *)(iVar15 + 0x58)) {
    *(short *)(iVar15 + 0x58) = (short)iVar13;
  }
  if (0x400 < iVar11) {
    iVar11 = 0x400;
  }
  if (iVar11 <= *(short *)(iVar14 + 0x58)) {
    *(short *)(iVar14 + 0x58) = (short)iVar11;
  }
  if ((*(ushort *)(iVar14 + 0x60) & 1) != 0) {
    dVar17 = (double)(float)(dVar20 + dVar24);
    fVar2 = *(float *)(iVar15 + 0x1c);
    fVar5 = *(float *)(iVar10 + 0x18) - fVar2;
    fVar3 = *(float *)(iVar15 + 0x20);
    fVar4 = *(float *)(iVar15 + 0x24);
    fVar7 = *(float *)(iVar10 + 0x20) - fVar4;
    fVar6 = *(float *)(iVar10 + 0x1c) - fVar3;
    if (bVar9) {
      fVar6 = lbl_803DF590;
    }
    fVar8 = fVar7 * fVar7 + fVar5 * fVar5 + fVar6 * fVar6;
    if (lbl_803DF598 < fVar8) {
      fVar8 = (fVar7 * (*(float *)(iVar12 + 0x20) - fVar4) +
              fVar5 * (*(float *)(iVar12 + 0x18) - fVar2) +
              fVar6 * (*(float *)(iVar12 + 0x1c) - fVar3)) / fVar8;
      if ((lbl_803DF590 <= fVar8) && (fVar8 <= lbl_803DF598)) {
        fVar4 = (fVar8 * fVar7 + fVar4) - *(float *)(iVar12 + 0x20);
        fVar5 = (fVar8 * fVar5 + fVar2) - *(float *)(iVar12 + 0x18);
        fVar2 = (fVar8 * fVar6 + fVar3) - *(float *)(iVar12 + 0x1c);
        dVar18 = sqrtf((double)(fVar4 * fVar4 + fVar5 * fVar5 + fVar2 * fVar2));
      }
    }
    if ((dVar18 < dVar17) && ((double)lbl_803DF590 < dVar18)) {
      ObjHits_RecordObjectHit(iVar12,iVar10,*(char *)(iVar15 + 0x6c),*(undefined *)(iVar15 + 0x6d),0);
      ObjHits_RecordObjectHit(iVar10,iVar12,*(char *)(iVar14 + 0x6c),*(undefined *)(iVar14 + 0x6d),0);
      if (((*(ushort *)(iVar14 + 0x60) & 2) == 0) && ((*(ushort *)(iVar15 + 0x60) & 2) == 0)) {
        dVar20 = (double)(*(float *)(iVar14 + 0x1c) - *(float *)(iVar15 + 0x1c));
        dVar24 = (double)(*(float *)(iVar14 + 0x24) - *(float *)(iVar15 + 0x24));
        fVar2 = *(float *)(iVar14 + 0x20) - *(float *)(iVar15 + 0x20);
        if (bVar9) {
          fVar2 = lbl_803DF590;
        }
        dVar19 = (double)fVar2;
        dVar16 = sqrtf((double)(float)(dVar24 * dVar24 +
                                             (double)(float)(dVar20 * dVar20 +
                                                            (double)(float)(dVar19 * dVar19))));
        if (dVar16 <= (double)lbl_803DF590) {
          dVar20 = dVar23 / dVar18;
          dVar19 = dVar22 / dVar18;
          dVar24 = dVar21 / dVar18;
        }
        else {
          dVar20 = dVar20 / dVar16;
          dVar19 = dVar19 / dVar16;
          dVar24 = dVar24 / dVar16;
        }
        fVar2 = (float)(dVar17 - dVar18);
        ObjHits_ApplyPairResponse((double)((float)dVar20 * fVar2),(double)((float)dVar19 * fVar2),
                                  (double)((float)dVar24 * fVar2),iVar10,iVar12,0);
      }
    }
  }
LAB_800344f4:
  FUN_8028688c();
  return;
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
static void ObjHits_CheckSkeletonPairInner(undefined4 param_1, undefined4 param_2, int *param_3,
                                           int recursionDepth) {
  byte bVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  int iVar7;
  int *piVar8;
  int iVar9;
  double dVar10;
  double dVar11;
  undefined8 uVar12;
  int local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  
  uVar12 = FUN_80286840();
  iVar5 = (int)((ulonglong)uVar12 >> 0x20);
  iVar7 = (int)uVar12;
  iVar9 = *(int *)(iVar7 + 0x54);
  if ((((*(char *)(*(int *)(iVar5 + 0x54) + 0xaf) == '\0') && (*(char *)(iVar9 + 0xaf) == '\0'))
      && (*(char *)(iVar9 + 0xae) == '\0')) && (*(char *)(*(int *)(iVar5 + 0x54) + 0xae) == '\0'))
  {
    piVar8 = *(int **)(*(int *)(iVar5 + 0x7c) + *(char *)(iVar5 + 0xad) * 4);
    bVar1 = *(byte *)(iVar9 + 0x62);
    if ((bVar1 & 1) == 0) {
      if ((bVar1 & 2) == 0) {
        if (((bVar1 & 0x20) != 0) && (recursionDepth < 1)) {
          ObjHits_CheckSkeletonPairInner(iVar7, iVar5, param_3, recursionDepth + 1);
        }
      } else {
        local_60 = *(float *)(iVar7 + 0x18) - playerMapOffsetX;
        local_5c = *(float *)(iVar7 + 0x1c);
        local_58 = *(float *)(iVar7 + 0x20) - playerMapOffsetZ;
        uStack_2c = (int)*(short *)(iVar9 + 0x5a) ^ 0x80000000;
        local_30 = 0x43300000;
        uStack_24 = (int)*(short *)(iVar9 + 0x5e) ^ 0x80000000;
        local_28 = 0x43300000;
        uStack_1c = (int)*(short *)(iVar9 + 0x5c) ^ 0x80000000;
        local_20 = 0x43300000;
        local_3c = local_60;
        local_38 = local_5c;
        local_34 = local_58;
        local_68 = 0;
        ObjHits_CollectSkeletonHitsXZ(
            (double)(float)((double)CONCAT44(0x43300000, uStack_2c) - DOUBLE_803df5c0),
            (double)(local_5c +
                     (float)((double)CONCAT44(0x43300000, uStack_24) - DOUBLE_803df5c0)),
            (double)(local_5c +
                     (float)((double)CONCAT44(0x43300000, uStack_1c) - DOUBLE_803df5c0)),
            (undefined4)&local_60, piVar8[5], piVar8, param_3, &local_68, &local_64);
        if (local_68 != 0) {
          dVar11 = (double)((*(float *)(iVar7 + 0xa8) * *(float *)(iVar7 + 8)) /
                            (*(float *)(iVar5 + 0xa8) * *(float *)(iVar7 + 8)));
          uStack_1c = (int)*(short *)(iVar9 + 0x5a) ^ 0x80000000;
          local_20 = 0x43300000;
          dVar10 = (double)lbl_803DF590;
          if ((dVar10 <= dVar11) && (dVar10 = dVar11, (double)lbl_803DF598 < dVar11)) {
            dVar10 = (double)lbl_803DF598;
          }
          ObjHits_CalcSkeletonResponseXZ(
              (double)(float)((double)CONCAT44(0x43300000, uStack_1c) - DOUBLE_803df5c0),dVar10,
              (double)local_64,(undefined4)&local_3c,iVar7,(int)param_3,piVar8[5],*piVar8,
              local_68,&local_48);
          fVar2 = lbl_803DF5D8;
          if ((lbl_803DF5D8 <= local_48) && (fVar2 = local_48, lbl_803DF5DC < local_48)) {
            fVar2 = lbl_803DF5DC;
          }
          fVar3 = lbl_803DF5D8;
          if ((lbl_803DF5D8 <= local_44) && (fVar3 = local_44, lbl_803DF5DC < local_44)) {
            fVar3 = lbl_803DF5DC;
          }
          fVar4 = lbl_803DF5D8;
          if ((lbl_803DF5D8 <= local_40) && (fVar4 = local_40, lbl_803DF5DC < local_40)) {
            fVar4 = lbl_803DF5DC;
          }
          local_48 = fVar2;
          local_44 = fVar3;
          local_40 = fVar4;
          ObjHits_ApplyPairResponse((double)fVar2, (double)fVar3, (double)fVar4, iVar5, iVar7, 0);
        }
      }
    } else {
      local_54 = *(float *)(iVar7 + 0x18) - playerMapOffsetX;
      local_50 = *(float *)(iVar7 + 0x1c);
      local_4c = *(float *)(iVar7 + 0x20) - playerMapOffsetZ;
      uStack_2c = (int)*(short *)(iVar9 + 0x5a) ^ 0x80000000;
      local_30 = 0x43300000;
      local_3c = local_54;
      local_38 = local_50;
      local_34 = local_4c;
      local_68 = 0;
      ObjHits_CollectSkeletonHits3D((undefined4)&local_54, piVar8[5], piVar8, param_3, &local_68,
                                    &local_64);
      if (local_68 != 0) {
        dVar11 = (double)((*(float *)(iVar7 + 0xa8) * *(float *)(iVar7 + 8)) /
                          (*(float *)(iVar5 + 0xa8) * *(float *)(iVar5 + 8)));
        uStack_2c = (int)*(short *)(iVar9 + 0x5a) ^ 0x80000000;
        local_30 = 0x43300000;
        dVar10 = (double)lbl_803DF590;
        if ((dVar10 <= dVar11) && (dVar10 = dVar11, (double)lbl_803DF598 < dVar11)) {
          dVar10 = (double)lbl_803DF598;
        }
        ObjHits_CalcSkeletonResponse3D(
            (double)(float)((double)CONCAT44(0x43300000, uStack_2c) - DOUBLE_803df5c0),dVar10,
            (double)local_64,(undefined4)&local_3c,iVar7,(int)param_3,piVar8[5],*piVar8,
            local_68,&local_48);
        fVar2 = lbl_803DF5D8;
        if ((lbl_803DF5D8 <= local_48) && (fVar2 = local_48, lbl_803DF5DC < local_48)) {
          fVar2 = lbl_803DF5DC;
        }
        fVar3 = lbl_803DF5D8;
        if ((lbl_803DF5D8 <= local_44) && (fVar3 = local_44, lbl_803DF5DC < local_44)) {
          fVar3 = lbl_803DF5DC;
        }
        fVar4 = lbl_803DF5D8;
        if ((lbl_803DF5D8 <= local_40) && (fVar4 = local_40, lbl_803DF5DC < local_40)) {
          fVar4 = lbl_803DF5DC;
        }
        local_48 = fVar2;
        local_44 = fVar3;
        local_40 = fVar4;
        ObjHits_ApplyPairResponse((double)fVar2, (double)fVar3, (double)fVar4, iVar5, iVar7, 0);
      }
    }
  }
  FUN_8028688c();
}

void ObjHits_CheckSkeletonPair(undefined4 param_1,undefined4 param_2,int *param_3)
{
  ObjHits_CheckSkeletonPairInner(param_1, param_2, param_3, 0);
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
void ObjHits_CheckTrackContact(void)
{
  uint uVar1;
  uint uVar2;
  int iVar3;
  byte bVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  undefined4 *puVar8;
  int *piVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  undefined4 *puVar13;
  int iVar14;
  int iVar15;
  int iVar16;
  undefined4 *puVar17;
  int iVar18;
  undefined *puVar19;
  undefined *puVar20;
  float *pfVar21;
  float *pfVar22;
  int iVar23;
  undefined8 uVar24;
  uint auStack_148 [6];
  float local_130 [18];
  float local_e8 [18];
  undefined auStack_a0 [64];
  float local_60 [4];
  undefined local_50 [12];
  int local_44 [5];
  undefined4 local_30;
  uint uStack_2c;
  
  uVar24 = FUN_80286830();
  iVar23 = (int)((ulonglong)uVar24 >> 0x20);
  iVar5 = (int)uVar24;
  iVar6 = *(int *)(iVar23 + 0x54);
  if (iVar5 == iVar23) {
    uVar2 = *(uint *)(iVar6 + 0x48) >> 4;
  }
  else {
    uVar2 = *(uint *)(iVar6 + 0x48) & 0xf;
  }
  if ((uVar2 != 0) && (*(char *)(iVar6 + 0x70) == '\0')) {
    iVar6 = *(int *)(iVar5 + 0x54);
    if ((*(byte *)(iVar6 + 0xb6) & 0x10) == 0) {
      local_e8[0] = *(float *)(iVar23 + 0x18);
      local_e8[1] = *(float *)(iVar23 + 0x1c);
      local_e8[2] = *(float *)(iVar23 + 0x20);
      local_130[0] = *(float *)(iVar23 + 0x8c);
      local_130[1] = *(float *)(iVar23 + 0x90);
      local_130[2] = *(float *)(iVar23 + 0x94);
      uStack_2c = (uint)*(byte *)(*(int *)(iVar23 + 0x50) + 0x8f);
      local_30 = 0x43300000;
      local_60[0] = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803df5d0);
      if (local_60[0] < lbl_803DF59C) {
        local_60[0] = lbl_803DF59C;
      }
      local_50[0] = 0xff;
      local_50[4] = 7;
      iVar23 = 1;
    }
    else {
      piVar9 = *(int **)(*(int *)(iVar5 + 0x7c) + *(char *)(iVar5 + 0xad) * 4);
      iVar12 = *piVar9;
      uVar7 = *(ushort *)(piVar9 + 6) >> 2 & 1;
      puVar13 = (undefined4 *)piVar9[uVar7 + 0x12];
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
           ((uVar2 & 1 << (int)*(char *)(iVar18 + 0x17)) != 0)) {
          uVar7 = (uint)*(ushort *)(iVar18 + 0x14);
          if (uVar7 == 0) {
            if (iVar23 < 4) {
              *(float *)((int)local_e8 + iVar16) = playerMapOffsetX + (float)puVar8[1];
              *(undefined4 *)((int)local_e8 + iVar16 + 4) = puVar8[2];
              *(float *)((int)local_e8 + iVar16 + 8) = playerMapOffsetZ + (float)puVar8[3];
              *(float *)((int)local_130 + iVar16) = playerMapOffsetX + *(float *)(iVar10 + 4);
              *(undefined4 *)((int)local_130 + iVar16 + 4) = *(undefined4 *)(iVar10 + 8);
              *(float *)((int)local_130 + iVar16 + 8) = playerMapOffsetZ + *(float *)(iVar10 + 0xc);
              *(undefined4 *)((int)local_60 + iVar15) = *puVar8;
              local_50[iVar23] = 0xff;
              local_50[iVar23 + 4] = 7;
              iVar23 = iVar23 + 1;
              iVar15 = iVar15 + 4;
              iVar16 = iVar16 + 0xc;
            }
          }
          else {
            pfVar22 = (float *)((int)local_e8 + iVar16);
            pfVar21 = (float *)((int)local_130 + iVar16);
            puVar20 = auStack_a0 + iVar15;
            puVar19 = auStack_a0 + iVar23;
            for (; uVar7 != 0; uVar7 = (uVar7 & 0xfff) << 4) {
              uVar1 = ((int)(uVar7 & 0xf000) >> 0xc) + iVar11 & 0xffff;
              if (iVar23 < 4) {
                puVar17 = puVar13 + uVar1 * 4;
                *pfVar22 = playerMapOffsetX + (float)puVar17[1];
                pfVar22[1] = (float)puVar17[2];
                pfVar22[2] = playerMapOffsetZ + (float)puVar17[3];
                iVar18 = iVar14 + uVar1 * 0x10;
                *pfVar21 = playerMapOffsetX + *(float *)(iVar18 + 4);
                pfVar21[1] = *(float *)(iVar18 + 8);
                pfVar21[2] = playerMapOffsetZ + *(float *)(iVar18 + 0xc);
                *(undefined4 *)(puVar20 + 0x40) = *puVar17;
                puVar19[0x50] = 0xff;
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
        }
        iVar3 = iVar3 + 0x18;
        puVar8 = puVar8 + 4;
        iVar10 = iVar10 + 0x10;
      }
    }
    if (iVar23 != 0) {
      trackDolphin_buildSweptBounds(auStack_148,local_130,local_e8,local_60,iVar23);
      FUN_80063a74(iVar5,auStack_148,(uint)*(ushort *)(iVar6 + 0xb2),'\x01');
      bVar4 = FUN_80063a68();
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
        *(undefined *)(iVar6 + 0xac) = local_50[iVar23];
        *(float *)(iVar6 + 0x3c) = local_e8[iVar23 * 3];
        *(float *)(iVar6 + 0x40) = local_e8[iVar23 * 3 + 1];
        *(float *)(iVar6 + 0x44) = local_e8[iVar23 * 3 + 2];
        if (local_44[iVar23] == 0) {
          *(byte *)(iVar6 + 0xad) = *(byte *)(iVar6 + 0xad) | 1;
        }
        else {
          *(byte *)(iVar6 + 0xad) = *(byte *)(iVar6 + 0xad) | 2;
        }
      }
    }
  }
  FUN_8028687c();
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
void ObjHits_Update(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                    undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  int attachedObj;
  ObjHitsSweepEntry *candidateEntry;
  ObjHitsSweepEntry **entrySlot;
  int candidateObj;
  int obj;
  int currentIndex;
  int candidateIndex;
  int objState;
  int slotCount;
  int slotIndex;
  int attachedState;
  int objectCount;
  int candidateAttachedObj;
  int *objectList;
  bool broadphaseActive;
  bool canHit;
  bool canOverlap;
  bool hasPrimaryMask;
  bool hasSecondaryMask;
  bool shouldProcess;
  double dVar17;
  float fVar11;
  ObjHitsSweepEntry *nextEntry;
  ObjHitsSweepEntry *sweepEntries;
  ObjHitsSweepEntry **sweepPtrs;
  undefined4 uStack_f28;
  undefined4 auStack_f24[51];
  int aiStack_e58[918];
  
  objectCount = FUN_80286820();
  objectList = (int *)ObjList_GetObjects(&uStack_f28, auStack_f24);
  sweepPtrs = (ObjHitsSweepEntry **)&DAT_80341558;
  sweepEntries = (ObjHitsSweepEntry *)&DAT_80341b98;
  nextEntry = (ObjHitsSweepEntry *)&DAT_80341ba4;
  sweepEntries->maxX = lbl_803DF5E0;
  sweepEntries->minX = lbl_803DF5E0;
  sweepPtrs[0] = sweepEntries;
  slotCount = 1;
  entrySlot = (ObjHitsSweepEntry **)&DAT_8034155c;
  if (0 < objectCount) {
    do {
      obj = *objectList;
      objState = *(int *)(obj + 0x54);
      if (objState != 0) {
        if ((((*(ushort *)(objState + 0x60) & 3) != 0) && (*(char *)(objState + 0x62) != '\b')) &&
            (slotCount < 400)) {
          *entrySlot = nextEntry;
          (*entrySlot)->obj = obj;
          (*entrySlot)->minX = *(float *)(obj + 0x18) - *(float *)(objState + 0x38);
          nextEntry++;
          entrySlot++;
          sweepPtrs[slotCount]->maxX = *(float *)(obj + 0x18) + *(float *)(objState + 0x38);
          slotCount++;
        }
        *(ushort *)(objState + 0x60) = *(ushort *)(objState + 0x60) & 0xfff7;
        *(undefined *)(objState + 0xad) = 0;
        *(undefined *)(objState + 0xac) = 0xff;
        *(undefined4 *)objState = 0;
        attachedObj = *(int *)(obj + 0xc8);
        if ((attachedObj != 0) && (*(short *)(attachedObj + 0x44) == 0x2d)) {
          attachedState = *(int *)(attachedObj + 0x54);
          *(ushort *)(attachedState + 0x60) = *(ushort *)(attachedState + 0x60) & 0xfff7;
          *(undefined *)(attachedState + 0xad) = 0;
          *(undefined *)(attachedState + 0xac) = 0xff;
          *(undefined4 *)attachedState = 0;
        }
      }
      objectList++;
      objectCount--;
    } while (objectCount != 0);
  }
  ObjHits_SortSweepEntries((int)&DAT_80341558, slotCount);
  currentIndex = 1;
  slotIndex = 1;
  entrySlot = (ObjHitsSweepEntry **)&DAT_8034155c;
  do {
    if (slotCount <= slotIndex) {
      entrySlot = (ObjHitsSweepEntry **)&DAT_8034155c;
      for (currentIndex = 1; currentIndex < slotCount; currentIndex++) {
        obj = (*entrySlot)->obj;
        if (((*(ushort *)(*(int *)(obj + 0x54) + 0x60) & 0x200) != 0) &&
            (ObjHits_CheckTrackContact(), *(int *)(obj + 0xc8) != 0)) {
          ObjHits_CheckTrackContact();
        }
        entrySlot++;
      }
      entrySlot = (ObjHitsSweepEntry **)&DAT_8034155c;
      for (currentIndex = 1; currentIndex < slotCount; currentIndex++) {
        obj = (*entrySlot)->obj;
        objState = *(int *)(obj + 0x54);
        *(undefined4 *)(objState + 0x10) = *(undefined4 *)(obj + 0xc);
        *(undefined4 *)(objState + 0x14) = *(undefined4 *)(obj + 0x10);
        *(undefined4 *)(objState + 0x18) = *(undefined4 *)(obj + 0x14);
        if (*(int *)(obj + 0x30) == 0) {
          *(undefined4 *)(objState + 0x1c) = *(undefined4 *)(obj + 0xc);
          *(undefined4 *)(objState + 0x20) = *(undefined4 *)(obj + 0x10);
          *(undefined4 *)(objState + 0x24) = *(undefined4 *)(obj + 0x14);
        } else {
          Obj_TransformLocalPointToWorld((double)*(float *)(objState + 0x10), (double)*(float *)(objState + 0x14),
                       (double)*(float *)(objState + 0x18), (float *)(objState + 0x1c),
                       (float *)(objState + 0x20), (float *)(objState + 0x24),
                       *(int *)(obj + 0x30));
        }
        *(undefined *)(objState + 0xae) = 0;
        *(ushort *)(objState + 0x60) = *(ushort *)(objState + 0x60) & 0xdfff;
        if ((((*(char *)(objState + 0x71) != '\0') || ((*(ushort *)(objState + 0x60) & 8) != 0)) &&
            ((*(ushort *)(objState + 0x60) & 0x40) == 0)) &&
            ((*(ushort *)(objState + 0x60) & 0x4000) == 0)) {
          *(float *)(obj + 0x24) = lbl_803DC078 * (*(float *)(obj + 0xc) - *(float *)(obj + 0x80));
          *(float *)(obj + 0x2c) = lbl_803DC078 * (*(float *)(obj + 0x14) - *(float *)(obj + 0x88));
        }
        entrySlot++;
      }
      gObjHitsActiveHitVolumeObjects[0] = 0;
      gObjHitsActiveHitVolumeObjects[1] = 0;
      gObjHitsActiveHitVolumeObjects[2] = 0;
      gObjHitsActiveHitVolumeObjects[3] = 0;
      gObjHitsActiveHitVolumeObjects[4] = 0;
      FUN_8028686c();
      return;
    }
    obj = (*entrySlot)->obj;
    objState = *(int *)(obj + 0x54);
    attachedObj = *(int *)(obj + 0xc8);
    if ((attachedObj != 0) &&
        ((*(int *)(attachedObj + 0x54) == 0) || ((*(ushort *)(*(int *)(attachedObj + 0x54) + 0x60) & 1) == 0)))
    {
      attachedObj = 0;
    }
    if ((*(ushort *)(objState + 0x60) & 4) != 0) {
      candidateIndex = currentIndex;
      while ((candidateIndex < slotCount) && (sweepPtrs[candidateIndex]->maxX < (*entrySlot)->minX)) {
        candidateIndex++;
      }
      currentIndex = candidateIndex;
      while (candidateIndex < slotCount) {
        candidateEntry = sweepPtrs[candidateIndex];
        if ((*entrySlot)->maxX <= candidateEntry->minX) {
          break;
        }
        candidateObj = candidateEntry->obj;
        attachedState = *(int *)(candidateObj + 0x54);
        if ((slotIndex != candidateIndex) && (*(int *)(obj + 0x30) != candidateObj)) {
          dVar17 = (double)(*(float *)(obj + 0x20) - *(float *)(candidateObj + 0x20));
          if (dVar17 <= (double)lbl_803DF590) {
            dVar17 = -dVar17;
          }
          if (dVar17 < (double)(*(float *)(objState + 0x2c) + *(float *)(attachedState + 0x2c))) {
            dVar17 = (double)(*(float *)(obj + 0x1c) - *(float *)(candidateObj + 0x1c));
            if (dVar17 <= (double)lbl_803DF590) {
              dVar17 = -dVar17;
            }
            canOverlap = dVar17 < (double)(*(float *)(objState + 0x28) + *(float *)(attachedState + 0x28));
            broadphaseActive = ((*(ushort *)(objState + 0x60) & 0x40) == 0) &&
                               ((*(ushort *)(attachedState + 0x60) & 0x40) == 0);
            shouldProcess = ((*(ushort *)(attachedState + 0x60) & 4) == 0) || (candidateIndex <= slotIndex);
            hasPrimaryMask = (*(byte *)(*(int *)(obj + 0x50) + 0x71) & *(byte *)(attachedState + 0xb5)) != 0;
            hasSecondaryMask = (*(byte *)(*(int *)(candidateObj + 0x50) + 0x71) & *(byte *)(objState + 0xb5)) != 0;
            if (canOverlap && broadphaseActive && shouldProcess && hasPrimaryMask && hasSecondaryMask) {
              if ((*(byte *)(attachedState + 0x62) & 0x20) == 0) {
                if ((*(byte *)(objState + 0x62) & 0x20) == 0) {
                  if ((*(byte *)(objState + 0x62) == 0x10) || (*(byte *)(attachedState + 0x62) == 0x10)) {
                    if ((*(char *)(objState + 0x6a) != '\0') || (*(char *)(attachedState + 0x6a) != '\0')) {
                      ObjHits_CheckHitVolumes((double)*(float *)(objState + 0x28), param_2, param_3,
                                              param_4, param_5, param_6, param_7, param_8, obj,
                                              candidateObj, obj, 0, 1, 0xffffffff, 0, 0);
                    }
                  } else if ((*(char *)(objState + 0x6a) != '\0') || (*(char *)(attachedState + 0x6a) != '\0')) {
                    ObjHits_DetectObjectPair();
                  }
                } else {
                  ObjHits_CheckSkeletonPair(obj, candidateObj, aiStack_e58);
                }
              } else {
                ObjHits_CheckSkeletonPair(candidateObj, obj, aiStack_e58);
              }
            }
            if (dVar17 < (double)(*(float *)(objState + 0x34) + *(float *)(attachedState + 0x34))) {
              param_2 = (double)(*(float *)(obj + 0x1c) - *(float *)(candidateObj + 0x1c));
              if (param_2 <= (double)lbl_803DF590) {
                param_2 = -param_2;
              }
              canHit = param_2 < (double)(*(float *)(objState + 0x30) + *(float *)(attachedState + 0x30));
              broadphaseActive = ((*(ushort *)(objState + 0x60) & 0x100) == 0) &&
                                 ((*(ushort *)(attachedState + 0x60) & 0x100) == 0);
              hasPrimaryMask = (*(byte *)(objState + 0xb4) & *(byte *)(attachedState + 0xb5)) != 0;
              hasSecondaryMask = ((*(byte *)(attachedState + 0xb4) & 0x80) != 0) ||
                                 ((*(byte *)(attachedState + 0xb4) & *(byte *)(objState + 0xb5)) != 0);
              if (canHit && broadphaseActive && hasPrimaryMask && hasSecondaryMask) {
                candidateAttachedObj = *(int *)(candidateObj + 0xc8);
                if ((candidateAttachedObj != 0) &&
                    ((*(int *)(candidateAttachedObj + 0x54) == 0) ||
                     ((*(ushort *)(*(int *)(candidateAttachedObj + 0x54) + 0x60) & 1) == 0))) {
                  candidateAttachedObj = 0;
                }
                ObjHits_CheckObjectHitVolumes((double)lbl_803DC074, param_2, param_3, param_4,
                                              param_5, param_6, param_7, param_8, obj, candidateObj,
                                              attachedObj, candidateAttachedObj);
              }
            }
          }
        }
        candidateIndex++;
      }
    }
    entrySlot++;
    slotIndex++;
  } while (true);
}
