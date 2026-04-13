// Function: FUN_80030be4
// Entry: 80030be4
// Size: 988 bytes

/* WARNING: Removing unreachable block (ram,0x80030fa0) */
/* WARNING: Removing unreachable block (ram,0x80030f98) */
/* WARNING: Removing unreachable block (ram,0x80030f90) */
/* WARNING: Removing unreachable block (ram,0x80030f88) */
/* WARNING: Removing unreachable block (ram,0x80030f80) */
/* WARNING: Removing unreachable block (ram,0x80030c14) */
/* WARNING: Removing unreachable block (ram,0x80030c0c) */
/* WARNING: Removing unreachable block (ram,0x80030c04) */
/* WARNING: Removing unreachable block (ram,0x80030bfc) */
/* WARNING: Removing unreachable block (ram,0x80030bf4) */

void FUN_80030be4(undefined4 param_1,undefined4 param_2,int *param_3,int *param_4,int *param_5,
                 float *param_6)

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
    *param_6 = FLOAT_803df590;
    dVar20 = extraout_f1;
    iVar5 = FUN_80028630(param_3,0);
    local_a4 = *(float *)(iVar5 + 0xc);
    local_a0 = *(float *)(iVar5 + 0x1c);
    local_9c = *(float *)(iVar5 + 0x2c);
    dVar16 = FUN_80293900((double)((local_9c - pfVar4[2]) * (local_9c - pfVar4[2]) +
                                  (local_a4 - *pfVar4) * (local_a4 - *pfVar4) + FLOAT_803df590));
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
        iVar6 = FUN_80028630(param_3,uVar12);
        local_a4 = *(float *)(iVar6 + 0xc);
        local_a0 = *(float *)(iVar6 + 0x1c);
        local_9c = *(float *)(iVar6 + 0x2c);
        iVar6 = FUN_80028630(param_3,iVar11);
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
        if (fVar3 * fVar3 + fVar2 * fVar2 + FLOAT_803df590 < fVar1 * fVar1) {
          dVar19 = (double)*(float *)(*(int *)(iVar8 + 0xc) + iVar5);
          local_b4 = (float)((double)FLOAT_803df598 / dVar19);
          local_bc = (local_b0 - local_a4) * local_b4;
          local_b8 = (local_ac - local_a0) * local_b4;
          local_b4 = (local_a8 - local_9c) * local_b4;
          uVar7 = FUN_8003229c(dVar20,dVar17,dVar18,dVar19,pfVar4,&local_a4,&local_bc,&local_b0,
                               &local_c0,&local_c4,&local_c8);
          if (uVar7 != 0) {
            *(undefined *)(*(int *)(iVar8 + 0x18) + uVar12) = 1;
            *(undefined *)(*(int *)(iVar8 + 0x18) + iVar11) = 1;
            dVar17 = FUN_80293900((double)local_c4);
            param_4[0xc] = (int)(float)(dVar20 + (double)(float)(dVar17 - (double)local_c8));
            if (FLOAT_803df590 == (float)param_4[0xc]) {
              param_4[0xc] = (int)FLOAT_803df5a0;
            }
            fVar2 = (float)param_4[0xc];
            if (fVar2 <= FLOAT_803df590) {
              fVar2 = -fVar2;
            }
            param_4[0xf] = (int)(FLOAT_803df598 / fVar2);
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
            dVar17 = FUN_80293900((double)local_c4);
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

