// Function: FUN_80030780
// Entry: 80030780
// Size: 1124 bytes

/* WARNING: Removing unreachable block (ram,0x80030bc4) */
/* WARNING: Removing unreachable block (ram,0x80030bbc) */
/* WARNING: Removing unreachable block (ram,0x80030bb4) */
/* WARNING: Removing unreachable block (ram,0x80030bac) */
/* WARNING: Removing unreachable block (ram,0x80030ba4) */
/* WARNING: Removing unreachable block (ram,0x80030b9c) */
/* WARNING: Removing unreachable block (ram,0x80030b94) */
/* WARNING: Removing unreachable block (ram,0x800307c0) */
/* WARNING: Removing unreachable block (ram,0x800307b8) */
/* WARNING: Removing unreachable block (ram,0x800307b0) */
/* WARNING: Removing unreachable block (ram,0x800307a8) */
/* WARNING: Removing unreachable block (ram,0x800307a0) */
/* WARNING: Removing unreachable block (ram,0x80030798) */
/* WARNING: Removing unreachable block (ram,0x80030790) */

void FUN_80030780(undefined8 param_1,double param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,int *param_6,int *param_7,int *param_8,float *param_9)

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
    *param_9 = FLOAT_803df590;
    dVar20 = extraout_f1;
    iVar6 = FUN_80028630(param_6,0);
    local_c4 = *(float *)(iVar6 + 0xc);
    local_c0 = *(float *)(iVar6 + 0x1c);
    local_bc = *(float *)(iVar6 + 0x2c);
    dVar17 = FUN_80293900((double)((local_bc - pfVar5[2]) * (local_bc - pfVar5[2]) +
                                  (local_c4 - *pfVar5) * (local_c4 - *pfVar5) + FLOAT_803df590));
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
        iVar7 = FUN_80028630(param_6,uVar13);
        local_c4 = *(float *)(iVar7 + 0xc);
        local_c0 = *(float *)(iVar7 + 0x1c);
        local_bc = *(float *)(iVar7 + 0x2c);
        iVar7 = FUN_80028630(param_6,iVar12);
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
          if (fVar4 * fVar4 + fVar3 * fVar3 + FLOAT_803df590 < fVar2 * fVar2) {
            local_dc = local_d0 - local_c4;
            local_d8 = local_cc - local_c0;
            local_d4 = local_c8 - local_bc;
            fVar3 = *(float *)(*(int *)(iVar9 + 0xc) + iVar6);
            if (fVar3 != FLOAT_803df590) {
              fVar3 = FLOAT_803df598 / fVar3;
              local_dc = local_dc * fVar3;
              local_d8 = local_d8 * fVar3;
              local_d4 = local_d4 * fVar3;
            }
            *(undefined *)(*(int *)(iVar9 + 0x18) + uVar13) = 0;
            *(undefined *)(*(int *)(iVar9 + 0x18) + iVar12) = 0;
            uVar8 = FUN_80032188(dVar20,dVar18,dVar19,
                                 (double)*(float *)(*(int *)(iVar9 + 0xc) + iVar6),pfVar5,&local_c4,
                                 &local_dc,&local_d0,&local_e0,&local_e4,&local_e8);
            if (uVar8 != 0) {
              *(undefined *)(*(int *)(iVar9 + 0x18) + uVar13) = 1;
              *(undefined *)(*(int *)(iVar9 + 0x18) + iVar12) = 1;
              dVar18 = FUN_80293900((double)local_e4);
              param_7[0xc] = (int)(float)(dVar20 + (double)(float)(dVar18 - (double)local_e8));
              if (FLOAT_803df590 == (float)param_7[0xc]) {
                param_7[0xc] = (int)FLOAT_803df5a0;
              }
              fVar3 = (float)param_7[0xc];
              if (fVar3 <= FLOAT_803df590) {
                fVar3 = -fVar3;
              }
              param_7[0xf] = (int)(FLOAT_803df598 / fVar3);
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
              dVar18 = FUN_80293900((double)local_e4);
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

