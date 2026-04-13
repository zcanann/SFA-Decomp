// Function: FUN_8029b6fc
// Entry: 8029b6fc
// Size: 1824 bytes

/* WARNING: Removing unreachable block (ram,0x8029bdfc) */
/* WARNING: Removing unreachable block (ram,0x8029bdf4) */
/* WARNING: Removing unreachable block (ram,0x8029bdec) */
/* WARNING: Removing unreachable block (ram,0x8029b71c) */
/* WARNING: Removing unreachable block (ram,0x8029b714) */
/* WARNING: Removing unreachable block (ram,0x8029b70c) */

void FUN_8029b6fc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  float fVar1;
  float fVar2;
  short *psVar3;
  int iVar4;
  uint uVar5;
  short sVar6;
  int iVar7;
  int iVar8;
  float *in_r6;
  undefined4 *in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  int in_r10;
  int *piVar9;
  ushort uVar10;
  int iVar11;
  undefined8 extraout_f1;
  double dVar12;
  double dVar13;
  undefined8 extraout_f1_00;
  double dVar14;
  double in_f29;
  double in_f30;
  double dVar15;
  double in_f31;
  double dVar16;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar17;
  short local_78 [2];
  undefined auStack_74 [6];
  undefined2 local_6e;
  float local_6c;
  float fStack_68;
  undefined4 uStack_64;
  float afStack_60 [2];
  undefined8 local_58;
  undefined4 local_50;
  uint uStack_4c;
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
  uVar17 = FUN_8028683c();
  psVar3 = (short *)((ulonglong)uVar17 >> 0x20);
  iVar7 = (int)uVar17;
  iVar11 = *(int *)(psVar3 + 0x5c);
  iVar4 = FUN_802acf3c(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,psVar3,
                       iVar7,iVar11,in_r6,in_r7,in_r8,in_r9,in_r10);
  fVar1 = FLOAT_803e8b3c;
  if (iVar4 != 0) goto LAB_8029bdec;
  *(float *)(iVar7 + 0x294) = FLOAT_803e8b3c;
  *(float *)(iVar7 + 0x284) = fVar1;
  *(float *)(iVar7 + 0x280) = fVar1;
  *(float *)(psVar3 + 0x12) = fVar1;
  *(float *)(psVar3 + 0x14) = fVar1;
  *(float *)(psVar3 + 0x16) = fVar1;
  *(uint *)(iVar11 + 0x360) = *(uint *)(iVar11 + 0x360) | 0x2000000;
  FUN_8011f6d0(6);
  FUN_8011f6ac(10);
  if (psVar3[0x50] == 0x43e) {
    fVar1 = *(float *)(iVar7 + 0x28c) / FLOAT_803e8c40;
    fVar2 = FLOAT_803e8b64;
    if ((FLOAT_803e8b64 <= fVar1) && (fVar2 = fVar1, FLOAT_803e8b78 < fVar1)) {
      fVar2 = FLOAT_803e8b78;
    }
    dVar12 = FUN_80021434((double)(fVar2 - *(float *)(iVar11 + 0x7bc)),(double)FLOAT_803e8b94,
                          (double)FLOAT_803dc074);
    *(float *)(iVar11 + 0x7bc) = (float)((double)*(float *)(iVar11 + 0x7bc) + dVar12);
    fVar1 = *(float *)(iVar7 + 0x290) / FLOAT_803e8c40;
    fVar2 = FLOAT_803e8b64;
    if ((FLOAT_803e8b64 <= fVar1) && (fVar2 = fVar1, FLOAT_803e8b78 < fVar1)) {
      fVar2 = FLOAT_803e8b78;
    }
    dVar12 = (double)FLOAT_803dc074;
    dVar13 = FUN_80021434((double)(fVar2 - *(float *)(iVar11 + 0x7b8)),(double)FLOAT_803e8b94,dVar12
                         );
    *(float *)(iVar11 + 0x7b8) = (float)((double)*(float *)(iVar11 + 0x7b8) + dVar13);
    dVar14 = (double)*(float *)(iVar11 + 0x7b8);
    dVar13 = (double)FLOAT_803e8b3c;
    if (dVar14 <= dVar13) {
      dVar16 = (double)(float)((double)FLOAT_803e8b38 + dVar14);
      if (dVar13 < (double)(float)((double)FLOAT_803e8b38 + dVar14)) {
        dVar16 = dVar13;
      }
    }
    else {
      dVar16 = (double)(float)(dVar14 - (double)FLOAT_803e8b38);
      if ((double)(float)(dVar14 - (double)FLOAT_803e8b38) < dVar13) {
        dVar16 = dVar13;
      }
    }
    dVar14 = (double)*(float *)(iVar11 + 0x7bc);
    if (dVar14 <= (double)FLOAT_803e8b3c) {
      iVar4 = (int)((double)FLOAT_803e8c44 * -dVar14);
      local_58 = (double)(longlong)iVar4;
      FUN_8002ee64((double)FLOAT_803e8c44,dVar14,dVar12,param_4,param_5,param_6,param_7,param_8,
                   (int)psVar3,0x440,(short)iVar4);
    }
    else {
      local_58 = (double)(longlong)(int)((double)FLOAT_803e8c44 * dVar14);
      FUN_8002ee64(dVar13,dVar14,dVar12,param_4,param_5,param_6,param_7,param_8,(int)psVar3,0x441,
                   (short)(int)((double)FLOAT_803e8c44 * dVar14));
    }
    iVar4 = (int)(FLOAT_803e8c48 * *(float *)(iVar11 + 0x7b8));
    local_58 = (double)(longlong)iVar4;
    *(short *)(iVar11 + 0x4d2) = (short)iVar4;
    FUN_800396d0((int)psVar3,9);
    *(uint *)(iVar11 + 0x360) = *(uint *)(iVar11 + 0x360) & 0xfffffbff;
    if (DAT_803df132 == 0x2d) {
      dVar13 = (double)*(float *)(iVar11 + 0x7bc);
      dVar15 = (double)*(float *)(iVar11 + 0x7b8);
      uVar5 = FUN_80070050();
      dVar12 = DOUBLE_803e8b58;
      uStack_4c = (int)uVar5 >> 0x11;
      dVar14 = (double)FLOAT_803e8b30;
      uVar5 = (int)(uVar5 & 0xffff) >> 1 ^ 0x80000000;
      local_58 = (double)CONCAT44(0x43300000,uVar5);
      *(float *)(iVar11 + 0x788) =
           (float)(dVar14 * (double)(float)(dVar15 * (double)(float)(local_58 - DOUBLE_803e8b58)) +
                  (double)(float)((double)CONCAT44(0x43300000,uVar5) - DOUBLE_803e8b58));
      if ((double)FLOAT_803e8b3c <= dVar13) {
        dVar14 = (double)FLOAT_803e8bdc;
        local_58 = (double)CONCAT44(0x43300000,uStack_4c ^ 0x80000000);
        *(float *)(iVar11 + 0x78c) =
             (float)(dVar14 * (double)(float)(dVar13 * (double)(float)((double)CONCAT44(0x43300000,
                                                                                        uStack_4c ^
                                                                                        0x80000000)
                                                                      - dVar12)) +
                    (double)(float)(local_58 - dVar12));
      }
      else {
        local_58 = (double)CONCAT44(0x43300000,uStack_4c ^ 0x80000000);
        *(float *)(iVar11 + 0x78c) =
             (float)(dVar14 * (double)(float)(dVar13 * (double)(float)((double)CONCAT44(0x43300000,
                                                                                        uStack_4c ^
                                                                                        0x80000000)
                                                                      - dVar12)) +
                    (double)(float)(local_58 - dVar12));
      }
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      *(uint *)(iVar11 + 0x360) = *(uint *)(iVar11 + 0x360) | 0x400;
    }
    if (DAT_803df0ac == '\0') {
      if ((*(ushort *)(iVar11 + 0x6e2) & 0x900) != 0) {
        if ((*(ushort *)(iVar11 + 0x6e2) & 0x800) == 0) {
          sVar6 = 0;
          local_78[0] = DAT_803df132;
          uVar10 = 0x100;
        }
        else {
          sVar6 = FUN_8011f68c(local_78);
          uVar10 = 0x800;
        }
        if (((*(ushort *)(iVar11 + 0x6e2) & 0x100) != 0) ||
           ((sVar6 == 1 && ((local_78[0] == 0x2d || (local_78[0] == 0x5ce)))))) {
          uVar17 = FUN_80014b68(0,0x900);
          *(ushort *)(iVar11 + 0x6e2) = *(ushort *)(iVar11 + 0x6e2) & 0xf6ff;
          DAT_803df132 = local_78[0];
          if ((int)local_78[0] != (int)*(short *)(iVar11 + 0x80a)) {
            uVar17 = FUN_802abaec((uint)psVar3,iVar11,(int)local_78[0]);
          }
          if (DAT_803df132 == 0x5ce) {
            if (*(short *)(*(int *)(*(int *)(psVar3 + 0x5c) + 0x35c) + 4) < 1) {
              FUN_8000bb38(0,0x40c);
            }
            else {
              FUN_802a9e38(uVar17,dVar14,dVar12,param_4,param_5,param_6,param_7,param_8);
              DAT_803df0ac = '\x01';
              FLOAT_803df0b0 = FLOAT_803e8b3c;
              DAT_803df134 = uVar10;
              *(float *)(iVar11 + 0x854) = FLOAT_803e8bf0;
              iVar8 = *(int *)(*(int *)(psVar3 + 0x5c) + 0x35c);
              iVar4 = *(short *)(iVar8 + 4) + -1;
              if (iVar4 < 0) {
                iVar4 = 0;
              }
              else if (*(short *)(iVar8 + 6) < iVar4) {
                iVar4 = (int)*(short *)(iVar8 + 6);
              }
              *(short *)(iVar8 + 4) = (short)iVar4;
            }
          }
          else if (DAT_803df132 < 0x5ce) {
            if (DAT_803df132 == 0x2d) {
              if (1 < *(short *)(*(int *)(*(int *)(psVar3 + 0x5c) + 0x35c) + 4)) {
                *(code **)(iVar7 + 0x308) = FUN_8029ac08;
                goto LAB_8029bdec;
              }
              FUN_8000bb38(0,0x40c);
            }
          }
          else if (DAT_803df132 == 0x958) {
            if (-1 < *(short *)(*(int *)(*(int *)(psVar3 + 0x5c) + 0x35c) + 4)) {
              *(code **)(iVar7 + 0x308) = FUN_8029ac08;
              goto LAB_8029bdec;
            }
            FUN_8000bb38(0,0x40c);
          }
        }
      }
    }
    else {
      FUN_8000da78((uint)psVar3,0x382);
      fVar1 = *(float *)(iVar11 + 0x854) - FLOAT_803dc074;
      *(float *)(iVar11 + 0x854) = fVar1;
      if (fVar1 <= FLOAT_803e8b3c) {
        iVar8 = *(int *)(*(int *)(psVar3 + 0x5c) + 0x35c);
        iVar4 = *(short *)(iVar8 + 4) + -1;
        if (iVar4 < 0) {
          iVar4 = 0;
        }
        else if (*(short *)(iVar8 + 6) < iVar4) {
          iVar4 = (int)*(short *)(iVar8 + 6);
        }
        *(short *)(iVar8 + 4) = (short)iVar4;
        *(float *)(iVar11 + 0x854) = FLOAT_803e8bf0;
      }
      FUN_80038524(DAT_803df0cc,5,&fStack_68,&uStack_64,afStack_60,0);
      local_6c = FLOAT_803e8c34;
      local_6e = 0;
      (**(code **)(*DAT_803dd708 + 8))(DAT_803df0cc,0x7f5,auStack_74,0x200001,0xffffffff,0);
      local_6e = 1;
      uVar17 = (**(code **)(*DAT_803dd708 + 8))(DAT_803df0cc,0x7f5,auStack_74,0x200001,0xffffffff,0)
      ;
      if ((((*(ushort *)(iVar11 + 0x6e0) & DAT_803df134) == 0) ||
          (*(short *)(*(int *)(*(int *)(psVar3 + 0x5c) + 0x35c) + 4) == 0)) ||
         (iVar4 = FUN_80080490(), uVar17 = extraout_f1_00, iVar4 != 0)) {
        DAT_803df0ac = '\0';
        iVar4 = 0;
        piVar9 = &DAT_80333b34;
        do {
          if (*piVar9 != 0) {
            uVar17 = FUN_8002cc9c(uVar17,dVar14,dVar12,param_4,param_5,param_6,param_7,param_8,
                                  *piVar9);
            *piVar9 = 0;
          }
          piVar9 = piVar9 + 1;
          iVar4 = iVar4 + 1;
        } while (iVar4 < 7);
        if (DAT_803df0d4 != (undefined *)0x0) {
          FUN_80013e4c(DAT_803df0d4);
          DAT_803df0d4 = (undefined *)0x0;
        }
      }
    }
    uStack_4c = (int)*(short *)(iVar11 + 0x478) ^ 0x80000000;
    local_50 = 0x43300000;
    iVar4 = (int)((double)FLOAT_803e8c4c * dVar16 +
                 (double)(float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e8b58));
    local_58 = (double)(longlong)iVar4;
    *(short *)(iVar11 + 0x478) = (short)iVar4;
    *(short *)(iVar11 + 0x484) = *(short *)(iVar11 + 0x478);
    *psVar3 = *(short *)(iVar11 + 0x478);
  }
  else {
    FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 psVar3,0x43e,0,in_r6,in_r7,in_r8,in_r9,in_r10);
    *(float *)(iVar7 + 0x2a0) = FLOAT_803e8bcc;
    DAT_803df0ac = '\0';
    FLOAT_803df0b0 = FLOAT_803e8b3c;
  }
  if (((*(ushort *)(iVar11 + 0x6e2) & 0x200) != 0) || (*(char *)(iVar11 + 0x8c8) != 'R')) {
    *(uint *)(iVar11 + 0x360) = *(uint *)(iVar11 + 0x360) & 0xfdffffff;
    *(code **)(iVar7 + 0x308) = FUN_8029ab80;
  }
LAB_8029bdec:
  FUN_80286888();
  return;
}

