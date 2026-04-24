// Function: FUN_800d68ec
// Entry: 800d68ec
// Size: 1136 bytes

/* WARNING: Removing unreachable block (ram,0x800d6d3c) */
/* WARNING: Removing unreachable block (ram,0x800d6d34) */
/* WARNING: Removing unreachable block (ram,0x800d6d2c) */
/* WARNING: Removing unreachable block (ram,0x800d6d24) */
/* WARNING: Removing unreachable block (ram,0x800d6d1c) */
/* WARNING: Removing unreachable block (ram,0x800d6d14) */
/* WARNING: Removing unreachable block (ram,0x800d6d0c) */
/* WARNING: Removing unreachable block (ram,0x800d6d04) */
/* WARNING: Removing unreachable block (ram,0x800d6cfc) */
/* WARNING: Removing unreachable block (ram,0x800d6cf4) */
/* WARNING: Removing unreachable block (ram,0x800d6944) */
/* WARNING: Removing unreachable block (ram,0x800d693c) */
/* WARNING: Removing unreachable block (ram,0x800d6934) */
/* WARNING: Removing unreachable block (ram,0x800d692c) */
/* WARNING: Removing unreachable block (ram,0x800d6924) */
/* WARNING: Removing unreachable block (ram,0x800d691c) */
/* WARNING: Removing unreachable block (ram,0x800d6914) */
/* WARNING: Removing unreachable block (ram,0x800d690c) */
/* WARNING: Removing unreachable block (ram,0x800d6904) */
/* WARNING: Removing unreachable block (ram,0x800d68fc) */

void FUN_800d68ec(void)

{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  double in_f22;
  double in_f23;
  double dVar15;
  double in_f24;
  double in_f25;
  double in_f26;
  double dVar16;
  double in_f27;
  double dVar17;
  double in_f28;
  double in_f29;
  double in_f30;
  double in_f31;
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
  undefined8 uVar18;
  int iStack_d8;
  int aiStack_d4 [3];
  undefined4 local_c8;
  uint uStack_c4;
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
  uVar18 = FUN_80286840();
  iVar3 = (int)((ulonglong)uVar18 >> 0x20);
  iVar6 = (int)uVar18;
  if (*(int *)(iVar6 + 0x18) < 0) {
    *(undefined4 *)(iVar6 + 0x1c) = 0;
    *(float *)(iVar6 + 0xc) = FLOAT_803e1168;
    if (*(int *)(iVar6 + 0x10) < 0) goto LAB_800d6cf4;
    *(int *)(iVar6 + 0x18) = *(int *)(iVar6 + 0x10);
  }
  iVar4 = FUN_800d57bc(*(uint *)(iVar6 + 0x18),&iStack_d8);
  if (iVar4 == 0) {
    *(undefined4 *)(iVar6 + 0x18) = 0xffffffff;
  }
  else {
    aiStack_d4[2] = (uint)*(byte *)(iVar4 + 0x29) << 8 ^ 0x80000000;
    aiStack_d4[1] = 0x43300000;
    dVar7 = (double)FUN_802945e0();
    uStack_c4 = (uint)*(byte *)(iVar4 + 0x29) << 8 ^ 0x80000000;
    local_c8 = 0x43300000;
    dVar8 = (double)FUN_80294964();
    dVar15 = -(double)(float)((double)*(float *)(iVar4 + 8) * dVar7 +
                             (double)(float)((double)*(float *)(iVar4 + 0x10) * dVar8));
    dVar17 = (double)(float)(dVar15 + (double)(float)(dVar7 * (double)*(float *)(iVar3 + 0xc) +
                                                     (double)(float)(dVar8 * (double)*(float *)(
                                                  iVar3 + 0x14))));
    if ((*(int *)(iVar4 + 0x18) < 0) || (dVar17 < (double)FLOAT_803e1168)) {
      if (-1 < (int)*(uint *)(iVar4 + 0x20)) {
        iVar5 = FUN_800d57bc(*(uint *)(iVar4 + 0x20),aiStack_d4);
        FUN_80021884();
        uStack_c4 = (uint)*(byte *)(iVar5 + 0x29) << 8 ^ 0x80000000;
        local_c8 = 0x43300000;
        dVar9 = (double)FUN_802945e0();
        aiStack_d4[2] = (uint)*(byte *)(iVar5 + 0x29) << 8 ^ 0x80000000;
        aiStack_d4[1] = 0x43300000;
        dVar10 = (double)FUN_80294964();
        fVar2 = FLOAT_803e1168;
        dVar13 = (double)*(float *)(iVar5 + 8);
        dVar12 = (double)*(float *)(iVar5 + 0x10);
        fVar1 = -(float)(dVar13 * dVar9 + (double)(float)(dVar12 * dVar10));
        dVar16 = (double)(fVar1 + (float)(dVar9 * (double)*(float *)(iVar3 + 0xc) +
                                         (double)(float)(dVar10 * (double)*(float *)(iVar3 + 0x14)))
                         );
        dVar11 = (double)FLOAT_803e1168;
        if (dVar11 <= dVar16) {
          dVar15 = (double)(float)(dVar15 + (double)(float)(dVar7 * dVar13 +
                                                           (double)(float)(dVar8 * dVar12)));
          dVar14 = (double)(fVar1 + (float)(dVar9 * (double)*(float *)(iVar4 + 8) +
                                           (double)(float)(dVar10 * (double)*(float *)(iVar4 + 0x10)
                                                          )));
          if ((((dVar15 < dVar11) && (dVar17 < dVar11)) ||
              (((double)FLOAT_803e1168 <= dVar15 && ((double)FLOAT_803e1168 <= dVar17)))) &&
             (((dVar14 <= (double)FLOAT_803e1168 && (dVar16 <= (double)FLOAT_803e1168)) ||
              (((double)FLOAT_803e1168 < dVar14 && ((double)FLOAT_803e1168 < dVar16)))))) {
            dVar13 = (double)(float)((double)*(float *)(iVar4 + 8) - dVar13);
            fVar1 = *(float *)(iVar4 + 0xc) - *(float *)(iVar5 + 0xc);
            dVar11 = (double)(float)((double)*(float *)(iVar4 + 0x10) - dVar12);
            dVar15 = FUN_80293900((double)(float)(dVar11 * dVar11 +
                                                 (double)(float)(dVar13 * dVar13 +
                                                                (double)(fVar1 * fVar1))));
            if ((double)FLOAT_803e1168 < dVar15) {
              in_f25 = (double)(float)(dVar13 * (double)(float)((double)FLOAT_803e1184 / dVar15));
              in_f24 = (double)(float)(dVar11 * (double)(float)((double)FLOAT_803e1184 / dVar15));
            }
            dVar7 = (double)(float)(dVar7 * in_f25 + (double)(float)(dVar8 * in_f24));
            if ((dVar7 <= (double)FLOAT_803e1190) || ((double)FLOAT_803e1194 <= dVar7)) {
              dVar8 = (double)(float)(dVar9 * in_f25 + (double)(float)(dVar10 * in_f24));
              if ((dVar8 <= (double)FLOAT_803e1190) || ((double)FLOAT_803e1194 <= dVar8)) {
                fVar1 = (float)(-dVar17 / dVar7) + (float)(dVar16 / dVar8);
                fVar2 = FLOAT_803e1168;
                if (FLOAT_803e1168 != fVar1) {
                  fVar2 = (float)(-dVar17 / dVar7) / fVar1;
                }
                *(float *)(iVar6 + 0xc) = fVar2;
                if (*(float *)(iVar6 + 0xc) < FLOAT_803e1168) {
                  *(float *)(iVar6 + 0xc) = FLOAT_803e1168;
                }
                if (FLOAT_803e1198 <= *(float *)(iVar6 + 0xc)) {
                  *(float *)(iVar6 + 0xc) = FLOAT_803e1198;
                }
              }
            }
          }
        }
        else {
          *(undefined4 *)(iVar6 + 0x18) = *(undefined4 *)(iVar4 + 0x20);
          *(float *)(iVar6 + 0xc) = fVar2;
          *(int *)(iVar6 + 0x1c) = *(int *)(iVar6 + 0x1c) + 1;
        }
      }
    }
    else {
      *(int *)(iVar6 + 0x18) = *(int *)(iVar4 + 0x18);
      *(float *)(iVar6 + 0xc) = FLOAT_803e118c;
      *(int *)(iVar6 + 0x1c) = *(int *)(iVar6 + 0x1c) + -1;
    }
  }
LAB_800d6cf4:
  FUN_8028688c();
  return;
}

