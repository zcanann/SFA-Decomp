// Function: FUN_8013ab4c
// Entry: 8013ab4c
// Size: 688 bytes

/* WARNING: Removing unreachable block (ram,0x8013addc) */

void FUN_8013ab4c(undefined4 param_1,undefined4 param_2,ushort param_3,undefined4 *param_4)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  uint uVar5;
  int iVar6;
  int *piVar7;
  int iVar8;
  float *pfVar9;
  byte bVar10;
  int iVar11;
  uint uVar12;
  int iVar13;
  uint unaff_r26;
  uint uVar14;
  int iVar15;
  int iVar16;
  undefined4 uVar17;
  undefined8 in_f31;
  double dVar18;
  undefined8 uVar19;
  float local_68 [4];
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  undefined auStack8 [8];
  
  uVar17 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar19 = FUN_802860c8();
  iVar6 = (int)((ulonglong)uVar19 >> 0x20);
  iVar11 = (int)uVar19;
  iVar13 = *(int *)(iVar6 + 0xb8);
  piVar7 = (int *)(**(code **)(*DAT_803dca9c + 0x10))(local_68);
  local_68[2] = FLOAT_803e2418;
  local_68[1] = FLOAT_803e2418;
  *param_4 = 0;
  param_4[1] = 0;
  local_68[3] = local_68[2];
  param_4[2] = 0;
  local_58 = local_68[2];
  param_4[3] = 0;
  local_54 = local_68[2];
  param_4[4] = 0;
  local_50 = local_68[2];
  param_4[5] = 0;
  local_4c = local_68[2];
  param_4[6] = 0;
  local_48 = local_68[2];
  param_4[7] = 0;
  if (param_3 != 0) {
    for (iVar16 = 0; iVar16 < (int)local_68[0]; iVar16 = iVar16 + 1) {
      iVar15 = *piVar7;
      if ((((*(char *)(iVar15 + 0x19) == '$') && (*(char *)(iVar15 + 3) == '\0')) &&
          ((*(short *)(iVar15 + 0x30) == -1 || (iVar8 = FUN_8001ffb4(), iVar8 != 0)))) &&
         (((*(short *)(iVar15 + 0x32) == -1 || (iVar8 = FUN_8001ffb4(), iVar8 == 0)) &&
          (pfVar9 = *(float **)(iVar13 + 0x28), fVar1 = pfVar9[2] - *(float *)(iVar15 + 0x10),
          fVar3 = *pfVar9 - *(float *)(iVar15 + 8),
          fVar4 = *(float *)(iVar6 + 0x18) - *(float *)(iVar15 + 8),
          fVar2 = *(float *)(iVar6 + 0x20) - *(float *)(iVar15 + 0x10),
          dVar18 = (double)(fVar1 * fVar1 + fVar3 * fVar3 + fVar4 * fVar4 + fVar2 * fVar2),
          dVar18 < (double)local_48)))) {
        for (uVar14 = 0; (uVar14 & 0xff) < 4; uVar14 = uVar14 + 1) {
          if (((-1 < *(int *)(iVar15 + (uVar14 & 0xff) * 4 + 0x1c)) &&
              (*(byte *)(iVar15 + (uVar14 & 0xff) + 4) == param_3)) &&
             ((*(char *)(iVar15 + 0x1a) != '\b' ||
              ((iVar8 = (**(code **)(*DAT_803dca9c + 0x1c))(), iVar8 == 0 ||
               (*(char *)(iVar8 + 0x1a) != '\t')))))) {
            unaff_r26 = (int)*(char *)(iVar15 + 0x1b) >> (uVar14 & 0x3f) & 0xff;
            break;
          }
        }
        if ((uVar14 & 0xff) != 4) {
          bVar10 = 0;
LAB_8013adbc:
          if (bVar10 < 8) {
            uVar14 = (uint)bVar10;
            if ((double)local_68[uVar14 + 1] <= dVar18) goto LAB_8013adb8;
            for (uVar12 = 7; uVar14 < (uVar12 & 0xff); uVar12 = uVar12 - 1) {
              uVar5 = uVar12 & 0xff;
              *(undefined *)(iVar11 + uVar5) = *(undefined *)(iVar11 + (uVar5 - 1));
              param_4[uVar5] = param_4[uVar5 - 1];
              local_68[uVar5 + 1] = local_68[uVar5];
            }
            *(byte *)(iVar11 + uVar14) = (byte)unaff_r26 & 1 ^ 1;
            param_4[uVar14] = iVar15;
            local_68[uVar14 + 1] = (float)dVar18;
          }
        }
      }
      piVar7 = piVar7 + 1;
    }
  }
  __psq_l0(auStack8,uVar17);
  __psq_l1(auStack8,uVar17);
  FUN_80286114();
  return;
LAB_8013adb8:
  bVar10 = bVar10 + 1;
  goto LAB_8013adbc;
}

