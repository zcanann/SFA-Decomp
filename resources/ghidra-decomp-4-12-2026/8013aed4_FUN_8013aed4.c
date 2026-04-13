// Function: FUN_8013aed4
// Entry: 8013aed4
// Size: 688 bytes

/* WARNING: Removing unreachable block (ram,0x8013b164) */
/* WARNING: Removing unreachable block (ram,0x8013aee4) */

void FUN_8013aed4(undefined4 param_1,undefined4 param_2,ushort param_3,undefined4 *param_4)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  uint uVar5;
  int iVar6;
  int *piVar7;
  uint uVar8;
  float *pfVar9;
  int iVar10;
  byte bVar11;
  int iVar12;
  uint uVar13;
  int iVar14;
  uint unaff_r26;
  int iVar15;
  int iVar16;
  double in_f31;
  double dVar17;
  double in_ps31_1;
  undefined8 uVar18;
  float local_68 [4];
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar18 = FUN_8028682c();
  iVar6 = (int)((ulonglong)uVar18 >> 0x20);
  iVar12 = (int)uVar18;
  iVar14 = *(int *)(iVar6 + 0xb8);
  piVar7 = (int *)(**(code **)(*DAT_803dd71c + 0x10))(local_68);
  local_68[2] = FLOAT_803e30a8;
  local_68[1] = FLOAT_803e30a8;
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
          (((int)*(short *)(iVar15 + 0x30) == 0xffffffff ||
           (uVar8 = FUN_80020078((int)*(short *)(iVar15 + 0x30)), uVar8 != 0)))) &&
         ((((int)*(short *)(iVar15 + 0x32) == 0xffffffff ||
           (uVar8 = FUN_80020078((int)*(short *)(iVar15 + 0x32)), uVar8 == 0)) &&
          (pfVar9 = *(float **)(iVar14 + 0x28), fVar1 = pfVar9[2] - *(float *)(iVar15 + 0x10),
          fVar3 = *pfVar9 - *(float *)(iVar15 + 8),
          fVar4 = *(float *)(iVar6 + 0x18) - *(float *)(iVar15 + 8),
          fVar2 = *(float *)(iVar6 + 0x20) - *(float *)(iVar15 + 0x10),
          dVar17 = (double)(fVar1 * fVar1 + fVar3 * fVar3 + fVar4 * fVar4 + fVar2 * fVar2),
          dVar17 < (double)local_48)))) {
        for (uVar8 = 0; (uVar8 & 0xff) < 4; uVar8 = uVar8 + 1) {
          if (((-1 < *(int *)(iVar15 + (uVar8 & 0xff) * 4 + 0x1c)) &&
              (*(byte *)(iVar15 + (uVar8 & 0xff) + 4) == param_3)) &&
             ((*(char *)(iVar15 + 0x1a) != '\b' ||
              ((iVar10 = (**(code **)(*DAT_803dd71c + 0x1c))(), iVar10 == 0 ||
               (*(char *)(iVar10 + 0x1a) != '\t')))))) {
            unaff_r26 = (int)*(char *)(iVar15 + 0x1b) >> (uVar8 & 0x3f) & 0xff;
            break;
          }
        }
        if ((uVar8 & 0xff) != 4) {
          bVar11 = 0;
LAB_8013b144:
          if (bVar11 < 8) {
            uVar8 = (uint)bVar11;
            if ((double)local_68[uVar8 + 1] <= dVar17) goto LAB_8013b140;
            for (uVar13 = 7; uVar8 < (uVar13 & 0xff); uVar13 = uVar13 - 1) {
              uVar5 = uVar13 & 0xff;
              *(undefined *)(iVar12 + uVar5) = *(undefined *)(iVar12 + (uVar5 - 1));
              param_4[uVar5] = param_4[uVar5 - 1];
              local_68[uVar5 + 1] = local_68[uVar5];
            }
            *(byte *)(iVar12 + uVar8) = (byte)unaff_r26 & 1 ^ 1;
            param_4[uVar8] = iVar15;
            local_68[uVar8 + 1] = (float)dVar17;
          }
        }
      }
      piVar7 = piVar7 + 1;
    }
  }
  FUN_80286878();
  return;
LAB_8013b140:
  bVar11 = bVar11 + 1;
  goto LAB_8013b144;
}

