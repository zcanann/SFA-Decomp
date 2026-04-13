// Function: FUN_80055758
// Entry: 80055758
// Size: 932 bytes

uint FUN_80055758(int param_1)

{
  int iVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  bool bVar9;
  uint uVar10;
  int iVar11;
  int iVar12;
  double dVar13;
  
  iVar12 = *(int *)(param_1 + 0x4c);
  if (iVar12 == 0) {
    return 0;
  }
  if ((*(byte *)(iVar12 + 4) & 2) != 0) {
    return 0;
  }
  uVar10 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_1 + 0xac));
  uVar10 = uVar10 & 0xff;
  if (uVar10 == 0xffffffff) {
    bVar9 = false;
    goto LAB_80055824;
  }
  if (uVar10 != 0) {
    if (uVar10 < 9) {
      if (((int)(uint)*(byte *)(iVar12 + 3) >> (uVar10 - 1 & 0x3f) & 1U) != 0) {
        bVar9 = false;
        goto LAB_80055824;
      }
    }
    else if (((int)(uint)*(byte *)(iVar12 + 5) >> (0x10 - uVar10 & 0x3f) & 1U) != 0) {
      bVar9 = false;
      goto LAB_80055824;
    }
  }
  bVar9 = true;
LAB_80055824:
  if (bVar9) {
    if ((*(byte *)(iVar12 + 4) & 1) == 0) {
      if ((*(byte *)(iVar12 + 4) & 0x10) == 0) {
        if ((*(int *)(param_1 + 0xc0) == 0) || (-1 < *(short *)(param_1 + 0xb4))) {
          if (*(int *)(param_1 + 0xc4) == 0) {
            if (*(int *)(param_1 + 0x30) == 0) {
              dVar13 = (double)FUN_802925a0();
              iVar11 = (int)dVar13;
              dVar13 = (double)FUN_802925a0();
              iVar1 = (int)dVar13;
              if ((((iVar11 < 0) || (iVar1 < 0)) || (0xf < iVar11)) || (0xf < iVar1)) {
                return 1;
              }
              iVar11 = iVar11 + iVar1 * 0x10;
              if (*(char *)(iVar11 + DAT_80382f24) < '\0' &&
                  (*(char *)(iVar11 + DAT_80382f20) < '\0' &&
                  (*(char *)(iVar11 + DAT_80382f1c) < '\0' &&
                  (*(char *)(iVar11 + DAT_80382f18) < '\0' &&
                  *(char *)(iVar11 + DAT_80382f14) < '\0')))) {
                return 1;
              }
            }
            if ((*(byte *)(iVar12 + 4) & 0x20) == 0) {
              if ((((*(byte *)(iVar12 + 4) & 4) == 0) || (iVar12 = FUN_8002bac4(), iVar12 == 0)) ||
                 (*(int *)(param_1 + 0x30) != 0)) {
                if (*(int *)(param_1 + 0x30) == 0) {
                  iVar12 = 0;
                }
                else {
                  iVar12 = *(char *)(*(int *)(param_1 + 0x30) + 0x35) + 1;
                }
                fVar2 = (float)(&DAT_803872a8)[iVar12 * 4];
                fVar3 = (float)(&DAT_803872ac)[iVar12 * 4];
                fVar4 = (float)(&DAT_803872b0)[iVar12 * 4];
              }
              else {
                fVar2 = *(float *)(iVar12 + 0x18);
                fVar3 = *(float *)(iVar12 + 0x1c);
                fVar4 = *(float *)(iVar12 + 0x20);
              }
              if (*(int *)(param_1 + 0x30) == 0) {
                fVar5 = *(float *)(param_1 + 0x18);
                fVar6 = *(float *)(param_1 + 0x1c);
                fVar7 = *(float *)(param_1 + 0x20);
              }
              else {
                fVar5 = *(float *)(param_1 + 0xc);
                fVar6 = *(float *)(param_1 + 0x10);
                fVar7 = *(float *)(param_1 + 0x14);
              }
              fVar8 = FLOAT_803df838 + *(float *)(param_1 + 0x3c);
              if (fVar8 * fVar8 <=
                  (fVar4 - fVar7) * (fVar4 - fVar7) +
                  (fVar2 - fVar5) * (fVar2 - fVar5) + (fVar3 - fVar6) * (fVar3 - fVar6)) {
                uVar10 = 1;
              }
              else {
                uVar10 = 0;
              }
            }
            else {
              uVar10 = 0;
            }
          }
          else {
            uVar10 = 0;
          }
        }
        else {
          uVar10 = 0;
        }
      }
      else {
        uVar10 = (**(code **)(*DAT_803dd72c + 0x4c))
                           ((int)*(char *)(param_1 + 0xac),*(undefined *)(iVar12 + 6));
        uVar10 = countLeadingZeros(uVar10 & 0xff);
        uVar10 = uVar10 >> 5;
      }
    }
    else {
      uVar10 = 0;
    }
  }
  else {
    uVar10 = 1;
  }
  return uVar10;
}

