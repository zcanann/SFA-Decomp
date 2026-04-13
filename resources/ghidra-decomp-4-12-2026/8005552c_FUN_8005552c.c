// Function: FUN_8005552c
// Entry: 8005552c
// Size: 556 bytes

void FUN_8005552c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,uint *param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  byte bVar1;
  int iVar2;
  int *piVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  bool bVar8;
  uint uVar9;
  int iVar10;
  uint uVar11;
  uint uVar12;
  undefined8 extraout_f1;
  undefined8 uVar13;
  
  uVar13 = FUN_80286838();
  iVar5 = (int)uVar13;
  iVar6 = iVar5 * 0x8c + -0x7fc7d0d8;
  iVar2 = *(int *)(iVar6 + param_11 * 4);
  if (iVar2 != -1) {
    uVar12 = 0;
    uVar9 = *(uint *)((int)((ulonglong)uVar13 >> 0x20) + 0x20);
    uVar11 = uVar9 + iVar2;
    for (uVar4 = uVar9; uVar4 < uVar11; uVar4 = uVar4 + (uint)*(byte *)(uVar4 + 2) * 4) {
      uVar12 = uVar12 + 1;
    }
    iVar7 = param_11 + 1;
    piVar3 = (int *)(iVar6 + iVar7 * 4);
    iVar2 = 0x21 - iVar7;
    if (iVar7 < 0x21) {
      do {
        if (*piVar3 != -1) break;
        piVar3 = piVar3 + 1;
        iVar7 = iVar7 + 1;
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
    }
    iVar2 = *(int *)(iVar6 + iVar7 * 4);
    for (; uVar11 < uVar9 + iVar2; uVar11 = uVar11 + (uint)*(byte *)(uVar11 + 2) * 4) {
      iVar6 = (int)uVar12 >> 3;
      if ((int)uVar12 < 0) {
        bVar8 = false;
      }
      else if (iVar6 < 0xc4) {
        bVar8 = true;
        if ((1 << (uVar12 & 7) & (int)*(char *)(*(int *)((&DAT_803870c8)[iVar5] + 0x10) + iVar6)) ==
            0) {
          bVar8 = false;
        }
      }
      else {
        bVar8 = false;
      }
      if (!bVar8) {
        uVar4 = (**(code **)(*DAT_803dd72c + 0x40))(iVar5);
        uVar4 = uVar4 & 0xff;
        if (uVar4 == 0xffffffff) {
          bVar8 = false;
          goto LAB_800556c4;
        }
        if (uVar4 == 0) {
LAB_800556c0:
          bVar8 = true;
        }
        else if (uVar4 < 9) {
          if (((int)(uint)*(byte *)(uVar11 + 3) >> (uVar4 - 1 & 0x3f) & 1U) == 0) goto LAB_800556c0;
          bVar8 = false;
        }
        else {
          if (((int)(uint)*(byte *)(uVar11 + 5) >> (0x10 - uVar4 & 0x3f) & 1U) == 0)
          goto LAB_800556c0;
          bVar8 = false;
        }
LAB_800556c4:
        if (bVar8) {
          if (-1 < (int)uVar12) {
            iVar10 = (&DAT_803870c8)[iVar5];
            iVar7 = *(int *)(iVar10 + 0x10);
            bVar1 = (byte)(1 << (uVar12 & 7));
            *(byte *)(iVar7 + iVar6) = *(byte *)(iVar7 + iVar6) & ~bVar1;
            iVar7 = *(int *)(iVar10 + 0x10);
            *(byte *)(iVar7 + iVar6) = *(byte *)(iVar7 + iVar6) | bVar1;
          }
          FUN_8002e088(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar11,1,
                       (char)uVar13,uVar12,param_12,param_14,param_15,param_16);
        }
      }
      uVar12 = uVar12 + 1;
    }
  }
  FUN_80286884();
  return;
}

