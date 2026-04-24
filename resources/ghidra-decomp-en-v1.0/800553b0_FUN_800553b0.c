// Function: FUN_800553b0
// Entry: 800553b0
// Size: 556 bytes

void FUN_800553b0(undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4)

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
  undefined8 uVar13;
  
  uVar13 = FUN_802860d4();
  iVar6 = (int)uVar13;
  iVar7 = iVar6 * 0x8c + -0x7fc7dd38;
  iVar2 = *(int *)(iVar7 + param_3 * 4);
  if (iVar2 != -1) {
    uVar12 = 0;
    uVar9 = *(uint *)((int)((ulonglong)uVar13 >> 0x20) + 0x20);
    uVar11 = uVar9 + iVar2;
    for (uVar4 = uVar9; uVar4 < uVar11; uVar4 = uVar4 + (uint)*(byte *)(uVar4 + 2) * 4) {
      uVar12 = uVar12 + 1;
    }
    param_3 = param_3 + 1;
    piVar3 = (int *)(iVar7 + param_3 * 4);
    iVar2 = 0x21 - param_3;
    if (param_3 < 0x21) {
      do {
        if (*piVar3 != -1) break;
        piVar3 = piVar3 + 1;
        param_3 = param_3 + 1;
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
    }
    iVar2 = *(int *)(iVar7 + param_3 * 4);
    for (; uVar11 < uVar9 + iVar2; uVar11 = uVar11 + (uint)*(byte *)(uVar11 + 2) * 4) {
      iVar7 = (int)uVar12 >> 3;
      if ((int)uVar12 < 0) {
        bVar8 = false;
      }
      else if (iVar7 < 0xc4) {
        bVar8 = true;
        if ((1 << (uVar12 & 7) & (int)*(char *)(*(int *)((&DAT_80386468)[iVar6] + 0x10) + iVar7)) ==
            0) {
          bVar8 = false;
        }
      }
      else {
        bVar8 = false;
      }
      if (!bVar8) {
        uVar4 = (**(code **)(*DAT_803dcaac + 0x40))(iVar6);
        uVar4 = uVar4 & 0xff;
        if (uVar4 == 0xffffffff) {
          bVar8 = false;
          goto LAB_80055548;
        }
        if (uVar4 == 0) {
LAB_80055544:
          bVar8 = true;
        }
        else if (uVar4 < 9) {
          if (((int)(uint)*(byte *)(uVar11 + 3) >> (uVar4 - 1 & 0x3f) & 1U) == 0) goto LAB_80055544;
          bVar8 = false;
        }
        else {
          if (((int)(uint)*(byte *)(uVar11 + 5) >> (0x10 - uVar4 & 0x3f) & 1U) == 0)
          goto LAB_80055544;
          bVar8 = false;
        }
LAB_80055548:
        if (bVar8) {
          if (-1 < (int)uVar12) {
            iVar10 = (&DAT_80386468)[iVar6];
            iVar5 = *(int *)(iVar10 + 0x10);
            bVar1 = (byte)(1 << (uVar12 & 7));
            *(byte *)(iVar5 + iVar7) = *(byte *)(iVar5 + iVar7) & ~bVar1;
            iVar5 = *(int *)(iVar10 + 0x10);
            *(byte *)(iVar5 + iVar7) = *(byte *)(iVar5 + iVar7) | bVar1;
          }
          FUN_8002df90(uVar11,1,iVar6,uVar12,param_4);
        }
      }
      uVar12 = uVar12 + 1;
    }
  }
  FUN_80286120();
  return;
}

