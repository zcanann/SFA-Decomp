// Function: FUN_8006a034
// Entry: 8006a034
// Size: 368 bytes

void FUN_8006a034(int param_1)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  int iVar9;
  
  uVar4 = FUN_80022b0c();
  uVar8 = 0;
  do {
    uVar6 = 0;
    iVar1 = (uVar8 >> 2) * 0x100;
    iVar2 = (uVar8 & 3) * 8;
    uVar5 = (uVar8 + param_1) * 0xff;
    iVar9 = 0x10;
    do {
      uVar3 = uVar5;
      if (0x3fc0 < uVar5) {
        uVar3 = 0x3fc0;
      }
      *(char *)(uVar4 + (uVar6 & 7) + (uVar6 >> 3) * 0x20 + iVar2 + iVar1) =
           (char)(uVar3 * uVar6 >> 0xc);
      uVar7 = uVar6 + 1;
      uVar3 = uVar5;
      if (0x3fc0 < uVar5) {
        uVar3 = 0x3fc0;
      }
      *(char *)(uVar4 + (uVar7 & 7) + (uVar7 >> 3) * 0x20 + iVar2 + iVar1) =
           (char)(uVar3 * uVar7 >> 0xc);
      uVar7 = uVar6 + 2;
      uVar3 = uVar5;
      if (0x3fc0 < uVar5) {
        uVar3 = 0x3fc0;
      }
      *(char *)(uVar4 + (uVar7 & 7) + (uVar7 >> 3) * 0x20 + iVar2 + iVar1) =
           (char)(uVar3 * uVar7 >> 0xc);
      uVar7 = uVar6 + 3;
      uVar3 = uVar5;
      if (0x3fc0 < uVar5) {
        uVar3 = 0x3fc0;
      }
      *(char *)(uVar4 + (uVar7 & 7) + (uVar7 >> 3) * 0x20 + iVar2 + iVar1) =
           (char)(uVar3 * uVar7 >> 0xc);
      uVar6 = uVar6 + 4;
      iVar9 = iVar9 + -1;
    } while (iVar9 != 0);
    uVar8 = uVar8 + 1;
  } while (uVar8 < 0x40);
  FUN_80022a0c(DAT_803ddc38 + 0x60,uVar4,0);
  DAT_803ddc00 = (char)param_1;
  return;
}

