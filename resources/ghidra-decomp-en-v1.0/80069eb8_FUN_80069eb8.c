// Function: FUN_80069eb8
// Entry: 80069eb8
// Size: 368 bytes

void FUN_80069eb8(int param_1)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  int iVar9;
  
  iVar4 = FUN_80022a48();
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
      *(char *)(iVar4 + (uVar6 & 7) + (uVar6 >> 3) * 0x20 + iVar2 + iVar1) =
           (char)(uVar3 * uVar6 >> 0xc);
      uVar7 = uVar6 + 1;
      uVar3 = uVar5;
      if (0x3fc0 < uVar5) {
        uVar3 = 0x3fc0;
      }
      *(char *)(iVar4 + (uVar7 & 7) + (uVar7 >> 3) * 0x20 + iVar2 + iVar1) =
           (char)(uVar3 * uVar7 >> 0xc);
      uVar7 = uVar6 + 2;
      uVar3 = uVar5;
      if (0x3fc0 < uVar5) {
        uVar3 = 0x3fc0;
      }
      *(char *)(iVar4 + (uVar7 & 7) + (uVar7 >> 3) * 0x20 + iVar2 + iVar1) =
           (char)(uVar3 * uVar7 >> 0xc);
      uVar7 = uVar6 + 3;
      uVar3 = uVar5;
      if (0x3fc0 < uVar5) {
        uVar3 = 0x3fc0;
      }
      *(char *)(iVar4 + (uVar7 & 7) + (uVar7 >> 3) * 0x20 + iVar2 + iVar1) =
           (char)(uVar3 * uVar7 >> 0xc);
      uVar6 = uVar6 + 4;
      iVar9 = iVar9 + -1;
    } while (iVar9 != 0);
    uVar8 = uVar8 + 1;
  } while (uVar8 < 0x40);
  FUN_80022948(DAT_803dcfb8 + 0x60,iVar4,0);
  DAT_803dcf80 = (char)param_1;
  return;
}

