// Function: FUN_8000d734
// Entry: 8000d734
// Size: 432 bytes

void FUN_8000d734(void)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  bool bVar4;
  short sVar5;
  uint uVar6;
  undefined2 *puVar7;
  undefined4 *puVar8;
  int *piVar9;
  byte *pbVar10;
  
  FUN_802860d4();
  uVar6 = (uint)(short)(DAT_803dc878 - 1);
  pbVar10 = &DAT_80336d10 + uVar6;
  piVar9 = &DAT_80336e90 + uVar6;
  puVar7 = &DAT_80336d90 + uVar6;
  for (; -1 < (short)uVar6; uVar6 = uVar6 - 1) {
    bVar4 = false;
    if (((*pbVar10 & 1) != 0) && ((*pbVar10 & 2) == 0)) {
      bVar4 = true;
    }
    iVar3 = *piVar9;
    if (((iVar3 != 0) && ((*(ushort *)(iVar3 + 0xb0) & 0x40) != 0)) || (bVar4)) {
      FUN_8000b824(iVar3,*puVar7);
      uVar2 = (uint)DAT_803dc878;
      DAT_803dc878 = (ushort)(uVar2 - 1);
      uVar1 = uVar6 & 0xffff;
      FUN_8028f2cc(&DAT_80336e90 + uVar1,&DAT_80336e90 + uVar1 + 1,
                   ((uVar2 - 1 & 0xffff) - uVar1) * 4 & 0xfffc);
      FUN_8028f2cc(&DAT_80336d90 + uVar1,&DAT_80336d90 + uVar1 + 1,
                   (DAT_803dc878 - uVar1) * 2 & 0xfffe);
      FUN_8028f2cc(&DAT_80336d10 + uVar1,uVar1 + 0x80336d11,DAT_803dc878 - uVar1 & 0xffff);
    }
    else {
      *pbVar10 = *pbVar10 & 0xfd;
    }
    pbVar10 = pbVar10 + -1;
    piVar9 = piVar9 + -1;
    puVar7 = puVar7 + -1;
  }
  puVar7 = &DAT_80336d90;
  puVar8 = &DAT_80336e90;
  for (sVar5 = 0; (int)sVar5 < (int)(uint)DAT_803dc878; sVar5 = sVar5 + 1) {
    iVar3 = FUN_8000b5d0(*puVar8,*puVar7);
    if (iVar3 == 0) {
      FUN_8000bb18(*puVar8,*puVar7);
    }
    puVar7 = puVar7 + 1;
    puVar8 = puVar8 + 1;
  }
  FUN_80286120();
  return;
}

