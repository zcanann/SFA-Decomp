// Function: FUN_8000d754
// Entry: 8000d754
// Size: 432 bytes

void FUN_8000d754(void)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  bool bVar4;
  short sVar5;
  uint uVar6;
  ushort *puVar7;
  uint *puVar8;
  short *psVar9;
  int *piVar10;
  byte *pbVar11;
  
  FUN_80286838();
  uVar6 = (uint)(short)(DAT_803dd4f8 - 1);
  pbVar11 = &DAT_80337970 + uVar6;
  piVar10 = &DAT_80337af0 + uVar6;
  psVar9 = &DAT_803379f0 + uVar6;
  for (; -1 < (short)uVar6; uVar6 = uVar6 - 1) {
    bVar4 = false;
    if (((*pbVar11 & 1) != 0) && ((*pbVar11 & 2) == 0)) {
      bVar4 = true;
    }
    iVar2 = *piVar10;
    if (((iVar2 != 0) && ((*(ushort *)(iVar2 + 0xb0) & 0x40) != 0)) || (bVar4)) {
      FUN_8000b844(iVar2,*psVar9);
      uVar3 = (uint)DAT_803dd4f8;
      DAT_803dd4f8 = (ushort)(uVar3 - 1);
      uVar1 = uVar6 & 0xffff;
      FUN_8028fa2c((uint)(&DAT_80337af0 + uVar1),(uint)(&DAT_80337af0 + uVar1 + 1),
                   ((uVar3 - 1 & 0xffff) - uVar1) * 4 & 0xfffc);
      FUN_8028fa2c((uint)(&DAT_803379f0 + uVar1),(uint)(&DAT_803379f0 + uVar1 + 1),
                   (DAT_803dd4f8 - uVar1) * 2 & 0xfffe);
      FUN_8028fa2c((uint)(&DAT_80337970 + uVar1),uVar1 + 0x80337971,DAT_803dd4f8 - uVar1 & 0xffff);
    }
    else {
      *pbVar11 = *pbVar11 & 0xfd;
    }
    pbVar11 = pbVar11 + -1;
    piVar10 = piVar10 + -1;
    psVar9 = psVar9 + -1;
  }
  puVar7 = &DAT_803379f0;
  puVar8 = &DAT_80337af0;
  for (sVar5 = 0; (int)sVar5 < (int)(uint)DAT_803dd4f8; sVar5 = sVar5 + 1) {
    bVar4 = FUN_8000b5f0(*puVar8,*puVar7);
    if (!bVar4) {
      FUN_8000bb38(*puVar8,*puVar7);
    }
    puVar7 = puVar7 + 1;
    puVar8 = puVar8 + 1;
  }
  FUN_80286884();
  return;
}

