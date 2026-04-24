// Function: FUN_801de910
// Entry: 801de910
// Size: 272 bytes

void FUN_801de910(void)

{
  ushort uVar1;
  ushort uVar2;
  int iVar3;
  uint uVar4;
  undefined2 extraout_r4;
  byte bVar5;
  byte bVar6;
  ushort local_28 [20];
  
  iVar3 = FUN_8028683c();
  for (bVar6 = 0; bVar6 < 3; bVar6 = bVar6 + 1) {
    uVar4 = FUN_80020078((uint)*(ushort *)(iVar3 + (uint)bVar6 * 2));
    local_28[bVar6] = (ushort)uVar4;
  }
  local_28[3] = extraout_r4;
  for (bVar6 = 0; bVar6 < 3; bVar6 = bVar6 + 1) {
    for (bVar5 = 0; bVar5 < 3; bVar5 = bVar5 + 1) {
      uVar1 = local_28[bVar5 + 1];
      if (uVar1 != 0) {
        uVar2 = local_28[bVar5];
        if ((uVar1 < uVar2) || (uVar2 == 0)) {
          local_28[bVar5] = uVar1;
          local_28[bVar5 + 1] = uVar2;
        }
      }
    }
  }
  for (bVar6 = 0; bVar6 < 3; bVar6 = bVar6 + 1) {
    FUN_800201ac((uint)*(ushort *)(iVar3 + (uint)bVar6 * 2),(uint)local_28[bVar6]);
  }
  FUN_80286888();
  return;
}

