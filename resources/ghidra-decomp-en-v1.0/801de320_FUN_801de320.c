// Function: FUN_801de320
// Entry: 801de320
// Size: 272 bytes

void FUN_801de320(void)

{
  ushort uVar1;
  int iVar2;
  ushort uVar3;
  undefined2 extraout_r4;
  byte bVar4;
  byte bVar5;
  undefined4 uVar6;
  ushort local_28 [20];
  
  iVar2 = FUN_802860d8();
  uVar6 = 0;
  for (bVar5 = 0; bVar5 < 3; bVar5 = bVar5 + 1) {
    uVar3 = FUN_8001ffb4(*(undefined2 *)(iVar2 + (uint)bVar5 * 2));
    local_28[bVar5] = uVar3;
  }
  local_28[3] = extraout_r4;
  for (bVar5 = 0; bVar5 < 3; bVar5 = bVar5 + 1) {
    for (bVar4 = 0; bVar4 < 3; bVar4 = bVar4 + 1) {
      uVar3 = local_28[bVar4 + 1];
      if (uVar3 != 0) {
        uVar1 = local_28[bVar4];
        if ((uVar3 < uVar1) || (uVar1 == 0)) {
          local_28[bVar4] = uVar3;
          local_28[bVar4 + 1] = uVar1;
          uVar6 = 1;
        }
      }
    }
  }
  for (bVar5 = 0; bVar5 < 3; bVar5 = bVar5 + 1) {
    FUN_800200e8(*(undefined2 *)(iVar2 + (uint)bVar5 * 2),local_28[bVar5]);
  }
  FUN_80286124(uVar6);
  return;
}

