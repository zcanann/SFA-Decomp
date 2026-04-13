// Function: FUN_80219638
// Entry: 80219638
// Size: 344 bytes

undefined4 FUN_80219638(int param_1)

{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  uint *puVar5;
  int local_28 [6];
  
  local_28[3] = DAT_802c2cf8;
  local_28[4] = DAT_802c2cfc;
  local_28[5] = DAT_802c2d00;
  local_28[0] = DAT_802c2d04;
  local_28[1] = DAT_802c2d08;
  local_28[2] = DAT_802c2d0c;
  iVar4 = 0;
  FUN_8002bac4();
  iVar3 = *(int *)(param_1 + 0xb8);
  FUN_800e85f4(param_1);
  FUN_80035ff8(param_1);
  puVar5 = (uint *)(local_28 + 3);
  while ((*puVar5 != 0xffffffff && (uVar1 = FUN_80020078(*puVar5), uVar1 != 0))) {
    puVar5 = puVar5 + 1;
    iVar4 = iVar4 + 1;
  }
  if (0 < iVar4) {
    *(undefined **)(iVar3 + 0x6d0) = &DAT_8032b454;
  }
  uVar1 = countLeadingZeros(1 - iVar4);
  FUN_800201ac(0xeb9,uVar1 >> 5);
  iVar3 = local_28[iVar4];
  if (iVar3 == -1) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    uVar2 = 1;
  }
  else {
    iVar4 = FUN_8003811c(param_1);
    if (iVar4 != 0) {
      *(code **)(param_1 + 0xbc) = FUN_80219614;
      (**(code **)(*DAT_803dd6d4 + 0x48))(iVar3,param_1,0xffffffff);
    }
    uVar2 = 0;
  }
  return uVar2;
}

