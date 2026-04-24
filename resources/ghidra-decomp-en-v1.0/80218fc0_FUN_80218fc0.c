// Function: FUN_80218fc0
// Entry: 80218fc0
// Size: 344 bytes

undefined4 FUN_80218fc0(int param_1)

{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  int local_28 [6];
  
  local_28[3] = DAT_802c2578;
  local_28[4] = DAT_802c257c;
  local_28[5] = DAT_802c2580;
  local_28[0] = DAT_802c2584;
  local_28[1] = DAT_802c2588;
  local_28[2] = DAT_802c258c;
  iVar5 = 0;
  FUN_8002b9ec();
  iVar4 = *(int *)(param_1 + 0xb8);
  FUN_800e8370(param_1);
  FUN_80035f00(param_1);
  piVar6 = local_28 + 3;
  while ((*piVar6 != -1 && (iVar2 = FUN_8001ffb4(), iVar2 != 0))) {
    piVar6 = piVar6 + 1;
    iVar5 = iVar5 + 1;
  }
  if (0 < iVar5) {
    *(undefined **)(iVar4 + 0x6d0) = &DAT_8032a7fc;
  }
  uVar1 = countLeadingZeros(1 - iVar5);
  FUN_800200e8(0xeb9,uVar1 >> 5);
  iVar4 = local_28[iVar5];
  if (iVar4 == -1) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    uVar3 = 1;
  }
  else {
    iVar5 = FUN_80038024(param_1);
    if (iVar5 != 0) {
      *(code **)(param_1 + 0xbc) = FUN_80218f9c;
      (**(code **)(*DAT_803dca54 + 0x48))(iVar4,param_1,0xffffffff);
    }
    uVar3 = 0;
  }
  return uVar3;
}

