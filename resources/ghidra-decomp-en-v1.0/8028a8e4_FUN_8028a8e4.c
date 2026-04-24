// Function: FUN_8028a8e4
// Entry: 8028a8e4
// Size: 424 bytes

int FUN_8028a8e4(undefined4 param_1,undefined param_2,undefined4 *param_3,undefined *param_4)

{
  int iVar1;
  uint uVar2;
  short sVar3;
  undefined4 unaff_r31;
  int local_28;
  undefined4 local_24;
  undefined4 local_20 [2];
  
  *param_3 = 0;
  iVar1 = FUN_802877c8(&local_24,&local_28);
  if (iVar1 == 0) {
    uVar2 = *(uint *)(local_28 + 0xc);
    if (uVar2 < 0x880) {
      *(uint *)(local_28 + 0xc) = uVar2 + 1;
      iVar1 = 0;
      *(undefined *)(local_28 + uVar2 + 0x10) = 0xd2;
      *(int *)(local_28 + 8) = *(int *)(local_28 + 8) + 1;
    }
    else {
      iVar1 = 0x301;
    }
  }
  if (iVar1 == 0) {
    uVar2 = *(uint *)(local_28 + 0xc);
    if (uVar2 < 0x880) {
      *(uint *)(local_28 + 0xc) = uVar2 + 1;
      iVar1 = 0;
      *(undefined *)(local_28 + uVar2 + 0x10) = param_2;
      *(int *)(local_28 + 8) = *(int *)(local_28 + 8) + 1;
    }
    else {
      iVar1 = 0x301;
    }
  }
  if (iVar1 == 0) {
    sVar3 = FUN_802918a4(param_1);
    iVar1 = FUN_80287544(local_28,sVar3 + 1);
  }
  if (iVar1 == 0) {
    iVar1 = FUN_802918a4(param_1);
    iVar1 = FUN_802873f0(local_28,param_1,iVar1 + 1);
  }
  if (iVar1 == 0) {
    *param_4 = 0;
    iVar1 = FUN_8028aa8c(local_28,local_20,7,3,0);
    if (iVar1 == 0) {
      unaff_r31 = FUN_8028779c(local_20[0]);
      FUN_802876c8(unaff_r31,2);
      iVar1 = FUN_802872c8(unaff_r31,param_4);
    }
    if (iVar1 == 0) {
      iVar1 = FUN_80287148(unaff_r31,param_3);
    }
    FUN_80287738(local_20[0]);
  }
  FUN_80287738(local_24);
  return iVar1;
}

