// Function: FUN_8028a658
// Entry: 8028a658
// Size: 364 bytes

int FUN_8028a658(undefined4 param_1,undefined4 param_2,undefined param_3,undefined *param_4)

{
  int iVar1;
  uint uVar2;
  undefined4 uVar3;
  int local_28;
  undefined4 local_24;
  undefined4 local_20 [2];
  
  iVar1 = FUN_802877c8(&local_24,&local_28);
  if (iVar1 == 0) {
    uVar2 = *(uint *)(local_28 + 0xc);
    if (uVar2 < 0x880) {
      *(uint *)(local_28 + 0xc) = uVar2 + 1;
      iVar1 = 0;
      *(undefined *)(local_28 + uVar2 + 0x10) = 0xd4;
      *(int *)(local_28 + 8) = *(int *)(local_28 + 8) + 1;
    }
    else {
      iVar1 = 0x301;
    }
  }
  if (iVar1 == 0) {
    iVar1 = FUN_802874e0(local_28,param_1);
  }
  if (iVar1 == 0) {
    iVar1 = FUN_802874e0(local_28,param_2);
  }
  if (iVar1 == 0) {
    uVar2 = *(uint *)(local_28 + 0xc);
    if (uVar2 < 0x880) {
      *(uint *)(local_28 + 0xc) = uVar2 + 1;
      iVar1 = 0;
      *(undefined *)(local_28 + uVar2 + 0x10) = param_3;
      *(int *)(local_28 + 8) = *(int *)(local_28 + 8) + 1;
    }
    else {
      iVar1 = 0x301;
    }
  }
  if (iVar1 == 0) {
    *param_4 = 0;
    iVar1 = FUN_8028aa8c(local_28,local_20,3,3,0);
    if (iVar1 == 0) {
      uVar3 = FUN_8028779c(local_20[0]);
      FUN_802876c8(uVar3,2);
      iVar1 = FUN_802872c8(uVar3,param_4);
    }
    FUN_80287738(local_20[0]);
  }
  FUN_80287738(local_24);
  return iVar1;
}

