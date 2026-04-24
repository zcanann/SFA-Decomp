// Function: FUN_8028af0c
// Entry: 8028af0c
// Size: 216 bytes

int FUN_8028af0c(char param_1)

{
  int iVar1;
  uint uVar2;
  int local_18;
  undefined4 local_14;
  undefined4 local_10 [2];
  
  iVar1 = FUN_802877c8(&local_14,&local_18);
  if (iVar1 == 0) {
    uVar2 = *(uint *)(local_18 + 0xc);
    if (uVar2 < 0x880) {
      *(uint *)(local_18 + 0xc) = uVar2 + 1;
      iVar1 = 0;
      *(char *)(local_18 + uVar2 + 0x10) = param_1;
      *(int *)(local_18 + 8) = *(int *)(local_18 + 8) + 1;
    }
    else {
      iVar1 = 0x301;
    }
    if (iVar1 == 0) {
      if (param_1 == -0x70) {
        FUN_8028bab0(local_18);
      }
      else {
        FUN_8028ba04(local_18);
      }
    }
    iVar1 = FUN_8028aa8c(local_18,local_10,2,3,1);
    if (iVar1 == 0) {
      FUN_80287738(local_10[0]);
    }
    FUN_80287738(local_14);
  }
  return iVar1;
}

