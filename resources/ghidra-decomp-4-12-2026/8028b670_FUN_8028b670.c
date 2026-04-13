// Function: FUN_8028b670
// Entry: 8028b670
// Size: 216 bytes

int FUN_8028b670(char param_1)

{
  int iVar1;
  uint uVar2;
  int local_18;
  int local_14;
  int local_10 [2];
  
  iVar1 = FUN_80287f2c(&local_14,&local_18);
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
        FUN_8028c214(local_18);
      }
      else {
        FUN_8028c168(local_18);
      }
    }
    iVar1 = FUN_8028b1f0(local_18,local_10,2,3,1);
    if (iVar1 == 0) {
      FUN_80287e9c(local_10[0]);
    }
    FUN_80287e9c(local_14);
  }
  return iVar1;
}

