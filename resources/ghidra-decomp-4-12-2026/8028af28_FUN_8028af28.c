// Function: FUN_8028af28
// Entry: 8028af28
// Size: 288 bytes

int FUN_8028af28(undefined4 param_1,undefined *param_2)

{
  int iVar1;
  uint uVar2;
  undefined *puVar3;
  int local_28;
  int local_24;
  int local_20 [4];
  
  iVar1 = FUN_80287f2c(&local_24,&local_28);
  if (iVar1 == 0) {
    uVar2 = *(uint *)(local_28 + 0xc);
    if (uVar2 < 0x880) {
      *(uint *)(local_28 + 0xc) = uVar2 + 1;
      iVar1 = 0;
      *(undefined *)(local_28 + uVar2 + 0x10) = 0xd3;
      *(int *)(local_28 + 8) = *(int *)(local_28 + 8) + 1;
    }
    else {
      iVar1 = 0x301;
    }
  }
  if (iVar1 == 0) {
    iVar1 = FUN_80287c44(local_28,param_1);
  }
  if (iVar1 == 0) {
    *param_2 = 0;
    iVar1 = FUN_8028b1f0(local_28,local_20,3,3,0);
    if (iVar1 == 0) {
      puVar3 = FUN_80287f00(local_20[0]);
      FUN_80287e2c((int)puVar3,2);
      iVar1 = FUN_80287a2c((int)puVar3,(int)param_2);
    }
    FUN_80287e9c(local_20[0]);
  }
  FUN_80287e9c(local_24);
  return iVar1;
}

