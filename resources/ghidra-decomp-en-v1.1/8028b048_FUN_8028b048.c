// Function: FUN_8028b048
// Entry: 8028b048
// Size: 424 bytes

int FUN_8028b048(undefined *param_1,undefined param_2,undefined4 *param_3,undefined *param_4)

{
  int iVar1;
  uint uVar2;
  undefined *unaff_r31;
  int local_28;
  int local_24;
  int local_20 [2];
  
  *param_3 = 0;
  iVar1 = FUN_80287f2c(&local_24,&local_28);
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
    iVar1 = FUN_80292004((int)param_1);
    iVar1 = FUN_80287ca8(local_28,(short)iVar1 + 1);
  }
  if (iVar1 == 0) {
    iVar1 = FUN_80292004((int)param_1);
    iVar1 = FUN_80287b54(local_28,param_1,iVar1 + 1);
  }
  if (iVar1 == 0) {
    *param_4 = 0;
    iVar1 = FUN_8028b1f0(local_28,local_20,7,3,0);
    if (iVar1 == 0) {
      unaff_r31 = FUN_80287f00(local_20[0]);
      FUN_80287e2c((int)unaff_r31,2);
      iVar1 = FUN_80287a2c((int)unaff_r31,(int)param_4);
    }
    if (iVar1 == 0) {
      iVar1 = FUN_802878ac((int)unaff_r31,(undefined *)param_3);
    }
    FUN_80287e9c(local_20[0]);
  }
  FUN_80287e9c(local_24);
  return iVar1;
}

