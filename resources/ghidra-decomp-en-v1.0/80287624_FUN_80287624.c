// Function: FUN_80287624
// Entry: 80287624
// Size: 164 bytes

undefined4 FUN_80287624(int param_1,undefined *param_2,uint param_3)

{
  int iVar1;
  undefined4 uVar2;
  
  uVar2 = 0;
  if (param_3 == 0) {
    uVar2 = 0;
  }
  else {
    iVar1 = *(int *)(param_1 + 0xc);
    if (0x880U - iVar1 < param_3) {
      uVar2 = 0x301;
      param_3 = 0x880U - iVar1;
    }
    if (param_3 == 1) {
      *(undefined *)(param_1 + iVar1 + 0x10) = *param_2;
    }
    else {
      FUN_80003514(param_1 + iVar1 + 0x10,param_2,param_3);
    }
    *(uint *)(param_1 + 0xc) = *(int *)(param_1 + 0xc) + param_3;
    *(undefined4 *)(param_1 + 8) = *(undefined4 *)(param_1 + 0xc);
  }
  return uVar2;
}

