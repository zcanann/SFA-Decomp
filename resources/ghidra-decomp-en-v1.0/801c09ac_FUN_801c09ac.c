// Function: FUN_801c09ac
// Entry: 801c09ac
// Size: 172 bytes

void FUN_801c09ac(int param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  undefined uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  FUN_80035df4(param_1,0,0,0);
  FUN_80035974(param_1,0);
  FUN_80035f00(param_1);
  if (param_3 == 0) {
    uVar1 = FUN_800221a0(0xf0,0x1e0);
    *(float *)(iVar3 + 0xc) =
         (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e4dc8);
    uVar2 = FUN_800221a0(0,9);
    *(undefined *)(iVar3 + 1) = uVar2;
  }
  return;
}

