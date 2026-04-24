// Function: FUN_801cda50
// Entry: 801cda50
// Size: 136 bytes

void FUN_801cda50(int param_1)

{
  int iVar1;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10 [2];
  
  iVar1 = *(int *)(param_1 + 0xb8);
  FUN_8003b8f4((double)FLOAT_803e51f8);
  if (*(int *)(iVar1 + 8) != 0) {
    FUN_8003842c(param_1,0,local_10,&local_14,&local_18,0);
    *(undefined4 *)(*(int *)(iVar1 + 8) + 0xc) = local_10[0];
    *(undefined4 *)(*(int *)(iVar1 + 8) + 0x10) = local_14;
    *(undefined4 *)(*(int *)(iVar1 + 8) + 0x14) = local_18;
  }
  return;
}

