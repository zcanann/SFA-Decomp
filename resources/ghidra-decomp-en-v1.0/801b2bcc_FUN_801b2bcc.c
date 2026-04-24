// Function: FUN_801b2bcc
// Entry: 801b2bcc
// Size: 152 bytes

void FUN_801b2bcc(undefined2 *param_1)

{
  undefined2 uVar1;
  int iVar2;
  
  if (param_1[0x23] == 0x1d6) {
    FUN_8003b8f4((double)FLOAT_803e48e8);
  }
  else {
    iVar2 = *(int *)(param_1 + 0x5c);
    uVar1 = *param_1;
    *param_1 = (short)((int)*(char *)(*(int *)(param_1 + 0x26) + 0x28) << 8);
    FUN_8003b8f4((double)FLOAT_803e48e8);
    *param_1 = uVar1;
    FUN_8003842c(param_1,0,iVar2 + 0x8c,iVar2 + 0x90,iVar2 + 0x94,0);
  }
  return;
}

