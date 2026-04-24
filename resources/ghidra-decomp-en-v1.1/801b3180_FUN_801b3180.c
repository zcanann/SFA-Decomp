// Function: FUN_801b3180
// Entry: 801b3180
// Size: 152 bytes

void FUN_801b3180(undefined2 *param_1)

{
  undefined2 uVar1;
  int iVar2;
  
  if (param_1[0x23] == 0x1d6) {
    FUN_8003b9ec((int)param_1);
  }
  else {
    iVar2 = *(int *)(param_1 + 0x5c);
    uVar1 = *param_1;
    *param_1 = (short)((int)*(char *)(*(int *)(param_1 + 0x26) + 0x28) << 8);
    FUN_8003b9ec((int)param_1);
    *param_1 = uVar1;
    FUN_80038524(param_1,0,(float *)(iVar2 + 0x8c),(undefined4 *)(iVar2 + 0x90),
                 (float *)(iVar2 + 0x94),0);
  }
  return;
}

