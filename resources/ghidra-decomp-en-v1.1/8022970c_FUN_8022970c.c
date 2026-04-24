// Function: FUN_8022970c
// Entry: 8022970c
// Size: 168 bytes

void FUN_8022970c(int param_1)

{
  int iVar1;
  int *piVar2;
  float local_38;
  float local_34;
  float local_30;
  undefined auStack_2c [2];
  ushort local_2a;
  
  piVar2 = *(int **)(param_1 + 0xb8);
  if (*(char *)((int)piVar2 + 6) == '\x02') {
    local_2a = (ushort)(*(char *)(param_1 + 0xad) == '\0');
    local_38 = FLOAT_803e7ac8;
    local_34 = FLOAT_803e7acc;
    local_30 = FLOAT_803e7ac0;
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x805,auStack_2c,2,0xffffffff,&local_38);
  }
  iVar1 = *piVar2;
  if (iVar1 != 0) {
    FUN_8001d774(iVar1);
  }
  return;
}

