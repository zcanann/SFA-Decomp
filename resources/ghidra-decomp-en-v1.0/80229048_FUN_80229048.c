// Function: FUN_80229048
// Entry: 80229048
// Size: 168 bytes

void FUN_80229048(int param_1)

{
  int *piVar1;
  float local_38;
  float local_34;
  float local_30;
  undefined auStack44 [2];
  ushort local_2a;
  
  piVar1 = *(int **)(param_1 + 0xb8);
  if (*(char *)((int)piVar1 + 6) == '\x02') {
    local_2a = (ushort)(*(char *)(param_1 + 0xad) == '\0');
    local_38 = FLOAT_803e6e30;
    local_34 = FLOAT_803e6e34;
    local_30 = FLOAT_803e6e28;
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x805,auStack44,2,0xffffffff,&local_38);
  }
  if (*piVar1 != 0) {
    FUN_8001d6b0();
  }
  return;
}

