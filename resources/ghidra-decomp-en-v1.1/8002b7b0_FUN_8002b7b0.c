// Function: FUN_8002b7b0
// Entry: 8002b7b0
// Size: 128 bytes

void FUN_8002b7b0(int param_1,int param_2,int param_3,int param_4,char param_5,char param_6)

{
  undefined *puVar1;
  
  if (param_1 == 0) {
    return;
  }
  if (*(int *)(param_1 + 0x78) == 0) {
    return;
  }
  puVar1 = (undefined *)(*(int *)(param_1 + 0x78) + (uint)*(byte *)(param_1 + 0xe4) * 5);
  if (param_2 != 0) {
    *puVar1 = (char)(param_2 >> 2);
  }
  if (param_4 != 0) {
    puVar1[1] = (char)(param_4 >> 2);
  }
  if (param_3 != 0) {
    puVar1[2] = (char)(param_3 >> 2);
  }
  if (param_5 != '\0') {
    puVar1[3] = param_5;
  }
  if (param_6 == '\0') {
    return;
  }
  puVar1[4] = param_6;
  return;
}

