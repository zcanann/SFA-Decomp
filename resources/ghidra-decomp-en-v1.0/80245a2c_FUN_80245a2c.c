// Function: FUN_80245a2c
// Entry: 80245a2c
// Size: 60 bytes

void FUN_80245a2c(int param_1)

{
  undefined8 uVar1;
  
  *(undefined4 *)(param_1 + 0x30) = 1;
  uVar1 = FUN_80246c50();
  *(int *)(param_1 + 0x2c) = (int)uVar1;
  *(int *)(param_1 + 0x28) = (int)((ulonglong)uVar1 >> 0x20);
  return;
}

