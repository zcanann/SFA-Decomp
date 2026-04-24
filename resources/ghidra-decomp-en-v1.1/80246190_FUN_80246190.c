// Function: FUN_80246190
// Entry: 80246190
// Size: 60 bytes

void FUN_80246190(int param_1)

{
  undefined8 uVar1;
  
  *(undefined4 *)(param_1 + 0x30) = 1;
  uVar1 = FUN_802473b4();
  *(undefined8 *)(param_1 + 0x28) = uVar1;
  return;
}

