// Function: FUN_8002b738
// Entry: 8002b738
// Size: 28 bytes

void FUN_8002b738(int param_1,ushort param_2)

{
  undefined uVar1;
  
  uVar1 = (undefined)param_2;
  if (4 < param_2) {
    uVar1 = 0;
  }
  *(undefined *)(param_1 + 0xe8) = uVar1;
  return;
}

