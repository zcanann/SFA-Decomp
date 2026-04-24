// Function: FUN_80221cd0
// Entry: 80221cd0
// Size: 92 bytes

void FUN_80221cd0(int param_1,undefined4 param_2,short param_3)

{
  undefined4 *puVar1;
  
  puVar1 = *(undefined4 **)(param_1 + 0xb8);
  *puVar1 = param_2;
  *(undefined *)(puVar1 + 1) = 0;
  FUN_800803f8(puVar1 + 2);
  FUN_80080404((float *)(puVar1 + 2),param_3 - (short)DAT_803dd000);
  return;
}

