// Function: FUN_80221680
// Entry: 80221680
// Size: 92 bytes

void FUN_80221680(int param_1,undefined4 param_2,short param_3)

{
  undefined4 *puVar1;
  
  puVar1 = *(undefined4 **)(param_1 + 0xb8);
  *puVar1 = param_2;
  *(undefined *)(puVar1 + 1) = 0;
  FUN_8008016c(puVar1 + 2);
  FUN_80080178(puVar1 + 2,(int)(short)(param_3 - (short)DAT_803dc398));
  return;
}

