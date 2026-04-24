// Function: FUN_8026e7d4
// Entry: 8026e7d4
// Size: 116 bytes

void FUN_8026e7d4(int param_1,undefined4 *param_2)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  
  puVar1 = *(undefined4 **)(param_1 + 0x1c);
  puVar3 = (undefined4 *)0x0;
  while( true ) {
    puVar2 = puVar1;
    if (puVar2 == (undefined4 *)0x0) {
      param_2[1] = puVar3;
      if (puVar3 == (undefined4 *)0x0) {
        *(undefined4 **)(param_1 + 0x1c) = param_2;
      }
      else {
        *puVar3 = param_2;
      }
      *param_2 = 0;
      return;
    }
    if ((uint)param_2[2] < (uint)puVar2[2]) break;
    puVar1 = (undefined4 *)*puVar2;
    puVar3 = puVar2;
  }
  *param_2 = puVar2;
  param_2[1] = puVar3;
  if (puVar3 == (undefined4 *)0x0) {
    *(undefined4 **)(param_1 + 0x1c) = param_2;
  }
  else {
    *puVar3 = param_2;
  }
  puVar2[1] = param_2;
  return;
}

