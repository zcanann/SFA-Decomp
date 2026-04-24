// Function: FUN_80003494
// Entry: 80003494
// Size: 80 bytes

void FUN_80003494(uint param_1,uint param_2,int param_3)

{
  undefined *puVar1;
  undefined *puVar2;
  
  if (param_1 <= param_2) {
    puVar1 = (undefined *)(param_2 - 1);
    puVar2 = (undefined *)(param_1 - 1);
    param_3 = param_3 + 1;
    while( true ) {
      param_3 = param_3 + -1;
      if (param_3 == 0) break;
      puVar1 = puVar1 + 1;
      puVar2 = puVar2 + 1;
      *puVar2 = *puVar1;
    }
    return;
  }
  puVar1 = (undefined *)(param_2 + param_3);
  puVar2 = (undefined *)(param_1 + param_3);
  param_3 = param_3 + 1;
  while( true ) {
    param_3 = param_3 + -1;
    if (param_3 == 0) break;
    puVar1 = puVar1 + -1;
    puVar2 = puVar2 + -1;
    *puVar2 = *puVar1;
  }
  return;
}

