// Function: FUN_8001b7b4
// Entry: 8001b7b4
// Size: 184 bytes

void FUN_8001b7b4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  undefined4 uVar1;
  int iVar2;
  uint *puVar3;
  
  if (DAT_803dd684 != 0) {
    DAT_803dd684 = 0;
    puVar3 = &DAT_8033bea0;
    for (iVar2 = 0; iVar2 < DAT_803dd694; iVar2 = iVar2 + 1) {
      if (*puVar3 != 0) {
        uVar1 = FUN_800238f8(0);
        param_1 = FUN_800238c4(*puVar3);
        FUN_800238f8(uVar1);
        *puVar3 = 0;
      }
      puVar3 = puVar3 + 1;
    }
    if (DAT_803dc040 != -1) {
      FUN_800199a8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,DAT_803dc040);
      DAT_803dc040 = -1;
    }
  }
  return;
}

