// Function: FUN_801e5a9c
// Entry: 801e5a9c
// Size: 260 bytes

void FUN_801e5a9c(uint param_1)

{
  float fVar1;
  uint uVar2;
  int *piVar3;
  
  *(undefined4 *)(param_1 + 0xf4) = 0xb4;
  uVar2 = FUN_80022264(0x14,0x28);
  fVar1 = FLOAT_803e65e0;
  *(float *)(param_1 + 0x24) =
       -(FLOAT_803e65e4 * (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e65d8)
        + FLOAT_803e65e0);
  *(float *)(param_1 + 0x28) = FLOAT_803e65c4;
  *(float *)(param_1 + 0x2c) = FLOAT_803e65e8;
  *(float *)(param_1 + 8) = *(float *)(param_1 + 8) * fVar1;
  piVar3 = (int *)FUN_80013ee8(0x75);
  (**(code **)(*piVar3 + 4))(param_1,DAT_803dcd00,0,0x10002,0xffffffff,0);
  DAT_803dcd00 = DAT_803dcd00 + 1;
  if (3 < DAT_803dcd00) {
    DAT_803dcd00 = 1;
  }
  FUN_80013e4c((undefined *)piVar3);
  FUN_8000bb38(param_1,0x35);
  FUN_8000bb38(param_1,0x2ca);
  return;
}

