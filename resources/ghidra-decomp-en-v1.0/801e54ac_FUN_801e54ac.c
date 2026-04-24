// Function: FUN_801e54ac
// Entry: 801e54ac
// Size: 260 bytes

void FUN_801e54ac(int param_1)

{
  float fVar1;
  uint uVar2;
  int *piVar3;
  
  *(undefined4 *)(param_1 + 0xf4) = 0xb4;
  uVar2 = FUN_800221a0(0x14,0x28);
  fVar1 = FLOAT_803e5948;
  *(float *)(param_1 + 0x24) =
       -(FLOAT_803e594c * (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e5940)
        + FLOAT_803e5948);
  *(float *)(param_1 + 0x28) = FLOAT_803e592c;
  *(float *)(param_1 + 0x2c) = FLOAT_803e5950;
  *(float *)(param_1 + 8) = *(float *)(param_1 + 8) * fVar1;
  piVar3 = (int *)FUN_80013ec8(0x75,1);
  (**(code **)(*piVar3 + 4))(param_1,DAT_803dc098,0,0x10002,0xffffffff,0);
  DAT_803dc098 = DAT_803dc098 + 1;
  if (3 < DAT_803dc098) {
    DAT_803dc098 = 1;
  }
  FUN_80013e2c(piVar3);
  FUN_8000bb18(param_1,0x35);
  FUN_8000bb18(param_1,0x2ca);
  return;
}

