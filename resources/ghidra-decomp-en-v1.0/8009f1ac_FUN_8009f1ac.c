// Function: FUN_8009f1ac
// Entry: 8009f1ac
// Size: 288 bytes

void FUN_8009f1ac(undefined param_1,undefined4 param_2)

{
  short sVar1;
  byte bVar2;
  
  sVar1 = FUN_80008b4c(0xffffffff);
  if (sVar1 != 1) {
    FLOAT_803dd25c = FLOAT_803dd25c + FLOAT_803db414;
    if (FLOAT_803df418 <= FLOAT_803dd25c) {
      FLOAT_803dd25c = FLOAT_803df35c;
    }
    FLOAT_803dd260 = FLOAT_803dd260 + FLOAT_803db414;
    if (FLOAT_803df384 <= FLOAT_803dd260) {
      FLOAT_803dd260 = FLOAT_803df35c;
    }
    FLOAT_803dd264 = FLOAT_803dd264 + FLOAT_803db414;
    if (FLOAT_803df354 <= FLOAT_803dd264) {
      FLOAT_803dd264 = FLOAT_803df35c;
    }
    DAT_803dc7b0 = 1;
    FUN_8009b9c8(param_1,param_2,0);
    DAT_803dc7b0 = 0;
    bVar2 = 0x50;
    while (bVar2 != 0) {
      bVar2 = bVar2 - 1;
      (&DAT_8030f968)[bVar2] = 0;
    }
    (**(code **)(*DAT_803dca88 + 0xc))(0);
    DAT_803dd254 = 1;
  }
  return;
}

