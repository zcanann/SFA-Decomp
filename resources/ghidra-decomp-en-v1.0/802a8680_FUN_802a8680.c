// Function: FUN_802a8680
// Entry: 802a8680
// Size: 332 bytes

undefined4
FUN_802a8680(undefined4 param_1,int param_2,int param_3,undefined4 *param_4,int param_5,int param_6)

{
  float fVar1;
  float fVar2;
  float fVar3;
  
  *(undefined4 *)(param_5 + 0x44) = *param_4;
  *(undefined4 *)(param_5 + 0x48) = *(undefined4 *)(param_3 + 0xc);
  *(undefined4 *)(param_5 + 0x4c) = param_4[2];
  *(undefined4 *)(param_5 + 0x50) = *(undefined4 *)(param_2 + 0x768);
  *(float *)(param_5 + 0x54) = FLOAT_803e7ea4;
  *(undefined4 *)(param_5 + 0x58) = *(undefined4 *)(param_2 + 0x770);
  if (param_6 == 0) {
    *(undefined *)(param_5 + 1) = 0;
  }
  else {
    *(undefined *)(param_5 + 1) = 1;
  }
  *(undefined4 *)(param_5 + 0x24) = *(undefined4 *)(param_3 + 0x1c);
  *(undefined4 *)(param_5 + 0x28) = *(undefined4 *)(param_3 + 0x20);
  *(undefined4 *)(param_5 + 0x2c) = *(undefined4 *)(param_3 + 0x24);
  *(undefined4 *)(param_5 + 0x30) = *(undefined4 *)(param_3 + 0x28);
  *(float *)(param_5 + 0x34) = -*(float *)(param_3 + 0x24);
  fVar2 = FLOAT_803e7ea4;
  *(float *)(param_5 + 0x38) = FLOAT_803e7ea4;
  *(undefined4 *)(param_5 + 0x3c) = *(undefined4 *)(param_3 + 0x1c);
  *(float *)(param_5 + 0x40) =
       -(*(float *)(param_5 + 0x4c) * *(float *)(param_5 + 0x3c) +
        *(float *)(param_5 + 0x44) * *(float *)(param_5 + 0x34) +
        *(float *)(param_5 + 0x48) * *(float *)(param_5 + 0x38));
  fVar3 = -*(float *)(param_5 + 0x2c);
  fVar1 = *(float *)(param_5 + 0x24);
  fVar2 = fVar2 * *(float *)(param_5 + 0x48);
  if ((FLOAT_803e80bc <
       -(fVar3 * *(float *)(param_3 + 4) + fVar1 * *(float *)(param_3 + 0x14)) +
       fVar1 * *(float *)(param_5 + 0x4c) + fVar3 * *(float *)(param_5 + 0x44) + fVar2) &&
     (FLOAT_803e80bc <
      -(-fVar3 * *(float *)(param_3 + 8) + -fVar1 * *(float *)(param_3 + 0x18)) +
      -fVar1 * *(float *)(param_5 + 0x4c) + -fVar3 * *(float *)(param_5 + 0x44) + fVar2)) {
    *(undefined4 *)(param_5 + 8) = *(undefined4 *)(param_3 + 0xc);
    *(undefined4 *)(param_5 + 4) = *(undefined4 *)(param_3 + 0x3c);
    *(undefined *)(param_5 + 2) = *(undefined *)(param_3 + 0x53);
    return 1;
  }
  return 0;
}

