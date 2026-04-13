// Function: FUN_8015336c
// Entry: 8015336c
// Size: 232 bytes

void FUN_8015336c(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  float local_18;
  float local_14 [3];
  
  fVar1 = FLOAT_803e3504;
  *(float *)(param_2 + 0x2ac) = FLOAT_803e3504;
  *(undefined4 *)(param_2 + 0x2e4) = 1;
  *(float *)(param_2 + 0x308) = FLOAT_803e3538;
  *(float *)(param_2 + 0x300) = FLOAT_803e353c;
  fVar2 = FLOAT_803e352c;
  *(float *)(param_2 + 0x304) = FLOAT_803e352c;
  *(undefined *)(param_2 + 800) = 1;
  *(float *)(param_2 + 0x314) = fVar2;
  *(undefined *)(param_2 + 0x321) = 3;
  *(float *)(param_2 + 0x318) = fVar2;
  *(undefined *)(param_2 + 0x322) = 1;
  *(float *)(param_2 + 0x31c) = fVar2;
  *(undefined4 *)(param_2 + 0x324) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(param_2 + 0x328) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(param_2 + 0x32c) = *(undefined4 *)(param_1 + 0x14);
  *(undefined *)(param_2 + 0x33a) = 0;
  *(undefined *)(param_2 + 0x33b) = 0;
  *(undefined2 *)(param_2 + 0x338) = 0;
  *(float *)(param_2 + 0x330) = fVar1;
  *(float *)(param_2 + 0x334) = fVar1;
  *(float *)(param_2 + 0x2fc) = FLOAT_803e3540;
  FUN_80293778((uint)*(ushort *)(param_2 + 0x338),local_14,&local_18);
  *(float *)(param_1 + 0xc) =
       local_14[0] * *(float *)(param_2 + 0x2a8) + *(float *)(param_2 + 0x324);
  *(float *)(param_1 + 0x14) = local_18 * *(float *)(param_2 + 0x2a8) + *(float *)(param_2 + 0x32c);
  return;
}

