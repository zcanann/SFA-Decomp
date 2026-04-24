// Function: FUN_802b0f38
// Entry: 802b0f38
// Size: 328 bytes

void FUN_802b0f38(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)

{
  uint uVar1;
  undefined2 *puVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  
  if ((DAT_803df0cc == 0) && (uVar1 = FUN_8002e144(), (uVar1 & 0xff) != 0)) {
    puVar2 = FUN_8002becc(0x18,0x69);
    DAT_803df0cc = FUN_8002e088(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                puVar2,4,0xff,0xffffffff,*(uint **)(param_9 + 0x30),in_r8,in_r9,
                                in_r10);
    FUN_80037e24(param_9,DAT_803df0cc,2);
  }
  if (DAT_803df0cc != 0) {
    *(undefined4 *)(DAT_803df0cc + 0x30) = *(undefined4 *)(param_9 + 0x30);
  }
  *(float *)(param_10 + 0x7d4) = -(FLOAT_803e8b30 * FLOAT_803dc074 - *(float *)(param_10 + 0x7d4));
  if (*(float *)(param_10 + 0x7d4) < FLOAT_803e8b3c) {
    *(float *)(param_10 + 0x7d4) = FLOAT_803e8b3c;
  }
  *(float *)(param_10 + 0x7d8) = -(FLOAT_803e8b30 * FLOAT_803dc074 - *(float *)(param_10 + 0x7d8));
  if (*(float *)(param_10 + 0x7d8) < FLOAT_803e8b3c) {
    *(float *)(param_10 + 0x7d8) = FLOAT_803e8b3c;
  }
  FUN_8011f630((char)(int)*(float *)(param_10 + 0x7d4));
  if (param_9 == 0) {
    uVar1 = 0;
  }
  else {
    uVar1 = (uint)(-(int)*(char *)(param_9 + 0xad) | (int)*(char *)(param_9 + 0xad)) >> 0x1f;
  }
  if ((uVar1 == 0) && (uVar1 = FUN_80020078(0x75), uVar1 != 0)) {
    FUN_80296454(param_9,0);
  }
  return;
}

