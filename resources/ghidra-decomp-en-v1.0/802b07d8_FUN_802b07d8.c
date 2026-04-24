// Function: FUN_802b07d8
// Entry: 802b07d8
// Size: 328 bytes

void FUN_802b07d8(int param_1,int param_2)

{
  uint uVar1;
  char cVar4;
  undefined4 uVar2;
  int iVar3;
  
  if ((DAT_803de44c == 0) && (cVar4 = FUN_8002e04c(), cVar4 != '\0')) {
    uVar2 = FUN_8002bdf4(0x18,0x69);
    DAT_803de44c = FUN_8002df90(uVar2,4,0xffffffff,0xffffffff,*(undefined4 *)(param_1 + 0x30));
    FUN_80037d2c(param_1,DAT_803de44c,2);
  }
  if (DAT_803de44c != 0) {
    *(undefined4 *)(DAT_803de44c + 0x30) = *(undefined4 *)(param_1 + 0x30);
  }
  *(float *)(param_2 + 0x7d4) = -(FLOAT_803e7e98 * FLOAT_803db414 - *(float *)(param_2 + 0x7d4));
  if (*(float *)(param_2 + 0x7d4) < FLOAT_803e7ea4) {
    *(float *)(param_2 + 0x7d4) = FLOAT_803e7ea4;
  }
  *(float *)(param_2 + 0x7d8) = -(FLOAT_803e7e98 * FLOAT_803db414 - *(float *)(param_2 + 0x7d8));
  if (*(float *)(param_2 + 0x7d8) < FLOAT_803e7ea4) {
    *(float *)(param_2 + 0x7d8) = FLOAT_803e7ea4;
  }
  FUN_8011f34c((int)*(float *)(param_2 + 0x7d4) & 0xff);
  if (param_1 == 0) {
    uVar1 = 0;
  }
  else {
    uVar1 = (uint)(-(int)*(char *)(param_1 + 0xad) | (int)*(char *)(param_1 + 0xad)) >> 0x1f;
  }
  if ((uVar1 == 0) && (iVar3 = FUN_8001ffb4(0x75), iVar3 != 0)) {
    FUN_80295cf4(param_1,0);
  }
  return;
}

