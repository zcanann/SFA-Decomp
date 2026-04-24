// Function: FUN_800d8414
// Entry: 800d8414
// Size: 400 bytes

void FUN_800d8414(short *param_1,int param_2)

{
  short sVar1;
  uint uVar2;
  uint uVar3;
  double dVar4;
  
  *(undefined4 *)(param_2 + 0x29c) = *(undefined4 *)(param_2 + 0x298);
  dVar4 = (double)FUN_802931a0((double)(*(float *)(param_2 + 0x290) * *(float *)(param_2 + 0x290) +
                                       *(float *)(param_2 + 0x28c) * *(float *)(param_2 + 0x28c)));
  *(float *)(param_2 + 0x298) = (float)dVar4;
  if (FLOAT_803e0578 < *(float *)(param_2 + 0x298)) {
    *(float *)(param_2 + 0x298) = FLOAT_803e0578;
  }
  *(float *)(param_2 + 0x298) = *(float *)(param_2 + 0x298) / FLOAT_803e0578;
  sVar1 = FUN_800217c0((double)*(float *)(param_2 + 0x290),-(double)*(float *)(param_2 + 0x28c));
  DAT_803dd44c = sVar1 - *(short *)(param_2 + 0x330);
  uVar2 = (int)DAT_803dd44c - ((int)*param_1 & 0xffffU);
  if (0x8000 < (int)uVar2) {
    uVar2 = uVar2 - 0xffff;
  }
  if ((int)uVar2 < -0x8000) {
    uVar2 = uVar2 + 0xffff;
  }
  *(short *)(param_2 + 0x336) =
       (short)(int)((float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e0598) /
                   FLOAT_803e0590);
  if ((int)uVar2 < 0) {
    *(short *)(param_2 + 0x334) = -*(short *)(param_2 + 0x336);
  }
  else {
    *(undefined2 *)(param_2 + 0x334) = *(undefined2 *)(param_2 + 0x336);
  }
  if (FLOAT_803e0594 <= *(float *)(param_2 + 0x298)) {
    uVar3 = uVar2 + 0xa000;
    if ((int)uVar3 < 0) {
      uVar3 = uVar2 + 0x19fff;
    }
    if (0xffff < (int)uVar3) {
      uVar3 = uVar3 - 0xffff;
    }
    *(char *)(param_2 + 0x34b) =
         '\x04' - ((char)((int)uVar3 >> 0xe) + ((int)uVar3 < 0 && (uVar3 & 0x3fff) != 0));
  }
  else {
    *(undefined *)(param_2 + 0x34b) = 0;
  }
  return;
}

