// Function: FUN_801ee3b4
// Entry: 801ee3b4
// Size: 692 bytes

void FUN_801ee3b4(short *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  short sVar3;
  uint uVar4;
  
  iVar1 = *(int *)(param_2 + 0x74) * -6000;
  iVar1 = iVar1 / 0x46 + (iVar1 >> 0x1f);
  iVar2 = *(int *)(param_2 + 0x70) * -12000;
  iVar2 = iVar2 / 0x46 + (iVar2 >> 0x1f);
  *(short *)(param_2 + 0x2c) =
       (short)(int)-(((float)((double)CONCAT44(0x43300000,*(int *)(param_2 + 0x70) << 3 ^ 0x80000000
                                              ) - DOUBLE_803e5ca0) / FLOAT_803e5c98) *
                     FLOAT_803db414 -
                    (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x2c) ^ 0x80000000
                                            ) - DOUBLE_803e5ca0));
  *(short *)(param_2 + 0x2c) =
       *(short *)(param_2 + 0x2c) -
       (short)((int)((int)*(short *)(param_2 + 0x2c) * (uint)DAT_803db410) >> 5);
  uVar4 = (iVar1 - (iVar1 >> 0x1f)) - ((int)param_1[1] & 0xffffU);
  if (0x8000 < (int)uVar4) {
    uVar4 = uVar4 - 0xffff;
  }
  if ((int)uVar4 < -0x8000) {
    uVar4 = uVar4 + 0xffff;
  }
  param_1[1] = (short)(int)(FLOAT_803e5ca8 *
                            (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) -
                                   DOUBLE_803e5ca0) * FLOAT_803db414 +
                           (float)((double)CONCAT44(0x43300000,(int)param_1[1] ^ 0x80000000) -
                                  DOUBLE_803e5ca0));
  uVar4 = (iVar2 - (iVar2 >> 0x1f)) - ((int)*(short *)(param_2 + 0x2e) & 0xffffU);
  if (0x8000 < (int)uVar4) {
    uVar4 = uVar4 - 0xffff;
  }
  if ((int)uVar4 < -0x8000) {
    uVar4 = uVar4 + 0xffff;
  }
  *(short *)(param_2 + 0x2e) =
       (short)(int)(FLOAT_803e5ca8 *
                    (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803e5ca0) *
                    FLOAT_803db414 +
                   (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x2e) ^ 0x80000000)
                          - DOUBLE_803e5ca0));
  sVar3 = param_1[1];
  if (sVar3 < -8000) {
    sVar3 = -8000;
  }
  else if (8000 < sVar3) {
    sVar3 = 8000;
  }
  param_1[1] = sVar3;
  sVar3 = *(short *)(param_2 + 0x2e);
  if (sVar3 < -13000) {
    sVar3 = -13000;
  }
  else if (13000 < sVar3) {
    sVar3 = 13000;
  }
  *(short *)(param_2 + 0x2e) = sVar3;
  *param_1 = *(short *)(param_2 + 0x2c) + 0x4000;
  param_1[2] = *(short *)(param_2 + 0x2e);
  if (param_1[0x50] != 0xf) {
    FUN_80030334((double)FLOAT_803e5c70,param_1,0xf,0);
  }
  iVar1 = FUN_8002fa48((double)FLOAT_803e5cac,(double)FLOAT_803db414,param_1,0);
  if (iVar1 != 0) {
    *(undefined *)(param_2 + 0x65) = 0;
  }
  *(undefined4 *)(param_1 + 0x7a) = 1;
  return;
}

