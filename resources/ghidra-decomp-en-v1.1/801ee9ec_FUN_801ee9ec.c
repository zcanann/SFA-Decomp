// Function: FUN_801ee9ec
// Entry: 801ee9ec
// Size: 692 bytes

void FUN_801ee9ec(short *param_1,int param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  double dVar1;
  int iVar2;
  int iVar3;
  short sVar4;
  uint uVar5;
  double dVar6;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  
  iVar2 = *(int *)(param_2 + 0x74) * -6000;
  iVar2 = iVar2 / 0x46 + (iVar2 >> 0x1f);
  iVar2 = iVar2 - (iVar2 >> 0x1f);
  iVar3 = *(int *)(param_2 + 0x70) * -12000;
  iVar3 = iVar3 / 0x46 + (iVar3 >> 0x1f);
  *(short *)(param_2 + 0x2c) =
       (short)(int)-(((float)((double)CONCAT44(0x43300000,*(int *)(param_2 + 0x70) << 3 ^ 0x80000000
                                              ) - DOUBLE_803e6938) / FLOAT_803e6930) *
                     FLOAT_803dc074 -
                    (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x2c) ^ 0x80000000
                                            ) - DOUBLE_803e6938));
  *(short *)(param_2 + 0x2c) =
       *(short *)(param_2 + 0x2c) -
       (short)((int)((int)*(short *)(param_2 + 0x2c) * (uint)DAT_803dc070) >> 5);
  uVar5 = iVar2 - (uint)(ushort)param_1[1];
  if (0x8000 < (int)uVar5) {
    uVar5 = uVar5 - 0xffff;
  }
  if ((int)uVar5 < -0x8000) {
    uVar5 = uVar5 + 0xffff;
  }
  param_1[1] = (short)(int)(FLOAT_803e6940 *
                            (float)((double)CONCAT44(0x43300000,uVar5 ^ 0x80000000) -
                                   DOUBLE_803e6938) * FLOAT_803dc074 +
                           (float)((double)CONCAT44(0x43300000,(int)param_1[1] ^ 0x80000000) -
                                  DOUBLE_803e6938));
  dVar1 = DOUBLE_803e6938;
  uVar5 = (iVar3 - (iVar3 >> 0x1f)) - (uint)*(ushort *)(param_2 + 0x2e);
  if (0x8000 < (int)uVar5) {
    uVar5 = uVar5 - 0xffff;
  }
  if ((int)uVar5 < -0x8000) {
    uVar5 = uVar5 + 0xffff;
  }
  dVar6 = (double)FLOAT_803e6940;
  *(short *)(param_2 + 0x2e) =
       (short)(int)(dVar6 * (double)((float)((double)CONCAT44(0x43300000,uVar5 ^ 0x80000000) -
                                            DOUBLE_803e6938) * FLOAT_803dc074) +
                   (double)(float)((double)CONCAT44(0x43300000,
                                                    (int)*(short *)(param_2 + 0x2e) ^ 0x80000000) -
                                  DOUBLE_803e6938));
  sVar4 = param_1[1];
  if (sVar4 < -8000) {
    sVar4 = -8000;
  }
  else if (8000 < sVar4) {
    sVar4 = 8000;
  }
  param_1[1] = sVar4;
  sVar4 = *(short *)(param_2 + 0x2e);
  if (sVar4 < -13000) {
    sVar4 = -13000;
  }
  else if (13000 < sVar4) {
    sVar4 = 13000;
  }
  *(short *)(param_2 + 0x2e) = sVar4;
  *param_1 = *(short *)(param_2 + 0x2c) + 0x4000;
  param_1[2] = *(short *)(param_2 + 0x2e);
  if (param_1[0x50] != 0xf) {
    FUN_8003042c((double)FLOAT_803e6908,dVar1,dVar6,in_f4,in_f5,in_f6,in_f7,in_f8,param_1,0xf,0,
                 iVar2,param_5,param_6,param_7,param_8);
  }
  iVar2 = FUN_8002fb40((double)FLOAT_803e6944,(double)FLOAT_803dc074);
  if (iVar2 != 0) {
    *(undefined *)(param_2 + 0x65) = 0;
  }
  param_1[0x7a] = 0;
  param_1[0x7b] = 1;
  return;
}

