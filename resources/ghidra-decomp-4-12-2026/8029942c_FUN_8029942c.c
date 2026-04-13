// Function: FUN_8029942c
// Entry: 8029942c
// Size: 392 bytes

undefined4
FUN_8029942c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  int iVar2;
  double dVar3;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_80035f84(param_9);
  }
  fVar1 = FLOAT_803e8b3c;
  dVar3 = (double)FLOAT_803e8b3c;
  *(float *)(param_10 + 0x294) = FLOAT_803e8b3c;
  *(float *)(param_10 + 0x284) = fVar1;
  *(float *)(param_10 + 0x280) = fVar1;
  *(float *)(param_9 + 0x24) = fVar1;
  *(float *)(param_9 + 0x28) = fVar1;
  *(float *)(param_9 + 0x2c) = fVar1;
  if (*(short *)(param_9 + 0xa0) == 0xdd) {
    if (FLOAT_803e8bdc < *(float *)(param_9 + 0x98)) {
      FUN_8018a764((int)DAT_803df0b4,0);
    }
    if ((FLOAT_803e8be0 < *(float *)(param_9 + 0x98)) && ((*(byte *)(param_10 + 0x356) & 1) == 0)) {
      FUN_8000bb38(param_9,0x2c3);
      *(byte *)(param_10 + 0x356) = *(byte *)(param_10 + 0x356) | 1;
    }
    if (*(char *)(param_10 + 0x346) != '\0') {
      *(uint *)(iVar2 + 0x360) = *(uint *)(iVar2 + 0x360) | 0x800000;
      *(code **)(param_10 + 0x308) = FUN_802a58ac;
      return 2;
    }
  }
  else {
    FUN_8003042c(dVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,0xdd,0,
                 param_12,param_13,param_14,param_15,param_16);
    FUN_8018a4b4((int)DAT_803df0b4,(float *)(param_9 + 0xc),(float *)(param_9 + 0x14));
    *(float *)(param_10 + 0x2a0) = FLOAT_803e8b90;
    *(undefined *)(param_10 + 0x356) = 0;
    *(undefined2 *)(iVar2 + 0x478) = *DAT_803df0b4;
    *(undefined2 *)(iVar2 + 0x484) = *(undefined2 *)(iVar2 + 0x478);
    if ((DAT_803df0cc != 0) && ((*(byte *)(iVar2 + 0x3f4) >> 6 & 1) != 0)) {
      *(undefined *)(iVar2 + 0x8b4) = 4;
      *(byte *)(iVar2 + 0x3f4) = *(byte *)(iVar2 + 0x3f4) & 0xf7 | 8;
    }
  }
  return 0;
}

