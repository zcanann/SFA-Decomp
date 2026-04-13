// Function: FUN_8015c44c
// Entry: 8015c44c
// Size: 276 bytes

undefined4
FUN_8015c44c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  bool bVar1;
  float fVar2;
  int iVar3;
  
  iVar3 = *(int *)(*(int *)(param_9 + 0xb8) + 0x40c);
  *(byte *)(iVar3 + 0x44) = *(byte *)(iVar3 + 0x44) | 0xc;
  bVar1 = *(char *)(param_10 + 0x27a) != '\0';
  if (bVar1) {
    if (bVar1) {
      FUN_8003042c((double)FLOAT_803e39ac,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0xf,0,param_12,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    *(undefined *)(param_10 + 0x34d) = 1;
  }
  *(float *)(param_10 + 0x2a0) = *(float *)(param_10 + 0x2c0) / FLOAT_803e39d4;
  if (*(float *)(param_10 + 0x2a0) <= FLOAT_803e39d8) {
    if (*(float *)(param_10 + 0x2a0) < FLOAT_803e39d0) {
      *(float *)(param_10 + 0x2a0) = FLOAT_803e39d0;
    }
  }
  else {
    *(float *)(param_10 + 0x2a0) = FLOAT_803e39d8;
  }
  fVar2 = *(float *)(param_9 + 0x98);
  if (FLOAT_803e39bc <= fVar2) {
    *(float *)(param_10 + 0x280) = FLOAT_803e39dc * (FLOAT_803e39e0 - fVar2);
  }
  else {
    *(float *)(param_10 + 0x280) = FLOAT_803e39dc * fVar2;
  }
  (**(code **)(*DAT_803dd70c + 0x30))((double)FLOAT_803dc074,param_9,param_10,4);
  return 0;
}

