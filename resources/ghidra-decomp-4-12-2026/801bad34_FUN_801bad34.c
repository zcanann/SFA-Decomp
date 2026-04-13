// Function: FUN_801bad34
// Entry: 801bad34
// Size: 256 bytes

undefined4
FUN_801bad34(int param_1,int param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,
            undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  float fVar1;
  int iVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27a) != '\0') {
    DAT_803de800 = DAT_803de800 | 0x2000;
    FUN_8000faf8();
    dVar4 = (double)FLOAT_803e5860;
    dVar5 = (double)FLOAT_803e5864;
    FUN_8000e670((double)FLOAT_803e585c,dVar4,dVar5);
    FUN_80014acc((double)FLOAT_803e5868);
    *(undefined2 *)(param_1 + 0xa2) = 0xffff;
    *(float *)(param_2 + 0x2a0) = FLOAT_803e5880;
    fVar1 = FLOAT_803e5870;
    dVar3 = (double)FLOAT_803e5870;
    *(float *)(param_2 + 0x280) = FLOAT_803e5870;
    *(float *)(param_2 + 0x284) = fVar1;
    if (*(char *)(param_2 + 0x27a) != '\0') {
      FUN_8003042c(dVar3,dVar4,dVar5,in_f4,in_f5,in_f6,in_f7,in_f8,param_1,0xe,0,param_4,param_5,
                   param_6,param_7,param_8);
      *(undefined *)(param_2 + 0x346) = 0;
    }
    if (*(short *)(iVar2 + 0x402) == 1) {
      *(float *)(*(int *)(iVar2 + 0x40c) + 0xa8) = FLOAT_803e5884;
    }
  }
  (**(code **)(*DAT_803dd70c + 0x34))(param_1,param_2,0,1,&DAT_803dcb98);
  return 0;
}

