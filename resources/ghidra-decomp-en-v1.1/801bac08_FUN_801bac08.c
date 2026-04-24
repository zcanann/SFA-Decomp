// Function: FUN_801bac08
// Entry: 801bac08
// Size: 300 bytes

undefined4
FUN_801bac08(int param_1,int param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,
            undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  float fVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  
  if (FLOAT_803e5858 < *(float *)(param_1 + 0x98)) {
    DAT_803de800 = DAT_803de800 & 0xffffffdf;
  }
  if (*(char *)(param_2 + 0x27a) != '\0') {
    DAT_803de800 = DAT_803de800 | 0x8020;
    FUN_8000faf8();
    dVar4 = (double)FLOAT_803e5864;
    FUN_8000e670((double)FLOAT_803e585c,(double)FLOAT_803e5860,dVar4);
    FUN_80014acc((double)FLOAT_803e5868);
    *(undefined2 *)(param_1 + 0xa2) = 0xffff;
    dVar3 = (double)FLOAT_803e586c;
    *(float *)(param_2 + 0x2a0) =
         (float)(dVar3 * (double)(float)((double)CONCAT44(0x43300000,
                                                          (int)*(char *)(param_2 + 0x354) + 1U ^
                                                          0x80000000) - DOUBLE_803e5878));
    fVar1 = FLOAT_803e5870;
    dVar2 = (double)FLOAT_803e5870;
    *(float *)(param_2 + 0x280) = FLOAT_803e5870;
    *(float *)(param_2 + 0x284) = fVar1;
    if (*(char *)(param_2 + 0x27a) != '\0') {
      FUN_8003042c(dVar2,dVar3,dVar4,in_f4,in_f5,in_f6,in_f7,in_f8,param_1,0x15,0,param_4,param_5,
                   param_6,param_7,param_8);
      *(undefined *)(param_2 + 0x346) = 0;
    }
  }
  (**(code **)(*DAT_803dd70c + 0x34))(param_1,param_2,0,0,&DAT_803dcb98);
  return 0;
}

