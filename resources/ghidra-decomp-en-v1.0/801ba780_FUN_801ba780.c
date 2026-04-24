// Function: FUN_801ba780
// Entry: 801ba780
// Size: 256 bytes

undefined4 FUN_801ba780(int param_1,int param_2)

{
  float fVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27a) != '\0') {
    DAT_803ddb80 = DAT_803ddb80 | 0x2000;
    FUN_8000fad8();
    FUN_8000e650((double)FLOAT_803e4bc4,(double)FLOAT_803e4bc8,(double)FLOAT_803e4bcc);
    FUN_80014aa0((double)FLOAT_803e4bd0);
    *(undefined2 *)(param_1 + 0xa2) = 0xffff;
    *(float *)(param_2 + 0x2a0) = FLOAT_803e4be8;
    fVar1 = FLOAT_803e4bd8;
    *(float *)(param_2 + 0x280) = FLOAT_803e4bd8;
    *(float *)(param_2 + 0x284) = fVar1;
    if (*(char *)(param_2 + 0x27a) != '\0') {
      FUN_80030334(param_1,0xe,0);
      *(undefined *)(param_2 + 0x346) = 0;
    }
    if (*(short *)(iVar2 + 0x402) == 1) {
      *(float *)(*(int *)(iVar2 + 0x40c) + 0xa8) = FLOAT_803e4bec;
    }
  }
  (**(code **)(*DAT_803dca8c + 0x34))(param_1,param_2,0,1,&DAT_803dbf30);
  return 0;
}

