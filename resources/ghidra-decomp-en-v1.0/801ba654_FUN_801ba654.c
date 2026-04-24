// Function: FUN_801ba654
// Entry: 801ba654
// Size: 300 bytes

undefined4 FUN_801ba654(int param_1,int param_2)

{
  float fVar1;
  
  if (FLOAT_803e4bc0 < *(float *)(param_1 + 0x98)) {
    DAT_803ddb80 = DAT_803ddb80 & 0xffffffdf;
  }
  if (*(char *)(param_2 + 0x27a) != '\0') {
    DAT_803ddb80 = DAT_803ddb80 | 0x8020;
    FUN_8000fad8();
    FUN_8000e650((double)FLOAT_803e4bc4,(double)FLOAT_803e4bc8,(double)FLOAT_803e4bcc);
    FUN_80014aa0((double)FLOAT_803e4bd0);
    *(undefined2 *)(param_1 + 0xa2) = 0xffff;
    *(float *)(param_2 + 0x2a0) =
         FLOAT_803e4bd4 *
         (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x354) + 1U ^ 0x80000000) -
                DOUBLE_803e4be0);
    fVar1 = FLOAT_803e4bd8;
    *(float *)(param_2 + 0x280) = FLOAT_803e4bd8;
    *(float *)(param_2 + 0x284) = fVar1;
    if (*(char *)(param_2 + 0x27a) != '\0') {
      FUN_80030334(param_1,0x15,0);
      *(undefined *)(param_2 + 0x346) = 0;
    }
  }
  (**(code **)(*DAT_803dca8c + 0x34))(param_1,param_2,0,0,&DAT_803dbf30);
  return 0;
}

