// Function: FUN_801ba880
// Entry: 801ba880
// Size: 216 bytes

undefined4 FUN_801ba880(undefined4 param_1,int param_2)

{
  float fVar1;
  
  *(float *)(param_2 + 0x2a0) = FLOAT_803e4bf0;
  fVar1 = FLOAT_803e4bd8;
  *(float *)(param_2 + 0x280) = FLOAT_803e4bd8;
  *(float *)(param_2 + 0x284) = fVar1;
  FUN_80035df4(param_1,10,1,0xffffffff);
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e4bd8,param_1,0xf,0);
    *(undefined *)(param_2 + 0x346) = 0;
  }
  if ((*(uint *)(param_2 + 0x314) & 1) != 0) {
    DAT_803ddb80 = DAT_803ddb80 | 0x4004;
    FUN_8000bb18(param_1,0x17d);
    FUN_8000fad8();
    FUN_8000e650((double)FLOAT_803e4bc8,(double)FLOAT_803e4bf4,(double)FLOAT_803e4bf8);
    FUN_80014aa0((double)FLOAT_803e4bfc);
    FUN_800200e8(0x26b,1);
  }
  return 0;
}

