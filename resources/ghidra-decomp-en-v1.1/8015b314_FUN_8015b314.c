// Function: FUN_8015b314
// Entry: 8015b314
// Size: 168 bytes

void FUN_8015b314(int param_1,int param_2)

{
  float fVar1;
  int iVar2;
  
  *(float *)(param_2 + 0x2ac) = FLOAT_803e3980;
  *(char *)(param_2 + 0x33b) = (char)(int)*(float *)(param_2 + 0x2a8);
  *(float *)(param_2 + 0x2a8) = FLOAT_803e3984;
  *(undefined4 *)(param_2 + 0x2e4) = 0x42001;
  *(float *)(param_2 + 0x308) = FLOAT_803e3988;
  *(float *)(param_2 + 0x300) = FLOAT_803e398c;
  *(float *)(param_2 + 0x304) = FLOAT_803e3990;
  *(undefined *)(param_2 + 800) = 0;
  fVar1 = FLOAT_803e3994;
  *(float *)(param_2 + 0x314) = FLOAT_803e3994;
  *(undefined *)(param_2 + 0x321) = 5;
  *(float *)(param_2 + 0x318) = fVar1;
  *(undefined *)(param_2 + 0x322) = 7;
  *(float *)(param_2 + 0x31c) = fVar1;
  *(undefined *)(param_2 + 0x33a) = 1;
  *(undefined *)(param_2 + 0x33b) = 0;
  iVar2 = FUN_8002b660(param_1);
  FUN_80028600(iVar2,FUN_8007068c);
  return;
}

