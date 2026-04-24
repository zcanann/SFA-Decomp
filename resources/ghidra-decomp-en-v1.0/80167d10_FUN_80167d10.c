// Function: FUN_80167d10
// Entry: 80167d10
// Size: 148 bytes

undefined4 FUN_80167d10(short *param_1,int param_2)

{
  bool bVar1;
  
  bVar1 = *(char *)(param_2 + 0x27a) != '\0';
  if (bVar1) {
    if (bVar1) {
      FUN_80030334((double)FLOAT_803e3060,param_1,8,0);
      *(undefined *)(param_2 + 0x346) = 0;
    }
    FUN_8000bb18(param_1,0x277);
  }
  *param_1 = *param_1 + 0x222;
  *(undefined *)(param_2 + 0x34d) = 1;
  *(float *)(param_2 + 0x2a0) = FLOAT_803e3090;
  *(float *)(param_2 + 0x280) = FLOAT_803e3060;
  return 0;
}

