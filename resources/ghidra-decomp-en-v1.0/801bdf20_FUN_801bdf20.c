// Function: FUN_801bdf20
// Entry: 801bdf20
// Size: 92 bytes

undefined4 FUN_801bdf20(undefined4 param_1,int param_2)

{
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e4c90,param_1,0,0);
    *(undefined *)(param_2 + 0x346) = 0;
  }
  *(float *)(param_2 + 0x2a0) = FLOAT_803e4c98;
  return 0;
}

