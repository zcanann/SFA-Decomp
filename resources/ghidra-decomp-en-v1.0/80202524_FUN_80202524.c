// Function: FUN_80202524
// Entry: 80202524
// Size: 156 bytes

undefined4 FUN_80202524(undefined4 param_1,int param_2)

{
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80035f20();
  }
  FUN_80035df4(param_1,10,1,0xffffffff);
  *(float *)(param_2 + 0x2a0) = FLOAT_803e62f4;
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e62a8,param_1,5,0);
    *(undefined *)(param_2 + 0x346) = 0;
  }
  *(undefined *)(param_2 + 0x34d) = 1;
  return 0;
}

