// Function: FUN_8015e520
// Entry: 8015e520
// Size: 188 bytes

undefined4 FUN_8015e520(int param_1,int param_2)

{
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80035f20();
  }
  FUN_80035df4(param_1,10,1,0xffffffff);
  *(undefined *)(*(int *)(param_1 + 0x54) + 0x6c) = 10;
  *(undefined *)(*(int *)(param_1 + 0x54) + 0x6d) = 1;
  FUN_8003393c(param_1);
  *(float *)(param_2 + 0x2a0) = FLOAT_803e2dd8;
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e2dc8,param_1,5,0);
    *(undefined *)(param_2 + 0x346) = 0;
  }
  *(undefined *)(param_2 + 0x34d) = 1;
  return 0;
}

