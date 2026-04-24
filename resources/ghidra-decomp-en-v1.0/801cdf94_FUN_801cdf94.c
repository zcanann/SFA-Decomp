// Function: FUN_801cdf94
// Entry: 801cdf94
// Size: 228 bytes

void FUN_801cdf94(undefined4 param_1,int param_2,int param_3)

{
  if (((param_3 == 0) || (*(int *)(param_2 + 0x28) == 0)) ||
     (FLOAT_803e5214 <= *(float *)(param_2 + 0x18))) {
    *(undefined *)(param_2 + 0x40c) = 0;
  }
  else {
    *(undefined *)(param_2 + 0x40c) = 1;
    *(undefined4 *)(param_2 + 0x410) = *(undefined4 *)(*(int *)(param_2 + 0x28) + 0xc);
    *(undefined4 *)(param_2 + 0x414) = *(undefined4 *)(*(int *)(param_2 + 0x28) + 0x10);
    *(undefined4 *)(param_2 + 0x418) = *(undefined4 *)(*(int *)(param_2 + 0x28) + 0x14);
  }
  if (((&DAT_803268b4)[*(byte *)(param_2 + 0x408)] & 2) == 0) {
    FUN_8003a230((double)FLOAT_803e520c,param_1,param_2 + 0x40c);
    FUN_8003b310(param_1,param_2 + 0x40c);
  }
  else {
    FUN_8003a168(param_1,param_2 + 0x40c);
    FUN_8003b228(param_1,param_2 + 0x40c);
  }
  return;
}

