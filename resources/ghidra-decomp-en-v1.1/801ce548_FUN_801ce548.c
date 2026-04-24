// Function: FUN_801ce548
// Entry: 801ce548
// Size: 228 bytes

void FUN_801ce548(short *param_1,int param_2,int param_3)

{
  if (((param_3 == 0) || (*(int *)(param_2 + 0x28) == 0)) ||
     (FLOAT_803e5eac <= *(float *)(param_2 + 0x18))) {
    *(undefined *)(param_2 + 0x40c) = 0;
  }
  else {
    *(undefined *)(param_2 + 0x40c) = 1;
    *(undefined4 *)(param_2 + 0x410) = *(undefined4 *)(*(int *)(param_2 + 0x28) + 0xc);
    *(undefined4 *)(param_2 + 0x414) = *(undefined4 *)(*(int *)(param_2 + 0x28) + 0x10);
    *(undefined4 *)(param_2 + 0x418) = *(undefined4 *)(*(int *)(param_2 + 0x28) + 0x14);
  }
  if (((&DAT_803274f4)[*(byte *)(param_2 + 0x408)] & 2) == 0) {
    FUN_8003a328((double)FLOAT_803e5ea4,param_1,(char *)(param_2 + 0x40c));
    FUN_8003b408((int)param_1,param_2 + 0x40c);
  }
  else {
    FUN_8003a260((int)param_1,param_2 + 0x40c);
    FUN_8003b320((int)param_1,param_2 + 0x40c);
  }
  return;
}

