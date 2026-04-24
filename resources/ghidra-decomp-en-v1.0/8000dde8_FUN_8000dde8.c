// Function: FUN_8000dde8
// Entry: 8000dde8
// Size: 204 bytes

void FUN_8000dde8(short *param_1)

{
  short *psVar1;
  
  psVar1 = *(short **)(param_1 + 0x20);
  if (psVar1 == (short *)0x0) {
    *(undefined4 *)(param_1 + 0x22) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(param_1 + 0x24) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(param_1 + 0x26) = *(undefined4 *)(param_1 + 10);
    param_1[0x28] = *param_1;
    param_1[0x29] = param_1[1];
    param_1[0x2a] = param_1[2];
  }
  else {
    FUN_800226cc((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
                 (double)*(float *)(param_1 + 10),*(char *)((int)psVar1 + 0x35) * 0x40 + -0x7fcc87f0
                 ,param_1 + 0x22,param_1 + 0x24,param_1 + 0x26);
    param_1[0x28] = *param_1 - *psVar1;
    param_1[0x29] = param_1[1];
    param_1[0x2a] = param_1[2];
  }
  return;
}

