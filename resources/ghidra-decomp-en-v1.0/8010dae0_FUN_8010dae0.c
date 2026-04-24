// Function: FUN_8010dae0
// Entry: 8010dae0
// Size: 148 bytes

void FUN_8010dae0(undefined2 *param_1,undefined4 param_2,undefined2 *param_3)

{
  if (param_3 != (undefined2 *)0x0) {
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_3 + 0xc);
    *(undefined4 *)(param_1 + 0xe) = *(undefined4 *)(param_3 + 0xe);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_3 + 0x10);
    FUN_8000e034((double)*(float *)(param_3 + 0xc),(double)*(float *)(param_3 + 0xe),
                 (double)*(float *)(param_3 + 0x10),param_1 + 6,param_1 + 8,param_1 + 10,
                 *(undefined4 *)(param_1 + 0x18));
    *param_1 = *param_3;
    param_1[1] = param_3[1];
    param_1[2] = param_3[2];
    *(undefined4 *)(param_1 + 0x5a) = *(undefined4 *)(param_3 + 0x5a);
  }
  return;
}

