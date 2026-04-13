// Function: FUN_8010dd7c
// Entry: 8010dd7c
// Size: 148 bytes

void FUN_8010dd7c(undefined2 *param_1,undefined4 param_2,undefined2 *param_3)

{
  if (param_3 != (undefined2 *)0x0) {
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_3 + 0xc);
    *(undefined4 *)(param_1 + 0xe) = *(undefined4 *)(param_3 + 0xe);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_3 + 0x10);
    FUN_8000e054((double)*(float *)(param_3 + 0xc),(double)*(float *)(param_3 + 0xe),
                 (double)*(float *)(param_3 + 0x10),(float *)(param_1 + 6),(float *)(param_1 + 8),
                 (float *)(param_1 + 10),*(int *)(param_1 + 0x18));
    *param_1 = *param_3;
    param_1[1] = param_3[1];
    param_1[2] = param_3[2];
    *(undefined4 *)(param_1 + 0x5a) = *(undefined4 *)(param_3 + 0x5a);
  }
  return;
}

