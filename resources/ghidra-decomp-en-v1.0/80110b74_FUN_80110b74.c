// Function: FUN_80110b74
// Entry: 80110b74
// Size: 260 bytes

void FUN_80110b74(undefined2 *param_1,undefined4 param_2,undefined2 *param_3)

{
  if (DAT_803dd5c0 == 0) {
    DAT_803dd5c0 = FUN_80023cc8(0x28,0xf,0);
  }
  FUN_800033a8(DAT_803dd5c0,0,0x28);
  *(float *)(DAT_803dd5c0 + 0x10) = FLOAT_803e1b5c;
  *(undefined *)(DAT_803dd5c0 + 0xc) = 0;
  if (param_3 != (undefined2 *)0x0) {
    *(undefined4 *)(param_1 + 6) = *(undefined4 *)(param_3 + 0xc);
    *(undefined4 *)(param_1 + 8) = *(undefined4 *)(param_3 + 0xe);
    *(undefined4 *)(param_1 + 10) = *(undefined4 *)(param_3 + 0x10);
    *param_1 = *param_3;
    param_1[1] = param_3[1];
    param_1[2] = param_3[2];
    *(undefined4 *)(param_1 + 0x5a) = *(undefined4 *)(param_3 + 0x5a);
  }
  *(undefined4 *)(DAT_803dd5c0 + 0x14) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(DAT_803dd5c0 + 0x18) = *(undefined4 *)(param_1 + 0xe);
  *(undefined4 *)(DAT_803dd5c0 + 0x1c) = *(undefined4 *)(param_1 + 0x10);
  *(undefined2 *)(DAT_803dd5c0 + 0x20) = *param_1;
  *(undefined2 *)(DAT_803dd5c0 + 0x22) = param_1[1];
  *(undefined2 *)(DAT_803dd5c0 + 0x24) = param_1[2];
  return;
}

