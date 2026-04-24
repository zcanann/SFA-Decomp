// Function: FUN_801c0b34
// Entry: 801c0b34
// Size: 196 bytes

void FUN_801c0b34(short *param_1,int param_2)

{
  if (*(short *)(param_2 + 0x1c) == -1) {
    FUN_80037200(param_1,0x14);
    **(undefined **)(param_1 + 0x5c) = 1;
  }
  *param_1 = (ushort)*(byte *)(param_2 + 0x18) << 8;
  *(undefined4 *)(param_1 + 4) = *(undefined4 *)(*(int *)(param_1 + 0x28) + 4);
  *(float *)(param_1 + 4) =
       (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x19)) - DOUBLE_803e4dd8) *
       FLOAT_803e4dd0 + *(float *)(param_1 + 4);
  if (*(float *)(param_1 + 4) < FLOAT_803e4dd4) {
    *(float *)(param_1 + 4) = FLOAT_803e4dd4;
  }
  if (*(char *)(param_2 + 0x1a) == '\0') {
    *(undefined *)(param_2 + 0x1a) = 0xff;
  }
  return;
}

