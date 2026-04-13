// Function: FUN_802069b4
// Entry: 802069b4
// Size: 240 bytes

void FUN_802069b4(undefined2 *param_1,int param_2)

{
  undefined4 *puVar1;
  
  puVar1 = *(undefined4 **)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(undefined **)(param_1 + 0x5e) = &LAB_80206578;
  *puVar1 = *(undefined4 *)(param_1 + 8);
  *(undefined *)(puVar1 + 2) = *(undefined *)(param_2 + 0x19);
  if ((int)*(short *)(param_2 + 0x1c) != 0) {
    *(float *)(param_1 + 4) =
         FLOAT_803e7090 /
         ((float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1c) ^ 0x80000000) -
                 DOUBLE_803e7098) / FLOAT_803e7094);
  }
  if (*(short *)(param_2 + 0x1a) != 0) {
    param_1[2] = *(short *)(param_2 + 0x1a);
  }
  param_1[0x58] = param_1[0x58] | 0x4000;
  puVar1[1] = 0;
  DAT_8032a618 = 0;
  DAT_8032a619 = 0;
  DAT_8032a61a = 0;
  DAT_8032a61b = 0;
  DAT_8032a61c = 0;
  DAT_8032a61d = 0;
  DAT_8032a61e = 0;
  DAT_8032a61f = 0;
  DAT_8032a620 = 0;
  return;
}

