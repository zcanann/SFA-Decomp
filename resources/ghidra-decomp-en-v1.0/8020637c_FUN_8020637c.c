// Function: FUN_8020637c
// Entry: 8020637c
// Size: 240 bytes

void FUN_8020637c(undefined2 *param_1,int param_2)

{
  undefined4 *puVar1;
  
  puVar1 = *(undefined4 **)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(undefined **)(param_1 + 0x5e) = &LAB_80205f40;
  *puVar1 = *(undefined4 *)(param_1 + 8);
  *(undefined *)(puVar1 + 2) = *(undefined *)(param_2 + 0x19);
  if ((int)*(short *)(param_2 + 0x1c) != 0) {
    *(float *)(param_1 + 4) =
         FLOAT_803e63f8 /
         ((float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1c) ^ 0x80000000) -
                 DOUBLE_803e6400) / FLOAT_803e63fc);
  }
  if (*(short *)(param_2 + 0x1a) != 0) {
    param_1[2] = *(short *)(param_2 + 0x1a);
  }
  param_1[0x58] = param_1[0x58] | 0x4000;
  puVar1[1] = 0;
  DAT_803299d8 = 0;
  DAT_803299d9 = 0;
  DAT_803299da = 0;
  DAT_803299db = 0;
  DAT_803299dc = 0;
  DAT_803299dd = 0;
  DAT_803299de = 0;
  DAT_803299df = 0;
  DAT_803299e0 = 0;
  return;
}

