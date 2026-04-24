// Function: FUN_80104540
// Entry: 80104540
// Size: 436 bytes

void FUN_80104540(int param_1)

{
  double dVar1;
  float local_28;
  float local_24;
  float local_20;
  float local_1c;
  undefined4 local_18;
  uint uStack20;
  undefined4 local_10;
  uint uStack12;
  
  if (*(short *)((int)DAT_803dd530 + 0x82) != 0) {
    *(ushort *)((int)DAT_803dd530 + 0x82) =
         *(short *)((int)DAT_803dd530 + 0x82) - (ushort)DAT_803db410;
    if (*(short *)((int)DAT_803dd530 + 0x82) < 0) {
      *(undefined2 *)((int)DAT_803dd530 + 0x82) = 0;
    }
    uStack20 = (int)*(short *)(DAT_803dd530 + 0x21) - (int)*(short *)((int)DAT_803dd530 + 0x82) ^
               0x80000000;
    local_18 = 0x43300000;
    uStack12 = (int)*(short *)(DAT_803dd530 + 0x21) ^ 0x80000000;
    local_10 = 0x43300000;
    local_28 = FLOAT_803e16ac;
    local_24 = FLOAT_803e16a4;
    local_20 = FLOAT_803e16ac;
    local_1c = FLOAT_803e16ac;
    dVar1 = (double)FUN_80010dc0((double)((float)((double)CONCAT44(0x43300000,uStack20) -
                                                 DOUBLE_803e1698) /
                                         (float)((double)CONCAT44(0x43300000,uStack12) -
                                                DOUBLE_803e1698)),&local_28,0);
    DAT_803dd530[0x23] =
         (float)(dVar1 * (double)(float)((double)DAT_803dd530[0x25] - (double)DAT_803dd530[0x24]) +
                (double)DAT_803dd530[0x24]);
    *DAT_803dd530 =
         (float)(dVar1 * (double)(float)((double)DAT_803dd530[0xc] - (double)DAT_803dd530[0xb]) +
                (double)DAT_803dd530[0xb]);
    DAT_803dd530[1] =
         (float)(dVar1 * (double)(float)((double)DAT_803dd530[0xe] - (double)DAT_803dd530[0xd]) +
                (double)DAT_803dd530[0xd]);
    DAT_803dd530[2] =
         (float)(dVar1 * (double)(float)((double)DAT_803dd530[0x10] - (double)DAT_803dd530[0xf]) +
                (double)DAT_803dd530[0xf]);
    DAT_803dd530[3] =
         (float)(dVar1 * (double)(float)((double)DAT_803dd530[0x12] - (double)DAT_803dd530[0x11]) +
                (double)DAT_803dd530[0x11]);
    DAT_803dd530[4] =
         (float)(dVar1 * (double)(float)((double)DAT_803dd530[0x14] - (double)DAT_803dd530[0x13]) +
                (double)DAT_803dd530[0x13]);
    DAT_803dd530[5] =
         (float)(dVar1 * (double)(float)((double)DAT_803dd530[0x16] - (double)DAT_803dd530[0x15]) +
                (double)DAT_803dd530[0x15]);
    DAT_803dd530[6] =
         (float)(dVar1 * (double)(float)((double)DAT_803dd530[0x18] - (double)DAT_803dd530[0x17]) +
                (double)DAT_803dd530[0x17]);
    DAT_803dd530[7] =
         (float)(dVar1 * (double)(float)((double)DAT_803dd530[0x1a] - (double)DAT_803dd530[0x19]) +
                (double)DAT_803dd530[0x19]);
    *(float *)(param_1 + 0xb4) =
         (float)(dVar1 * (double)(float)((double)DAT_803dd530[0x1c] - (double)DAT_803dd530[0x1b]) +
                (double)DAT_803dd530[0x1b]);
  }
  return;
}

