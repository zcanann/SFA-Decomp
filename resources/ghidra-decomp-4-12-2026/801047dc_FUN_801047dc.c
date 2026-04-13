// Function: FUN_801047dc
// Entry: 801047dc
// Size: 436 bytes

void FUN_801047dc(int param_1)

{
  double dVar1;
  float local_28;
  float local_24;
  float local_20;
  float local_1c;
  undefined4 local_18;
  uint uStack_14;
  undefined4 local_10;
  uint uStack_c;
  
  if (*(short *)((int)DAT_803de1a8 + 0x82) != 0) {
    *(ushort *)((int)DAT_803de1a8 + 0x82) =
         *(short *)((int)DAT_803de1a8 + 0x82) - (ushort)DAT_803dc070;
    if (*(short *)((int)DAT_803de1a8 + 0x82) < 0) {
      *(undefined2 *)((int)DAT_803de1a8 + 0x82) = 0;
    }
    uStack_14 = (int)*(short *)(DAT_803de1a8 + 0x21) - (int)*(short *)((int)DAT_803de1a8 + 0x82) ^
                0x80000000;
    local_18 = 0x43300000;
    uStack_c = (int)*(short *)(DAT_803de1a8 + 0x21) ^ 0x80000000;
    local_10 = 0x43300000;
    local_28 = FLOAT_803e232c;
    local_24 = FLOAT_803e2324;
    local_20 = FLOAT_803e232c;
    local_1c = FLOAT_803e232c;
    dVar1 = FUN_80010de0((double)((float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e2318)
                                 / (float)((double)CONCAT44(0x43300000,uStack_c) - DOUBLE_803e2318))
                         ,&local_28,(float *)0x0);
    DAT_803de1a8[0x23] =
         (float)(dVar1 * (double)(float)((double)DAT_803de1a8[0x25] - (double)DAT_803de1a8[0x24]) +
                (double)DAT_803de1a8[0x24]);
    *DAT_803de1a8 =
         (float)(dVar1 * (double)(float)((double)DAT_803de1a8[0xc] - (double)DAT_803de1a8[0xb]) +
                (double)DAT_803de1a8[0xb]);
    DAT_803de1a8[1] =
         (float)(dVar1 * (double)(float)((double)DAT_803de1a8[0xe] - (double)DAT_803de1a8[0xd]) +
                (double)DAT_803de1a8[0xd]);
    DAT_803de1a8[2] =
         (float)(dVar1 * (double)(float)((double)DAT_803de1a8[0x10] - (double)DAT_803de1a8[0xf]) +
                (double)DAT_803de1a8[0xf]);
    DAT_803de1a8[3] =
         (float)(dVar1 * (double)(float)((double)DAT_803de1a8[0x12] - (double)DAT_803de1a8[0x11]) +
                (double)DAT_803de1a8[0x11]);
    DAT_803de1a8[4] =
         (float)(dVar1 * (double)(float)((double)DAT_803de1a8[0x14] - (double)DAT_803de1a8[0x13]) +
                (double)DAT_803de1a8[0x13]);
    DAT_803de1a8[5] =
         (float)(dVar1 * (double)(float)((double)DAT_803de1a8[0x16] - (double)DAT_803de1a8[0x15]) +
                (double)DAT_803de1a8[0x15]);
    DAT_803de1a8[6] =
         (float)(dVar1 * (double)(float)((double)DAT_803de1a8[0x18] - (double)DAT_803de1a8[0x17]) +
                (double)DAT_803de1a8[0x17]);
    DAT_803de1a8[7] =
         (float)(dVar1 * (double)(float)((double)DAT_803de1a8[0x1a] - (double)DAT_803de1a8[0x19]) +
                (double)DAT_803de1a8[0x19]);
    *(float *)(param_1 + 0xb4) =
         (float)(dVar1 * (double)(float)((double)DAT_803de1a8[0x1c] - (double)DAT_803de1a8[0x1b]) +
                (double)DAT_803de1a8[0x1b]);
  }
  return;
}

