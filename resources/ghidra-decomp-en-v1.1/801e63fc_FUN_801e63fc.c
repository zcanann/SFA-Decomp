// Function: FUN_801e63fc
// Entry: 801e63fc
// Size: 276 bytes

void FUN_801e63fc(int param_1)

{
  double dVar1;
  undefined8 local_18;
  
  if (*(short *)(param_1 + 0x46) == 0x187) {
    FUN_8002fb40((double)FLOAT_803e6644,
                 (double)(float)((double)CONCAT44(0x43300000,(uint)DAT_803dc070) - DOUBLE_803e6650))
    ;
  }
  else if (*(short *)(param_1 + 0x46) == 0x803) {
    FUN_8002bac4();
    dVar1 = DOUBLE_803e6638;
    if ((*(ushort *)(*(int *)(param_1 + 0x30) + 0xb0) & 0x1000) == 0) {
      *(float *)(param_1 + 0x24) =
           (float)((double)CONCAT44(0x43300000,
                                    (int)*(short *)(*(int *)(param_1 + 0x30) + 4) ^ 0x80000000) -
                  DOUBLE_803e6638) * FLOAT_803e6634;
      *(short *)(param_1 + 4) =
           (short)(int)((float)((double)CONCAT44(0x43300000,
                                                 (int)*(short *)(param_1 + 4) ^ 0x80000000) - dVar1)
                       + *(float *)(param_1 + 0x24));
    }
    else {
      *(float *)(param_1 + 0x24) = FLOAT_803e6630;
    }
  }
  else {
    local_18 = (double)CONCAT44(0x43300000,(uint)DAT_803dc070);
    FUN_8002fb40((double)FLOAT_803e6648,(double)(float)(local_18 - DOUBLE_803e6650));
  }
  return;
}

