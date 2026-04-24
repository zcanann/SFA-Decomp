// Function: FUN_801e5e0c
// Entry: 801e5e0c
// Size: 276 bytes

void FUN_801e5e0c(int param_1)

{
  double dVar1;
  double local_18;
  
  if (*(short *)(param_1 + 0x46) == 0x187) {
    FUN_8002fa48((double)FLOAT_803e59ac,
                 (double)(float)((double)CONCAT44(0x43300000,(uint)DAT_803db410) - DOUBLE_803e59b8),
                 param_1,0);
  }
  else if (*(short *)(param_1 + 0x46) == 0x803) {
    FUN_8002b9ec();
    dVar1 = DOUBLE_803e59a0;
    if ((*(ushort *)(*(int *)(param_1 + 0x30) + 0xb0) & 0x1000) == 0) {
      *(float *)(param_1 + 0x24) =
           (float)((double)CONCAT44(0x43300000,
                                    (int)*(short *)(*(int *)(param_1 + 0x30) + 4) ^ 0x80000000) -
                  DOUBLE_803e59a0) * FLOAT_803e599c;
      *(short *)(param_1 + 4) =
           (short)(int)((float)((double)CONCAT44(0x43300000,
                                                 (int)*(short *)(param_1 + 4) ^ 0x80000000) - dVar1)
                       + *(float *)(param_1 + 0x24));
    }
    else {
      *(float *)(param_1 + 0x24) = FLOAT_803e5998;
    }
  }
  else {
    local_18 = (double)CONCAT44(0x43300000,(uint)DAT_803db410);
    FUN_8002fa48((double)FLOAT_803e59b0,(double)(float)(local_18 - DOUBLE_803e59b8),param_1,0);
  }
  return;
}

