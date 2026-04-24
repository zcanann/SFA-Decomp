// Function: FUN_802347a8
// Entry: 802347a8
// Size: 248 bytes

void FUN_802347a8(short *param_1)

{
  double dVar1;
  int iVar2;
  
  dVar1 = DOUBLE_803e7268;
  iVar2 = *(int *)(param_1 + 0x26);
  *param_1 = (short)(int)((float)((double)CONCAT44(0x43300000,
                                                   (int)*(short *)(iVar2 + 0x20) ^ 0x80000000) -
                                 DOUBLE_803e7268) * FLOAT_803db414 +
                         (float)((double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000) -
                                DOUBLE_803e7268));
  param_1[1] = (short)(int)((float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)(iVar2 + 0x22) ^ 0x80000000) -
                                   dVar1) * FLOAT_803db414 +
                           (float)((double)CONCAT44(0x43300000,(int)param_1[1] ^ 0x80000000) - dVar1
                                  ));
  param_1[2] = (short)(int)((float)((double)CONCAT44(0x43300000,
                                                     (int)*(char *)(iVar2 + 0x35) << 4 ^ 0x80000000)
                                   - dVar1) * FLOAT_803db414 +
                           (float)((double)CONCAT44(0x43300000,(int)param_1[2] ^ 0x80000000) - dVar1
                                  ));
  return;
}

