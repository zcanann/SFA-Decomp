// Function: FUN_800deb74
// Entry: 800deb74
// Size: 428 bytes

void FUN_800deb74(int param_1,int param_2)

{
  double dVar1;
  
  if ((param_2 != 0) && (param_2 != *(int *)(param_1 + 0xa4))) {
    *(int *)(param_1 + 0xa4) = param_2;
    *(undefined4 *)(param_1 + 0xbc) = *(undefined4 *)(*(int *)(param_1 + 0xa4) + 8);
    dVar1 = (double)FUN_802945e0();
    *(float *)(param_1 + 0xc4) =
         FLOAT_803e1290 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)(*(int *)(param_1 + 0xa4) + 0x2e))
                                - DOUBLE_803e12a8) * dVar1);
    *(undefined4 *)(param_1 + 0xdc) = *(undefined4 *)(*(int *)(param_1 + 0xa4) + 0xc);
    dVar1 = (double)FUN_802945e0();
    *(float *)(param_1 + 0xe4) =
         FLOAT_803e1290 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)(*(int *)(param_1 + 0xa4) + 0x2e))
                                - DOUBLE_803e12a8) * dVar1);
    *(undefined4 *)(param_1 + 0xfc) = *(undefined4 *)(*(int *)(param_1 + 0xa4) + 0x10);
    dVar1 = (double)FUN_80294964();
    *(float *)(param_1 + 0x104) =
         FLOAT_803e1290 *
         (float)((double)(float)((double)CONCAT44(0x43300000,
                                                  (uint)*(byte *)(*(int *)(param_1 + 0xa4) + 0x2e))
                                - DOUBLE_803e12a8) * dVar1);
  }
  return;
}

