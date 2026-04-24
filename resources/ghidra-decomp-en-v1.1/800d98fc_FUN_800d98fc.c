// Function: FUN_800d98fc
// Entry: 800d98fc
// Size: 412 bytes

/* WARNING: Removing unreachable block (ram,0x800d9a74) */
/* WARNING: Removing unreachable block (ram,0x800d990c) */

void FUN_800d98fc(int param_1,uint *param_2,int param_3)

{
  double dVar1;
  double dVar2;
  
  if ((*(byte *)(param_2 + 0xd3) & 1) != 0) {
    dVar1 = (double)FUN_802945e0();
    dVar2 = (double)FUN_80294964();
    if ((*(byte *)(param_2 + 0xd3) & 8) == 0) {
      param_2[0xa1] =
           (uint)(float)((double)*(float *)(param_1 + 0x24) * dVar2 -
                        (double)(float)((double)*(float *)(param_1 + 0x2c) * dVar1));
      param_2[0xa0] =
           (uint)(float)(-(double)*(float *)(param_1 + 0x2c) * dVar2 -
                        (double)(float)((double)*(float *)(param_1 + 0x24) * dVar1));
      if ((*(byte *)(param_2 + 0xd3) & 4) != 0) {
        dVar1 = FUN_80293900((double)(*(float *)(param_1 + 0x24) * *(float *)(param_1 + 0x24) +
                                     *(float *)(param_1 + 0x2c) * *(float *)(param_1 + 0x2c)));
        param_2[0xa5] = (uint)(float)dVar1;
      }
    }
    else {
      param_2[0xa0] =
           (uint)(float)(-(double)*(float *)(param_1 + 0x2c) * dVar2 -
                        (double)(float)((double)*(float *)(param_1 + 0x24) * dVar1));
      param_2[0xa5] = param_2[0xa0];
    }
    *(undefined *)(param_2 + 0xd3) = 0;
    *param_2 = *param_2 | 0x80000;
    DAT_803de0b4 = 1;
    DAT_803de0cf = 0;
    DAT_803de0ce = 1;
    FUN_800d955c(param_1,param_2,param_3);
  }
  return;
}

