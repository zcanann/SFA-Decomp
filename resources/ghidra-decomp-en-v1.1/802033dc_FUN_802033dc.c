// Function: FUN_802033dc
// Entry: 802033dc
// Size: 332 bytes

/* WARNING: Removing unreachable block (ram,0x80203504) */
/* WARNING: Removing unreachable block (ram,0x802034fc) */
/* WARNING: Removing unreachable block (ram,0x802034f4) */
/* WARNING: Removing unreachable block (ram,0x802033fc) */
/* WARNING: Removing unreachable block (ram,0x802033f4) */
/* WARNING: Removing unreachable block (ram,0x802033ec) */

undefined4
FUN_802033dc(double param_1,double param_2,undefined8 param_3,double param_4,ushort *param_5,
            int param_6)

{
  int iVar1;
  int iVar2;
  double dVar3;
  float local_58 [7];
  
  iVar2 = *(int *)(param_5 + 0x5c);
  if ((param_5 != (ushort *)0x0) && (param_6 != 0)) {
    iVar1 = FUN_800386e0(param_5,param_6,local_58);
    if ((double)FLOAT_803e6f40 != param_4) {
      if ((double)local_58[0] < param_1) {
        dVar3 = (double)(*(float *)(param_5 + 8) - *(float *)(param_6 + 0x10));
        if (dVar3 < (double)FLOAT_803e6f40) {
          dVar3 = -dVar3;
        }
        if (dVar3 < (double)FLOAT_803e7010) {
          return 1;
        }
      }
      *(float *)(iVar2 + 0x280) =
           FLOAT_803dc074 * FLOAT_803e6fe4 *
           ((float)(param_2 *
                   (double)(FLOAT_803e6f60 -
                           (float)((double)CONCAT44(0x43300000,(int)(short)iVar1 ^ 0x80000000) -
                                  DOUBLE_803e7000) / FLOAT_803e700c)) - *(float *)(iVar2 + 0x280)) +
           *(float *)(iVar2 + 0x280);
      *(float *)(iVar2 + 0x284) = FLOAT_803e6f40;
    }
  }
  return 0;
}

