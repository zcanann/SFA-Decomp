// Function: FUN_802032b0
// Entry: 802032b0
// Size: 300 bytes

/* WARNING: Removing unreachable block (ram,0x802033c0) */
/* WARNING: Removing unreachable block (ram,0x802033b8) */
/* WARNING: Removing unreachable block (ram,0x802033b0) */
/* WARNING: Removing unreachable block (ram,0x802032d0) */
/* WARNING: Removing unreachable block (ram,0x802032c8) */
/* WARNING: Removing unreachable block (ram,0x802032c0) */

undefined4
FUN_802032b0(double param_1,double param_2,undefined8 param_3,double param_4,ushort *param_5,
            int param_6)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  float local_48 [5];
  
  iVar3 = *(int *)(param_5 + 0x5c);
  iVar1 = FUN_800386e0(param_5,param_6,local_48);
  if ((double)FLOAT_803e6f40 == param_4) {
    uVar2 = 0;
  }
  else {
    dVar5 = (double)(float)((double)(float)((double)local_48[0] - param_1) / param_4);
    dVar4 = dVar5;
    if (dVar5 < (double)FLOAT_803e6f40) {
      dVar4 = -dVar5;
    }
    if ((double)FLOAT_803e7008 <= dVar4) {
      if (dVar5 < (double)FLOAT_803e6f40) {
        param_2 = -param_2;
      }
      *(float *)(iVar3 + 0x280) =
           FLOAT_803dc074 * FLOAT_803e6fe4 *
           ((float)(param_2 *
                   (double)(FLOAT_803e6f60 -
                           (float)((double)CONCAT44(0x43300000,(int)(short)iVar1 ^ 0x80000000) -
                                  DOUBLE_803e7000) / FLOAT_803e700c)) - *(float *)(iVar3 + 0x280)) +
           *(float *)(iVar3 + 0x280);
      *(float *)(iVar3 + 0x284) = FLOAT_803e6f40;
      uVar2 = 0;
    }
    else {
      uVar2 = 1;
    }
  }
  return uVar2;
}

