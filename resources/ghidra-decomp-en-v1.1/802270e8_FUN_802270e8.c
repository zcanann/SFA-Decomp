// Function: FUN_802270e8
// Entry: 802270e8
// Size: 236 bytes

/* WARNING: Removing unreachable block (ram,0x802271b4) */
/* WARNING: Removing unreachable block (ram,0x802271ac) */
/* WARNING: Removing unreachable block (ram,0x80227100) */
/* WARNING: Removing unreachable block (ram,0x802270f8) */

void FUN_802270e8(double param_1,double param_2,undefined4 param_3,short *param_4,short *param_5)

{
  int iVar1;
  float local_48;
  float local_44 [7];
  
  FUN_8005b224(local_44,&local_48);
  iVar1 = (int)(short)(int)((float)(param_1 - (double)local_44[0]) - FLOAT_803e7a68);
  iVar1 = iVar1 / 0x30 + (iVar1 >> 0x1f);
  *param_4 = (short)iVar1 - (short)(iVar1 >> 0x1f);
  iVar1 = (int)(short)(int)((float)(param_2 - (double)local_48) - FLOAT_803e7a6c);
  iVar1 = iVar1 / 0x30 + (iVar1 >> 0x1f);
  *param_5 = (short)iVar1 - (short)(iVar1 >> 0x1f);
  return;
}

