// Function: FUN_80226950
// Entry: 80226950
// Size: 236 bytes

/* WARNING: Removing unreachable block (ram,0x80226a1c) */
/* WARNING: Removing unreachable block (ram,0x80226a14) */
/* WARNING: Removing unreachable block (ram,0x80226968) */
/* WARNING: Removing unreachable block (ram,0x80226960) */

void FUN_80226950(double param_1,double param_2,undefined4 param_3,short *param_4,short *param_5)

{
  int iVar1;
  float local_48;
  float local_44 [7];
  
  FUN_8005b224(local_44,&local_48);
  iVar1 = (int)(short)(int)((float)(param_1 - (double)local_44[0]) - FLOAT_803e7a50);
  iVar1 = iVar1 / 0x30 + (iVar1 >> 0x1f);
  *param_4 = (short)iVar1 - (short)(iVar1 >> 0x1f);
  iVar1 = (int)(short)(int)((float)(param_2 - (double)local_48) - FLOAT_803e7a58);
  iVar1 = iVar1 / 0x30 + (iVar1 >> 0x1f);
  *param_5 = (short)iVar1 - (short)(iVar1 >> 0x1f);
  return;
}

