// Function: FUN_8009ab54
// Entry: 8009ab54
// Size: 164 bytes

/* WARNING: Removing unreachable block (ram,0x8009abdc) */
/* WARNING: Removing unreachable block (ram,0x8009ab64) */

void FUN_8009ab54(double param_1,int param_2)

{
  int iVar1;
  double dVar2;
  
  iVar1 = FUN_8002bac4();
  if (((iVar1 != 0) && ((*(ushort *)(iVar1 + 0xb0) & 0x1000) == 0)) &&
     (dVar2 = (double)FUN_8000f4a0((double)*(float *)(param_2 + 0x18),
                                   (double)*(float *)(param_2 + 0x1c),
                                   (double)*(float *)(param_2 + 0x20)), dVar2 <= param_1)) {
    dVar2 = (double)(FLOAT_803dffd4 - (float)(dVar2 / param_1));
    FUN_8000e670((double)(float)((double)FLOAT_803e0020 * dVar2),
                 (double)(float)((double)FLOAT_803e0004 * dVar2),(double)FLOAT_803e0024);
    FUN_80014acc((double)(float)((double)FLOAT_803e0028 * dVar2));
  }
  return;
}

