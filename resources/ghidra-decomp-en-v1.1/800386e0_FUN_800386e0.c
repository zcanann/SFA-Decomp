// Function: FUN_800386e0
// Entry: 800386e0
// Size: 212 bytes

/* WARNING: Removing unreachable block (ram,0x80038790) */
/* WARNING: Removing unreachable block (ram,0x80038788) */
/* WARNING: Removing unreachable block (ram,0x800386f8) */
/* WARNING: Removing unreachable block (ram,0x800386f0) */

int FUN_800386e0(ushort *param_1,int param_2,float *param_3)

{
  int iVar1;
  double dVar2;
  double dVar3;
  
  dVar3 = (double)(*(float *)(param_1 + 6) - *(float *)(param_2 + 0xc));
  dVar2 = (double)(*(float *)(param_1 + 10) - *(float *)(param_2 + 0x14));
  iVar1 = FUN_80021884();
  if (param_3 != (float *)0x0) {
    dVar2 = FUN_80293900((double)(float)(dVar3 * dVar3 + (double)(float)(dVar2 * dVar2)));
    *param_3 = (float)dVar2;
  }
  iVar1 = (int)(short)iVar1 - (uint)*param_1;
  if (0x8000 < iVar1) {
    iVar1 = iVar1 + -0xffff;
  }
  if (iVar1 < -0x8000) {
    iVar1 = iVar1 + 0xffff;
  }
  return (int)(short)iVar1;
}

