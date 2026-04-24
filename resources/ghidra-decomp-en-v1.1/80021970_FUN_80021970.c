// Function: FUN_80021970
// Entry: 80021970
// Size: 540 bytes

/* WARNING: Removing unreachable block (ram,0x80021b6c) */
/* WARNING: Removing unreachable block (ram,0x80021b64) */
/* WARNING: Removing unreachable block (ram,0x80021b5c) */
/* WARNING: Removing unreachable block (ram,0x80021b54) */
/* WARNING: Removing unreachable block (ram,0x80021b4c) */
/* WARNING: Removing unreachable block (ram,0x800219a0) */
/* WARNING: Removing unreachable block (ram,0x80021998) */
/* WARNING: Removing unreachable block (ram,0x80021990) */
/* WARNING: Removing unreachable block (ram,0x80021988) */
/* WARNING: Removing unreachable block (ram,0x80021980) */

void FUN_80021970(undefined4 param_1,float *param_2)

{
  double dVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  
  dVar6 = (double)*param_2;
  dVar5 = (double)param_2[1];
  dVar4 = (double)param_2[2];
  dVar1 = (double)FUN_802945e0();
  dVar2 = (double)(float)(dVar6 * dVar1);
  dVar3 = (double)(float)(dVar4 * dVar1);
  dVar1 = (double)FUN_80294964();
  dVar6 = (double)(float)((double)(float)(dVar6 * dVar1) + dVar3);
  dVar4 = (double)(float)((double)(float)(dVar4 * dVar1) - dVar2);
  dVar1 = (double)FUN_802945e0();
  dVar3 = (double)(float)(dVar5 * dVar1);
  dVar2 = (double)(float)(dVar4 * dVar1);
  dVar1 = (double)FUN_80294964();
  dVar5 = (double)(float)((double)(float)(dVar5 * dVar1) - dVar2);
  dVar4 = (double)(float)((double)(float)(dVar4 * dVar1) + dVar3);
  dVar1 = (double)FUN_802945e0();
  dVar3 = (double)(float)(dVar6 * dVar1);
  dVar2 = (double)(float)(dVar5 * dVar1);
  dVar1 = (double)FUN_80294964();
  *param_2 = (float)((double)(float)(dVar6 * dVar1) - dVar2);
  param_2[1] = (float)((double)(float)(dVar5 * dVar1) + dVar3);
  param_2[2] = (float)dVar4;
  return;
}

