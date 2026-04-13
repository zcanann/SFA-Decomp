// Function: FUN_80070580
// Entry: 80070580
// Size: 216 bytes

/* WARNING: Removing unreachable block (ram,0x80070640) */
/* WARNING: Removing unreachable block (ram,0x80070638) */
/* WARNING: Removing unreachable block (ram,0x80070598) */
/* WARNING: Removing unreachable block (ram,0x80070590) */

void FUN_80070580(double param_1,double param_2)

{
  double dVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  double in_f30;
  double in_f31;
  double in_ps30_1;
  double in_ps31_1;
  uint3 local_28 [4];
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  dVar1 = FUN_8000fc3c();
  FLOAT_803ddcb8 = (float)dVar1;
  dVar1 = FUN_8000fc08();
  FLOAT_803ddcb4 = (float)dVar1;
  dVar2 = (double)(float)((double)FLOAT_803dfb58 * param_1);
  dVar3 = (double)(float)((double)FLOAT_803dfb58 * param_2);
  dVar1 = (double)FLOAT_803dfb5c;
  if ((dVar1 <= dVar2) && (dVar1 = dVar2, (double)FLOAT_803dfb60 < dVar2)) {
    dVar1 = (double)FLOAT_803dfb60;
  }
  dVar2 = (double)FLOAT_803dfb5c;
  if ((dVar2 <= dVar3) && (dVar2 = dVar3, (double)FLOAT_803dfb60 < dVar3)) {
    dVar2 = (double)FLOAT_803dfb60;
  }
  dVar3 = (double)FLOAT_803ddcb8;
  dVar4 = (double)(float)((double)FLOAT_803ddcb4 - dVar3);
  FLOAT_803ddca4 = (float)(dVar1 * dVar4 + dVar3);
  FLOAT_803ddca0 = (float)(dVar2 * dVar4 + dVar3);
  local_28[0]._0_4_ = DAT_803ddc9c;
  FUN_8025ca38((double)FLOAT_803ddca4,(double)FLOAT_803ddca0,dVar3,(double)FLOAT_803ddcb4,4,local_28
              );
  return;
}

