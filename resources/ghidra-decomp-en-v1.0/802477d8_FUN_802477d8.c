// Function: FUN_802477d8
// Entry: 802477d8
// Size: 24 bytes

/* WARNING: Removing unreachable block (ram,0x802477d8) */

undefined8 FUN_802477d8(int param_1)

{
  float fVar1;
  float fVar2;
  float fVar3;
  
  fVar1 = (float)__psq_l0(param_1,0);
  fVar2 = (float)__psq_l1(param_1,0);
  fVar3 = (float)((ulonglong)(double)*(float *)(param_1 + 8) >> 0x20);
  return CONCAT44(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2,fVar2 * fVar2);
}

