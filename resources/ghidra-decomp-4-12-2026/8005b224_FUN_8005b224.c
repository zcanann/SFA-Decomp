// Function: FUN_8005b224
// Entry: 8005b224
// Size: 196 bytes

/* WARNING: Removing unreachable block (ram,0x8005b2c4) */
/* WARNING: Removing unreachable block (ram,0x8005b234) */

void FUN_8005b224(float *param_1,float *param_2)

{
  float fVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  
  dVar3 = (double)FUN_802925a0();
  dVar4 = (double)FUN_802925a0();
  dVar2 = DOUBLE_803df840;
  fVar1 = FLOAT_803df834;
  *param_1 = FLOAT_803df834 *
             (float)((double)CONCAT44(0x43300000,(int)dVar3 ^ 0x80000000) - DOUBLE_803df840);
  *param_2 = fVar1 * (float)((double)CONCAT44(0x43300000,(int)dVar4 ^ 0x80000000) - dVar2);
  return;
}

