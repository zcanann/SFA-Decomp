// Function: FUN_80065800
// Entry: 80065800
// Size: 228 bytes

/* WARNING: Removing unreachable block (ram,0x800658c8) */
/* WARNING: Removing unreachable block (ram,0x80065810) */

undefined4
FUN_80065800(undefined8 param_1,double param_2,double param_3,undefined4 param_4,float *param_5,
            uint param_6)

{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  undefined4 *local_28 [5];
  
  iVar4 = FUN_80065fcc(param_1,param_2,param_3,param_4,local_28,0,param_6);
  if (iVar4 == 0) {
    *param_5 = FLOAT_803df934;
    uVar5 = 0;
  }
  else {
    fVar1 = (float)(param_2 - (double)*(float *)*local_28[0]);
    iVar3 = iVar4 + -1;
    if (1 < iVar4) {
      do {
        local_28[0] = local_28[0] + 1;
        fVar2 = (float)(param_2 - (double)*(float *)*local_28[0]);
        if ((FLOAT_803df934 <= fVar2) && ((fVar1 < FLOAT_803df934 || (fVar2 < fVar1)))) {
          fVar1 = fVar2;
        }
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
    }
    if (fVar1 < FLOAT_803df934) {
      *param_5 = FLOAT_803df934;
      uVar5 = 0;
    }
    else {
      *param_5 = fVar1;
      uVar5 = 1;
    }
  }
  return uVar5;
}

