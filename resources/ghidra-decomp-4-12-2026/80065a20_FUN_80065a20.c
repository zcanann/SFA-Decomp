// Function: FUN_80065a20
// Entry: 80065a20
// Size: 260 bytes

/* WARNING: Removing unreachable block (ram,0x80065b08) */
/* WARNING: Removing unreachable block (ram,0x80065a30) */

undefined4
FUN_80065a20(undefined8 param_1,double param_2,double param_3,undefined4 param_4,float *param_5,
            uint param_6)

{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  undefined4 *puVar6;
  int iVar7;
  int iVar8;
  undefined4 *local_28 [5];
  
  iVar4 = FUN_80065fcc(param_1,param_2,param_3,param_4,local_28,0,param_6);
  if (iVar4 == 0) {
    *param_5 = FLOAT_803df934;
    uVar5 = 1;
  }
  else {
    fVar1 = (float)(param_2 - (double)*(float *)*local_28[0]);
    if (fVar1 < FLOAT_803df934) {
      fVar1 = -fVar1;
    }
    iVar8 = 0;
    iVar7 = 1;
    iVar3 = iVar4 + -1;
    puVar6 = local_28[0];
    if (1 < iVar4) {
      do {
        puVar6 = puVar6 + 1;
        fVar2 = (float)(param_2 - (double)*(float *)*puVar6);
        if (fVar2 < FLOAT_803df934) {
          fVar2 = -fVar2;
        }
        if (fVar2 < fVar1) {
          iVar8 = iVar7;
          fVar1 = fVar2;
        }
        iVar7 = iVar7 + 1;
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
    }
    *param_5 = (float)(param_2 - (double)*(float *)local_28[0][iVar8]);
    uVar5 = 0;
  }
  return uVar5;
}

