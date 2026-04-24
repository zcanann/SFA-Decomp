// Function: FUN_800658e4
// Entry: 800658e4
// Size: 316 bytes

/* WARNING: Removing unreachable block (ram,0x80065a00) */
/* WARNING: Removing unreachable block (ram,0x800658f4) */

undefined4
FUN_800658e4(undefined8 param_1,double param_2,double param_3,undefined4 param_4,float *param_5,
            undefined4 *param_6,uint param_7)

{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  undefined4 *puVar6;
  int iVar7;
  int iVar8;
  undefined4 *local_28 [4];
  
  iVar4 = FUN_80065fcc(param_1,param_2,param_3,param_4,local_28,0,param_7);
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
    *param_6 = *(undefined4 *)(local_28[0][iVar8] + 4);
    param_6[1] = *(undefined4 *)(local_28[0][iVar8] + 8);
    param_6[2] = *(undefined4 *)(local_28[0][iVar8] + 0xc);
    uVar5 = 0;
  }
  return uVar5;
}

