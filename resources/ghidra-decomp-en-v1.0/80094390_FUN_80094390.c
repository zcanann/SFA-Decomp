// Function: FUN_80094390
// Entry: 80094390
// Size: 260 bytes

undefined4 FUN_80094390(float *param_1,float *param_2)

{
  float fVar1;
  float fVar2;
  double dVar3;
  undefined4 *puVar4;
  undefined4 uVar5;
  int iVar6;
  
  fVar1 = FLOAT_803df2b4;
  if (DAT_8039ab28 == 0) {
    *param_1 = FLOAT_803df2b4;
    *param_2 = fVar1;
    uVar5 = 0;
  }
  else {
    puVar4 = (undefined4 *)FUN_8002b588();
    uVar5 = FUN_80028424(*puVar4,0);
    puVar4 = (undefined4 *)FUN_8004c250(uVar5,0);
    iVar6 = FUN_800394ac(DAT_8039ab28,0,0);
    dVar3 = DOUBLE_803df2b8;
    fVar2 = FLOAT_803df2b4;
    fVar1 = FLOAT_803df2b0;
    if (iVar6 == 0) {
      *param_1 = FLOAT_803df2b4;
      *param_2 = fVar2;
    }
    else {
      *param_1 = FLOAT_803df2b0 *
                 (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 8) ^ 0x80000000) -
                        DOUBLE_803df2b8);
      *param_2 = fVar1 * (float)((double)CONCAT44(0x43300000,
                                                  (int)*(short *)(iVar6 + 10) ^ 0x80000000) - dVar3)
      ;
    }
    uVar5 = FUN_800536c0(*puVar4);
  }
  return uVar5;
}

