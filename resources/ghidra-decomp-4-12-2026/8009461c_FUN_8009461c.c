// Function: FUN_8009461c
// Entry: 8009461c
// Size: 260 bytes

uint FUN_8009461c(float *param_1,float *param_2)

{
  float fVar1;
  float fVar2;
  double dVar3;
  int *piVar4;
  int iVar5;
  uint *puVar6;
  uint uVar7;
  
  fVar1 = FLOAT_803dff34;
  if (DAT_8039b788 == 0) {
    *param_1 = FLOAT_803dff34;
    *param_2 = fVar1;
    uVar7 = 0;
  }
  else {
    piVar4 = (int *)FUN_8002b660(DAT_8039b788);
    iVar5 = FUN_800284e8(*piVar4,0);
    puVar6 = (uint *)FUN_8004c3cc(iVar5,0);
    iVar5 = FUN_800395a4(DAT_8039b788,0);
    dVar3 = DOUBLE_803dff38;
    fVar2 = FLOAT_803dff34;
    fVar1 = FLOAT_803dff30;
    if (iVar5 == 0) {
      *param_1 = FLOAT_803dff34;
      *param_2 = fVar2;
    }
    else {
      *param_1 = FLOAT_803dff30 *
                 (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar5 + 8) ^ 0x80000000) -
                        DOUBLE_803dff38);
      *param_2 = fVar1 * (float)((double)CONCAT44(0x43300000,
                                                  (int)*(short *)(iVar5 + 10) ^ 0x80000000) - dVar3)
      ;
    }
    uVar7 = FUN_8005383c(*puVar6);
  }
  return uVar7;
}

