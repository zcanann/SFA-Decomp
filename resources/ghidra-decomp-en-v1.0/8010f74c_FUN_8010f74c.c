// Function: FUN_8010f74c
// Entry: 8010f74c
// Size: 696 bytes

void FUN_8010f74c(short *param_1)

{
  uint uVar1;
  short sVar3;
  int iVar2;
  int iVar4;
  short *psVar5;
  double dVar6;
  float local_48;
  float local_44;
  undefined auStack64 [4];
  float local_3c;
  undefined4 local_38;
  uint uStack52;
  undefined4 local_30;
  uint uStack44;
  undefined4 local_28;
  uint uStack36;
  undefined4 local_20;
  uint uStack28;
  longlong local_18;
  
  psVar5 = *(short **)(param_1 + 0x52);
  if (psVar5 != (short *)0x0) {
    if (*(char *)(DAT_803dd598 + 8) < '\0') {
      iVar2 = (**(code **)(*DAT_803dca50 + 0x18))();
      (**(code **)(*DAT_803dca50 + 0x38))
                ((double)FLOAT_803e1adc,param_1,&local_3c,auStack64,&local_44,&local_48,0);
      uVar1 = FUN_800217c0((double)local_3c,(double)local_44);
      iVar4 = (0x8000 - (uVar1 & 0xffff)) - ((int)*param_1 & 0xffffU);
      if (0x8000 < iVar4) {
        iVar4 = iVar4 + -0xffff;
      }
      if (iVar4 < -0x8000) {
        iVar4 = iVar4 + 0xffff;
      }
      *param_1 = *param_1 + (short)iVar4;
      (**(code **)(**(int **)(iVar2 + 4) + 0x18))
                ((double)*(float *)(psVar5 + 0xe),(double)local_48,param_1);
    }
    else {
      uStack52 = (int)*psVar5 ^ 0x80000000;
      local_38 = 0x43300000;
      dVar6 = (double)FUN_80293e80((double)((FLOAT_803e1ac0 *
                                            (float)((double)CONCAT44(0x43300000,uStack52) -
                                                   DOUBLE_803e1ac8)) / FLOAT_803e1ac4));
      *(float *)(param_1 + 0xc) =
           (float)((double)FLOAT_803e1ad0 * dVar6 + (double)*(float *)(psVar5 + 0xc));
      uStack44 = (int)*psVar5 ^ 0x80000000;
      local_30 = 0x43300000;
      dVar6 = (double)FUN_80294204((double)((FLOAT_803e1ac0 *
                                            (float)((double)CONCAT44(0x43300000,uStack44) -
                                                   DOUBLE_803e1ac8)) / FLOAT_803e1ac4));
      *(float *)(param_1 + 0x10) =
           (float)((double)FLOAT_803e1ad0 * dVar6 + (double)*(float *)(psVar5 + 0x10));
      *(float *)(param_1 + 0xe) = FLOAT_803e1ad4 + *(float *)(psVar5 + 0xe);
      local_3c = *(float *)(param_1 + 6) - *(float *)(psVar5 + 0xc);
      local_44 = *(float *)(param_1 + 10) - *(float *)(psVar5 + 0x10);
      uVar1 = FUN_800217c0();
      uStack36 = (0x8000 - (uVar1 & 0xffff)) - ((int)*param_1 & 0xffffU);
      if (0x8000 < (int)uStack36) {
        uStack36 = uStack36 - 0xffff;
      }
      if ((int)uStack36 < -0x8000) {
        uStack36 = uStack36 + 0xffff;
      }
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      dVar6 = (double)FUN_80021370((double)(float)((double)CONCAT44(0x43300000,uStack36) -
                                                  DOUBLE_803e1ac8),(double)FLOAT_803e1ad8,
                                   (double)FLOAT_803db414);
      uStack28 = (int)*param_1 ^ 0x80000000;
      local_20 = 0x43300000;
      iVar2 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e1ac8) + dVar6
                   );
      local_18 = (longlong)iVar2;
      *param_1 = (short)iVar2;
      sVar3 = FUN_800217c0((double)local_3c,(double)local_44);
      *param_1 = -0x8000 - sVar3;
      param_1[1] = 0x800;
    }
    FUN_8000e034((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
                 (double)*(float *)(param_1 + 0x10),param_1 + 6,param_1 + 8,param_1 + 10,
                 *(undefined4 *)(param_1 + 0x18));
  }
  return;
}

