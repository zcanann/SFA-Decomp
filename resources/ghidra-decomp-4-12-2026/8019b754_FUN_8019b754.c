// Function: FUN_8019b754
// Entry: 8019b754
// Size: 544 bytes

/* WARNING: Removing unreachable block (ram,0x8019b950) */
/* WARNING: Removing unreachable block (ram,0x8019b948) */
/* WARNING: Removing unreachable block (ram,0x8019b76c) */
/* WARNING: Removing unreachable block (ram,0x8019b764) */

undefined4
FUN_8019b754(double param_1,short *param_2,short *param_3,float *param_4,undefined4 param_5,
            undefined4 param_6,undefined4 param_7,undefined4 param_8,undefined4 param_9)

{
  int iVar1;
  short sVar2;
  undefined4 uVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  float local_58;
  float local_54;
  float local_50 [2];
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  longlong local_38;
  
  if (param_3 == (short *)0x0) {
    uVar3 = 0;
  }
  else {
    local_50[0] = *(float *)(param_3 + 6) - *(float *)(param_2 + 6);
    dVar6 = (double)local_50[0];
    local_54 = *(float *)(param_3 + 8) - *(float *)(param_2 + 8);
    local_58 = *(float *)(param_3 + 10) - *(float *)(param_2 + 10);
    dVar4 = FUN_80293900((double)(local_58 * local_58 + (float)(dVar6 * dVar6) + local_54 * local_54
                                 ));
    if ((double)(float)((double)FLOAT_803e4dbc * param_1) <= dVar4) {
      FUN_80070320(local_50,&local_54,&local_58);
      *(float *)(param_2 + 0x12) = FLOAT_803dc074 * (float)((double)local_50[0] * param_1);
      *(float *)(param_2 + 0x14) = FLOAT_803dc074 * (float)((double)local_54 * param_1);
      *(float *)(param_2 + 0x16) = FLOAT_803dc074 * (float)((double)local_58 * param_1);
      sVar2 = (*param_3 + -0x8000) - *param_2;
      if (0x8000 < sVar2) {
        sVar2 = sVar2 + 1;
      }
      if (sVar2 < -0x8000) {
        sVar2 = sVar2 + -1;
      }
      uStack_44 = (int)*param_2 ^ 0x80000000;
      local_48 = 0x43300000;
      uStack_3c = (int)sVar2 ^ 0x80000000;
      local_40 = 0x43300000;
      iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e4db0) +
                   (float)((double)((FLOAT_803e4dc0 +
                                    (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e4db0
                                           )) * (float)(param_1 * (double)FLOAT_803dc074)) / dVar4))
      ;
      local_38 = (longlong)iVar1;
      *param_2 = (short)iVar1;
      dVar4 = (double)*(float *)(param_2 + 0x14);
      dVar5 = (double)*(float *)(param_2 + 0x16);
      FUN_8002ba34((double)*(float *)(param_2 + 0x12),dVar4,dVar5,(int)param_2);
      if (param_2[0x50] != 0x1a) {
        FUN_8003042c((double)FLOAT_803e4da8,dVar4,dVar5,dVar6,in_f5,in_f6,in_f7,in_f8,param_2,0x1a,0
                     ,param_5,param_6,param_7,param_8,param_9);
      }
      FUN_8002f6cc(param_1,(int)param_2,param_4);
      uVar3 = 0;
    }
    else {
      uVar3 = 1;
    }
  }
  return uVar3;
}

