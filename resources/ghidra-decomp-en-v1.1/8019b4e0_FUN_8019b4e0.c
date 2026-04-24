// Function: FUN_8019b4e0
// Entry: 8019b4e0
// Size: 628 bytes

/* WARNING: Removing unreachable block (ram,0x8019b734) */
/* WARNING: Removing unreachable block (ram,0x8019b4f0) */
/* WARNING: Type propagation algorithm not settling */

void FUN_8019b4e0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,float *param_12,int param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  short sVar1;
  short *psVar2;
  int iVar3;
  char cVar4;
  float *pfVar5;
  float *pfVar6;
  float *pfVar7;
  double extraout_f1;
  double dVar8;
  double in_f31;
  double in_ps31_1;
  undefined8 uVar9;
  float local_58 [3];
  short local_4c [6];
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar9 = FUN_8028683c();
  psVar2 = (short *)((ulonglong)uVar9 >> 0x20);
  pfVar5 = (float *)uVar9;
  local_58[0] = FLOAT_803e4da8;
  if (*(int *)(psVar2 + 0x7a) != -1) {
    dVar8 = extraout_f1;
    if (*(int *)(psVar2 + 0x7a) == 0) {
      pfVar7 = (float *)(param_11 & 0xff);
      pfVar6 = (float *)0x2;
      iVar3 = FUN_8019b974((int)psVar2,pfVar7,(undefined4 *)0x0,2);
      local_40 = *(undefined4 *)(iVar3 + 8);
      local_3c = *(undefined4 *)(iVar3 + 0xc);
      local_38 = *(undefined4 *)(iVar3 + 0x10);
      local_4c[0] = (short)((int)*(char *)(iVar3 + 0x2c) << 8);
      iVar3 = FUN_8019b754(dVar8,psVar2,local_4c,param_12,pfVar6,param_13,param_14,param_15,param_16
                          );
      if (iVar3 != 0) {
        local_58[1] = 3.50325e-44;
        local_58[2] = 2.94273e-44;
        param_13 = *DAT_803dd71c;
        (**(code **)(param_13 + 0x8c))((double)FLOAT_803e4db8,pfVar5,psVar2,local_58 + 1);
        psVar2[0x7a] = 0;
        psVar2[0x7b] = 1;
        pfVar6 = pfVar7;
      }
    }
    else {
      cVar4 = '\0';
      pfVar6 = param_12;
      iVar3 = FUN_80010340(extraout_f1,pfVar5);
      if ((iVar3 != 0) || (pfVar5[4] != 0.0)) {
        cVar4 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar5);
      }
      *(float *)(psVar2 + 6) = pfVar5[0x1a];
      *(float *)(psVar2 + 8) = pfVar5[0x1b];
      *(float *)(psVar2 + 10) = pfVar5[0x1c];
      if (cVar4 != '\0') {
        psVar2[0x7a] = -1;
        psVar2[0x7b] = -1;
      }
      param_3 = (double)*(float *)(psVar2 + 10);
      iVar3 = FUN_80065a20((double)*(float *)(psVar2 + 6),(double)*(float *)(psVar2 + 8),param_3,
                           psVar2,local_58,0);
      if (iVar3 == 0) {
        *(float *)(psVar2 + 8) = *(float *)(psVar2 + 8) - local_58[0];
      }
    }
    FUN_8002f6cc(dVar8,(int)psVar2,param_12);
    dVar8 = (double)(*(float *)(psVar2 + 10) - *(float *)(psVar2 + 0x44));
    iVar3 = FUN_80021884();
    sVar1 = ((short)iVar3 + -0x8000) - *psVar2;
    if (0x8000 < sVar1) {
      sVar1 = sVar1 + 1;
    }
    if (sVar1 < -0x8000) {
      sVar1 = sVar1 + -1;
    }
    *psVar2 = *psVar2 + (sVar1 >> 3);
    if (psVar2[0x50] != 0x1a) {
      FUN_8003042c((double)FLOAT_803e4da8,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,
                   psVar2,0x1a,0,pfVar6,param_13,param_14,param_15,param_16);
    }
  }
  FUN_80286888();
  return;
}

