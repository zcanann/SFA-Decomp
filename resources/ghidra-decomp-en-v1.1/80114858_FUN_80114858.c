// Function: FUN_80114858
// Entry: 80114858
// Size: 512 bytes

/* WARNING: Removing unreachable block (ram,0x80114a38) */
/* WARNING: Removing unreachable block (ram,0x80114868) */
/* WARNING: Type propagation algorithm not settling */

void FUN_80114858(undefined4 param_1,undefined4 param_2,float *param_3,uint param_4,float *param_5,
                 uint *param_6)

{
  short *psVar1;
  int iVar2;
  char cVar3;
  float *pfVar4;
  double extraout_f1;
  double in_f31;
  double dVar5;
  double in_ps31_1;
  undefined8 uVar6;
  float local_48 [16];
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar6 = FUN_80286838();
  psVar1 = (short *)((ulonglong)uVar6 >> 0x20);
  pfVar4 = (float *)uVar6;
  local_48[0] = FLOAT_803e2910;
  if ((*param_6 & 0x10) == 0) {
    dVar5 = extraout_f1;
    if ((*param_6 & 4) == 0) {
      cVar3 = '\0';
      iVar2 = FUN_80010340(extraout_f1,pfVar4);
      if ((iVar2 != 0) || (pfVar4[4] != 0.0)) {
        cVar3 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar4);
      }
      *(float *)(psVar1 + 6) = pfVar4[0x1a];
      *(float *)(psVar1 + 8) = pfVar4[0x1b];
      *(float *)(psVar1 + 10) = pfVar4[0x1c];
      if (cVar3 != '\0') {
        *param_6 = *param_6 | 0x10;
      }
    }
    else {
      iVar2 = FUN_801146a4(psVar1,0,param_3,param_3 + 0xc);
      if (iVar2 != 0) {
        local_48[1] = 3.50325e-44;
        local_48[2] = 2.94273e-44;
        (**(code **)(*DAT_803dd71c + 0x8c))
                  ((double)FLOAT_803e2930,pfVar4,psVar1,local_48 + 1,param_4 & 0xff);
        *param_6 = *param_6 | 8;
      }
    }
    FUN_8002f6cc(dVar5,(int)psVar1,param_5);
    if (((*param_6 & 1) != 0) &&
       (iVar2 = FUN_80065a20((double)*(float *)(psVar1 + 6),(double)*(float *)(psVar1 + 8),
                             (double)*(float *)(psVar1 + 10),psVar1,local_48,0), iVar2 == 0)) {
      *(float *)(psVar1 + 8) = *(float *)(psVar1 + 8) - local_48[0];
    }
    if ((*param_6 & 2) != 0) {
      iVar2 = FUN_80021884();
      *psVar1 = *psVar1 + (short)((int)(short)((short)iVar2 + -0x8000) - (int)*psVar1 >> 3);
    }
  }
  FUN_80286884();
  return;
}

