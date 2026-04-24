// Function: FUN_802a7940
// Entry: 802a7940
// Size: 708 bytes

/* WARNING: Removing unreachable block (ram,0x802a7be4) */
/* WARNING: Removing unreachable block (ram,0x802a7bdc) */
/* WARNING: Removing unreachable block (ram,0x802a7958) */
/* WARNING: Removing unreachable block (ram,0x802a7950) */

void FUN_802a7940(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,float *param_12,
                 float *param_13,uint param_14,uint param_15,undefined4 param_16)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  undefined2 uVar4;
  int *piVar5;
  double extraout_f1;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double in_f30;
  double in_f31;
  double dVar11;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar12;
  short asStack_68 [4];
  float afStack_60 [4];
  longlong local_50;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar12 = FUN_80286830();
  iVar2 = (int)((ulonglong)uVar12 >> 0x20);
  piVar5 = *(int **)(*(int *)(iVar2 + 0x7c) + *(char *)(iVar2 + 0xad) * 4);
  uVar3 = 0;
  if ((param_15 & 2) != 0) {
    uVar3 = 2;
  }
  if ((param_15 & 0x40) != 0) {
    uVar3 = uVar3 | 4;
  }
  if ((param_15 & 0x10) != 0) {
    uVar3 = uVar3 | 8;
  }
  if ((param_15 & 0x20) != 0) {
    uVar3 = uVar3 | 1;
  }
  uVar1 = param_15 & 4;
  dVar10 = extraout_f1;
  if (uVar1 == 0) {
    FUN_8002f334((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 iVar2,(uint)uVar12,(char)uVar3);
    FUN_8002eeb8(param_2,(double)FLOAT_803e8b3c,iVar2,0);
    dVar6 = (double)*(float *)(iVar2 + 8);
    uVar12 = FUN_80027ec4(dVar10,dVar6,piVar5,1,0,afStack_60,asStack_68);
  }
  else {
    FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 iVar2,(uint)uVar12,uVar3,param_12,param_13,param_14,param_15,param_16);
    FUN_8002fb40(param_2,(double)FLOAT_803e8b3c);
    dVar6 = (double)*(float *)(iVar2 + 8);
    uVar12 = FUN_80027ec4(dVar10,dVar6,piVar5,0,0,afStack_60,asStack_68);
  }
  dVar11 = (double)afStack_60[param_14 & 0xff];
  if (dVar11 < (double)FLOAT_803e8b3c) {
    dVar11 = -dVar11;
  }
  if (uVar1 == 0) {
    FUN_8002ee10(uVar12,dVar6,param_3,param_4,param_5,param_6,param_7,param_8,iVar2,param_11,0);
    FUN_80027ec4(dVar10,(double)*(float *)(iVar2 + 8),piVar5,1,2,afStack_60,asStack_68);
  }
  else {
    FUN_8002ee64(uVar12,dVar6,param_3,param_4,param_5,param_6,param_7,param_8,iVar2,param_11,0);
    FUN_80027ec4(dVar10,(double)*(float *)(iVar2 + 8),piVar5,0,2,afStack_60,asStack_68);
  }
  dVar10 = (double)afStack_60[param_14 & 0xff];
  if (dVar10 < (double)FLOAT_803e8b3c) {
    dVar10 = -dVar10;
  }
  dVar9 = (double)param_13[3];
  dVar8 = (double)*param_12;
  dVar7 = (double)*param_13;
  dVar6 = (double)(float)(dVar9 + (double)(float)(dVar8 * dVar7 +
                                                 (double)(param_12[2] * param_13[2])));
  if (dVar6 < (double)FLOAT_803e8b3c) {
    dVar6 = -dVar6;
  }
  dVar6 = (double)((float)(dVar6 - dVar11) / (float)(dVar10 - dVar11));
  if ((param_15 & 1) == 0) {
    if (dVar6 < (double)FLOAT_803e8b3c) {
      dVar6 = -dVar6;
    }
  }
  else if (dVar6 < (double)FLOAT_803e8b3c) {
    dVar6 = (double)FLOAT_803e8b3c;
  }
  if ((double)FLOAT_803e8b78 < dVar6) {
    dVar6 = (double)FLOAT_803e8b78;
  }
  local_50 = (longlong)(int)((double)FLOAT_803e8c44 * dVar6);
  uVar4 = (undefined2)(int)((double)FLOAT_803e8c44 * dVar6);
  if (uVar1 == 0) {
    FUN_8002ee10(dVar6,dVar7,dVar8,dVar9,dVar10,param_6,param_7,param_8,iVar2,param_11,uVar4);
  }
  else {
    FUN_8002ee64(dVar6,dVar7,dVar8,dVar9,dVar10,param_6,param_7,param_8,iVar2,param_11,uVar4);
  }
  FUN_8028687c();
  return;
}

