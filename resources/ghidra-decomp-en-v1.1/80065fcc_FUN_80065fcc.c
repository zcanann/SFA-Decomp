// Function: FUN_80065fcc
// Entry: 80065fcc
// Size: 632 bytes

/* WARNING: Removing unreachable block (ram,0x80066224) */
/* WARNING: Removing unreachable block (ram,0x8006621c) */
/* WARNING: Removing unreachable block (ram,0x80065fe4) */
/* WARNING: Removing unreachable block (ram,0x80065fdc) */

void FUN_80065fcc(undefined8 param_1,double param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,int param_6,uint param_7)

{
  bool bVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined *puVar4;
  int iVar5;
  float *pfVar6;
  int iVar7;
  int *piVar8;
  double extraout_f1;
  double in_f30;
  double dVar9;
  double in_f31;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar10;
  float local_88;
  float fStack_84;
  float local_80;
  int local_7c;
  int local_78;
  int local_74;
  int local_70;
  int local_6c;
  int local_68;
  longlong local_60;
  longlong local_58;
  longlong local_50;
  longlong local_48;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar10 = FUN_80286840();
  piVar8 = &DAT_8038e8c4;
  dVar9 = extraout_f1;
  if (param_6 < 0) {
    if (param_6 == -1) {
      param_6 = 0;
    }
    else {
      param_6 = 1;
    }
  }
  else {
    local_7c = (int)extraout_f1;
    local_60 = (longlong)local_7c;
    local_78 = (int)(param_2 - (double)FLOAT_803df968);
    local_58 = (longlong)local_78;
    local_6c = (int)((double)FLOAT_803df968 + param_2);
    local_50 = (longlong)local_6c;
    local_74 = (int)param_3;
    local_48 = (longlong)local_74;
    local_70 = local_7c;
    local_68 = local_74;
    FUN_8006933c((int)((ulonglong)uVar10 >> 0x20),&local_7c,param_7,'\x01');
  }
  DAT_803ddbe8 = &DAT_8038e57c;
  DAT_803ddbe4 = &DAT_8038e4f0;
  DAT_803ddbe0 = '\0';
  uVar2 = (uint)DAT_803ddbec;
  while ((piVar8 < &DAT_8038e8c4 + uVar2 * 6 && (DAT_803ddbe0 < '#'))) {
    if (*piVar8 == 0) {
      FUN_80065b24(dVar9,param_3,DAT_803ddbb0 + *(short *)(piVar8 + 1) * 0x4c,
                   DAT_803ddbb0 + *(short *)(piVar8 + 7) * 0x4c,piVar8,param_6);
    }
    else {
      FUN_80022790(dVar9,(double)FLOAT_803df934,param_3,(float *)piVar8[2],&local_80,&fStack_84,
                   &local_88);
      FUN_80065b24((double)local_80,(double)local_88,DAT_803ddbb0 + *(short *)(piVar8 + 1) * 0x4c,
                   DAT_803ddbb0 + *(short *)(piVar8 + 7) * 0x4c,piVar8,param_6);
    }
    piVar8 = piVar8 + 6;
  }
  puVar4 = &DAT_8038e57c;
  iVar5 = 0;
  for (iVar7 = 0; iVar7 < DAT_803ddbe0; iVar7 = iVar7 + 1) {
    *(undefined **)((int)DAT_803ddbe4 + iVar5) = puVar4;
    puVar4 = puVar4 + 0x18;
    iVar5 = iVar5 + 4;
  }
  bVar1 = false;
  while (!bVar1) {
    bVar1 = true;
    iVar5 = 0;
    for (iVar7 = 0; iVar7 < DAT_803ddbe0 + -1; iVar7 = iVar7 + 1) {
      puVar3 = (undefined4 *)((int)DAT_803ddbe4 + iVar5);
      pfVar6 = (float *)*puVar3;
      if (*pfVar6 < *(float *)puVar3[1]) {
        bVar1 = false;
        *puVar3 = (float *)puVar3[1];
        *(float **)((int)DAT_803ddbe4 + iVar5 + 4) = pfVar6;
      }
      iVar5 = iVar5 + 4;
    }
  }
  *(undefined4 *)uVar10 = &DAT_8038e4f0;
  FUN_8028688c();
  return;
}

