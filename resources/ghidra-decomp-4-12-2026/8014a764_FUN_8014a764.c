// Function: FUN_8014a764
// Entry: 8014a764
// Size: 760 bytes

/* WARNING: Removing unreachable block (ram,0x8014aa3c) */
/* WARNING: Removing unreachable block (ram,0x8014aa34) */
/* WARNING: Removing unreachable block (ram,0x8014aa2c) */
/* WARNING: Removing unreachable block (ram,0x8014aa24) */
/* WARNING: Removing unreachable block (ram,0x8014aa1c) */
/* WARNING: Removing unreachable block (ram,0x8014aa14) */
/* WARNING: Removing unreachable block (ram,0x8014a79c) */
/* WARNING: Removing unreachable block (ram,0x8014a794) */
/* WARNING: Removing unreachable block (ram,0x8014a78c) */
/* WARNING: Removing unreachable block (ram,0x8014a784) */
/* WARNING: Removing unreachable block (ram,0x8014a77c) */
/* WARNING: Removing unreachable block (ram,0x8014a774) */

void FUN_8014a764(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  short sVar1;
  short sVar2;
  int *piVar3;
  char cVar5;
  int iVar4;
  int iVar6;
  ushort uVar7;
  double extraout_f1;
  double dVar8;
  double in_f26;
  double in_f27;
  double in_f28;
  double in_f29;
  double in_f30;
  double dVar9;
  double in_f31;
  double dVar10;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar11;
  char local_110 [4];
  short asStack_10c [4];
  short asStack_104 [4];
  float afStack_fc [3];
  uint local_f0 [4];
  float local_e0;
  float local_dc;
  float local_d8;
  int aiStack_d4 [21];
  undefined4 local_80;
  uint uStack_7c;
  float local_58;
  float fStack_54;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  uVar11 = FUN_8028683c();
  piVar3 = (int *)((ulonglong)uVar11 >> 0x20);
  iVar6 = (int)uVar11;
  local_f0[0] = DAT_802c2970;
  local_f0[1] = DAT_802c2974;
  local_f0[2] = DAT_802c2978;
  local_f0[3] = DAT_802c297c;
  local_e0 = (float)piVar3[3];
  local_dc = FLOAT_803e3234 + (float)piVar3[4];
  local_d8 = (float)piVar3[5];
  dVar10 = extraout_f1;
  FUN_80012d20(&local_e0,asStack_10c);
  if ((short *)piVar3[0xc] == (short *)0x0) {
    sVar2 = *(short *)piVar3;
  }
  else {
    sVar2 = *(short *)piVar3 + *(short *)piVar3[0xc];
  }
  dVar9 = (double)FLOAT_803e3244;
  for (uVar7 = 0; uVar7 < 4; uVar7 = uVar7 + 1) {
    uStack_7c = (int)sVar2 + (uint)uVar7 * 0x4000 ^ 0x80000000;
    local_80 = 0x43300000;
    dVar8 = (double)FUN_802945e0();
    local_e0 = -(float)(dVar10 * dVar8 - (double)(float)piVar3[6]);
    local_dc = (float)piVar3[7];
    dVar8 = (double)FUN_80294964();
    local_d8 = -(float)(dVar10 * dVar8 - (double)(float)piVar3[8]);
    sVar1 = *(short *)((int)piVar3 + 0x46);
    if (((((sVar1 != 0x613) && (sVar1 != 0x642)) && (sVar1 != 0x3fe)) &&
        ((sVar1 != 0x7c6 && (sVar1 != 0x7c8)))) && ((sVar1 != 0x251 && (sVar1 != 0x851)))) {
      local_dc = local_dc + FLOAT_803e3234;
    }
    FUN_80012d20(&local_e0,asStack_104);
    FUN_80247eb8((float *)(piVar3 + 6),&local_e0,afStack_fc);
    dVar8 = FUN_80247f54(afStack_fc);
    if (dVar9 <= dVar8) {
      cVar5 = '\0';
    }
    else if (piVar3[0xc] == 0) {
      cVar5 = FUN_800128fc(dVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,asStack_104
                           ,asStack_10c,(undefined4 *)0x0,local_110,0);
      if (local_110[0] == '\x01') {
        cVar5 = '\x01';
      }
    }
    else {
      cVar5 = '\x01';
    }
    if ((cVar5 != '\0') && ((*(uint *)(iVar6 + 0x2e4) & 8) != 0)) {
      iVar4 = FUN_80064248(piVar3 + 6,&local_e0,(float *)0x0,aiStack_d4,piVar3,
                           (uint)*(byte *)(iVar6 + 0x261),0xffffffff,0,0);
      if (iVar4 != 0) {
        cVar5 = '\0';
      }
    }
    if (cVar5 == '\0') {
      *(uint *)(iVar6 + 0x2dc) = *(uint *)(iVar6 + 0x2dc) & ~local_f0[uVar7];
    }
    else {
      *(uint *)(iVar6 + 0x2dc) = *(uint *)(iVar6 + 0x2dc) | local_f0[uVar7];
    }
  }
  FUN_80286888();
  return;
}

