// Function: FUN_80114000
// Entry: 80114000
// Size: 544 bytes

/* WARNING: Removing unreachable block (ram,0x80114200) */
/* WARNING: Removing unreachable block (ram,0x801141f8) */
/* WARNING: Removing unreachable block (ram,0x801141f0) */
/* WARNING: Removing unreachable block (ram,0x801141e8) */
/* WARNING: Removing unreachable block (ram,0x801141e0) */
/* WARNING: Removing unreachable block (ram,0x801141d8) */
/* WARNING: Removing unreachable block (ram,0x80114038) */
/* WARNING: Removing unreachable block (ram,0x80114030) */
/* WARNING: Removing unreachable block (ram,0x80114028) */
/* WARNING: Removing unreachable block (ram,0x80114020) */
/* WARNING: Removing unreachable block (ram,0x80114018) */
/* WARNING: Removing unreachable block (ram,0x80114010) */

void FUN_80114000(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  short sVar1;
  int *piVar2;
  char cVar3;
  ushort uVar4;
  double extraout_f1;
  double dVar5;
  undefined8 uVar6;
  double in_f26;
  double in_f27;
  double in_f28;
  double in_f29;
  double in_f30;
  double dVar7;
  double in_f31;
  double dVar8;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar9;
  char local_100 [4];
  short asStack_fc [4];
  short asStack_f4 [4];
  float local_ec;
  float local_e8;
  float local_e4;
  int aiStack_e0 [22];
  undefined4 local_88;
  uint uStack_84;
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
  uVar9 = FUN_80286834();
  piVar2 = (int *)((ulonglong)uVar9 >> 0x20);
  local_ec = (float)piVar2[3];
  local_e8 = FLOAT_803e28e8 + (float)piVar2[4];
  local_e4 = (float)piVar2[5];
  dVar8 = extraout_f1;
  FUN_80012d20(&local_ec,asStack_fc);
  if ((short *)piVar2[0xc] == (short *)0x0) {
    sVar1 = *(short *)piVar2;
  }
  else {
    sVar1 = *(short *)piVar2 + *(short *)piVar2[0xc];
  }
  dVar7 = (double)FLOAT_803e28e8;
  for (uVar4 = 0; uVar4 < 4; uVar4 = uVar4 + 1) {
    uStack_84 = (int)sVar1 + (uint)uVar4 * 0x4000 ^ 0x80000000;
    local_88 = 0x43300000;
    dVar5 = (double)FUN_802945e0();
    local_ec = -(float)(dVar8 * dVar5 - (double)(float)piVar2[3]);
    local_e8 = (float)(dVar7 + (double)(float)piVar2[4]);
    dVar5 = (double)FUN_80294964();
    local_e4 = -(float)(dVar8 * dVar5 - (double)(float)piVar2[5]);
    uVar6 = FUN_80012d20(&local_ec,asStack_f4);
    if (piVar2[0xc] == 0) {
      cVar3 = FUN_800128fc(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,asStack_f4,
                           asStack_fc,(undefined4 *)0x0,local_100,0);
      if (local_100[0] == '\x01') {
        cVar3 = '\x01';
      }
    }
    else {
      cVar3 = '\x01';
    }
    if (cVar3 != '\0') {
      FUN_80064248(piVar2 + 3,&local_ec,(float *)0x0,aiStack_e0,piVar2,
                   (uint)*(byte *)((int)uVar9 + 0x261),0xffffffff,0,0);
    }
  }
  FUN_80286880();
  return;
}

