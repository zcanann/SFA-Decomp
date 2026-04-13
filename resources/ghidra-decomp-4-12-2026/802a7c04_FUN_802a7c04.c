// Function: FUN_802a7c04
// Entry: 802a7c04
// Size: 1496 bytes

/* WARNING: Removing unreachable block (ram,0x802a88f8) */
/* WARNING: Removing unreachable block (ram,0x802a88f0) */
/* WARNING: Removing unreachable block (ram,0x802a88e8) */
/* WARNING: Removing unreachable block (ram,0x802a88e0) */
/* WARNING: Removing unreachable block (ram,0x802a88d8) */
/* WARNING: Removing unreachable block (ram,0x802a82b4) */
/* WARNING: Removing unreachable block (ram,0x802a8228) */
/* WARNING: Removing unreachable block (ram,0x802a7c34) */
/* WARNING: Removing unreachable block (ram,0x802a7c2c) */
/* WARNING: Removing unreachable block (ram,0x802a7c24) */
/* WARNING: Removing unreachable block (ram,0x802a7c1c) */
/* WARNING: Removing unreachable block (ram,0x802a7c14) */
/* WARNING: Removing unreachable block (ram,0x802a7ff0) */
/* WARNING: Removing unreachable block (ram,0x802a8034) */
/* WARNING: Removing unreachable block (ram,0x802a7ffc) */
/* WARNING: Removing unreachable block (ram,0x802a8068) */
/* WARNING: Removing unreachable block (ram,0x802a7fa0) */
/* WARNING: Removing unreachable block (ram,0x802a80c4) */
/* WARNING: Removing unreachable block (ram,0x802a80cc) */
/* WARNING: Restarted to delay deadcode elimination for space: stack */

void FUN_802a7c04(undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4,uint param_5)

{
  int *piVar1;
  uint uVar2;
  char cVar5;
  int *piVar3;
  int iVar4;
  int iVar6;
  int iVar7;
  char *pcVar8;
  ushort *puVar9;
  int iVar10;
  double dVar11;
  double in_f27;
  double in_f28;
  double in_f29;
  double in_f30;
  double in_f31;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar12;
  int local_18c;
  undefined4 local_188;
  undefined4 local_184;
  undefined4 local_180;
  undefined local_17c;
  float local_178;
  float local_174;
  float local_170;
  float local_16c;
  float local_168;
  float local_164;
  float local_160;
  float local_15c;
  float local_158;
  float local_154;
  float local_150;
  float local_14c;
  float local_148;
  float local_144;
  float local_140;
  float local_13c;
  float local_138;
  float local_134;
  undefined4 local_118;
  undefined4 local_114;
  undefined4 local_110;
  undefined4 local_10c;
  undefined4 local_108;
  undefined4 local_104;
  undefined2 local_100;
  int aiStack_fc [7];
  float local_e0;
  float local_dc;
  float local_d8;
  undefined4 local_a8;
  uint uStack_a4;
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
  uVar12 = FUN_80286818();
  piVar1 = (int *)((ulonglong)uVar12 >> 0x20);
  iVar6 = (int)uVar12;
  local_188 = DAT_802c33f8;
  local_184 = DAT_802c33fc;
  local_180 = DAT_802c3400;
  local_17c = DAT_802c3404;
  local_118 = DAT_802c3408;
  local_114 = DAT_802c340c;
  local_110 = DAT_802c3410;
  local_10c = DAT_802c3414;
  local_108 = DAT_802c3418;
  local_104 = DAT_802c341c;
  local_100 = DAT_802c3420;
  uVar2 = FUN_80021884();
  uStack_a4 = (uVar2 & 0xffff) - (int)*(short *)(param_3 + 0x330) ^ 0x80000000;
  local_a8 = 0x43300000;
  dVar11 = (double)FUN_802945e0();
  local_13c = (float)-dVar11;
  local_138 = FLOAT_803e8b3c;
  dVar11 = (double)FUN_80294964();
  local_134 = (float)-dVar11;
  FUN_802a8918((int)piVar1,iVar6,&local_148);
  local_16c = FLOAT_803e8d24 * local_13c;
  local_168 = FLOAT_803e8d24 * local_138;
  local_164 = FLOAT_803e8d24 * local_134;
  local_178 = FLOAT_803e8d24 * local_148;
  local_174 = FLOAT_803e8d24 * local_144;
  local_170 = FLOAT_803e8d24 * local_140;
  *(uint *)(iVar6 + 0x360) = *(uint *)(iVar6 + 0x360) & 0xfffffeff;
  uVar2 = 0;
  iVar10 = 0;
  puVar9 = (ushort *)&local_118;
  pcVar8 = (char *)&local_188;
  do {
    if ((param_5 & *puVar9) != 0) {
      if (uVar2 < 0xd) {
                    /* WARNING: Could not recover jumptable at 0x802a7dec. Too many branches */
                    /* WARNING: Treating indirect jump as call */
        (**(code **)((int)&PTR_LAB_80335920 + iVar10))();
        return;
      }
      if (FLOAT_803e8b94 <= *(float *)(param_3 + 0x298)) {
        local_160 = (float)piVar1[3] + local_16c;
        local_15c = (float)piVar1[4] + local_168;
        local_158 = (float)piVar1[5] + local_164;
        local_154 = (float)piVar1[3];
        local_150 = (float)piVar1[4];
        local_14c = (float)piVar1[5];
        cVar5 = FUN_80064248(&local_154,&local_160,(float *)0x3,aiStack_fc,piVar1,1,(int)*pcVar8,
                             0xff,10);
        if (cVar5 != '\0') {
          if (uVar2 < 0xb) {
                    /* WARNING: Could not recover jumptable at 0x802a8124. Too many branches */
                    /* WARNING: Treating indirect jump as call */
            (**(code **)((int)&DAT_803358f4 + iVar10))();
            return;
          }
          if (FLOAT_803e8d28 < local_d8 * local_134 + local_e0 * local_13c + local_dc * local_138) {
            cVar5 = '\0';
          }
        }
        if (cVar5 != '\0') {
          local_154 = (float)piVar1[3];
          local_150 = (float)piVar1[4];
          local_14c = (float)piVar1[5];
          local_160 = -(FLOAT_803e8d24 * local_e0 - (float)piVar1[3]);
          local_15c = (float)piVar1[4];
          local_158 = -(FLOAT_803e8d24 * local_d8 - (float)piVar1[5]);
          cVar5 = FUN_80064248(&local_154,&local_160,(float *)0x3,aiStack_fc,piVar1,1,(int)*pcVar8,
                               0xff,10);
        }
        if ((cVar5 != '\0') && (uVar2 < 0xd)) {
                    /* WARNING: Could not recover jumptable at 0x802a82d4. Too many branches */
                    /* WARNING: Treating indirect jump as call */
          (**(code **)((int)&PTR_LAB_803358c0 + iVar10))();
          return;
        }
      }
    }
    puVar9 = puVar9 + 1;
    pcVar8 = pcVar8 + 1;
    uVar2 = uVar2 + 1;
    iVar10 = iVar10 + 4;
  } while ((int)uVar2 < 0xd);
  if (((*(uint *)(param_3 + 0x31c) & 0x100) != 0) && ((param_5 & 0x200) != 0)) {
    piVar3 = FUN_80037048(10,&local_18c);
    for (iVar10 = 0; iVar10 < local_18c; iVar10 = iVar10 + 1) {
      iVar7 = *piVar3;
      iVar4 = (**(code **)(**(int **)(iVar7 + 0x68) + 0x20))(iVar7,piVar1);
      if (iVar4 != 0) {
        *(int *)(iVar6 + 0x7f0) = iVar7;
        break;
      }
      piVar3 = piVar3 + 1;
    }
  }
  FUN_80286864();
  return;
}

