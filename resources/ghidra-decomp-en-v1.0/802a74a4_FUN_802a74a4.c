// Function: FUN_802a74a4
// Entry: 802a74a4
// Size: 1496 bytes

/* WARNING: Removing unreachable block (ram,0x802a8190) */
/* WARNING: Removing unreachable block (ram,0x802a8180) */
/* WARNING: Removing unreachable block (ram,0x802a7b54) */
/* WARNING: Removing unreachable block (ram,0x802a7ac8) */
/* WARNING: Removing unreachable block (ram,0x802a7890) */
/* WARNING: Removing unreachable block (ram,0x802a78d4) */
/* WARNING: Removing unreachable block (ram,0x802a789c) */
/* WARNING: Removing unreachable block (ram,0x802a7908) */
/* WARNING: Removing unreachable block (ram,0x802a7840) */
/* WARNING: Removing unreachable block (ram,0x802a8178) */
/* WARNING: Removing unreachable block (ram,0x802a8188) */
/* WARNING: Removing unreachable block (ram,0x802a8198) */
/* WARNING: Removing unreachable block (ram,0x802a7964) */
/* WARNING: Removing unreachable block (ram,0x802a796c) */
/* WARNING: Restarted to delay deadcode elimination for space: stack */

void FUN_802a74a4(undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4,uint param_5)

{
  int iVar1;
  uint uVar2;
  char cVar6;
  int *piVar3;
  int iVar4;
  undefined4 uVar5;
  int iVar7;
  int iVar8;
  undefined4 *puVar9;
  undefined4 *puVar10;
  int iVar11;
  undefined4 uVar12;
  double dVar13;
  undefined8 in_f27;
  undefined8 in_f28;
  double dVar14;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  undefined8 uVar15;
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
  undefined auStack252 [28];
  float local_e0;
  float local_dc;
  float local_d8;
  undefined4 local_a8;
  uint uStack164;
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar12 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  uVar15 = FUN_802860b4();
  iVar1 = (int)((ulonglong)uVar15 >> 0x20);
  iVar7 = (int)uVar15;
  local_188 = DAT_802c2c78;
  local_184 = DAT_802c2c7c;
  local_180 = DAT_802c2c80;
  local_17c = DAT_802c2c84;
  local_118 = DAT_802c2c88;
  local_114 = DAT_802c2c8c;
  local_110 = DAT_802c2c90;
  local_10c = DAT_802c2c94;
  local_108 = DAT_802c2c98;
  local_104 = DAT_802c2c9c;
  local_100 = DAT_802c2ca0;
  uVar2 = FUN_800217c0((double)*(float *)(param_3 + 0x290),-(double)*(float *)(param_3 + 0x28c));
  uStack164 = (uVar2 & 0xffff) - (int)*(short *)(param_3 + 0x330) ^ 0x80000000;
  local_a8 = 0x43300000;
  dVar14 = (double)((FLOAT_803e7f94 *
                    (float)((double)CONCAT44(0x43300000,uStack164) - DOUBLE_803e7ec0)) /
                   FLOAT_803e7f98);
  dVar13 = (double)FUN_80293e80(dVar14);
  local_13c = (float)-dVar13;
  local_138 = FLOAT_803e7ea4;
  dVar13 = (double)FUN_80294204(dVar14);
  local_134 = (float)-dVar13;
  FUN_802a81b8(iVar1,iVar7,&local_148);
  local_16c = FLOAT_803e808c * local_13c;
  local_168 = FLOAT_803e808c * local_138;
  local_164 = FLOAT_803e808c * local_134;
  local_178 = FLOAT_803e808c * local_148;
  local_174 = FLOAT_803e808c * local_144;
  local_170 = FLOAT_803e808c * local_140;
  *(uint *)(iVar7 + 0x360) = *(uint *)(iVar7 + 0x360) & 0xfffffeff;
  uVar2 = 0;
  iVar11 = 0;
  puVar10 = &local_118;
  puVar9 = &local_188;
  do {
    if ((param_5 & *(ushort *)puVar10) != 0) {
      if (uVar2 < 0xd) {
                    /* WARNING: Could not recover jumptable at 0x802a768c. Too many branches */
                    /* WARNING: Treating indirect jump as call */
        (**(code **)((int)&PTR_LAB_80334cc0 + iVar11))();
        return;
      }
      if (FLOAT_803e7efc <= *(float *)(param_3 + 0x298)) {
        local_160 = *(float *)(iVar1 + 0xc) + local_16c;
        local_15c = *(float *)(iVar1 + 0x10) + local_168;
        local_158 = *(float *)(iVar1 + 0x14) + local_164;
        local_154 = *(float *)(iVar1 + 0xc);
        local_150 = *(float *)(iVar1 + 0x10);
        local_14c = *(float *)(iVar1 + 0x14);
        cVar6 = FUN_800640cc((double)FLOAT_803e7ea4,&local_154,&local_160,3,auStack252,iVar1,1,
                             (int)*(char *)puVar9,0xff,10);
        if (cVar6 != '\0') {
          if (uVar2 < 0xb) {
                    /* WARNING: Could not recover jumptable at 0x802a79c4. Too many branches */
                    /* WARNING: Treating indirect jump as call */
            (**(code **)((int)&DAT_80334c94 + iVar11))();
            return;
          }
          if (FLOAT_803e8090 < local_d8 * local_134 + local_e0 * local_13c + local_dc * local_138) {
            cVar6 = '\0';
          }
        }
        if (cVar6 != '\0') {
          local_154 = *(float *)(iVar1 + 0xc);
          local_150 = *(float *)(iVar1 + 0x10);
          local_14c = *(float *)(iVar1 + 0x14);
          local_160 = -(FLOAT_803e808c * local_e0 - *(float *)(iVar1 + 0xc));
          local_15c = *(float *)(iVar1 + 0x10);
          local_158 = -(FLOAT_803e808c * local_d8 - *(float *)(iVar1 + 0x14));
          cVar6 = FUN_800640cc((double)FLOAT_803e7ea4,&local_154,&local_160,3,auStack252,iVar1,1,
                               (int)*(char *)puVar9,0xff,10);
        }
        if ((cVar6 != '\0') && (uVar2 < 0xd)) {
                    /* WARNING: Could not recover jumptable at 0x802a7b74. Too many branches */
                    /* WARNING: Treating indirect jump as call */
          (**(code **)((int)&PTR_LAB_80334c60 + iVar11))();
          return;
        }
      }
    }
    puVar10 = (undefined4 *)((int)puVar10 + 2);
    puVar9 = (undefined4 *)((int)puVar9 + 1);
    uVar2 = uVar2 + 1;
    iVar11 = iVar11 + 4;
  } while ((int)uVar2 < 0xd);
  if (((*(uint *)(param_3 + 0x31c) & 0x100) != 0) && ((param_5 & 0x200) != 0)) {
    piVar3 = (int *)FUN_80036f50(10,&local_18c);
    for (iVar11 = 0; iVar11 < local_18c; iVar11 = iVar11 + 1) {
      iVar8 = *piVar3;
      iVar4 = (**(code **)(**(int **)(iVar8 + 0x68) + 0x20))(iVar8,iVar1);
      if (iVar4 != 0) {
        *(int *)(iVar7 + 0x7f0) = iVar8;
        uVar5 = 10;
        goto LAB_802a8178;
      }
      piVar3 = piVar3 + 1;
    }
  }
  uVar5 = 0xffffffff;
LAB_802a8178:
  __psq_l0(auStack8,uVar12);
  __psq_l1(auStack8,uVar12);
  __psq_l0(auStack24,uVar12);
  __psq_l1(auStack24,uVar12);
  __psq_l0(auStack40,uVar12);
  __psq_l1(auStack40,uVar12);
  __psq_l0(auStack56,uVar12);
  __psq_l1(auStack56,uVar12);
  __psq_l0(auStack72,uVar12);
  __psq_l1(auStack72,uVar12);
  FUN_80286100(uVar5);
  return;
}

