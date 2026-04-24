// Function: FUN_801b48e4
// Entry: 801b48e4
// Size: 1236 bytes

/* WARNING: Removing unreachable block (ram,0x801b4d98) */
/* WARNING: Removing unreachable block (ram,0x801b48f4) */

void FUN_801b48e4(void)

{
  undefined uVar2;
  int iVar1;
  ushort *puVar3;
  int iVar4;
  ushort uVar7;
  float *pfVar5;
  undefined4 *puVar6;
  uint uVar8;
  int iVar9;
  char in_r8;
  float *pfVar10;
  int iVar11;
  float *pfVar12;
  uint uVar13;
  double dVar14;
  double in_f31;
  double in_ps31_1;
  undefined4 local_188;
  undefined4 local_184;
  undefined4 local_180;
  undefined4 local_17c;
  float afStack_178 [12];
  float afStack_148 [12];
  float afStack_118 [12];
  float afStack_e8 [12];
  float afStack_b8 [12];
  undefined4 local_88;
  uint uStack_84;
  undefined4 local_80;
  uint uStack_7c;
  undefined4 local_78;
  uint uStack_74;
  undefined4 local_70;
  float fStack_6c;
  undefined4 local_68;
  float fStack_64;
  undefined4 local_60;
  float fStack_5c;
  longlong local_58;
  undefined4 local_50;
  float fStack_4c;
  undefined4 local_48;
  float fStack_44;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  puVar3 = (ushort *)FUN_80286828();
  local_17c = DAT_803e55c0;
  local_180 = DAT_803e90e8;
  pfVar10 = *(float **)(puVar3 + 0x5c);
  iVar4 = FUN_8002b660((int)puVar3);
  if (in_r8 != '\0') {
    FUN_80257b5c();
    FUN_802570dc(9,1);
    FUN_802570dc(0xd,1);
    FUN_8025d888(0);
    pfVar12 = pfVar10;
    for (iVar11 = 0; iVar11 < (int)(uint)*(byte *)(pfVar10 + 0x296); iVar11 = iVar11 + 1) {
      if (*(char *)((int)pfVar12 + 0x2f) != '\0') {
        FUN_8002b554(puVar3,afStack_b8,'\0');
        uStack_84 = (int)*(short *)(pfVar12 + 10) ^ 0x80000000;
        local_88 = 0x43300000;
        FUN_8024782c((double)(float)((DOUBLE_803e5610 *
                                     ((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e55e0)) /
                                    DOUBLE_803e5618),afStack_178,0x7a);
        uVar7 = FUN_8000fa90();
        uStack_7c = (uint)uVar7;
        local_80 = 0x43300000;
        FUN_8024782c((double)(float)((DOUBLE_803e5610 *
                                     ((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e5628)) /
                                    DOUBLE_803e5618),afStack_118,0x78);
        FUN_80247618(afStack_118,afStack_178,afStack_118);
        uVar7 = FUN_8000fab0();
        uStack_74 = 0x10000 - uVar7 ^ 0x80000000;
        local_78 = 0x43300000;
        FUN_8024782c((double)(float)((DOUBLE_803e5610 *
                                     ((double)CONCAT44(0x43300000,uStack_74) - DOUBLE_803e55e0)) /
                                    DOUBLE_803e5618),afStack_148,0x79);
        FUN_80247618(afStack_148,afStack_118,afStack_148);
        dVar14 = (double)pfVar12[3];
        FUN_80247a7c(dVar14,dVar14,dVar14,afStack_e8);
        FUN_80247618(afStack_e8,afStack_148,afStack_e8);
        FUN_80247a48((double)(*pfVar12 - FLOAT_803dda58),(double)pfVar12[1],
                     (double)(pfVar12[2] - FLOAT_803dda5c),afStack_b8);
        FUN_80247618(afStack_b8,afStack_e8,afStack_b8);
        pfVar5 = (float *)FUN_8000f56c();
        FUN_80247618(pfVar5,afStack_b8,afStack_b8);
        FUN_8025d80c(afStack_b8,0);
        local_17c = CONCAT31(local_17c._0_3_,*(undefined *)((int)pfVar12 + 0x2e));
        fStack_6c = -pfVar12[5];
        local_70 = 0x43300000;
        fStack_64 = -pfVar12[4];
        local_68 = 0x43300000;
        local_60 = 0x43300000;
        fStack_5c = fStack_6c;
        dVar14 = (double)FUN_80292538();
        iVar9 = (int)(FLOAT_803de7e8 * (float)((double)FLOAT_803e55d0 * dVar14));
        local_58 = (longlong)iVar9;
        uVar2 = (undefined)iVar9;
        local_180 = CONCAT31(CONCAT21(CONCAT11(uVar2,uVar2),uVar2),uVar2);
        fStack_4c = -pfVar12[4];
        local_50 = 0x43300000;
        fStack_44 = -pfVar12[5];
        local_48 = 0x43300000;
        FUN_801b466c(*(byte *)((int)pfVar10 + 0xa5d),(undefined *)&local_17c);
        puVar6 = (undefined4 *)(&DAT_803ad5c0)[*(byte *)((int)pfVar10 + 0xa5d)];
        iVar9 = 0;
        uVar8 = (uint)*(byte *)(pfVar12 + 0xb);
        if (uVar8 != 0) {
          if ((8 < uVar8) && (uVar13 = uVar8 - 1 >> 3, 0 < (int)(uVar8 - 8))) {
            do {
              puVar6 = *(undefined4 **)**(undefined4 **)**(undefined4 **)**(undefined4 **)*puVar6;
              iVar9 = iVar9 + 8;
              uVar13 = uVar13 - 1;
            } while (uVar13 != 0);
          }
          iVar1 = uVar8 - iVar9;
          if (iVar9 < (int)uVar8) {
            do {
              puVar6 = (undefined4 *)*puVar6;
              iVar1 = iVar1 + -1;
            } while (iVar1 != 0);
          }
        }
        local_188 = local_180;
        local_184 = local_17c;
        FUN_80073c28((int)puVar6,&local_184,&local_188);
        FUN_80259000(0x80,2,4);
        DAT_cc008000 = FLOAT_803e5620;
        DAT_cc008000 = FLOAT_803e5620;
        DAT_cc008000 = FLOAT_803e55f8;
        DAT_cc008000 = FLOAT_803e55f8;
        DAT_cc008000 = FLOAT_803e55f8;
        DAT_cc008000 = FLOAT_803e55c4;
        DAT_cc008000 = FLOAT_803e5620;
        DAT_cc008000 = FLOAT_803e55f8;
        DAT_cc008000 = FLOAT_803e55c4;
        DAT_cc008000 = FLOAT_803e55f8;
        DAT_cc008000 = FLOAT_803e55c4;
        DAT_cc008000 = FLOAT_803e55c4;
        DAT_cc008000 = FLOAT_803e55f8;
        DAT_cc008000 = FLOAT_803e55c4;
        DAT_cc008000 = FLOAT_803e55c4;
        DAT_cc008000 = FLOAT_803e5620;
        DAT_cc008000 = FLOAT_803e55c4;
        DAT_cc008000 = FLOAT_803e55f8;
        DAT_cc008000 = FLOAT_803e55f8;
        DAT_cc008000 = FLOAT_803e55c4;
      }
      pfVar12 = pfVar12 + 0xc;
    }
    if (((int)pfVar10[0x293] < (int)pfVar10[0x294]) && (*(char *)((int)pfVar10 + 0xa59) != '\0')) {
      pfVar12 = pfVar10;
      for (iVar11 = 0; iVar11 < (int)(uint)*(byte *)((int)pfVar10 + 0xa59); iVar11 = iVar11 + 1) {
        puVar3[1] = *(ushort *)(pfVar12 + 0x291);
        *puVar3 = *(ushort *)((int)pfVar12 + 0xa46);
        local_48 = 0x43300000;
        fStack_44 = -(float)(int)in_r8;
        FUN_8003b9ec((int)puVar3);
        if (iVar11 < (int)(*(byte *)((int)pfVar10 + 0xa59) - 1)) {
          *(ushort *)(iVar4 + 0x18) = *(ushort *)(iVar4 + 0x18) & 0xfff7;
        }
        pfVar12 = pfVar12 + 1;
      }
    }
  }
  FUN_8003fd58();
  FUN_80286874();
  return;
}

