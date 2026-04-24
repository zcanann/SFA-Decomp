// Function: FUN_80080580
// Entry: 80080580
// Size: 1564 bytes

void FUN_80080580(undefined4 param_1,undefined4 param_2,short param_3,short param_4,short param_5,
                 short param_6,short param_7)

{
  int iVar1;
  float fVar2;
  float fVar3;
  uint uVar4;
  short *psVar5;
  int iVar6;
  int iVar7;
  short sVar12;
  float *pfVar8;
  undefined2 uVar13;
  undefined4 uVar9;
  undefined2 *puVar10;
  uint uVar11;
  int iVar14;
  int iVar15;
  short sVar16;
  undefined8 uVar17;
  float local_78;
  float local_74;
  float local_70;
  float local_6c;
  undefined4 local_68;
  uint uStack100;
  double local_60;
  undefined4 local_58;
  uint uStack84;
  double local_50;
  double local_48;
  double local_40;
  longlong local_38;
  undefined4 local_30;
  uint uStack44;
  double local_28;
  
  uVar17 = FUN_802860d0();
  psVar5 = (short *)((ulonglong)uVar17 >> 0x20);
  iVar14 = (int)uVar17;
  iVar6 = FUN_8002b9ec();
  uStack100 = (int)param_4 ^ 0x80000000;
  local_68 = 0x43300000;
  iVar15 = (int)(FLOAT_803defc0 * (float)((double)CONCAT44(0x43300000,uStack100) - DOUBLE_803defb8))
  ;
  local_60 = (double)(longlong)iVar15;
  uStack84 = (int)param_5 ^ 0x80000000;
  local_58 = 0x43300000;
  iVar7 = (int)(FLOAT_803defc0 * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803defb8));
  local_50 = (double)(longlong)iVar7;
  local_48 = (double)CONCAT44(0x43300000,(int)param_3 ^ 0x80000000);
  iVar1 = (int)(FLOAT_803defc0 * (float)(local_48 - DOUBLE_803defb8));
  local_40 = (double)(longlong)iVar1;
  if (*(char *)(iVar14 + 0x56) == '\x04') {
    *(ushort *)(iVar14 + 0x6e) = *(ushort *)(iVar14 + 0x6e) & 0xfffd;
    iVar7 = FUN_800395d8(psVar5,0);
    if (iVar7 != 0) {
      *(ushort *)(iVar14 + 0x6e) = *(ushort *)(iVar14 + 0x6e) & 0xfff7;
    }
    *(code **)(iVar14 + 0xe8) = FUN_80080548;
    fVar2 = FLOAT_803defb0;
    *(float *)(iVar14 + 0x40) = FLOAT_803defb0;
    *(float *)(iVar14 + 0x44) = fVar2;
    *(float *)(iVar14 + 0x48) = fVar2;
    sVar12 = FUN_800385e8(psVar5,iVar6,0);
    iVar7 = (int)sVar12;
    if (iVar7 < 0) {
      iVar7 = -iVar7;
    }
    sVar16 = (short)iVar15;
    if (iVar7 < sVar16) {
      sVar12 = 0;
    }
    else {
      if (0 < sVar12) {
        sVar16 = -sVar16;
      }
      sVar12 = sVar12 + sVar16;
    }
    *(short *)(iVar14 + 0x50) = sVar12;
    pfVar8 = *(float **)(psVar5 + 0x3a);
    if (pfVar8 == (float *)0x0) {
      local_74 = *(float *)(iVar6 + 0xc) - *(float *)(psVar5 + 6);
      local_70 = *(float *)(iVar6 + 0x10) - *(float *)(psVar5 + 8);
      local_6c = *(float *)(iVar6 + 0x14) - *(float *)(psVar5 + 10);
    }
    else {
      local_74 = *(float *)(iVar6 + 0xc) - *pfVar8;
      local_70 = *(float *)(iVar6 + 0x10) - pfVar8[1];
      local_6c = *(float *)(iVar6 + 0x14) - pfVar8[2];
    }
    local_70 = local_70 + FLOAT_803defc4;
    uVar17 = FUN_802931a0((double)(local_74 * local_74 + local_6c * local_6c));
    uVar13 = FUN_800217c0((double)local_70,uVar17);
    *(undefined2 *)(iVar14 + 0x52) = uVar13;
    *(undefined2 *)(iVar14 + 0x54) = 0;
    *(undefined *)(iVar14 + 0x56) = 5;
    fVar2 = FLOAT_803defb0;
    *(float *)(iVar14 + 0x4c) = FLOAT_803defb0;
    if ((int)sVar12 == 0) {
      *(float *)(iVar14 + 0x24) = FLOAT_803defc8;
    }
    else {
      local_40 = (double)CONCAT44(0x43300000,(int)(short)iVar1 ^ 0x80000000);
      local_48 = (double)CONCAT44(0x43300000,(int)sVar12 ^ 0x80000000);
      fVar3 = (float)(local_40 - DOUBLE_803defb8) / (float)(local_48 - DOUBLE_803defb8);
      if (fVar3 < fVar2) {
        fVar3 = -fVar3;
      }
      *(float *)(iVar14 + 0x24) = fVar3;
    }
    fVar2 = *(float *)(iVar14 + 0x24);
    fVar3 = FLOAT_803defb0;
    if ((FLOAT_803defb0 <= fVar2) && (fVar3 = fVar2, FLOAT_803defcc < fVar2)) {
      fVar3 = FLOAT_803defcc;
    }
    *(float *)(iVar14 + 0x24) = fVar3;
    iVar15 = (int)param_6;
    if ((iVar15 != -1) && (iVar7 = (int)param_7, iVar7 != -1)) {
      *(ushort *)(iVar14 + 0x6e) = *(ushort *)(iVar14 + 0x6e) & 0xfffb;
      if (*(short *)(iVar14 + 0x50) < 0) {
        if (iVar7 != -1) {
          FUN_80030334((double)FLOAT_803defb0,psVar5,iVar7,0);
        }
      }
      else if (iVar15 != -1) {
        FUN_80030334((double)FLOAT_803defb0,psVar5,iVar15,0);
      }
    }
    *(code **)(iVar14 + 0xe8) = FUN_80080548;
    uVar9 = 1;
  }
  else if (*(char *)(iVar14 + 0x56) == '\x05') {
    *(float *)(iVar14 + 0x4c) = *(float *)(iVar14 + 0x4c) + *(float *)(iVar14 + 0x24);
    if (FLOAT_803defc8 < *(float *)(iVar14 + 0x4c)) {
      *(float *)(iVar14 + 0x4c) = FLOAT_803defd0;
    }
    local_40 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar14 + 0x50) ^ 0x80000000);
    iVar15 = (int)(*(float *)(iVar14 + 0x24) * (float)(local_40 - DOUBLE_803defb8));
    local_48 = (double)(longlong)iVar15;
    *psVar5 = *psVar5 + (short)iVar15;
    puVar10 = (undefined2 *)FUN_800395d8(psVar5,0);
    if (puVar10 != (undefined2 *)0x0) {
      *(ushort *)(iVar14 + 0x6e) = *(ushort *)(iVar14 + 0x6e) & 0xfff7;
      sVar12 = FUN_800385e8(psVar5,iVar6,0);
      local_40 = (double)CONCAT44(0x43300000,(int)sVar12 ^ 0x80000000);
      local_48 = (double)CONCAT44(0x43300000,(int)(short)puVar10[1] ^ 0x80000000);
      fVar2 = (float)(local_48 - DOUBLE_803defb8) * (FLOAT_803defc8 - *(float *)(iVar14 + 0x4c)) +
              (float)(local_40 - DOUBLE_803defb8) * *(float *)(iVar14 + 0x4c);
      uVar11 = (uint)(short)iVar7;
      uVar4 = -uVar11 ^ 0x80000000;
      local_50 = (double)CONCAT44(0x43300000,uVar4);
      if ((float)(local_50 - DOUBLE_803defb8) <= fVar2) {
        uVar11 = uVar11 ^ 0x80000000;
        local_60 = (double)CONCAT44(0x43300000,uVar11);
        if ((float)(local_60 - DOUBLE_803defb8) < fVar2) {
          local_68 = 0x43300000;
          fVar2 = (float)((double)CONCAT44(0x43300000,uVar11) - DOUBLE_803defb8);
          uStack100 = uVar11;
        }
      }
      else {
        local_58 = 0x43300000;
        fVar2 = (float)((double)CONCAT44(0x43300000,uVar4) - DOUBLE_803defb8);
        uStack84 = uVar4;
      }
      local_38 = (longlong)(int)fVar2;
      puVar10[1] = (short)(int)fVar2;
      uStack44 = (int)*(short *)(iVar14 + 0x52) ^ 0x80000000;
      local_30 = 0x43300000;
      iVar15 = (int)((float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803defb8) *
                    *(float *)(iVar14 + 0x4c));
      local_28 = (double)(longlong)iVar15;
      *puVar10 = (short)iVar15;
    }
    if ((param_6 != -1) && (param_7 != -1)) {
      uVar4 = (uint)*(short *)(iVar14 + 0x50);
      if ((int)uVar4 < 0) {
        uVar4 = -uVar4;
      }
      local_28 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      FUN_8002f5d4((double)((FLOAT_803defd4 * (float)(local_28 - DOUBLE_803defb8)) / FLOAT_803defd8)
                   ,psVar5,&local_78);
      uStack44 = (uint)DAT_803db410;
      local_30 = 0x43300000;
      FUN_8002fa48((double)local_78,
                   (double)(float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803defe0),psVar5,0
                  );
    }
    if (FLOAT_803defc8 < *(float *)(iVar14 + 0x4c)) {
      *(undefined *)(iVar14 + 0x56) = 0;
      *(ushort *)(iVar14 + 0x6e) = *(ushort *)(iVar14 + 0x6e) | 8;
      puVar10 = (undefined2 *)FUN_800395d8(psVar5,0);
      if (puVar10 == (undefined2 *)0x0) {
        *(undefined2 *)(iVar14 + 0x114) = 0;
        *(undefined2 *)(iVar14 + 0x116) = 0;
      }
      else {
        *(undefined2 *)(iVar14 + 0x114) = puVar10[1];
        *(undefined2 *)(iVar14 + 0x116) = *puVar10;
      }
      if (FLOAT_803defc8 < *(float *)(iVar14 + 0x4c)) {
        *(ushort *)(iVar14 + 0x6e) = *(ushort *)(iVar14 + 0x6e) | 4;
      }
    }
    uVar9 = 1;
  }
  else {
    uVar9 = 0;
  }
  FUN_8028611c(uVar9);
  return;
}

