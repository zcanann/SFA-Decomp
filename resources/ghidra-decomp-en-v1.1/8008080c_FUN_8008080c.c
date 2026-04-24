// Function: FUN_8008080c
// Entry: 8008080c
// Size: 1564 bytes

void FUN_8008080c(undefined4 param_1,undefined4 param_2,short param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  int iVar1;
  float fVar2;
  float fVar3;
  double dVar4;
  short sVar6;
  uint uVar5;
  ushort *puVar7;
  int iVar8;
  int iVar9;
  float *pfVar10;
  int iVar11;
  undefined2 *puVar12;
  uint uVar13;
  int iVar14;
  undefined4 uVar15;
  undefined4 uVar16;
  undefined4 uVar17;
  undefined4 uVar18;
  short sVar19;
  double dVar20;
  double dVar21;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined8 uVar22;
  float local_78;
  float local_74;
  float local_70;
  float local_6c;
  undefined4 local_68;
  uint uStack_64;
  undefined8 local_60;
  undefined4 local_58;
  uint uStack_54;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  longlong local_38;
  undefined4 local_30;
  uint uStack_2c;
  undefined8 local_28;
  
  uVar22 = FUN_80286834();
  puVar7 = (ushort *)((ulonglong)uVar22 >> 0x20);
  iVar14 = (int)uVar22;
  uVar15 = param_4;
  uVar16 = param_5;
  uVar17 = param_6;
  uVar18 = param_7;
  iVar8 = FUN_8002bac4();
  uStack_64 = (int)(short)param_4 ^ 0x80000000;
  local_68 = 0x43300000;
  iVar11 = (int)(FLOAT_803dfc40 * (float)((double)CONCAT44(0x43300000,uStack_64) - DOUBLE_803dfc38))
  ;
  local_60 = (double)(longlong)iVar11;
  uStack_54 = (int)(short)param_5 ^ 0x80000000;
  local_58 = 0x43300000;
  iVar9 = (int)(FLOAT_803dfc40 * (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803dfc38));
  local_50 = (double)(longlong)iVar9;
  local_48 = (double)CONCAT44(0x43300000,(int)param_3 ^ 0x80000000);
  iVar1 = (int)(FLOAT_803dfc40 * (float)(local_48 - DOUBLE_803dfc38));
  local_40 = (double)(longlong)iVar1;
  if (*(char *)(iVar14 + 0x56) == '\x04') {
    *(ushort *)(iVar14 + 0x6e) = *(ushort *)(iVar14 + 0x6e) & 0xfffd;
    iVar9 = FUN_800396d0((int)puVar7,0);
    if (iVar9 != 0) {
      *(ushort *)(iVar14 + 0x6e) = *(ushort *)(iVar14 + 0x6e) & 0xfff7;
    }
    *(code **)(iVar14 + 0xe8) = FUN_800807d4;
    fVar2 = FLOAT_803dfc30;
    *(float *)(iVar14 + 0x40) = FLOAT_803dfc30;
    *(float *)(iVar14 + 0x44) = fVar2;
    *(float *)(iVar14 + 0x48) = fVar2;
    iVar9 = FUN_800386e0(puVar7,iVar8,(float *)0x0);
    sVar6 = (short)iVar9;
    iVar9 = (int)sVar6;
    if (iVar9 < 0) {
      iVar9 = -iVar9;
    }
    sVar19 = (short)iVar11;
    if (iVar9 < sVar19) {
      sVar6 = 0;
    }
    else {
      if (0 < sVar6) {
        sVar19 = -sVar19;
      }
      sVar6 = sVar6 + sVar19;
    }
    *(short *)(iVar14 + 0x50) = sVar6;
    pfVar10 = *(float **)(puVar7 + 0x3a);
    if (pfVar10 == (float *)0x0) {
      local_74 = *(float *)(iVar8 + 0xc) - *(float *)(puVar7 + 6);
      local_70 = *(float *)(iVar8 + 0x10) - *(float *)(puVar7 + 8);
      local_6c = *(float *)(iVar8 + 0x14) - *(float *)(puVar7 + 10);
    }
    else {
      local_74 = *(float *)(iVar8 + 0xc) - *pfVar10;
      local_70 = *(float *)(iVar8 + 0x10) - pfVar10[1];
      local_6c = *(float *)(iVar8 + 0x14) - pfVar10[2];
    }
    local_70 = local_70 + FLOAT_803dfc44;
    dVar20 = FUN_80293900((double)(local_74 * local_74 + local_6c * local_6c));
    iVar11 = FUN_80021884();
    *(short *)(iVar14 + 0x52) = (short)iVar11;
    *(undefined2 *)(iVar14 + 0x54) = 0;
    *(undefined *)(iVar14 + 0x56) = 5;
    dVar21 = (double)FLOAT_803dfc30;
    *(float *)(iVar14 + 0x4c) = FLOAT_803dfc30;
    dVar4 = DOUBLE_803dfc38;
    if ((int)sVar6 == 0) {
      *(float *)(iVar14 + 0x24) = FLOAT_803dfc48;
    }
    else {
      local_40 = (double)CONCAT44(0x43300000,(int)(short)iVar1 ^ 0x80000000);
      local_48 = (double)CONCAT44(0x43300000,(int)sVar6 ^ 0x80000000);
      dVar20 = (double)((float)(local_40 - DOUBLE_803dfc38) / (float)(local_48 - DOUBLE_803dfc38));
      if (dVar20 < dVar21) {
        dVar20 = -dVar20;
      }
      *(float *)(iVar14 + 0x24) = (float)dVar20;
      dVar20 = dVar4;
    }
    fVar2 = *(float *)(iVar14 + 0x24);
    fVar3 = FLOAT_803dfc30;
    if ((FLOAT_803dfc30 <= fVar2) && (fVar3 = fVar2, FLOAT_803dfc4c < fVar2)) {
      fVar3 = FLOAT_803dfc4c;
    }
    *(float *)(iVar14 + 0x24) = fVar3;
    iVar11 = (int)(short)param_6;
    if ((iVar11 != -1) && (iVar9 = (int)(short)param_7, iVar9 != -1)) {
      *(ushort *)(iVar14 + 0x6e) = *(ushort *)(iVar14 + 0x6e) & 0xfffb;
      if (*(short *)(iVar14 + 0x50) < 0) {
        if (iVar9 != -1) {
          FUN_8003042c((double)FLOAT_803dfc30,dVar20,dVar21,in_f4,in_f5,in_f6,in_f7,in_f8,puVar7,
                       iVar9,0,uVar15,uVar16,uVar17,uVar18,param_8);
        }
      }
      else if (iVar11 != -1) {
        FUN_8003042c((double)FLOAT_803dfc30,dVar20,dVar21,in_f4,in_f5,in_f6,in_f7,in_f8,puVar7,
                     iVar11,0,uVar15,uVar16,uVar17,uVar18,param_8);
      }
    }
    *(code **)(iVar14 + 0xe8) = FUN_800807d4;
  }
  else if (*(char *)(iVar14 + 0x56) == '\x05') {
    *(float *)(iVar14 + 0x4c) = *(float *)(iVar14 + 0x4c) + *(float *)(iVar14 + 0x24);
    if (FLOAT_803dfc48 < *(float *)(iVar14 + 0x4c)) {
      *(float *)(iVar14 + 0x4c) = FLOAT_803dfc50;
    }
    local_40 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar14 + 0x50) ^ 0x80000000);
    iVar11 = (int)(*(float *)(iVar14 + 0x24) * (float)(local_40 - DOUBLE_803dfc38));
    local_48 = (double)(longlong)iVar11;
    *puVar7 = *puVar7 + (short)iVar11;
    puVar12 = (undefined2 *)FUN_800396d0((int)puVar7,0);
    if (puVar12 != (undefined2 *)0x0) {
      *(ushort *)(iVar14 + 0x6e) = *(ushort *)(iVar14 + 0x6e) & 0xfff7;
      iVar11 = FUN_800386e0(puVar7,iVar8,(float *)0x0);
      local_40 = (double)CONCAT44(0x43300000,(int)(short)iVar11 ^ 0x80000000);
      local_48 = (double)CONCAT44(0x43300000,(int)(short)puVar12[1] ^ 0x80000000);
      fVar2 = (float)(local_48 - DOUBLE_803dfc38) * (FLOAT_803dfc48 - *(float *)(iVar14 + 0x4c)) +
              (float)(local_40 - DOUBLE_803dfc38) * *(float *)(iVar14 + 0x4c);
      uVar13 = (uint)(short)iVar9;
      uVar5 = -uVar13 ^ 0x80000000;
      local_50 = (double)CONCAT44(0x43300000,uVar5);
      if ((float)(local_50 - DOUBLE_803dfc38) <= fVar2) {
        uVar13 = uVar13 ^ 0x80000000;
        local_60 = (double)CONCAT44(0x43300000,uVar13);
        if ((float)(local_60 - DOUBLE_803dfc38) < fVar2) {
          local_68 = 0x43300000;
          fVar2 = (float)((double)CONCAT44(0x43300000,uVar13) - DOUBLE_803dfc38);
          uStack_64 = uVar13;
        }
      }
      else {
        local_58 = 0x43300000;
        fVar2 = (float)((double)CONCAT44(0x43300000,uVar5) - DOUBLE_803dfc38);
        uStack_54 = uVar5;
      }
      local_38 = (longlong)(int)fVar2;
      puVar12[1] = (short)(int)fVar2;
      uStack_2c = (int)*(short *)(iVar14 + 0x52) ^ 0x80000000;
      local_30 = 0x43300000;
      iVar11 = (int)((float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803dfc38) *
                    *(float *)(iVar14 + 0x4c));
      local_28 = (double)(longlong)iVar11;
      *puVar12 = (short)iVar11;
    }
    if (((short)param_6 != -1) && ((short)param_7 != -1)) {
      uVar5 = (uint)*(short *)(iVar14 + 0x50);
      if ((int)uVar5 < 0) {
        uVar5 = -uVar5;
      }
      local_28 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      FUN_8002f6cc((double)((FLOAT_803dfc54 * (float)(local_28 - DOUBLE_803dfc38)) / FLOAT_803dfc58)
                   ,(int)puVar7,&local_78);
      uStack_2c = (uint)DAT_803dc070;
      local_30 = 0x43300000;
      FUN_8002fb40((double)local_78,
                   (double)(float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803dfc60));
    }
    if (FLOAT_803dfc48 < *(float *)(iVar14 + 0x4c)) {
      *(undefined *)(iVar14 + 0x56) = 0;
      *(ushort *)(iVar14 + 0x6e) = *(ushort *)(iVar14 + 0x6e) | 8;
      puVar12 = (undefined2 *)FUN_800396d0((int)puVar7,0);
      if (puVar12 == (undefined2 *)0x0) {
        *(undefined2 *)(iVar14 + 0x114) = 0;
        *(undefined2 *)(iVar14 + 0x116) = 0;
      }
      else {
        *(undefined2 *)(iVar14 + 0x114) = puVar12[1];
        *(undefined2 *)(iVar14 + 0x116) = *puVar12;
      }
      if (FLOAT_803dfc48 < *(float *)(iVar14 + 0x4c)) {
        *(ushort *)(iVar14 + 0x6e) = *(ushort *)(iVar14 + 0x6e) | 4;
      }
    }
  }
  FUN_80286880();
  return;
}

