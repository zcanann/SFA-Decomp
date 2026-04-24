// Function: FUN_80057410
// Entry: 80057410
// Size: 2324 bytes

void FUN_80057410(void)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  char cVar7;
  float *pfVar5;
  short sVar6;
  int *piVar8;
  int *piVar9;
  undefined *puVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  double dVar15;
  undefined auStack328 [12];
  float local_13c;
  float local_138;
  float local_134;
  float local_130;
  float local_12c;
  float local_128;
  undefined4 local_118;
  longlong local_38;
  double local_30;
  undefined4 local_28;
  uint uStack36;
  undefined4 local_20;
  uint uStack28;
  
  if (DAT_803dceb8 == -1) {
    DAT_803dceb8 = -2;
    DAT_803dcde0 = 8;
  }
  (**(code **)(*DAT_803dca54 + 4))();
  FUN_80069990();
  iVar11 = 0;
  piVar8 = &DAT_803822b4;
  piVar9 = &DAT_803822a0;
  do {
    iVar13 = *piVar8;
    iVar3 = *piVar9;
    iVar12 = 0;
    iVar14 = 0x10;
    do {
      puVar10 = (undefined *)(iVar13 + iVar12);
      *puVar10 = 0xff;
      *(undefined *)(iVar3 + 9) = 0xff;
      puVar10[1] = 0xff;
      *(undefined *)(iVar3 + 0x15) = 0xff;
      puVar10[2] = 0xff;
      *(undefined *)(iVar3 + 0x21) = 0xff;
      puVar10[3] = 0xff;
      *(undefined *)(iVar3 + 0x2d) = 0xff;
      puVar10[4] = 0xff;
      *(undefined *)(iVar3 + 0x39) = 0xff;
      puVar10[5] = 0xff;
      *(undefined *)(iVar3 + 0x45) = 0xff;
      puVar10[6] = 0xff;
      *(undefined *)(iVar3 + 0x51) = 0xff;
      puVar10[7] = 0xff;
      *(undefined *)(iVar3 + 0x5d) = 0xff;
      puVar10 = (undefined *)(iVar13 + iVar12 + 8);
      *puVar10 = 0xff;
      *(undefined *)(iVar3 + 0x69) = 0xff;
      puVar10[1] = 0xff;
      *(undefined *)(iVar3 + 0x75) = 0xff;
      puVar10[2] = 0xff;
      *(undefined *)(iVar3 + 0x81) = 0xff;
      puVar10[3] = 0xff;
      *(undefined *)(iVar3 + 0x8d) = 0xff;
      puVar10[4] = 0xff;
      *(undefined *)(iVar3 + 0x99) = 0xff;
      puVar10[5] = 0xff;
      *(undefined *)(iVar3 + 0xa5) = 0xff;
      puVar10[6] = 0xff;
      *(undefined *)(iVar3 + 0xb1) = 0xff;
      puVar10[7] = 0xff;
      *(undefined *)(iVar3 + 0xbd) = 0xff;
      iVar3 = iVar3 + 0xc0;
      iVar12 = iVar12 + 0x10;
      iVar14 = iVar14 + -1;
    } while (iVar14 != 0);
    piVar8 = piVar8 + 1;
    piVar9 = piVar9 + 1;
    iVar11 = iVar11 + 1;
  } while (iVar11 < 5);
  iVar11 = 0;
  iVar3 = 0;
  iVar12 = 8;
  do {
    *(undefined2 *)(DAT_803dce94 + iVar11) = 0xffff;
    *(undefined4 *)(DAT_803dce9c + iVar3) = 0;
    *(undefined2 *)(DAT_803dce94 + iVar11 + 2) = 0xffff;
    *(undefined4 *)(DAT_803dce9c + iVar3 + 4) = 0;
    *(undefined2 *)(DAT_803dce94 + iVar11 + 4) = 0xffff;
    *(undefined4 *)(DAT_803dce9c + iVar3 + 8) = 0;
    *(undefined2 *)(DAT_803dce94 + iVar11 + 6) = 0xffff;
    *(undefined4 *)(DAT_803dce9c + iVar3 + 0xc) = 0;
    *(undefined2 *)(DAT_803dce94 + iVar11 + 8) = 0xffff;
    *(undefined4 *)(DAT_803dce9c + iVar3 + 0x10) = 0;
    *(undefined2 *)(DAT_803dce94 + iVar11 + 10) = 0xffff;
    *(undefined4 *)(DAT_803dce9c + iVar3 + 0x14) = 0;
    *(undefined2 *)(DAT_803dce94 + iVar11 + 0xc) = 0xffff;
    *(undefined4 *)(DAT_803dce9c + iVar3 + 0x18) = 0;
    *(undefined2 *)(DAT_803dce94 + iVar11 + 0xe) = 0xffff;
    *(undefined4 *)(DAT_803dce9c + iVar3 + 0x1c) = 0;
    iVar11 = iVar11 + 0x10;
    iVar3 = iVar3 + 0x20;
    iVar12 = iVar12 + -1;
  } while (iVar12 != 0);
  DAT_803dce98 = 0;
  DAT_803dcdec = 0;
  cVar7 = (**(code **)(*DAT_803dcaac + 0x74))();
  pfVar5 = (float *)(**(code **)(*DAT_803dcaac + 0x90))();
  dVar15 = (double)FUN_80291e40((double)(*pfVar5 / FLOAT_803debb4));
  DAT_803dcdd0 = (int)dVar15;
  local_38 = (longlong)DAT_803dcdd0;
  dVar15 = (double)FUN_80291e40((double)(pfVar5[2] / FLOAT_803debb4));
  DAT_803dcdd4 = (int)dVar15;
  local_30 = (double)(longlong)DAT_803dcdd4;
  DAT_80386648 = *pfVar5;
  DAT_8038664c = pfVar5[1];
  DAT_80386650 = pfVar5[2];
  DAT_80386654 = 1;
  DAT_803dcdc8 = DAT_803dcdd0 * 0x280;
  DAT_803dcdcc = DAT_803dcdd4 * 0x280;
  uStack36 = DAT_803dcdc8 ^ 0x80000000;
  local_28 = 0x43300000;
  FLOAT_803dcdd8 = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803debc0);
  uStack28 = DAT_803dcdcc ^ 0x80000000;
  local_20 = 0x43300000;
  FLOAT_803dcddc = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803debc0);
  DAT_803dcec8 = 0xffffffff;
  DAT_803dcec4 = DAT_803dcec4 + -1;
  DAT_803dcec0 = 0xffffffff;
  DAT_803dcde1 = *(undefined *)((int)pfVar5 + 0xd);
  DAT_803dcde8 = DAT_803dcde8 & 0x82008 | 0x489f4;
  DAT_803dce04 = 0;
  DAT_803dcdf4 = 0;
  DAT_803dcdf7 = 0;
  FLOAT_803db62c = FLOAT_803debcc;
  DAT_803dce00 = 0xffffffff;
  FLOAT_803dcecc = FLOAT_803dcddc;
  FLOAT_803dced0 = FLOAT_803dcdd8;
  FUN_800e8798();
  if ((((DAT_803dcde8 & 2) == 0) || ((DAT_803dcde8 & 0x800) != 0)) &&
     (uVar4 = DAT_803dcde8 | 2, uVar2 = DAT_803dcde8 & 0x800, DAT_803dcde8 = uVar4,
     FLOAT_803dce5c = pfVar5[2], FLOAT_803dce60 = pfVar5[1], FLOAT_803dce64 = *pfVar5, uVar2 != 0))
  {
    FUN_80058094();
  }
  DAT_803dcde8 = DAT_803dcde8 & 0xfffffffb;
  FUN_80064c8c();
  iVar11 = FUN_8000faac();
  *(float *)(iVar11 + 0xc) = *pfVar5;
  *(float *)(iVar11 + 0x10) = pfVar5[1];
  *(float *)(iVar11 + 0x14) = pfVar5[2];
  FUN_8002ba2c();
  DAT_803dcebd = 0;
  (**(code **)(*DAT_803dca98 + 0x1c))();
  (**(code **)(*DAT_803dca80 + 4))();
  (**(code **)(*DAT_803dca7c + 4))();
  (**(code **)(*DAT_803dca78 + 4))();
  (**(code **)(*DAT_803dca88 + 4))();
  (**(code **)(*DAT_803dca64 + 0x14))();
  (**(code **)(*DAT_803dca64 + 8))();
  (**(code **)(*DAT_803dca5c + 8))();
  (**(code **)(*DAT_803dca58 + 8))();
  (**(code **)(*DAT_803dca60 + 8))();
  FUN_8006fccc();
  iVar11 = FUN_8002b9ec();
  if (((DAT_803dceb8 == -2) && (iVar11 != 0)) && ((cVar7 == '\0' || (cVar7 == '\x01')))) {
    sVar6 = FUN_800e84e8();
    if (sVar6 != -1) {
      (**(code **)(*DAT_803dca50 + 0x24))(0,(int)sVar6,1);
    }
    pfVar5 = (float *)FUN_800e84f8();
    if ((int)*(short *)(pfVar5 + 1) != 0xffffffff) {
      FUN_80008b74(iVar11,iVar11,(int)*(short *)(pfVar5 + 1) & 0xffff,0);
    }
    if ((int)*(short *)((int)pfVar5 + 6) != 0xffffffff) {
      FUN_80008b74(iVar11,iVar11,(int)*(short *)((int)pfVar5 + 6) & 0xffff,0);
    }
    if ((int)*(short *)((int)pfVar5 + 10) != 0xffffffff) {
      FUN_80008b74(iVar11,iVar11,(int)*(short *)((int)pfVar5 + 10) & 0xffff,0);
    }
    if ((int)*(short *)(pfVar5 + 3) != 0xffffffff) {
      FUN_80008b74(iVar11,iVar11,(int)*(short *)(pfVar5 + 3) & 0xffff,0);
    }
    FUN_80088c94(1,(*(byte *)(pfVar5 + 0x10) & 2) != 0);
    FUN_80088c94(2,(*(byte *)(pfVar5 + 0x10) & 4) != 0);
    FUN_80088e54((double)FLOAT_803debcc,(*(byte *)(pfVar5 + 0x10) & 0x10) != 0);
    bVar1 = *(byte *)(pfVar5 + 0x10);
    iVar3 = FUN_800e84f8();
    if ((bVar1 & 1) == 0) {
      DAT_803dcde8 = DAT_803dcde8 & 0xffffffaf;
      *(byte *)(iVar3 + 0x40) = *(byte *)(iVar3 + 0x40) & 0xf6;
    }
    else {
      DAT_803dcde8 = DAT_803dcde8 | 0x50;
      *(byte *)(iVar3 + 0x40) = *(byte *)(iVar3 + 0x40) | 9;
    }
    bVar1 = *(byte *)(pfVar5 + 0x10);
    iVar3 = FUN_800e84f8();
    if ((bVar1 & 8) == 0) {
      DAT_803dcde8 = DAT_803dcde8 & 0xffffffbf;
      *(byte *)(iVar3 + 0x40) = *(byte *)(iVar3 + 0x40) & 0xf7;
    }
    else {
      DAT_803dcde8 = DAT_803dcde8 | 0x40;
      *(byte *)(iVar3 + 0x40) = *(byte *)(iVar3 + 0x40) | 8;
    }
    if ((*(byte *)(pfVar5 + 0x10) & 0x20) == 0) {
      DAT_803dce00 = 0xffffffff;
    }
    else {
      DAT_803dce00 = 1;
    }
    local_118 = 0;
    local_13c = FLOAT_803debcc;
    local_138 = FLOAT_803debcc;
    local_134 = FLOAT_803debcc;
    local_130 = FLOAT_803debcc;
    local_12c = FLOAT_803debcc;
    local_128 = FLOAT_803debcc;
    if ((int)*(short *)((int)pfVar5 + 0xe) != 0xffffffff) {
      uStack28 = (uint)pfVar5[5] ^ 0x80000000;
      local_20 = 0x43300000;
      local_13c = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803debc0);
      uStack36 = (uint)pfVar5[6] ^ 0x80000000;
      local_28 = 0x43300000;
      local_138 = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803debc0);
      local_30 = (double)CONCAT44(0x43300000,(uint)pfVar5[7] ^ 0x80000000);
      local_134 = (float)(local_30 - DOUBLE_803debc0);
      FUN_80008cbc(auStack328,iVar11,(int)*(short *)((int)pfVar5 + 0xe) & 0xffff,0);
    }
    if ((int)*(short *)(pfVar5 + 4) != 0xffffffff) {
      uStack28 = (uint)pfVar5[8] ^ 0x80000000;
      local_20 = 0x43300000;
      local_13c = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803debc0);
      uStack36 = (uint)pfVar5[9] ^ 0x80000000;
      local_28 = 0x43300000;
      local_138 = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803debc0);
      local_30 = (double)CONCAT44(0x43300000,(uint)pfVar5[10] ^ 0x80000000);
      local_134 = (float)(local_30 - DOUBLE_803debc0);
      FUN_80008cbc(auStack328,iVar11,(int)*(short *)(pfVar5 + 4) & 0xffff,0);
    }
    if ((int)*(short *)((int)pfVar5 + 0x12) != 0xffffffff) {
      uStack28 = (uint)pfVar5[0xb] ^ 0x80000000;
      local_20 = 0x43300000;
      local_13c = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803debc0);
      uStack36 = (uint)pfVar5[0xc] ^ 0x80000000;
      local_28 = 0x43300000;
      local_138 = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803debc0);
      local_30 = (double)CONCAT44(0x43300000,(uint)pfVar5[0xd] ^ 0x80000000);
      local_134 = (float)(local_30 - DOUBLE_803debc0);
      FUN_80008cbc(auStack328,iVar11,(int)*(short *)((int)pfVar5 + 0x12) & 0xffff,0);
    }
    (**(code **)(*DAT_803dca58 + 0x28))((double)*pfVar5);
  }
  else {
    (**(code **)(*DAT_803dca58 + 0x28))((double)FLOAT_803debd0);
    (**(code **)(*DAT_803dca64 + 0x1c))(1);
  }
  FUN_800e878c();
  FUN_8012fdb8(0);
  FUN_8012fdc0();
  return;
}

