// Function: FUN_801760e4
// Entry: 801760e4
// Size: 1540 bytes

/* WARNING: Removing unreachable block (ram,0x801766c8) */

void FUN_801760e4(void)

{
  float fVar1;
  short sVar2;
  bool bVar3;
  int iVar4;
  int iVar5;
  char cVar7;
  int iVar6;
  float *pfVar8;
  int iVar9;
  float *pfVar10;
  uint uVar11;
  uint uVar12;
  int iVar13;
  int iVar14;
  float *pfVar15;
  undefined4 uVar16;
  double dVar17;
  double in_f31;
  float local_128;
  int local_124;
  undefined4 local_120;
  undefined4 local_11c;
  undefined4 local_118;
  undefined4 local_114;
  float local_110 [4];
  undefined2 local_100;
  undefined2 local_fe;
  undefined2 local_fc;
  float local_f8;
  float local_f4;
  float local_f0;
  float local_ec;
  undefined auStack232 [4];
  uint local_e4;
  uint local_d8;
  undefined auStack208 [64];
  float local_90 [12];
  undefined4 local_60;
  uint uStack92;
  longlong local_58;
  undefined4 local_50;
  uint uStack76;
  double local_48;
  undefined auStack8 [8];
  
  uVar16 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,SUB84(in_f31,0),0);
  iVar4 = FUN_802860c8();
  local_120 = DAT_802c2270;
  local_11c = DAT_802c2274;
  local_118 = DAT_802c2278;
  local_114 = DAT_802c227c;
  FUN_8002b9ec();
  iVar14 = *(int *)(iVar4 + 0xb8);
  *(float *)(iVar14 + 0x110) = *(float *)(iVar14 + 0x110) - FLOAT_803db414;
  if (*(float *)(iVar14 + 0x110) <= FLOAT_803e3528) {
    *(float *)(iVar14 + 0x110) = FLOAT_803e3528;
  }
  if (-1 < *(char *)(iVar14 + 0x114)) {
    iVar5 = FUN_802969f0();
    fVar1 = FLOAT_803e35ac;
    if (iVar5 == 0xd) {
      fVar1 = FLOAT_803e35a8;
    }
    *(float *)(iVar14 + 0x108) = *(float *)(iVar14 + 0x108) * fVar1;
    if ((*(float *)(iVar14 + 0x108) < FLOAT_803e35b0) &&
       (FLOAT_803e35b4 < *(float *)(iVar14 + 0x108))) {
      *(float *)(iVar14 + 0x108) = FLOAT_803e3528;
    }
    *(float *)(iVar14 + 0x10c) = *(float *)(iVar14 + 0x10c) * fVar1;
    if ((*(float *)(iVar14 + 0x10c) < FLOAT_803e35b0) &&
       (FLOAT_803e35b4 < *(float *)(iVar14 + 0x10c))) {
      *(float *)(iVar14 + 0x10c) = FLOAT_803e3528;
    }
    if ((FLOAT_803e3528 != *(float *)(iVar14 + 0x108)) ||
       (FLOAT_803e3528 != *(float *)(iVar14 + 0x10c))) {
      local_100 = (undefined2)*(undefined4 *)(iVar14 + 0x140);
      local_fe = 0;
      local_fc = 0;
      local_f8 = FLOAT_803e3588;
      local_f4 = FLOAT_803e3528;
      local_f0 = FLOAT_803e3528;
      local_ec = FLOAT_803e3528;
      FUN_80021ee8(auStack208,&local_100);
      FUN_800226cc((double)*(float *)(iVar14 + 0x10c),(double)FLOAT_803e3528,
                   (double)*(float *)(iVar14 + 0x108),auStack208,iVar4 + 0x24,&local_128,
                   iVar4 + 0x2c);
      FUN_8002b95c((double)*(float *)(iVar4 + 0x24),(double)FLOAT_803e3528,
                   (double)*(float *)(iVar4 + 0x2c),iVar4);
      if ((*(ushort *)(iVar14 + 0x100) & 4) == 0) {
        FUN_80174bfc(iVar4,iVar14);
      }
      *(ushort *)(iVar14 + 0x100) = *(ushort *)(iVar14 + 0x100) | 2;
    }
  }
  *(byte *)(iVar14 + 0x114) = *(byte *)(iVar14 + 0x114) & 0xbf | 0x40;
  sVar2 = *(short *)(iVar4 + 0x46);
  if (sVar2 == 0x411) {
    iVar5 = FUN_8001ffb4((int)*(short *)(iVar14 + 0xac));
joined_r0x80176320:
    if (iVar5 != 0) goto LAB_801766c8;
  }
  else {
    if (sVar2 < 0x411) {
      if (sVar2 == 0x21e) {
        iVar5 = FUN_8001ffb4((int)*(short *)(iVar14 + 0xac));
      }
      else {
        if ((0x21d < sVar2) || (sVar2 != 0x108)) goto LAB_80176338;
        iVar5 = FUN_8001ffb4(0x272);
      }
      goto joined_r0x80176320;
    }
    if (sVar2 == 0x85a) {
      *(byte *)(iVar14 + 0x114) = *(byte *)(iVar14 + 0x114) & 0xbf;
    }
  }
LAB_80176338:
  if ((*(ushort *)(iVar14 + 0x100) & 4) != 0) {
    *(float *)(iVar4 + 0x28) = -(FLOAT_803e35b8 * FLOAT_803db414 - *(float *)(iVar4 + 0x28));
    *(float *)(iVar4 + 0x10) = *(float *)(iVar4 + 0x28) * FLOAT_803db414 + *(float *)(iVar4 + 0x10);
  }
  if (((*(ushort *)(iVar14 + 0x100) & 2) != 0) || ((*(ushort *)(iVar14 + 0x100) & 4) != 0)) {
    FUN_8000e318(iVar4);
    pfVar15 = local_90;
    pfVar10 = pfVar15;
    iVar5 = iVar14;
    for (iVar9 = 0; iVar9 < *(char *)(iVar14 + 0xb4); iVar9 = iVar9 + 1) {
      FUN_8000e0a0((double)*(float *)(iVar5 + 0x48),(double)*(float *)(iVar5 + 0x4c),
                   (double)*(float *)(iVar5 + 0x50),pfVar10,pfVar10 + 1,pfVar10 + 2,iVar4);
      pfVar10 = pfVar10 + 3;
      iVar5 = iVar5 + 0xc;
    }
    FUN_8006961c(auStack232,iVar14 + 0x78,local_90,&local_120,4);
    uStack92 = local_e4 ^ 0x80000000;
    local_60 = 0x43300000;
    local_e4 = (uint)((float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e3578) -
                     FLOAT_803e35bc);
    local_58 = (longlong)(int)local_e4;
    uStack76 = local_d8 ^ 0x80000000;
    local_50 = 0x43300000;
    local_d8 = (uint)((float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e3578) +
                     FLOAT_803e35bc);
    local_48 = (double)(longlong)(int)local_d8;
    FUN_800691c0(iVar4,auStack232,1,1);
    local_128 = FLOAT_803e3528;
    uVar12 = 0;
    uVar11 = 0;
    pfVar10 = local_110;
    for (iVar5 = 0; iVar5 < *(char *)(iVar14 + 0xb4); iVar5 = iVar5 + 1) {
      fVar1 = pfVar15[1];
      *pfVar10 = fVar1;
      in_f31 = (double)FLOAT_803e3528;
      cVar7 = FUN_80065e50((double)*pfVar15,(double)fVar1,(double)pfVar15[2],iVar4,&local_124,
                           0xffffffff,0);
      bVar3 = false;
      if (cVar7 != 0) {
        iVar9 = 0;
        for (iVar13 = 0; iVar13 < cVar7; iVar13 = iVar13 + 1) {
          pfVar8 = *(float **)(local_124 + iVar9);
          if (*(char *)(pfVar8 + 5) == '\x0e') {
            dVar17 = (double)(*pfVar8 - *(float *)(iVar4 + 0x10));
            if ((double)FLOAT_803e3528 < dVar17) {
              in_f31 = (double)(float)(in_f31 + dVar17);
              uVar11 = uVar11 + 1;
            }
          }
          else if (!bVar3) {
            fVar1 = *pfVar8;
            if (((fVar1 < FLOAT_803e3558 + pfVar15[1]) && (pfVar15[1] - FLOAT_803e35c0 < fVar1)) &&
               (FLOAT_803e35c4 < pfVar8[2])) {
              *pfVar10 = fVar1;
              local_128 = local_128 + fVar1;
              iVar6 = *(int *)(*(int *)(local_124 + iVar9) + 0x10);
              if (iVar6 != 0) {
                FUN_80036708(iVar6,iVar4);
              }
              uVar12 = uVar12 + 1;
              bVar3 = true;
            }
          }
          iVar9 = iVar9 + 4;
        }
      }
      pfVar15 = pfVar15 + 3;
      pfVar10 = pfVar10 + 1;
    }
    *(undefined4 *)(iVar14 + 0xf8) = *(undefined4 *)(iVar14 + 0xf4);
    if (uVar11 == 0) {
      *(float *)(iVar14 + 0xf4) = FLOAT_803e3528;
    }
    else {
      local_48 = (double)CONCAT44(0x43300000,uVar11 ^ 0x80000000);
      *(float *)(iVar14 + 0xf4) = (float)(in_f31 / (double)(float)(local_48 - DOUBLE_803e3578));
    }
    if ((uVar12 == 0) || (FLOAT_803e3528 < *(float *)(iVar14 + 0x110))) {
      if ((*(ushort *)(iVar14 + 0x100) & 4) == 0) {
        *(float *)(iVar14 + 0x110) = FLOAT_803e35c8;
      }
      *(ushort *)(iVar14 + 0x100) = *(ushort *)(iVar14 + 0x100) | 0xc;
    }
    else {
      *(float *)(iVar4 + 0x28) = FLOAT_803e3528;
      local_48 = (double)CONCAT44(0x43300000,uVar12 ^ 0x80000000);
      *(float *)(iVar4 + 0x10) = FLOAT_803e358c + local_128 / (float)(local_48 - DOUBLE_803e3578);
      *(ushort *)(iVar14 + 0x100) = *(ushort *)(iVar14 + 0x100) & 0xfff3;
    }
  }
  FUN_8000e318(iVar4);
  iVar5 = iVar14;
  for (iVar9 = 0; iVar9 < *(char *)(iVar14 + 0xb4); iVar9 = iVar9 + 1) {
    FUN_8000e0a0((double)*(float *)(iVar5 + 0x18),(double)*(float *)(iVar5 + 0x1c),
                 (double)*(float *)(iVar5 + 0x20),iVar5 + 0x78,iVar5 + 0x7c,iVar5 + 0x80,iVar4);
    iVar5 = iVar5 + 0xc;
  }
LAB_801766c8:
  __psq_l0(auStack8,uVar16);
  __psq_l1(auStack8,uVar16);
  FUN_80286114();
  return;
}

