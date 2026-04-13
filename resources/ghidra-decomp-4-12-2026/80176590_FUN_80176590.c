// Function: FUN_80176590
// Entry: 80176590
// Size: 1540 bytes

/* WARNING: Removing unreachable block (ram,0x80176b74) */
/* WARNING: Removing unreachable block (ram,0x801765a0) */

void FUN_80176590(void)

{
  float fVar1;
  short sVar2;
  bool bVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  char cVar8;
  int iVar7;
  float *pfVar9;
  int iVar10;
  float *pfVar11;
  uint uVar12;
  int iVar13;
  int iVar14;
  float *pfVar15;
  double dVar16;
  double in_f31;
  double in_ps31_1;
  float local_128;
  int local_124;
  float local_120;
  undefined4 local_11c;
  undefined4 local_118;
  undefined4 local_114;
  float local_110 [4];
  ushort local_100;
  undefined2 local_fe;
  undefined2 local_fc;
  float local_f8;
  float local_f4;
  float local_f0;
  float local_ec;
  uint uStack_e8;
  uint local_e4;
  uint local_d8;
  float afStack_d0 [16];
  float local_90 [12];
  undefined4 local_60;
  uint uStack_5c;
  longlong local_58;
  undefined4 local_50;
  uint uStack_4c;
  undefined8 local_48;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  iVar4 = FUN_8028682c();
  local_120 = DAT_802c29f0;
  local_11c = DAT_802c29f4;
  local_118 = DAT_802c29f8;
  local_114 = DAT_802c29fc;
  iVar5 = FUN_8002bac4();
  iVar14 = *(int *)(iVar4 + 0xb8);
  *(float *)(iVar14 + 0x110) = *(float *)(iVar14 + 0x110) - FLOAT_803dc074;
  if (*(float *)(iVar14 + 0x110) <= FLOAT_803e41c0) {
    *(float *)(iVar14 + 0x110) = FLOAT_803e41c0;
  }
  if (-1 < *(char *)(iVar14 + 0x114)) {
    uVar6 = FUN_80297150(iVar5);
    fVar1 = FLOAT_803e4244;
    if (uVar6 == 0xd) {
      fVar1 = FLOAT_803e4240;
    }
    *(float *)(iVar14 + 0x108) = *(float *)(iVar14 + 0x108) * fVar1;
    if ((*(float *)(iVar14 + 0x108) < FLOAT_803e4248) &&
       (FLOAT_803e424c < *(float *)(iVar14 + 0x108))) {
      *(float *)(iVar14 + 0x108) = FLOAT_803e41c0;
    }
    *(float *)(iVar14 + 0x10c) = *(float *)(iVar14 + 0x10c) * fVar1;
    if ((*(float *)(iVar14 + 0x10c) < FLOAT_803e4248) &&
       (FLOAT_803e424c < *(float *)(iVar14 + 0x10c))) {
      *(float *)(iVar14 + 0x10c) = FLOAT_803e41c0;
    }
    if ((FLOAT_803e41c0 != *(float *)(iVar14 + 0x108)) ||
       (FLOAT_803e41c0 != *(float *)(iVar14 + 0x10c))) {
      local_100 = (ushort)*(undefined4 *)(iVar14 + 0x140);
      local_fe = 0;
      local_fc = 0;
      local_f8 = FLOAT_803e4220;
      local_f4 = FLOAT_803e41c0;
      local_f0 = FLOAT_803e41c0;
      local_ec = FLOAT_803e41c0;
      FUN_80021fac(afStack_d0,&local_100);
      FUN_80022790((double)*(float *)(iVar14 + 0x10c),(double)FLOAT_803e41c0,
                   (double)*(float *)(iVar14 + 0x108),afStack_d0,(float *)(iVar4 + 0x24),&local_128,
                   (float *)(iVar4 + 0x2c));
      FUN_8002ba34((double)*(float *)(iVar4 + 0x24),(double)FLOAT_803e41c0,
                   (double)*(float *)(iVar4 + 0x2c),iVar4);
      if ((*(ushort *)(iVar14 + 0x100) & 4) == 0) {
        FUN_801750a8();
      }
      *(ushort *)(iVar14 + 0x100) = *(ushort *)(iVar14 + 0x100) | 2;
    }
  }
  *(byte *)(iVar14 + 0x114) = *(byte *)(iVar14 + 0x114) & 0xbf | 0x40;
  sVar2 = *(short *)(iVar4 + 0x46);
  if (sVar2 == 0x411) {
    uVar6 = FUN_80020078((int)*(short *)(iVar14 + 0xac));
joined_r0x801767cc:
    if (uVar6 != 0) goto LAB_80176b74;
  }
  else {
    if (sVar2 < 0x411) {
      if (sVar2 == 0x21e) {
        uVar6 = FUN_80020078((int)*(short *)(iVar14 + 0xac));
      }
      else {
        if ((0x21d < sVar2) || (sVar2 != 0x108)) goto LAB_801767e4;
        uVar6 = FUN_80020078(0x272);
      }
      goto joined_r0x801767cc;
    }
    if (sVar2 == 0x85a) {
      *(byte *)(iVar14 + 0x114) = *(byte *)(iVar14 + 0x114) & 0xbf;
    }
  }
LAB_801767e4:
  if ((*(ushort *)(iVar14 + 0x100) & 4) != 0) {
    *(float *)(iVar4 + 0x28) = -(FLOAT_803e4250 * FLOAT_803dc074 - *(float *)(iVar4 + 0x28));
    *(float *)(iVar4 + 0x10) = *(float *)(iVar4 + 0x28) * FLOAT_803dc074 + *(float *)(iVar4 + 0x10);
  }
  if (((*(ushort *)(iVar14 + 0x100) & 2) != 0) || ((*(ushort *)(iVar14 + 0x100) & 4) != 0)) {
    FUN_8000e338();
    pfVar15 = local_90;
    pfVar11 = pfVar15;
    iVar5 = iVar14;
    for (iVar10 = 0; iVar10 < *(char *)(iVar14 + 0xb4); iVar10 = iVar10 + 1) {
      FUN_8000e0c0((double)*(float *)(iVar5 + 0x48),(double)*(float *)(iVar5 + 0x4c),
                   (double)*(float *)(iVar5 + 0x50),pfVar11,pfVar11 + 1,pfVar11 + 2,iVar4);
      pfVar11 = pfVar11 + 3;
      iVar5 = iVar5 + 0xc;
    }
    FUN_80069798(&uStack_e8,(float *)(iVar14 + 0x78),local_90,&local_120,4);
    uStack_5c = local_e4 ^ 0x80000000;
    local_60 = 0x43300000;
    local_e4 = (uint)((float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e4210) -
                     FLOAT_803e4254);
    local_58 = (longlong)(int)local_e4;
    uStack_4c = local_d8 ^ 0x80000000;
    local_50 = 0x43300000;
    local_d8 = (uint)((float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e4210) +
                     FLOAT_803e4254);
    local_48 = (double)(longlong)(int)local_d8;
    FUN_8006933c(iVar4,&uStack_e8,1,'\x01');
    local_128 = FLOAT_803e41c0;
    uVar12 = 0;
    uVar6 = 0;
    pfVar11 = local_110;
    for (iVar5 = 0; iVar5 < *(char *)(iVar14 + 0xb4); iVar5 = iVar5 + 1) {
      fVar1 = pfVar15[1];
      *pfVar11 = fVar1;
      in_f31 = (double)FLOAT_803e41c0;
      cVar8 = FUN_80065fcc((double)*pfVar15,(double)fVar1,(double)pfVar15[2],iVar4,&local_124,-1,0);
      bVar3 = false;
      if (cVar8 != 0) {
        iVar10 = 0;
        for (iVar13 = 0; iVar13 < cVar8; iVar13 = iVar13 + 1) {
          pfVar9 = *(float **)(local_124 + iVar10);
          if (*(char *)(pfVar9 + 5) == '\x0e') {
            dVar16 = (double)(*pfVar9 - *(float *)(iVar4 + 0x10));
            if ((double)FLOAT_803e41c0 < dVar16) {
              in_f31 = (double)(float)(in_f31 + dVar16);
              uVar6 = uVar6 + 1;
            }
          }
          else if (!bVar3) {
            fVar1 = *pfVar9;
            if (((fVar1 < FLOAT_803e41f0 + pfVar15[1]) && (pfVar15[1] - FLOAT_803e4258 < fVar1)) &&
               (FLOAT_803e425c < pfVar9[2])) {
              *pfVar11 = fVar1;
              local_128 = local_128 + fVar1;
              iVar7 = *(int *)(*(int *)(local_124 + iVar10) + 0x10);
              if (iVar7 != 0) {
                FUN_80036800(iVar7,iVar4);
              }
              uVar12 = uVar12 + 1;
              bVar3 = true;
            }
          }
          iVar10 = iVar10 + 4;
        }
      }
      pfVar15 = pfVar15 + 3;
      pfVar11 = pfVar11 + 1;
    }
    *(undefined4 *)(iVar14 + 0xf8) = *(undefined4 *)(iVar14 + 0xf4);
    if (uVar6 == 0) {
      *(float *)(iVar14 + 0xf4) = FLOAT_803e41c0;
    }
    else {
      local_48 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      *(float *)(iVar14 + 0xf4) = (float)(in_f31 / (double)(float)(local_48 - DOUBLE_803e4210));
    }
    if ((uVar12 == 0) || (FLOAT_803e41c0 < *(float *)(iVar14 + 0x110))) {
      if ((*(ushort *)(iVar14 + 0x100) & 4) == 0) {
        *(float *)(iVar14 + 0x110) = FLOAT_803e4260;
      }
      *(ushort *)(iVar14 + 0x100) = *(ushort *)(iVar14 + 0x100) | 0xc;
    }
    else {
      *(float *)(iVar4 + 0x28) = FLOAT_803e41c0;
      local_48 = (double)CONCAT44(0x43300000,uVar12 ^ 0x80000000);
      *(float *)(iVar4 + 0x10) = FLOAT_803e4224 + local_128 / (float)(local_48 - DOUBLE_803e4210);
      *(ushort *)(iVar14 + 0x100) = *(ushort *)(iVar14 + 0x100) & 0xfff3;
    }
  }
  FUN_8000e338();
  iVar5 = iVar14;
  for (iVar10 = 0; iVar10 < *(char *)(iVar14 + 0xb4); iVar10 = iVar10 + 1) {
    FUN_8000e0c0((double)*(float *)(iVar5 + 0x18),(double)*(float *)(iVar5 + 0x1c),
                 (double)*(float *)(iVar5 + 0x20),(float *)(iVar5 + 0x78),(float *)(iVar5 + 0x7c),
                 (float *)(iVar5 + 0x80),iVar4);
    iVar5 = iVar5 + 0xc;
  }
LAB_80176b74:
  FUN_80286878();
  return;
}

