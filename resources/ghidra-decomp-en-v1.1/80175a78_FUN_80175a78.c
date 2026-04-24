// Function: FUN_80175a78
// Entry: 80175a78
// Size: 2284 bytes

/* WARNING: Removing unreachable block (ram,0x80176344) */
/* WARNING: Removing unreachable block (ram,0x8017633c) */
/* WARNING: Removing unreachable block (ram,0x80175a90) */
/* WARNING: Removing unreachable block (ram,0x80175a88) */

void FUN_80175a78(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 int param_5)

{
  bool bVar1;
  short sVar2;
  ushort uVar3;
  float fVar4;
  float fVar5;
  int *piVar6;
  int iVar7;
  byte bVar9;
  uint uVar8;
  ushort *puVar10;
  int iVar11;
  float *pfVar12;
  int iVar13;
  float *pfVar14;
  int iVar15;
  double dVar16;
  double extraout_f1;
  double in_f30;
  double dVar17;
  double in_f31;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar18;
  float fStack_1b0;
  float local_1ac;
  float local_1a8;
  float local_1a4;
  float local_1a0;
  float local_19c;
  float local_198;
  uint auStack_194 [6];
  ushort local_17c [4];
  float local_174;
  float local_170;
  float local_16c;
  float local_168;
  float local_164 [12];
  float local_134 [12];
  float afStack_104 [32];
  float local_84 [4];
  undefined local_74;
  undefined local_70;
  undefined2 local_58;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar18 = FUN_80286834();
  piVar6 = (int *)((ulonglong)uVar18 >> 0x20);
  puVar10 = (ushort *)uVar18;
  dVar17 = extraout_f1;
  iVar7 = FUN_8002bac4();
  iVar15 = piVar6[0x2e];
  iVar11 = 5;
  iVar13 = iVar15 + 0x14;
  while( true ) {
    bVar1 = iVar11 == 0;
    iVar11 = iVar11 + -1;
    if (bVar1) break;
    *(undefined4 *)(iVar13 + 0x114) = *(undefined4 *)(iVar13 + 0x110);
    *(undefined4 *)(iVar13 + 0x128) = *(undefined4 *)(iVar13 + 0x124);
    iVar13 = iVar13 + -4;
  }
  *(int *)(iVar15 + 0x118) = piVar6[3];
  *(int *)(iVar15 + 300) = piVar6[5];
  local_1a0 = *(float *)(puVar10 + 6);
  local_19c = FLOAT_803e4234 + *(float *)(puVar10 + 8);
  local_198 = *(float *)(puVar10 + 10);
  local_84[0] = FLOAT_803e4238;
  local_74 = 0xff;
  local_70 = 3;
  local_58 = 0;
  iVar13 = 0;
  dVar16 = (double)FLOAT_803e41c0;
  if (dVar17 <= dVar16) {
    if (param_2 <= dVar16) {
      if (param_2 < dVar16) {
        uStack_44 = *(int *)(iVar15 + 0x140) - 0x4000U ^ 0x80000000;
        local_48 = 0x43300000;
        dVar16 = (double)FUN_802945e0();
        local_1ac = (float)((double)FLOAT_803e423c * dVar16 + (double)local_1a0);
        local_1a8 = local_19c;
        uStack_4c = *(int *)(iVar15 + 0x140) - 0x4000U ^ 0x80000000;
        local_50 = 0x43300000;
        dVar16 = (double)FUN_80294964();
        local_1a4 = (float)((double)FLOAT_803e423c * dVar16 + (double)local_198);
        FUN_80069798(auStack_194,&local_1a0,&local_1ac,local_84,1);
        FUN_8006933c(0,auStack_194,0x208,'\x01');
        iVar13 = FUN_80067ad4();
        if (iVar13 == 0) {
          iVar13 = FUN_80064248(&local_1a0,&local_1ac,(float *)0x0,(int *)0x0,piVar6,1,0xffffffff,
                                0xff,0);
        }
        if (iVar13 != 0) {
          *(ushort *)(iVar15 + 0x100) = *(ushort *)(iVar15 + 0x100) | 0x400;
          fVar4 = FLOAT_803e41c0;
          *(float *)(iVar15 + 0x108) = FLOAT_803e41c0;
          *(float *)(iVar15 + 0x10c) = fVar4;
        }
      }
    }
    else {
      uStack_44 = *(int *)(iVar15 + 0x140) + 0x4000U ^ 0x80000000;
      local_48 = 0x43300000;
      dVar16 = (double)FUN_802945e0();
      local_1ac = (float)((double)FLOAT_803e423c * dVar16 + (double)local_1a0);
      local_1a8 = local_19c;
      uStack_4c = *(int *)(iVar15 + 0x140) + 0x4000U ^ 0x80000000;
      local_50 = 0x43300000;
      dVar16 = (double)FUN_80294964();
      local_1a4 = (float)((double)FLOAT_803e423c * dVar16 + (double)local_198);
      FUN_80069798(auStack_194,&local_1a0,&local_1ac,local_84,1);
      FUN_8006933c(0,auStack_194,0x208,'\x01');
      iVar13 = FUN_80067ad4();
      if (iVar13 == 0) {
        iVar13 = FUN_80064248(&local_1a0,&local_1ac,(float *)0x0,(int *)0x0,piVar6,1,0xffffffff,0xff
                              ,0);
      }
      if (iVar13 != 0) {
        *(ushort *)(iVar15 + 0x100) = *(ushort *)(iVar15 + 0x100) | 0x800;
        fVar4 = FLOAT_803e41c0;
        *(float *)(iVar15 + 0x108) = FLOAT_803e41c0;
        *(float *)(iVar15 + 0x10c) = fVar4;
      }
    }
  }
  else {
    uStack_4c = *(uint *)(iVar15 + 0x140) ^ 0x80000000;
    local_50 = 0x43300000;
    dVar16 = (double)FUN_802945e0();
    local_1ac = (float)((double)FLOAT_803e4238 * dVar16 + (double)local_1a0);
    local_1a8 = local_19c;
    uStack_44 = *(uint *)(iVar15 + 0x140) ^ 0x80000000;
    local_48 = 0x43300000;
    dVar16 = (double)FUN_80294964();
    local_1a4 = (float)((double)FLOAT_803e4238 * dVar16 + (double)local_198);
    FUN_80069798(auStack_194,&local_1a0,&local_1ac,local_84,1);
    FUN_8006933c(0,auStack_194,0x208,'\x01');
    iVar13 = FUN_80067ad4();
    if (iVar13 == 0) {
      iVar13 = FUN_80064248(&local_1a0,&local_1ac,(float *)0x0,(int *)0x0,piVar6,1,0xffffffff,0xff,0
                           );
    }
    if (iVar13 != 0) {
      *(ushort *)(iVar15 + 0x100) = *(ushort *)(iVar15 + 0x100) | 0x200;
      fVar4 = FLOAT_803e41c0;
      *(float *)(iVar15 + 0x108) = FLOAT_803e41c0;
      *(float *)(iVar15 + 0x10c) = fVar4;
    }
  }
  bVar9 = FUN_80296434(iVar7);
  if ((bVar9 == 0) && ((*(byte *)(iVar15 + 0x114) >> 6 & 1) == 0)) {
    iVar13 = 1;
    dVar16 = (double)FLOAT_803e41c0;
    if (dVar17 <= dVar16) {
      if (dVar16 <= dVar17) {
        if (param_2 <= dVar16) {
          *(ushort *)(iVar15 + 0x100) = *(ushort *)(iVar15 + 0x100) | 0x400;
        }
        else {
          *(ushort *)(iVar15 + 0x100) = *(ushort *)(iVar15 + 0x100) | 0x800;
        }
      }
      else {
        *(ushort *)(iVar15 + 0x100) = *(ushort *)(iVar15 + 0x100) | 0x100;
      }
    }
    else {
      *(ushort *)(iVar15 + 0x100) = *(ushort *)(iVar15 + 0x100) | 0x200;
    }
    fVar4 = FLOAT_803e41c0;
    *(float *)(iVar15 + 0x108) = FLOAT_803e41c0;
    *(float *)(iVar15 + 0x10c) = fVar4;
  }
  if ((param_5 == 0) || ((*(ushort *)(iVar15 + 0x100) & 8) != 0)) {
    iVar7 = piVar6[0x16];
    bVar9 = *(byte *)(iVar7 + 0x10c);
    iVar13 = iVar15;
    for (iVar11 = 0; iVar11 < *(char *)(iVar15 + 0xb4); iVar11 = iVar11 + 1) {
      FUN_80022790((double)*(float *)(iVar13 + 0x18),(double)*(float *)(iVar13 + 0x1c),
                   (double)*(float *)(iVar13 + 0x20),(float *)(iVar7 + (bVar9 + 2) * 0x40),
                   (float *)(iVar13 + 0x78),(float *)(iVar13 + 0x7c),(float *)(iVar13 + 0x80));
      iVar13 = iVar13 + 0xc;
    }
    goto LAB_801762c4;
  }
  *(ushort *)(iVar15 + 0x100) = *(ushort *)(iVar15 + 0x100) | 2;
  *(char *)(iVar15 + 0x115) = *(char *)(iVar15 + 0x115) + -1;
  if (*(char *)(iVar15 + 0x115) < '\x01') {
    uVar8 = FUN_80022264(0x28,0x3c);
    *(char *)(iVar15 + 0x115) = (char)uVar8;
    *(ushort *)(iVar15 + 0x100) = *(ushort *)(iVar15 + 0x100) | 0x20;
  }
  fVar4 = FLOAT_803e41c0;
  if ((*(ushort *)(iVar15 + 0x100) & 0x80) == 0) {
    if (iVar13 == 0) {
      *(float *)(iVar15 + 0x108) = (float)dVar17;
      *(float *)(iVar15 + 0x10c) = (float)param_2;
    }
  }
  else {
    *(float *)(iVar15 + 0x108) = FLOAT_803e41c0;
    *(float *)(iVar15 + 0x10c) = fVar4;
  }
  *(int *)(iVar15 + 0x140) = (int)(short)*puVar10;
  local_17c[0] = *puVar10;
  local_17c[1] = 0;
  local_17c[2] = 0;
  local_174 = FLOAT_803e4220;
  local_170 = FLOAT_803e41c0;
  local_16c = FLOAT_803e41c0;
  local_168 = FLOAT_803e41c0;
  FUN_80021fac(afStack_104,local_17c);
  FUN_80022790((double)*(float *)(iVar15 + 0x10c),(double)FLOAT_803e41c0,
               (double)*(float *)(iVar15 + 0x108),afStack_104,(float *)(piVar6 + 9),&fStack_1b0,
               (float *)(piVar6 + 0xb));
  *(byte *)(iVar15 + 0x114) = *(byte *)(iVar15 + 0x114) & 0x7f | 0x80;
  FUN_8002ba34((double)(float)piVar6[9],(double)FLOAT_803e41c0,(double)(float)piVar6[0xb],
               (int)piVar6);
  FUN_8000e338();
  pfVar12 = local_134;
  pfVar14 = local_164;
  iVar13 = iVar15;
  for (iVar7 = 0; iVar7 < *(char *)(iVar15 + 0xb4); iVar7 = iVar7 + 1) {
    FUN_8000e0c0((double)*(float *)(iVar13 + 0x18),(double)*(float *)(iVar13 + 0x1c),
                 (double)*(float *)(iVar13 + 0x20),pfVar12,pfVar12 + 1,pfVar12 + 2,(int)piVar6);
    *pfVar14 = (float)piVar6[3] - *pfVar12;
    pfVar14[1] = (float)piVar6[4] - pfVar12[1];
    pfVar14[2] = (float)piVar6[5] - pfVar12[2];
    pfVar12 = pfVar12 + 3;
    iVar13 = iVar13 + 0xc;
    pfVar14 = pfVar14 + 3;
  }
  if ((*(ushort *)(iVar15 + 0x100) & 4) == 0) {
    FUN_801750a8();
  }
  FUN_8000e338();
  if ((FLOAT_803e41c0 != *(float *)(iVar15 + 0x108)) ||
     (FLOAT_803e41c0 != *(float *)(iVar15 + 0x10c))) {
    iVar13 = piVar6[0x13];
    uVar3 = *(ushort *)(piVar6[0x2e] + 0x100);
    if ((uVar3 & 1) != 0) {
      *(ushort *)(piVar6[0x2e] + 0x100) = uVar3 & 0xfffe;
      uVar8 = (uint)*(short *)(iVar13 + 0x18);
      if (-1 < (int)uVar8) {
        sVar2 = *(short *)((int)piVar6 + 0x46);
        if (sVar2 != 0x411) {
          if (sVar2 < 0x411) {
            if (sVar2 != 0x21e) {
LAB_801761f4:
              if (-1 < *(char *)(iVar13 + 0x23)) {
                FUN_800201ac(uVar8,0);
              }
            }
          }
          else if (sVar2 != 0x7df) goto LAB_801761f4;
        }
      }
    }
  }
  fVar4 = (float)piVar6[3] - *(float *)(iVar15 + 0x128);
  fVar5 = (float)piVar6[5] - *(float *)(iVar15 + 0x13c);
  if ((FLOAT_803e4220 < fVar4 * fVar4 + fVar5 * fVar5) &&
     ((*(ushort *)(iVar15 + 0x100) & 0x20) != 0)) {
    FUN_8000bb38((uint)piVar6,100);
    *(ushort *)(iVar15 + 0x100) = *(ushort *)(iVar15 + 0x100) & 0xffdf;
  }
LAB_801762c4:
  *(ushort *)(iVar15 + 0x100) = *(ushort *)(iVar15 + 0x100) & 0xf0ff;
  FUN_80286880();
  return;
}

