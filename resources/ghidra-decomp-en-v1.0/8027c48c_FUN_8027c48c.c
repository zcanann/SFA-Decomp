// Function: FUN_8027c48c
// Entry: 8027c48c
// Size: 10828 bytes

/* WARNING: Removing unreachable block (ram,0x8027ca5c) */
/* WARNING: Removing unreachable block (ram,0x8027cef4) */
/* WARNING: Removing unreachable block (ram,0x8027cdb4) */
/* WARNING: Removing unreachable block (ram,0x8027dd34) */

void FUN_8027c48c(undefined4 param_1,uint param_2)

{
  ushort uVar1;
  undefined2 uVar2;
  ushort uVar3;
  short sVar4;
  uint uVar5;
  uint uVar6;
  undefined2 *puVar7;
  undefined4 *puVar8;
  int iVar9;
  byte bVar10;
  int iVar11;
  uint uVar12;
  undefined4 *puVar13;
  int unaff_r18;
  uint unaff_r19;
  uint uVar14;
  uint uVar15;
  int iVar16;
  int iVar17;
  ushort *puVar18;
  int iVar19;
  undefined2 *puVar20;
  int *piVar21;
  undefined2 *puVar22;
  short local_a8;
  undefined2 local_a6 [3];
  ushort local_a0 [4];
  undefined2 local_98;
  undefined4 local_94;
  uint local_90;
  int local_8c;
  int local_88;
  int local_84;
  byte local_80;
  undefined4 *local_7c;
  ushort *local_78;
  ushort *local_74;
  ushort *local_70;
  ushort *local_6c;
  undefined4 *local_68;
  undefined4 local_64;
  uint local_60;
  undefined *local_5c;
  undefined *local_58;
  uint local_54;
  int local_50;
  undefined2 *local_4c;
  
  local_7c = &DAT_803cc1e0;
  DAT_803de314 = (undefined2 *)0x0;
  DAT_803de328 = DAT_803de330;
  DAT_803de320 = DAT_803de330;
  DAT_803de324 = DAT_803de330 + 0xc0;
  if (param_2 < 200) {
    uVar15 = 0x28be;
  }
  else {
    uVar15 = (param_2 - 200) * ((DAT_800000f8 / 400) / 5000) + 0x28be;
  }
  if (DAT_803de334 != 0) {
    uVar15 = uVar15 + 45000;
  }
  puVar13 = &DAT_803cc1e0;
  local_a0[0] = 0;
  local_54 = DAT_800000f8 / 400;
  local_60 = 0x24924925;
  local_64 = 0x8000;
  local_5c = &DAT_802c26b8;
  local_50 = 0x55555556;
  local_58 = &DAT_8032fda0;
  local_80 = 0;
  local_94 = param_1;
  while( true ) {
    if (DAT_803de37c <= local_80) {
      if (DAT_803de324 + -4 < DAT_803de328 + 3) {
        *DAT_803de328 = 0xd;
        DAT_803de328[1] = (short)((uint)DAT_803de324 >> 0x10);
        DAT_803de328[2] = (short)DAT_803de324;
        uVar1 = ((short)DAT_803de328 - (short)DAT_803de320) + 0xbU & 0xfffc;
        uVar3 = uVar1;
        if (DAT_803de314 != (undefined2 *)0x0) {
          DAT_803de314[3] = uVar1;
          FUN_80241a80(DAT_803de318,DAT_803de31c);
          uVar3 = DAT_803de32c;
        }
        DAT_803de32c = uVar3;
        DAT_803de314 = DAT_803de328;
        DAT_803de328 = DAT_803de324;
        DAT_803de318 = DAT_803de320;
        DAT_803de320 = DAT_803de324;
        DAT_803de31c = uVar1;
        DAT_803de324 = DAT_803de324 + 0xc0;
      }
      *DAT_803de328 = 0x11;
      DAT_803de328[1] = (short)((uint)DAT_803de33c >> 0x10);
      DAT_803de328[2] = (short)DAT_803de33c;
      DAT_803de328 = DAT_803de328 + 3;
      for (bVar10 = 0; bVar10 < DAT_803de37c; bVar10 = bVar10 + 1) {
        if ((*(char *)(local_7c + 0x14) == '\x01') && (*(char *)((int)local_7c + 0x51) != '\0')) {
          if (DAT_803de324 + -4 < DAT_803de328 + 3) {
            *DAT_803de328 = 0xd;
            DAT_803de328[1] = (short)((uint)DAT_803de324 >> 0x10);
            DAT_803de328[2] = (short)DAT_803de324;
            uVar1 = ((short)DAT_803de328 - (short)DAT_803de320) + 0xbU & 0xfffc;
            uVar3 = uVar1;
            if (DAT_803de314 != (undefined2 *)0x0) {
              DAT_803de314[3] = uVar1;
              FUN_80241a80(DAT_803de318,DAT_803de31c);
              uVar3 = DAT_803de32c;
            }
            DAT_803de32c = uVar3;
            DAT_803de314 = DAT_803de328;
            DAT_803de328 = DAT_803de324;
            DAT_803de318 = DAT_803de320;
            DAT_803de320 = DAT_803de324;
            DAT_803de31c = uVar1;
            DAT_803de324 = DAT_803de324 + 0xc0;
          }
          *DAT_803de328 = 9;
          DAT_803de328[1] = (short)((uint)local_7c[DAT_803de37f + 10] >> 0x10);
          DAT_803de328[2] = (short)local_7c[DAT_803de37f + 10];
          DAT_803de328 = DAT_803de328 + 3;
        }
        local_7c = local_7c + 0x2f;
      }
      if (DAT_803de324 + -4 < DAT_803de328 + 5) {
        *DAT_803de328 = 0xd;
        DAT_803de328[1] = (short)((uint)DAT_803de324 >> 0x10);
        DAT_803de328[2] = (short)DAT_803de324;
        uVar1 = ((short)DAT_803de328 - (short)DAT_803de320) + 0xbU & 0xfffc;
        uVar3 = uVar1;
        if (DAT_803de314 != (undefined2 *)0x0) {
          DAT_803de314[3] = uVar1;
          FUN_80241a80(DAT_803de318,DAT_803de31c);
          uVar3 = DAT_803de32c;
        }
        DAT_803de32c = uVar3;
        DAT_803de314 = DAT_803de328;
        DAT_803de328 = DAT_803de324;
        DAT_803de318 = DAT_803de320;
        DAT_803de320 = DAT_803de324;
        DAT_803de31c = uVar1;
        DAT_803de324 = DAT_803de324 + 0xc0;
      }
      *DAT_803de328 = 0xe;
      DAT_803de328[1] = (short)((uint)DAT_803de33c >> 0x10);
      DAT_803de328[2] = (short)DAT_803de33c;
      DAT_803de328[3] = (short)((uint)local_94 >> 0x10);
      DAT_803de328[4] = (short)local_94;
      puVar20 = DAT_803de328 + 5;
      DAT_803de328 = DAT_803de328 + 6;
      *puVar20 = 0xf;
      uVar1 = ((short)DAT_803de328 - (short)DAT_803de320) + 3U & 0xfffc;
      if (DAT_803de314 != (undefined2 *)0x0) {
        DAT_803de314[3] = uVar1;
        FUN_80241a80(DAT_803de318,DAT_803de31c);
        uVar1 = DAT_803de32c;
      }
      DAT_803de32c = uVar1;
      FUN_80241a80(DAT_803de320,(int)DAT_803de328 - (int)DAT_803de320);
      return;
    }
    if (*(char *)(puVar13 + 0x14) == '\x01') break;
LAB_8027eb3c:
    puVar13 = puVar13 + 0x2f;
    local_80 = local_80 + 1;
  }
  iVar16 = puVar13[0x12];
  while (iVar11 = iVar16, iVar11 != 0) {
    iVar16 = *(int *)(iVar11 + 0xc);
    if ((*(char *)(iVar11 + 0xed) != '\0') || ((*(uint *)(iVar11 + 0x24) & 0x20) != 0)) {
      FUN_8027c0d8(puVar13,iVar11);
      if (*(int *)(iVar11 + 0xe8) != -1) {
        FUN_8027eed8(iVar11,3);
      }
      if ((*(char *)(iVar11 + 0xec) != '\x01') || (*(char *)(iVar11 + 0xee) != '\0')) {
        FUN_8027efc0(iVar11);
        *(undefined *)(iVar11 + 0xee) = 0;
      }
    }
  }
  for (iVar16 = puVar13[0x13]; iVar16 != 0; iVar16 = *(int *)(iVar16 + 0x14)) {
    FUN_8027c0d8(puVar13,iVar16);
  }
  puVar13[0x13] = 0;
  if (DAT_803de324 + -4 < DAT_803de328 + 3) {
    *DAT_803de328 = 0xd;
    DAT_803de328[1] = (short)((uint)DAT_803de324 >> 0x10);
    DAT_803de328[2] = (short)DAT_803de324;
    uVar1 = ((short)DAT_803de328 - (short)DAT_803de320) + 0xbU & 0xfffc;
    uVar3 = uVar1;
    if (DAT_803de314 != (undefined2 *)0x0) {
      DAT_803de314[3] = uVar1;
      FUN_80241a80(DAT_803de318,DAT_803de31c);
      uVar3 = DAT_803de32c;
    }
    DAT_803de32c = uVar3;
    DAT_803de314 = DAT_803de328;
    DAT_803de328 = DAT_803de324;
    DAT_803de318 = DAT_803de320;
    DAT_803de320 = DAT_803de324;
    DAT_803de31c = uVar1;
    DAT_803de324 = DAT_803de324 + 0xc0;
  }
  *DAT_803de328 = 0;
  uVar15 = uVar15 + 0x2c62;
  DAT_803de328[1] = (short)((uint)*puVar13 >> 0x10);
  DAT_803de328[2] = (short)*puVar13;
  DAT_803de328 = DAT_803de328 + 3;
  puVar8 = puVar13;
  for (uVar14 = 0; uVar14 < *(byte *)((int)puVar13 + 0x52); uVar14 = uVar14 + 1) {
    if (DAT_803de324 + -4 < DAT_803de328 + 6) {
      *DAT_803de328 = 0xd;
      DAT_803de328[1] = (short)((uint)DAT_803de324 >> 0x10);
      DAT_803de328[2] = (short)DAT_803de324;
      uVar1 = ((short)DAT_803de328 - (short)DAT_803de320) + 0xbU & 0xfffc;
      uVar3 = uVar1;
      if (DAT_803de314 != (undefined2 *)0x0) {
        DAT_803de314[3] = uVar1;
        FUN_80241a80(DAT_803de318,DAT_803de31c);
        uVar3 = DAT_803de32c;
      }
      DAT_803de32c = uVar3;
      DAT_803de314 = DAT_803de328;
      DAT_803de328 = DAT_803de324;
      DAT_803de318 = DAT_803de320;
      DAT_803de320 = DAT_803de324;
      DAT_803de31c = uVar1;
      DAT_803de324 = DAT_803de324 + 0xc0;
    }
    uVar15 = uVar15 + 0x294d;
    *DAT_803de328 = 1;
    DAT_803de328[1] =
         (short)((uint)local_7c[(DAT_803de37f ^ 1) + (uint)*(byte *)(puVar8 + 0x16) * 0x2f + 10] >>
                0x10);
    DAT_803de328[2] =
         (short)local_7c[(DAT_803de37f ^ 1) + (uint)*(byte *)(puVar8 + 0x16) * 0x2f + 10];
    DAT_803de328[3] = *(undefined2 *)((int)puVar8 + 0x5a);
    DAT_803de328[4] = *(undefined2 *)(puVar8 + 0x17);
    puVar20 = (undefined2 *)((int)puVar8 + 0x5e);
    puVar8 = puVar8 + 3;
    DAT_803de328[5] = *puVar20;
    DAT_803de328 = DAT_803de328 + 6;
  }
  iVar16 = puVar13[0x12];
  iVar11 = 0;
  local_4c = (undefined2 *)0x0;
  piVar21 = local_7c + 0x178;
  for (; iVar16 != 0; iVar16 = *(int *)(iVar16 + 0xc)) {
    *piVar21 = iVar16;
    piVar21 = piVar21 + 1;
    iVar11 = iVar11 + 1;
  }
  FUN_8027c390(local_7c + 0x178,0,iVar11 + -1);
  local_8c = 0;
  local_68 = local_7c + iVar11 + 0x178;
LAB_8027e000:
  if (0 < iVar11) {
    piVar21 = (int *)local_68[-1];
    if (*(char *)(piVar21 + 0x3b) == '\0') goto LAB_8027dff0;
    puVar20 = (undefined2 *)*piVar21;
    local_a0[1] = 0;
    local_a0[2] = 0;
    local_a0[3] = 0;
    local_98 = 0;
    if (*(char *)(piVar21 + 0x3b) != '\x01') {
      if ((((*(char *)(piVar21 + 0x24) == '\x04') || (*(char *)(piVar21 + 0x24) == '\x05')) &&
          (puVar20[0x5a] = (ushort)*(byte *)(piVar21 + 0x28), *(char *)(piVar21 + 0x24) == '\x05'))
         && ((*(char *)(piVar21 + 0x27) == '\0' && (puVar20[0x5d] != 0)))) {
        uVar6 = piVar21[0x26] - 1;
        piVar21[0x1e] = piVar21[0x25];
        iVar16 = (int)((ulonglong)local_60 * (ulonglong)uVar6 >> 0x20);
        uVar14 = (uVar6 - iVar16 >> 1) + iVar16;
        unaff_r18 = piVar21[0x25] * 2 + (uVar14 * 2 & 0xfffffff0) + 2 + uVar6 + (uVar14 >> 3) * -0xe
        ;
        puVar20[0x3b] = (short)((uint)unaff_r18 >> 0x10);
        puVar20[0x3c] = (short)unaff_r18;
        *(undefined *)(piVar21 + 0x27) = 1;
      }
      if ((piVar21[0x23] == 0) && ((uint)piVar21[0x21] <= (uint)piVar21[0x36])) {
        FUN_8027eed8(piVar21,0);
        FUN_8027efc0(piVar21);
      }
      else {
        if (((piVar21[9] & 0x10U) == 0) || (iVar16 = FUN_8027a8d4(piVar21 + 0x29), iVar16 == 0)) {
          if ((piVar21[9] & 1U) == 0) {
            uVar14 = FUN_8027bfe4(puVar20 + 9,puVar20 + 10,(int)piVar21 + 0x5e,
                                  *(undefined2 *)(piVar21 + 0x13),local_a0,1);
            uVar6 = FUN_8027bfe4(puVar20 + 0xb,puVar20 + 0xc,piVar21 + 0x18,
                                 *(undefined2 *)((int)piVar21 + 0x4e),local_a0,2);
            uVar5 = FUN_8027bfe4(puVar20 + 0x17,puVar20 + 0x18,(int)piVar21 + 0x62,
                                 *(undefined2 *)(piVar21 + 0x14),local_a0,4);
            uVar5 = uVar14 | uVar6 | uVar5;
          }
          else {
            uVar5 = 1;
            iVar16 = (int)*(short *)(piVar21 + 0x13) - (int)*(short *)((int)piVar21 + 0x5e);
            iVar16 = iVar16 / 0xa0 + (iVar16 >> 0x1f);
            puVar20[10] = (short)iVar16 - (short)(iVar16 >> 0x1f);
            *(short *)((int)piVar21 + 0x5e) = *(short *)((int)piVar21 + 0x5e) + puVar20[10] * 0xa0;
            iVar16 = (int)*(short *)((int)piVar21 + 0x4e) - (int)*(short *)(piVar21 + 0x18);
            iVar16 = iVar16 / 0xa0 + (iVar16 >> 0x1f);
            puVar20[0xc] = (short)iVar16 - (short)(iVar16 >> 0x1f);
            *(short *)(piVar21 + 0x18) = *(short *)(piVar21 + 0x18) + puVar20[0xc] * 0xa0;
            iVar16 = (int)*(short *)(piVar21 + 0x14) - (int)*(short *)((int)piVar21 + 0x62);
            iVar16 = iVar16 / 0xa0 + (iVar16 >> 0x1f);
            puVar20[0x18] = (short)iVar16 - (short)(iVar16 >> 0x1f);
            *(short *)((int)piVar21 + 0x62) = *(short *)((int)piVar21 + 0x62) + puVar20[0x18] * 0xa0
            ;
          }
          if ((piVar21[9] & 2U) == 0) {
            if ((puVar20[6] & 1) == 0) {
              puVar20[0xe] = 0;
              puVar20[0x10] = 0;
              puVar20[0x1a] = 0;
            }
            else {
              uVar14 = FUN_8027bfe4(puVar20 + 0xd,puVar20 + 0xe,piVar21 + 0x19,
                                    *(undefined2 *)((int)piVar21 + 0x52),local_a0,8);
              uVar6 = FUN_8027bfe4(puVar20 + 0xf,puVar20 + 0x10,(int)piVar21 + 0x66,
                                   *(undefined2 *)(piVar21 + 0x15),local_a0,0x10);
              uVar12 = FUN_8027bfe4(puVar20 + 0x19,puVar20 + 0x1a,piVar21 + 0x1a,
                                    *(undefined2 *)((int)piVar21 + 0x56),local_a0,0x20);
              if ((uVar14 | uVar6 | uVar12 |
                  (uint)(ushort)(puVar20[0x19] | puVar20[0xd] | puVar20[0xf])) == 0) {
                puVar20[6] = puVar20[6] & 0xfffe;
              }
              else {
                uVar5 = 1;
              }
            }
          }
          else {
            iVar16 = (int)*(short *)((int)piVar21 + 0x52) - (int)*(short *)(piVar21 + 0x19);
            iVar16 = iVar16 / 0xa0 + (iVar16 >> 0x1f);
            puVar20[0xe] = (short)iVar16 - (short)(iVar16 >> 0x1f);
            *(short *)(piVar21 + 0x19) = *(short *)(piVar21 + 0x19) + puVar20[0xe] * 0xa0;
            iVar16 = (int)*(short *)(piVar21 + 0x15) - (int)*(short *)((int)piVar21 + 0x66);
            iVar16 = iVar16 / 0xa0 + (iVar16 >> 0x1f);
            puVar20[0x10] = (short)iVar16 - (short)(iVar16 >> 0x1f);
            *(short *)((int)piVar21 + 0x66) = *(short *)((int)piVar21 + 0x66) + puVar20[0x10] * 0xa0
            ;
            iVar16 = (int)*(short *)((int)piVar21 + 0x56) - (int)*(short *)(piVar21 + 0x1a);
            iVar16 = iVar16 / 0xa0 + (iVar16 >> 0x1f);
            puVar20[0x1a] = (short)iVar16 - (short)(iVar16 >> 0x1f);
            *(short *)(piVar21 + 0x1a) = *(short *)(piVar21 + 0x1a) + puVar20[0x1a] * 0xa0;
            if ((ushort)(puVar20[0x1a] | puVar20[0xe] | puVar20[0x10]) == 0) {
              if ((ushort)(puVar20[0x19] | puVar20[0xd] | puVar20[0xf]) == 0) {
                puVar20[6] = puVar20[6] & 0xfffe;
              }
              else {
                puVar20[6] = puVar20[6] | 1;
              }
            }
            else {
              uVar5 = 1;
              puVar20[6] = puVar20[6] | 1;
            }
          }
          if ((piVar21[9] & 4U) == 0) {
            if (puVar13[0x15] == 0) {
              if ((puVar20[6] & 2) == 0) {
                puVar20[0x12] = 0;
                puVar20[0x14] = 0;
                puVar20[0x16] = 0;
              }
              else {
                uVar14 = FUN_8027bfe4(puVar20 + 0x11,puVar20 + 0x12,(int)piVar21 + 0x6a,
                                      *(undefined2 *)(piVar21 + 0x16),local_a0,0x40);
                uVar6 = FUN_8027bfe4(puVar20 + 0x13,puVar20 + 0x14,piVar21 + 0x1b,
                                     *(undefined2 *)((int)piVar21 + 0x5a),local_a0,0x80);
                uVar12 = FUN_8027bfe4(puVar20 + 0x15,puVar20 + 0x16,(int)piVar21 + 0x6e,
                                      *(undefined2 *)(piVar21 + 0x17),local_a0,0x100);
                if ((uVar14 | uVar6 | uVar12 |
                    (uint)(ushort)(puVar20[0x15] | puVar20[0x11] | puVar20[0x13])) == 0) {
                  puVar20[6] = puVar20[6] & 0xfffd;
                }
                else {
                  uVar5 = 1;
                }
              }
            }
            else if ((puVar20[6] & 0x10) == 0) {
              puVar20[0x12] = 0;
              puVar20[0x14] = 0;
              if ((puVar20[0x19] | puVar20[0x1a]) != 0) {
                puVar20[6] = puVar20[6] | 0x10;
              }
            }
            else {
              uVar14 = FUN_8027bfe4(puVar20 + 0x11,puVar20 + 0x12,(int)piVar21 + 0x6a,
                                    *(undefined2 *)(piVar21 + 0x16),local_a0,0x40);
              uVar6 = FUN_8027bfe4(puVar20 + 0x13,puVar20 + 0x14,piVar21 + 0x1b,
                                   *(undefined2 *)((int)piVar21 + 0x5a),local_a0,0x80);
              if ((uVar14 | uVar6 | (uint)(ushort)(puVar20[0x11] | puVar20[0x13])) == 0) {
                if ((puVar20[0x19] | puVar20[0x1a]) == 0) {
                  puVar20[6] = puVar20[6] & 0xffef;
                }
              }
              else {
                uVar5 = 1;
              }
            }
          }
          else if (puVar13[0x15] == 0) {
            iVar16 = (int)*(short *)(piVar21 + 0x16) - (int)*(short *)((int)piVar21 + 0x6a);
            iVar16 = iVar16 / 0xa0 + (iVar16 >> 0x1f);
            puVar20[0x12] = (short)iVar16 - (short)(iVar16 >> 0x1f);
            *(short *)((int)piVar21 + 0x6a) = *(short *)((int)piVar21 + 0x6a) + puVar20[0x12] * 0xa0
            ;
            iVar16 = (int)*(short *)((int)piVar21 + 0x5a) - (int)*(short *)(piVar21 + 0x1b);
            iVar16 = iVar16 / 0xa0 + (iVar16 >> 0x1f);
            puVar20[0x14] = (short)iVar16 - (short)(iVar16 >> 0x1f);
            *(short *)(piVar21 + 0x1b) = *(short *)(piVar21 + 0x1b) + puVar20[0x14] * 0xa0;
            iVar16 = (int)*(short *)(piVar21 + 0x17) - (int)*(short *)((int)piVar21 + 0x6e);
            iVar16 = iVar16 / 0xa0 + (iVar16 >> 0x1f);
            puVar20[0x16] = (short)iVar16 - (short)(iVar16 >> 0x1f);
            *(short *)((int)piVar21 + 0x6e) = *(short *)((int)piVar21 + 0x6e) + puVar20[0x16] * 0xa0
            ;
            if ((ushort)(puVar20[0x16] | puVar20[0x12] | puVar20[0x14]) == 0) {
              if ((ushort)(puVar20[0x15] | puVar20[0x11] | puVar20[0x13]) == 0) {
                puVar20[6] = puVar20[6] & 0xfffd;
              }
              else {
                puVar20[6] = puVar20[6] | 2;
              }
            }
            else {
              uVar5 = 1;
              puVar20[6] = puVar20[6] | 2;
            }
          }
          else {
            iVar16 = (int)*(short *)(piVar21 + 0x16) - (int)*(short *)((int)piVar21 + 0x6a);
            iVar16 = iVar16 / 0xa0 + (iVar16 >> 0x1f);
            puVar20[0x12] = (short)iVar16 - (short)(iVar16 >> 0x1f);
            *(short *)((int)piVar21 + 0x6a) = *(short *)((int)piVar21 + 0x6a) + puVar20[0x12] * 0xa0
            ;
            iVar16 = (int)*(short *)((int)piVar21 + 0x5a) - (int)*(short *)(piVar21 + 0x1b);
            iVar16 = iVar16 / 0xa0 + (iVar16 >> 0x1f);
            puVar20[0x14] = (short)iVar16 - (short)(iVar16 >> 0x1f);
            *(short *)(piVar21 + 0x1b) = *(short *)(piVar21 + 0x1b) + puVar20[0x14] * 0xa0;
            if ((puVar20[0x12] | puVar20[0x14]) == 0) {
              if ((ushort)(puVar20[0x1a] | puVar20[0x19] | puVar20[0x11] | puVar20[0x13]) == 0) {
                puVar20[6] = puVar20[6] & 0xffef;
              }
              else {
                puVar20[6] = puVar20[6] | 0x10;
              }
            }
            else {
              uVar5 = 1;
              puVar20[6] = puVar20[6] | 0x10;
            }
          }
          if (uVar5 == 0) {
            puVar20[6] = puVar20[6] & 0xfff7;
          }
          else {
            puVar20[6] = puVar20[6] | 8;
          }
          if (puVar13[0x15] == 0) {
            if ((((puVar20[0x17] == 0) && (puVar20[0x18] == 0)) && (puVar20[0x19] == 0)) &&
               (((puVar20[0x1a] == 0 && (puVar20[0x15] == 0)) && (puVar20[0x16] == 0)))) {
              puVar20[6] = puVar20[6] & 0xfffb;
            }
            else {
              puVar20[6] = puVar20[6] | 4;
            }
          }
          if ((piVar21[9] & 0x200U) != 0) {
            puVar20[0x20] = *(undefined2 *)(piVar21 + 0x34);
            puVar20[0x21] = *(undefined2 *)((int)piVar21 + 0xd2);
          }
          if ((piVar21[9] & 0x100U) != 0) {
            puVar20[4] = *(undefined2 *)(piVar21 + 0x33);
          }
          if ((piVar21[9] & 0x80U) != 0) {
            puVar20[5] = *(undefined2 *)((int)piVar21 + 0xce);
          }
          uVar14 = 0;
          local_88 = 0;
          piVar21[8] = *(int *)(puVar20 + 0x3d);
          goto LAB_8027d91c;
        }
        FUN_8027eed8(piVar21,0);
        FUN_8027efc0(piVar21);
      }
      goto LAB_8027dff0;
    }
    piVar21[0x3a] = -1;
    *(short *)(*piVar21 + 0x66) = (short)local_64;
    iVar16 = FUN_8027a8d4(piVar21 + 0x29);
    if (iVar16 != 0) {
      FUN_8027eed8(piVar21,0);
      FUN_8027efc0(piVar21);
      goto LAB_8027dff0;
    }
    piVar21[0x3a] = -1;
    if (*(char *)(piVar21 + 0x24) == '\x05') {
      piVar21[0x26] = 0;
      iVar16 = FUN_8027eed8(piVar21,2);
      piVar21[0x3a] = iVar16;
      if (piVar21[0x26] == 0) {
        FUN_8027eed8(piVar21,1);
        FUN_8027efc0(piVar21);
        goto LAB_8027dff0;
      }
    }
    puVar20[0x55] = 0;
    puVar20[0x56] = 0;
    puVar20[0x57] = 0;
    puVar20[0x58] = 0;
    puVar20[0x59] = 0;
    if ((piVar21[0x3c] & 0x80000000U) == 0) {
      puVar20[0x1b] = 0;
    }
    else {
      FUN_800033a8(piVar21[2],0,0x40);
      FUN_802419e8(piVar21[2],0x40);
      puVar20[0x20] = *(undefined2 *)(piVar21 + 0x34);
      puVar20[0x1e] = *(undefined2 *)(piVar21 + 0x34);
      puVar20[0x21] = *(undefined2 *)((int)piVar21 + 0xd2);
      puVar20[0x1f] = *(undefined2 *)((int)piVar21 + 0xd2);
      puVar20[0x1b] = 1;
    }
    bVar10 = *(byte *)(piVar21 + 0x24);
    if (bVar10 == 2) {
      puVar20[0x38] = 10;
      puVar20[0x4f] = 0x800;
      puVar20[0x3f] = 0;
      puVar20[0x40] = 0;
      puVar20[0x41] = 0;
      puVar20[0x42] = 0;
      puVar20[0x43] = 0;
      puVar20[0x44] = 0;
      puVar20[0x45] = 0;
      puVar20[0x46] = 0;
      puVar20[0x47] = 0;
      puVar20[0x48] = 0;
      puVar20[0x49] = 0;
      puVar20[0x4a] = 0;
      puVar20[0x4b] = 0;
      puVar20[0x4c] = 0;
      puVar20[0x4d] = 0;
      puVar20[0x4e] = 0;
      unaff_r19 = (uint)piVar21[0x1e] >> 1;
      piVar21[0x36] = piVar21[0x20];
      local_84 = piVar21[0x20] + unaff_r19;
      piVar21[0x37] = 0;
    }
    else if (bVar10 < 2) {
      if (bVar10 == 0) {
LAB_8027ca74:
        puVar20[0x38] = 0;
        puVar20[0x4f] = 0;
        iVar16 = piVar21[0x1f];
        puVar20[0x52] = 0;
        puVar20[0x51] = 0;
        puVar20[0x50] = (ushort)*(byte *)(iVar16 + 2);
        puVar20[0x3f] = *(undefined2 *)(iVar16 + 8);
        puVar20[0x40] = *(undefined2 *)(iVar16 + 10);
        puVar20[0x41] = *(undefined2 *)(iVar16 + 0xc);
        puVar20[0x42] = *(undefined2 *)(iVar16 + 0xe);
        puVar20[0x43] = *(undefined2 *)(iVar16 + 0x10);
        puVar20[0x44] = *(undefined2 *)(iVar16 + 0x12);
        puVar20[0x45] = *(undefined2 *)(iVar16 + 0x14);
        puVar20[0x46] = *(undefined2 *)(iVar16 + 0x16);
        puVar20[0x47] = *(undefined2 *)(iVar16 + 0x18);
        puVar20[0x48] = *(undefined2 *)(iVar16 + 0x1a);
        puVar20[0x49] = *(undefined2 *)(iVar16 + 0x1c);
        puVar20[0x4a] = *(undefined2 *)(iVar16 + 0x1e);
        puVar20[0x4b] = *(undefined2 *)(iVar16 + 0x20);
        puVar20[0x4c] = *(undefined2 *)(iVar16 + 0x22);
        puVar20[0x4d] = *(undefined2 *)(iVar16 + 0x24);
        puVar20[0x4e] = *(undefined2 *)(iVar16 + 0x26);
        piVar21[0x37] = 0;
        unaff_r19 = piVar21[0x1e] * 2;
        local_84 = unaff_r19 + 2;
        piVar21[0x36] = 0;
        if ((*(char *)(piVar21 + 0x24) == '\x04') || (*(char *)(piVar21 + 0x24) == '\x05')) {
          puVar20[8] = 1;
        }
        else {
          puVar20[0x5c] = *(undefined2 *)(iVar16 + 4);
          puVar20[0x5b] = *(undefined2 *)(iVar16 + 6);
          puVar20[0x5a] = (ushort)*(byte *)(iVar16 + 3);
          puVar20[8] = 0;
        }
      }
      else {
        puVar20[0x38] = 0;
        puVar20[0x4f] = 0;
        iVar9 = piVar21[0x1f];
        iVar16 = (int)((ulonglong)local_60 * (ulonglong)(piVar21[0x20] + 0xdU) >> 0x20);
        uVar6 = ((piVar21[0x20] + 0xdU) - iVar16 >> 1) + iVar16;
        uVar14 = uVar6 >> 3;
        iVar16 = iVar9 + uVar14 * 6;
        puVar20[0x52] = *(undefined2 *)(iVar16 + 0x28);
        puVar20[0x51] = *(undefined2 *)(iVar16 + 0x2a);
        puVar20[0x50] = (ushort)*(byte *)(iVar16 + 0x2c);
        puVar20[0x5c] = *(undefined2 *)(iVar9 + 4);
        puVar20[0x5b] = *(undefined2 *)(iVar9 + 6);
        puVar20[0x5a] = (ushort)*(byte *)(iVar9 + 3);
        puVar20[0x3f] = *(undefined2 *)(iVar9 + 8);
        puVar20[0x40] = *(undefined2 *)(iVar9 + 10);
        puVar20[0x41] = *(undefined2 *)(iVar9 + 0xc);
        puVar20[0x42] = *(undefined2 *)(iVar9 + 0xe);
        puVar20[0x43] = *(undefined2 *)(iVar9 + 0x10);
        puVar20[0x44] = *(undefined2 *)(iVar9 + 0x12);
        puVar20[0x45] = *(undefined2 *)(iVar9 + 0x14);
        puVar20[0x46] = *(undefined2 *)(iVar9 + 0x16);
        puVar20[0x47] = *(undefined2 *)(iVar9 + 0x18);
        puVar20[0x48] = *(undefined2 *)(iVar9 + 0x1a);
        puVar20[0x49] = *(undefined2 *)(iVar9 + 0x1c);
        puVar20[0x4a] = *(undefined2 *)(iVar9 + 0x1e);
        puVar20[0x4b] = *(undefined2 *)(iVar9 + 0x20);
        puVar20[0x4c] = *(undefined2 *)(iVar9 + 0x22);
        puVar20[0x4d] = *(undefined2 *)(iVar9 + 0x24);
        puVar20[0x4e] = *(undefined2 *)(iVar9 + 0x26);
        unaff_r19 = piVar21[0x1e] * 2;
        piVar21[0x36] = uVar14 * 0xe;
        local_84 = unaff_r19 + (uVar6 * 2 & 0xfffffff0) + 2;
        piVar21[0x37] = 0;
      }
    }
    else if (bVar10 < 6) {
      if (3 < bVar10) goto LAB_8027ca74;
      puVar20[0x38] = 0x19;
      puVar20[0x4f] = 0x100;
      puVar20[0x3f] = 0;
      puVar20[0x40] = 0;
      puVar20[0x41] = 0;
      puVar20[0x42] = 0;
      puVar20[0x43] = 0;
      puVar20[0x44] = 0;
      puVar20[0x45] = 0;
      puVar20[0x46] = 0;
      puVar20[0x47] = 0;
      puVar20[0x48] = 0;
      puVar20[0x49] = 0;
      puVar20[0x4a] = 0;
      puVar20[0x4b] = 0;
      puVar20[0x4c] = 0;
      puVar20[0x4d] = 0;
      puVar20[0x4e] = 0;
      unaff_r19 = piVar21[0x1e];
      piVar21[0x36] = piVar21[0x20];
      local_84 = piVar21[0x20] + unaff_r19;
      piVar21[0x37] = 0;
    }
    puVar20[0x3d] = (short)((uint)local_84 >> 0x10);
    puVar20[0x3e] = (short)local_84;
    piVar21[8] = local_84;
    if (piVar21[0x23] == 0) {
      puVar20[0x37] = 0;
      bVar10 = *(byte *)(piVar21 + 0x24);
      if (bVar10 == 3) {
        local_90 = DAT_803de310;
        unaff_r18 = unaff_r19 + piVar21[0x21];
      }
      else if (bVar10 < 3) {
        if (bVar10 < 2) {
LAB_8027cf00:
          uVar6 = piVar21[0x21];
          iVar16 = (int)((ulonglong)local_60 * (ulonglong)uVar6 >> 0x20);
          uVar14 = (uVar6 - iVar16 >> 1) + iVar16;
          local_90 = DAT_803de310 * 2 + 2;
          unaff_r18 = unaff_r19 + (uVar14 * 2 & 0xfffffff0) + 2 + uVar6 + (uVar14 >> 3) * -0xe;
        }
        else {
          local_90 = DAT_803de310 >> 1;
          unaff_r18 = unaff_r19 + piVar21[0x21];
        }
      }
      else if (bVar10 < 6) goto LAB_8027cf00;
      puVar20[0x39] = (short)(local_90 >> 0x10);
      puVar20[0x3a] = (short)local_90;
      puVar20[0x3b] = (short)((uint)unaff_r18 >> 0x10);
      puVar20[0x3c] = (short)unaff_r18;
    }
    else {
      puVar20[0x37] = 1;
      bVar10 = *(byte *)(piVar21 + 0x24);
      if (bVar10 == 4) {
LAB_8027cdc4:
        uVar6 = piVar21[0x22];
        uVar5 = uVar6 + piVar21[0x23] + -1;
        iVar16 = (int)((ulonglong)local_60 * (ulonglong)uVar6 >> 0x20);
        iVar9 = (int)((ulonglong)local_60 * (ulonglong)uVar5 >> 0x20);
        uVar14 = (uVar6 - iVar16 >> 1) + iVar16;
        uVar12 = (uVar5 - iVar9 >> 1) + iVar9;
        iVar16 = unaff_r19 + (uVar14 * 2 & 0xfffffff0) + 2 + uVar6 + (uVar14 >> 3) * -0xe;
        iVar9 = unaff_r19 + (uVar12 * 2 & 0xfffffff0) + 2 + uVar5 + (uVar12 >> 3) * -0xe;
      }
      else {
        if (bVar10 < 4) {
          if (bVar10 < 2) goto LAB_8027cdc4;
        }
        else if (bVar10 < 6) {
          uVar14 = piVar21[0x22] + piVar21[0x23] + -1;
          *(undefined *)(piVar21 + 0x27) = 0;
          iVar16 = (int)((ulonglong)local_60 * (ulonglong)uVar14 >> 0x20);
          uVar6 = (uVar14 - iVar16 >> 1) + iVar16;
          iVar16 = piVar21[0x25] * 2 + 2;
          iVar9 = unaff_r19 + (uVar6 * 2 & 0xfffffff0) + 2 + uVar14 + (uVar6 >> 3) * -0xe;
          goto LAB_8027cea8;
        }
        iVar16 = unaff_r19 + piVar21[0x22];
        iVar9 = piVar21[0x23] + iVar16 + -1;
      }
LAB_8027cea8:
      puVar20[0x39] = (short)((uint)iVar16 >> 0x10);
      puVar20[0x3a] = (short)iVar16;
      puVar20[0x3b] = (short)((uint)iVar9 >> 0x10);
      puVar20[0x3c] = (short)iVar9;
      puVar20[0x5d] = 0;
    }
    puVar20[4] = *(undefined2 *)(piVar21 + 0x33);
    puVar20[5] = *(undefined2 *)((int)piVar21 + 0xce);
    uVar14 = (uint)*(byte *)(piVar21 + 0x35);
    puVar20[7] = (ushort)(uVar14 == 0);
    *(undefined2 *)((int)piVar21 + 0x5e) = *(undefined2 *)(piVar21 + 0x13);
    puVar20[9] = *(undefined2 *)(piVar21 + 0x13);
    *(undefined2 *)(piVar21 + 0x18) = *(undefined2 *)((int)piVar21 + 0x4e);
    puVar20[0xb] = *(undefined2 *)((int)piVar21 + 0x4e);
    *(undefined2 *)((int)piVar21 + 0x62) = *(undefined2 *)(piVar21 + 0x14);
    puVar20[0x17] = *(undefined2 *)(piVar21 + 0x14);
    *(undefined2 *)(piVar21 + 0x19) = *(undefined2 *)((int)piVar21 + 0x52);
    puVar20[0xd] = *(undefined2 *)((int)piVar21 + 0x52);
    *(undefined2 *)((int)piVar21 + 0x66) = *(undefined2 *)(piVar21 + 0x15);
    puVar20[0xf] = *(undefined2 *)(piVar21 + 0x15);
    *(undefined2 *)(piVar21 + 0x1a) = *(undefined2 *)((int)piVar21 + 0x56);
    puVar20[0x19] = *(undefined2 *)((int)piVar21 + 0x56);
    puVar20[6] = (ushort)((ushort)(puVar20[0x19] | puVar20[0xd] | puVar20[0xf]) != 0);
    *(undefined2 *)((int)piVar21 + 0x6a) = *(undefined2 *)(piVar21 + 0x16);
    puVar20[0x11] = *(undefined2 *)(piVar21 + 0x16);
    *(undefined2 *)(piVar21 + 0x1b) = *(undefined2 *)((int)piVar21 + 0x5a);
    puVar20[0x13] = *(undefined2 *)((int)piVar21 + 0x5a);
    *(undefined2 *)((int)piVar21 + 0x6e) = *(undefined2 *)(piVar21 + 0x17);
    puVar20[0x15] = *(undefined2 *)(piVar21 + 0x17);
    puVar20[10] = 0;
    puVar20[0xc] = 0;
    puVar20[0x18] = 0;
    puVar20[0xe] = 0;
    puVar20[0x10] = 0;
    puVar20[0x1a] = 0;
    puVar20[0x12] = 0;
    puVar20[0x14] = 0;
    puVar20[0x16] = 0;
    if (puVar13[0x15] == 0) {
      if ((ushort)(puVar20[0x15] | puVar20[0x11] | puVar20[0x13]) != 0) {
        puVar20[6] = puVar20[6] | 2;
      }
      if ((ushort)(puVar20[0x15] | puVar20[0x17] | puVar20[0x19]) != 0) {
        puVar20[6] = puVar20[6] | 4;
      }
    }
    else if ((ushort)(puVar20[0x19] | puVar20[0x11] | puVar20[0x13]) != 0) {
      puVar20[6] = puVar20[6] | 0x10;
    }
    *(undefined *)(piVar21 + 0x3b) = 2;
    local_88 = 1;
LAB_8027d91c:
    if ((piVar21[uVar14 + 9] & 0x40U) != 0) {
      FUN_8027aa50(piVar21 + 0x29);
    }
    if ((piVar21[uVar14 + 9] & 8U) != 0) {
      puVar20[0x53] = (short)((uint)piVar21[uVar14 + 0xe] >> 0x10);
      puVar20[0x54] = (short)piVar21[uVar14 + 0xe];
      piVar21[0x38] = piVar21[uVar14 + 0xe];
    }
    iVar16 = FUN_8027aa94(piVar21 + 0x29,puVar20 + 0x32,puVar20 + 0x33);
    sVar4 = puVar20[0x33];
    local_6c = puVar20 + 0x23;
    puVar20[0x22] = 0;
    puVar20[0x23] = 0;
    local_70 = puVar20 + 0x24;
    local_74 = puVar20 + 0x25;
    puVar20[0x24] = 0;
    local_78 = puVar20 + 0x26;
    puVar20[0x25] = 0;
    puVar20[0x26] = 0;
    puVar22 = (undefined2 *)piVar21[1];
    if (uVar14 != 0) {
      *puVar22 = 7;
      puVar22[1] = 1;
      puVar22 = puVar22 + 2;
      puVar20[uVar14 + 0x22] = puVar20[uVar14 + 0x22] + 1;
    }
    if (piVar21[0x23] == 0) {
      if (*(short *)(*piVar21 + 8) == 2) {
        uVar6 = 0x200000;
      }
      else {
        uVar6 = piVar21[0x38] << 5;
      }
      uVar5 = piVar21[0x37];
      piVar21[0x37] = uVar5 + uVar6 * 0x10000;
      if ((uint)piVar21[0x37] < uVar5) {
        piVar21[0x36] = (uVar6 >> 0x10) + piVar21[0x36] + 1;
      }
      else {
        piVar21[0x36] = piVar21[0x36] + (uVar6 >> 0x10);
      }
    }
    uVar14 = uVar14 + 1;
    uVar6 = uVar14 * 2 & 0x1fe;
    puVar18 = (ushort *)((int)local_a0 + uVar6);
    iVar19 = (int)puVar20 + uVar6;
    iVar9 = (int)piVar21 + (uVar14 * 4 & 0x3fc);
    for (uVar14 = uVar14 & 0xff; (uVar14 & 0xff) < 5; uVar14 = uVar14 + 1) {
      if (iVar16 != 0) {
        *puVar22 = 7;
        puVar22[1] = 0;
        puVar22 = puVar22 + 2;
        puVar20[(uVar14 & 0xff) + 0x22] = puVar20[(uVar14 & 0xff) + 0x22] + 1;
        FUN_8027eed8(piVar21,0);
        FUN_8027efc0(piVar21);
        break;
      }
      if (*puVar18 != 0) {
        puVar7 = &DAT_802c26f8;
        for (bVar10 = 0; bVar10 < 9; bVar10 = bVar10 + 1) {
          if ((1 << (uint)bVar10 & (uint)*puVar18) != 0) {
            *puVar22 = *puVar7;
            puVar22[1] = 0;
            puVar22 = puVar22 + 2;
            *(short *)(iVar19 + 0x44) = *(short *)(iVar19 + 0x44) + 1;
          }
          puVar7 = puVar7 + 1;
        }
      }
      if ((*(uint *)(iVar9 + 0x24) & 0x20) == 0) {
        if (*(char *)((int)piVar21 + 0xed) == '\0') {
          if ((*(uint *)(iVar9 + 0x24) & 0x40) != 0) {
            FUN_8027aa50(piVar21 + 0x29);
          }
          if ((*(uint *)(iVar9 + 0x24) & 8) != 0) {
            *puVar22 = 0x53;
            puVar22[1] = (short)((uint)*(undefined4 *)(iVar9 + 0x38) >> 0x10);
            puVar22[2] = 0x54;
            puVar22[3] = (short)*(undefined4 *)(iVar9 + 0x38);
            puVar22 = puVar22 + 4;
            *(short *)(iVar19 + 0x44) = *(short *)(iVar19 + 0x44) + 2;
            piVar21[0x38] = *(int *)(iVar9 + 0x38);
          }
        }
      }
      else {
        FUN_8027a8fc(piVar21 + 0x29,10);
        *(undefined *)((int)piVar21 + 0xed) = 1;
      }
      iVar17 = piVar21[0x2d];
      iVar16 = FUN_8027aa94(piVar21 + 0x29,local_a6,&local_a8);
      if (sVar4 == local_a8) {
        if (iVar17 != 0) {
          *puVar22 = 0x32;
          puVar22[1] = local_a6[0];
          puVar22 = puVar22 + 2;
          *(short *)(iVar19 + 0x44) = *(short *)(iVar19 + 0x44) + 1;
        }
      }
      else {
        *puVar22 = 0x32;
        puVar22[1] = local_a6[0];
        puVar22[2] = 0x33;
        puVar22[3] = local_a8;
        puVar22 = puVar22 + 4;
        *(short *)(iVar19 + 0x44) = *(short *)(iVar19 + 0x44) + 2;
        sVar4 = local_a8;
      }
      if (piVar21[0x23] == 0) {
        if (*(short *)(*piVar21 + 8) == 2) {
          uVar6 = 0x200000;
        }
        else {
          uVar6 = piVar21[0x38] << 5;
        }
        uVar5 = piVar21[0x37];
        piVar21[0x37] = uVar5 + uVar6 * 0x10000;
        if ((uint)piVar21[0x37] < uVar5) {
          piVar21[0x36] = (uVar6 >> 0x10) + piVar21[0x36] + 1;
        }
        else {
          piVar21[0x36] = piVar21[0x36] + (uVar6 >> 0x10);
        }
      }
      puVar18 = puVar18 + 1;
      iVar19 = iVar19 + 2;
      iVar9 = iVar9 + 4;
    }
    if (iVar16 != 0) {
      FUN_8027eed8(piVar21,0);
      FUN_8027efc0(piVar21);
    }
    FUN_80241a80(piVar21[1],(int)puVar22 - piVar21[1]);
    if ((ushort)puVar20[0x53] < 2) {
      uVar1 = *(ushort *)(local_58 + (uint)(ushort)puVar20[4] * 2 + (uint)(ushort)puVar20[0x53] * 6)
      ;
    }
    else {
      uVar1 = *(ushort *)(local_58 + (uint)(ushort)puVar20[4] * 2 + 0xc);
    }
    uVar15 = *(ushort *)(local_5c + (uint)(ushort)puVar20[6] * 2) + uVar15 + 0x4fe + (uint)uVar1 +
             (uint)(ushort)puVar20[0x22] * 4 + (uint)*local_6c * 4 + (uint)*local_70 * 4 +
             (uint)*local_74 * 4 + (uint)*local_78 * 4;
    if (uVar15 <= local_54) {
      uVar2 = (undefined2)((uint)puVar20 >> 0x10);
      if (local_4c == (undefined2 *)0x0) {
        if (DAT_803de324 + -4 < DAT_803de328 + 3) {
          *DAT_803de328 = 0xd;
          DAT_803de328[1] = (short)((uint)DAT_803de324 >> 0x10);
          DAT_803de328[2] = (short)DAT_803de324;
          uVar1 = ((short)DAT_803de328 - (short)DAT_803de320) + 0xbU & 0xfffc;
          uVar3 = uVar1;
          if (DAT_803de314 != (undefined2 *)0x0) {
            DAT_803de314[3] = uVar1;
            FUN_80241a80(DAT_803de318,DAT_803de31c);
            uVar3 = DAT_803de32c;
          }
          DAT_803de32c = uVar3;
          DAT_803de314 = DAT_803de328;
          DAT_803de328 = DAT_803de324;
          DAT_803de318 = DAT_803de320;
          DAT_803de320 = DAT_803de324;
          DAT_803de31c = uVar1;
          DAT_803de324 = DAT_803de324 + 0xc0;
        }
        *DAT_803de328 = 2;
        local_8c = 1;
        DAT_803de328[1] = uVar2;
        DAT_803de328[2] = (short)puVar20;
        DAT_803de328 = DAT_803de328 + 3;
        local_4c = puVar20;
      }
      else {
        *local_4c = uVar2;
        local_4c[1] = (short)puVar20;
        local_8c = 1;
        FUN_80241a50(local_4c,0xbc);
        local_4c = puVar20;
      }
      goto LAB_8027dff0;
    }
    if ((local_88 == 0) && (iVar16 == 0)) {
      FUN_8027c0d8(puVar13,piVar21);
    }
    FUN_8027efc0(piVar21);
    FUN_8027eed8(piVar21,1);
    puVar8 = local_7c + iVar11 + 0x177;
    while (iVar11 = iVar11 + -1, 0 < iVar11) {
      if (*(char *)(puVar8[-1] + 0xec) == '\x02') {
        FUN_8027c0d8(puVar13);
      }
      FUN_8027efc0(puVar8[-1]);
      FUN_8027eed8(puVar8[-1],1);
      puVar8 = puVar8 + -1;
    }
    uVar14 = local_80 + 1 & 0xff;
    puVar8 = local_7c + uVar14 * 0x2f;
    for (; (uVar14 & 0xff) < (uint)DAT_803de37c; uVar14 = uVar14 + 1) {
      if (*(char *)(puVar8 + 0x14) == '\x01') {
        iVar16 = puVar8[0x12];
        while (iVar16 != 0) {
          iVar11 = *(int *)(iVar16 + 0xc);
          if (*(char *)(iVar16 + 0xec) == '\x02') {
            FUN_8027c0d8(puVar8,iVar16);
          }
          FUN_8027efc0(iVar16);
          FUN_8027eed8(iVar16,1);
          iVar16 = iVar11;
        }
      }
      puVar8 = puVar8 + 0x2f;
    }
  }
  if (local_8c != 0) {
    if (DAT_803de324 + -4 < DAT_803de328 + 1) {
      *DAT_803de328 = 0xd;
      DAT_803de328[1] = (short)((uint)DAT_803de324 >> 0x10);
      DAT_803de328[2] = (short)DAT_803de324;
      uVar1 = ((short)DAT_803de328 - (short)DAT_803de320) + 0xbU & 0xfffc;
      uVar3 = uVar1;
      if (DAT_803de314 != (undefined2 *)0x0) {
        DAT_803de314[3] = uVar1;
        FUN_80241a80(DAT_803de318,DAT_803de31c);
        uVar3 = DAT_803de32c;
      }
      DAT_803de32c = uVar3;
      DAT_803de314 = DAT_803de328;
      DAT_803de328 = DAT_803de324;
      DAT_803de318 = DAT_803de320;
      DAT_803de320 = DAT_803de324;
      DAT_803de31c = uVar1;
      DAT_803de324 = DAT_803de324 + 0xc0;
    }
    puVar20 = DAT_803de328 + 1;
    *DAT_803de328 = 3;
    DAT_803de328 = puVar20;
  }
  if (local_4c != (undefined2 *)0x0) {
    *local_4c = 0;
    local_4c[1] = 0;
    FUN_80241a50(local_4c,0xbc);
  }
  iVar16 = (int)((ulonglong)((longlong)local_50 * (longlong)(int)(DAT_803de37e + 1)) >> 0x20);
  uVar14 = DAT_803de37e + 1 + (iVar16 - (iVar16 >> 0x1f)) * -3 & 0xff;
  if (puVar13[0x2b] != 0) {
    if (DAT_803de324 + -4 < DAT_803de328 + 5) {
      *DAT_803de328 = 0xd;
      DAT_803de328[1] = (short)((uint)DAT_803de324 >> 0x10);
      DAT_803de328[2] = (short)DAT_803de324;
      uVar1 = ((short)DAT_803de328 - (short)DAT_803de320) + 0xbU & 0xfffc;
      uVar3 = uVar1;
      if (DAT_803de314 != (undefined2 *)0x0) {
        DAT_803de314[3] = uVar1;
        FUN_80241a80(DAT_803de318,DAT_803de31c);
        uVar3 = DAT_803de32c;
      }
      DAT_803de32c = uVar3;
      DAT_803de314 = DAT_803de328;
      DAT_803de328 = DAT_803de324;
      DAT_803de318 = DAT_803de320;
      DAT_803de320 = DAT_803de324;
      DAT_803de31c = uVar1;
      DAT_803de324 = DAT_803de324 + 0xc0;
    }
    *DAT_803de328 = 4;
    DAT_803de328[1] = (short)((uint)puVar13[DAT_803de37e + 0xc] >> 0x10);
    DAT_803de328[2] = (short)puVar13[DAT_803de37e + 0xc];
    DAT_803de328[3] = (short)((uint)puVar13[uVar14 + 0xc] >> 0x10);
    DAT_803de328[4] = (short)puVar13[uVar14 + 0xc];
    DAT_803de328 = DAT_803de328 + 5;
  }
  if (puVar13[0x15] == 0) {
    if (puVar13[0x2c] != 0) {
      if (DAT_803de324 + -4 < DAT_803de328 + 5) {
        *DAT_803de328 = 0xd;
        DAT_803de328[1] = (short)((uint)DAT_803de324 >> 0x10);
        DAT_803de328[2] = (short)DAT_803de324;
        uVar1 = ((short)DAT_803de328 - (short)DAT_803de320) + 0xbU & 0xfffc;
        uVar3 = uVar1;
        if (DAT_803de314 != (undefined2 *)0x0) {
          DAT_803de314[3] = uVar1;
          FUN_80241a80(DAT_803de318,DAT_803de31c);
          uVar3 = DAT_803de32c;
        }
        DAT_803de32c = uVar3;
        DAT_803de314 = DAT_803de328;
        DAT_803de328 = DAT_803de324;
        DAT_803de318 = DAT_803de320;
        DAT_803de320 = DAT_803de324;
        DAT_803de31c = uVar1;
        DAT_803de324 = DAT_803de324 + 0xc0;
      }
      *DAT_803de328 = 5;
      DAT_803de328[1] = (short)((uint)puVar13[DAT_803de37e + 0xf] >> 0x10);
      DAT_803de328[2] = (short)puVar13[DAT_803de37e + 0xf];
      DAT_803de328[3] = (short)((uint)puVar13[uVar14 + 0xf] >> 0x10);
      DAT_803de328[4] = (short)puVar13[uVar14 + 0xf];
      DAT_803de328 = DAT_803de328 + 5;
    }
  }
  else {
    if (DAT_803de324 + -4 < DAT_803de328 + 5) {
      *DAT_803de328 = 0xd;
      DAT_803de328[1] = (short)((uint)DAT_803de324 >> 0x10);
      DAT_803de328[2] = (short)DAT_803de324;
      uVar1 = ((short)DAT_803de328 - (short)DAT_803de320) + 0xbU & 0xfffc;
      uVar3 = uVar1;
      if (DAT_803de314 != (undefined2 *)0x0) {
        DAT_803de314[3] = uVar1;
        FUN_80241a80(DAT_803de318,DAT_803de31c);
        uVar3 = DAT_803de32c;
      }
      DAT_803de32c = uVar3;
      DAT_803de314 = DAT_803de328;
      DAT_803de328 = DAT_803de324;
      DAT_803de318 = DAT_803de320;
      DAT_803de320 = DAT_803de324;
      DAT_803de31c = uVar1;
      DAT_803de324 = DAT_803de324 + 0xc0;
    }
    *DAT_803de328 = 0x10;
    DAT_803de328[1] = (short)((uint)puVar13[DAT_803de37f + 0xf] >> 0x10);
    DAT_803de328[2] = (short)puVar13[DAT_803de37f + 0xf];
    DAT_803de328[3] = (short)((uint)puVar13[(DAT_803de37f ^ 1) + 0xf] >> 0x10);
    DAT_803de328[4] = (short)puVar13[(DAT_803de37f ^ 1) + 0xf];
    DAT_803de328 = DAT_803de328 + 5;
  }
  if (DAT_803de324 + -4 < DAT_803de328 + 3) {
    *DAT_803de328 = 0xd;
    DAT_803de328[1] = (short)((uint)DAT_803de324 >> 0x10);
    DAT_803de328[2] = (short)DAT_803de324;
    uVar1 = ((short)DAT_803de328 - (short)DAT_803de320) + 0xbU & 0xfffc;
    uVar3 = uVar1;
    if (DAT_803de314 != (undefined2 *)0x0) {
      DAT_803de314[3] = uVar1;
      FUN_80241a80(DAT_803de318,DAT_803de31c);
      uVar3 = DAT_803de32c;
    }
    DAT_803de32c = uVar3;
    DAT_803de314 = DAT_803de328;
    DAT_803de328 = DAT_803de324;
    DAT_803de318 = DAT_803de320;
    DAT_803de320 = DAT_803de324;
    DAT_803de31c = uVar1;
    DAT_803de324 = DAT_803de324 + 0xc0;
  }
  *DAT_803de328 = 6;
  DAT_803de328[1] = (short)((uint)puVar13[DAT_803de37f + 10] >> 0x10);
  DAT_803de328[2] = (short)puVar13[DAT_803de37f + 10];
  DAT_803de328 = DAT_803de328 + 3;
  iVar16 = puVar13[1];
  puVar8 = (undefined4 *)*puVar13;
  if (iVar16 < -0x9f) {
    if (iVar16 < -0xc7f) {
      sVar4 = 0x14;
    }
    else {
      iVar16 = -iVar16 / 0xa0 + (-iVar16 >> 0x1f);
      sVar4 = (short)iVar16 - (short)(iVar16 >> 0x1f);
    }
    *(short *)(puVar8 + 1) = sVar4;
  }
  else if (iVar16 < 0xa0) {
    *(undefined2 *)(puVar8 + 1) = 0;
  }
  else {
    if (iVar16 < 0xc80) {
      iVar16 = -iVar16 / 0xa0 + (-iVar16 >> 0x1f);
      sVar4 = (short)iVar16 - (short)(iVar16 >> 0x1f);
    }
    else {
      sVar4 = -0x14;
    }
    *(short *)(puVar8 + 1) = sVar4;
  }
  *puVar8 = puVar13[1];
  puVar13[1] = puVar13[1] + *(short *)(puVar8 + 1) * 0xa0;
  iVar16 = puVar13[2];
  if (iVar16 < -0x9f) {
    if (iVar16 < -0xc7f) {
      sVar4 = 0x14;
    }
    else {
      iVar16 = -iVar16 / 0xa0 + (-iVar16 >> 0x1f);
      sVar4 = (short)iVar16 - (short)(iVar16 >> 0x1f);
    }
    *(short *)((int)puVar8 + 10) = sVar4;
  }
  else if (iVar16 < 0xa0) {
    *(undefined2 *)((int)puVar8 + 10) = 0;
  }
  else {
    if (iVar16 < 0xc80) {
      iVar16 = -iVar16 / 0xa0 + (-iVar16 >> 0x1f);
      sVar4 = (short)iVar16 - (short)(iVar16 >> 0x1f);
    }
    else {
      sVar4 = -0x14;
    }
    *(short *)((int)puVar8 + 10) = sVar4;
  }
  *(undefined4 *)((int)puVar8 + 6) = puVar13[2];
  puVar13[2] = puVar13[2] + *(short *)((int)puVar8 + 10) * 0xa0;
  iVar16 = puVar13[3];
  if (iVar16 < -0x9f) {
    if (iVar16 < -0xc7f) {
      sVar4 = 0x14;
    }
    else {
      iVar16 = -iVar16 / 0xa0 + (-iVar16 >> 0x1f);
      sVar4 = (short)iVar16 - (short)(iVar16 >> 0x1f);
    }
    *(short *)(puVar8 + 4) = sVar4;
  }
  else if (iVar16 < 0xa0) {
    *(undefined2 *)(puVar8 + 4) = 0;
  }
  else {
    if (iVar16 < 0xc80) {
      iVar16 = -iVar16 / 0xa0 + (-iVar16 >> 0x1f);
      sVar4 = (short)iVar16 - (short)(iVar16 >> 0x1f);
    }
    else {
      sVar4 = -0x14;
    }
    *(short *)(puVar8 + 4) = sVar4;
  }
  puVar8[3] = puVar13[3];
  puVar13[3] = puVar13[3] + *(short *)(puVar8 + 4) * 0xa0;
  iVar16 = puVar13[4];
  if (iVar16 < -0x9f) {
    if (iVar16 < -0xc7f) {
      sVar4 = 0x14;
    }
    else {
      iVar16 = -iVar16 / 0xa0 + (-iVar16 >> 0x1f);
      sVar4 = (short)iVar16 - (short)(iVar16 >> 0x1f);
    }
    *(short *)((int)puVar8 + 0x16) = sVar4;
  }
  else if (iVar16 < 0xa0) {
    *(undefined2 *)((int)puVar8 + 0x16) = 0;
  }
  else {
    if (iVar16 < 0xc80) {
      iVar16 = -iVar16 / 0xa0 + (-iVar16 >> 0x1f);
      sVar4 = (short)iVar16 - (short)(iVar16 >> 0x1f);
    }
    else {
      sVar4 = -0x14;
    }
    *(short *)((int)puVar8 + 0x16) = sVar4;
  }
  *(undefined4 *)((int)puVar8 + 0x12) = puVar13[4];
  puVar13[4] = puVar13[4] + *(short *)((int)puVar8 + 0x16) * 0xa0;
  iVar16 = puVar13[5];
  if (iVar16 < -0x9f) {
    if (iVar16 < -0xc7f) {
      sVar4 = 0x14;
    }
    else {
      iVar16 = -iVar16 / 0xa0 + (-iVar16 >> 0x1f);
      sVar4 = (short)iVar16 - (short)(iVar16 >> 0x1f);
    }
    *(short *)(puVar8 + 7) = sVar4;
  }
  else if (iVar16 < 0xa0) {
    *(undefined2 *)(puVar8 + 7) = 0;
  }
  else {
    if (iVar16 < 0xc80) {
      iVar16 = -iVar16 / 0xa0 + (-iVar16 >> 0x1f);
      sVar4 = (short)iVar16 - (short)(iVar16 >> 0x1f);
    }
    else {
      sVar4 = -0x14;
    }
    *(short *)(puVar8 + 7) = sVar4;
  }
  puVar8[6] = puVar13[5];
  puVar13[5] = puVar13[5] + *(short *)(puVar8 + 7) * 0xa0;
  iVar16 = puVar13[6];
  if (iVar16 < -0x9f) {
    if (iVar16 < -0xc7f) {
      sVar4 = 0x14;
    }
    else {
      iVar16 = -iVar16 / 0xa0 + (-iVar16 >> 0x1f);
      sVar4 = (short)iVar16 - (short)(iVar16 >> 0x1f);
    }
    *(short *)((int)puVar8 + 0x22) = sVar4;
  }
  else if (iVar16 < 0xa0) {
    *(undefined2 *)((int)puVar8 + 0x22) = 0;
  }
  else {
    if (iVar16 < 0xc80) {
      iVar16 = -iVar16 / 0xa0 + (-iVar16 >> 0x1f);
      sVar4 = (short)iVar16 - (short)(iVar16 >> 0x1f);
    }
    else {
      sVar4 = -0x14;
    }
    *(short *)((int)puVar8 + 0x22) = sVar4;
  }
  *(undefined4 *)((int)puVar8 + 0x1e) = puVar13[6];
  puVar13[6] = puVar13[6] + *(short *)((int)puVar8 + 0x22) * 0xa0;
  iVar16 = puVar13[7];
  if (iVar16 < -0x9f) {
    if (iVar16 < -0xc7f) {
      sVar4 = 0x14;
    }
    else {
      iVar16 = -iVar16 / 0xa0 + (-iVar16 >> 0x1f);
      sVar4 = (short)iVar16 - (short)(iVar16 >> 0x1f);
    }
    *(short *)(puVar8 + 10) = sVar4;
  }
  else if (iVar16 < 0xa0) {
    *(undefined2 *)(puVar8 + 10) = 0;
  }
  else {
    if (iVar16 < 0xc80) {
      iVar16 = -iVar16 / 0xa0 + (-iVar16 >> 0x1f);
      sVar4 = (short)iVar16 - (short)(iVar16 >> 0x1f);
    }
    else {
      sVar4 = -0x14;
    }
    *(short *)(puVar8 + 10) = sVar4;
  }
  puVar8[9] = puVar13[7];
  puVar13[7] = puVar13[7] + *(short *)(puVar8 + 10) * 0xa0;
  iVar16 = puVar13[8];
  if (iVar16 < -0x9f) {
    if (iVar16 < -0xc7f) {
      sVar4 = 0x14;
    }
    else {
      iVar16 = -iVar16 / 0xa0 + (-iVar16 >> 0x1f);
      sVar4 = (short)iVar16 - (short)(iVar16 >> 0x1f);
    }
    *(short *)((int)puVar8 + 0x2e) = sVar4;
  }
  else if (iVar16 < 0xa0) {
    *(undefined2 *)((int)puVar8 + 0x2e) = 0;
  }
  else {
    if (iVar16 < 0xc80) {
      iVar16 = -iVar16 / 0xa0 + (-iVar16 >> 0x1f);
      sVar4 = (short)iVar16 - (short)(iVar16 >> 0x1f);
    }
    else {
      sVar4 = -0x14;
    }
    *(short *)((int)puVar8 + 0x2e) = sVar4;
  }
  *(undefined4 *)((int)puVar8 + 0x2a) = puVar13[8];
  puVar13[8] = puVar13[8] + *(short *)((int)puVar8 + 0x2e) * 0xa0;
  iVar16 = puVar13[9];
  if (iVar16 < -0x9f) {
    if (iVar16 < -0xc7f) {
      sVar4 = 0x14;
    }
    else {
      iVar16 = -iVar16 / 0xa0 + (-iVar16 >> 0x1f);
      sVar4 = (short)iVar16 - (short)(iVar16 >> 0x1f);
    }
    *(short *)(puVar8 + 0xd) = sVar4;
  }
  else if (iVar16 < 0xa0) {
    *(undefined2 *)(puVar8 + 0xd) = 0;
  }
  else {
    if (iVar16 < 0xc80) {
      iVar16 = -iVar16 / 0xa0 + (-iVar16 >> 0x1f);
      sVar4 = (short)iVar16 - (short)(iVar16 >> 0x1f);
    }
    else {
      sVar4 = -0x14;
    }
    *(short *)(puVar8 + 0xd) = sVar4;
  }
  puVar8[0xc] = puVar13[9];
  puVar13[9] = puVar13[9] + *(short *)(puVar8 + 0xd) * 0xa0;
  FUN_80241a50(puVar8,0x36);
  goto LAB_8027eb3c;
LAB_8027dff0:
  iVar11 = iVar11 + -1;
  local_68 = local_68 + -1;
  goto LAB_8027e000;
}

