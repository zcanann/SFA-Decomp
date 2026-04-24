// Function: FUN_8027cbf0
// Entry: 8027cbf0
// Size: 10828 bytes

/* WARNING: Removing unreachable block (ram,0x8027d1c0) */
/* WARNING: Removing unreachable block (ram,0x8027d658) */
/* WARNING: Removing unreachable block (ram,0x8027d518) */
/* WARNING: Removing unreachable block (ram,0x8027e498) */

void FUN_8027cbf0(undefined4 param_1,uint param_2)

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
  int iVar10;
  byte bVar11;
  int iVar12;
  uint uVar13;
  undefined4 *puVar14;
  int unaff_r18;
  uint unaff_r19;
  uint uVar15;
  uint uVar16;
  int *piVar17;
  int iVar18;
  int *piVar19;
  ushort *puVar20;
  int iVar21;
  undefined2 *puVar22;
  undefined2 *puVar23;
  short local_a8;
  undefined2 local_a6 [3];
  ushort local_a0 [6];
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
  
  local_7c = &DAT_803cce40;
  DAT_803def94 = (undefined2 *)0x0;
  DAT_803defa8 = DAT_803defb0;
  DAT_803defa0 = DAT_803defb0;
  DAT_803defa4 = DAT_803defb0 + 0xc0;
  if (param_2 < 200) {
    uVar16 = 0x28be;
  }
  else {
    uVar16 = (param_2 - 200) * (DAT_800000f8 / 2000000) + 0x28be;
  }
  if (DAT_803defb4 != 0) {
    uVar16 = uVar16 + 45000;
  }
  puVar14 = &DAT_803cce40;
  local_a0[0] = 0;
  local_54 = DAT_800000f8 / 400;
  local_60 = 0x24924925;
  local_64 = 0x8000;
  local_5c = &DAT_802c2e38;
  local_50 = 0x55555556;
  local_58 = &DAT_80330a00;
  local_80 = 0;
  local_94 = param_1;
  while( true ) {
    if (DAT_803deffc <= local_80) {
      if (DAT_803defa4 + -4 < DAT_803defa8 + 3) {
        *DAT_803defa8 = 0xd;
        DAT_803defa8[1] = (short)((uint)DAT_803defa4 >> 0x10);
        DAT_803defa8[2] = (short)DAT_803defa4;
        uVar1 = ((short)DAT_803defa8 - (short)DAT_803defa0) + 0xbU & 0xfffc;
        uVar3 = uVar1;
        if (DAT_803def94 != (undefined2 *)0x0) {
          DAT_803def94[3] = uVar1;
          FUN_80242178((uint)DAT_803def98,(uint)DAT_803def9c);
          uVar3 = DAT_803defac;
        }
        DAT_803defac = uVar3;
        DAT_803def94 = DAT_803defa8;
        DAT_803defa8 = DAT_803defa4;
        DAT_803def98 = DAT_803defa0;
        DAT_803defa0 = DAT_803defa4;
        DAT_803def9c = uVar1;
        DAT_803defa4 = DAT_803defa4 + 0xc0;
      }
      *DAT_803defa8 = 0x11;
      DAT_803defa8[1] = (short)((uint)DAT_803defbc >> 0x10);
      DAT_803defa8[2] = (short)DAT_803defbc;
      DAT_803defa8 = DAT_803defa8 + 3;
      for (bVar11 = 0; bVar11 < DAT_803deffc; bVar11 = bVar11 + 1) {
        if ((*(char *)(local_7c + 0x14) == '\x01') && (*(char *)((int)local_7c + 0x51) != '\0')) {
          if (DAT_803defa4 + -4 < DAT_803defa8 + 3) {
            *DAT_803defa8 = 0xd;
            DAT_803defa8[1] = (short)((uint)DAT_803defa4 >> 0x10);
            DAT_803defa8[2] = (short)DAT_803defa4;
            uVar1 = ((short)DAT_803defa8 - (short)DAT_803defa0) + 0xbU & 0xfffc;
            uVar3 = uVar1;
            if (DAT_803def94 != (undefined2 *)0x0) {
              DAT_803def94[3] = uVar1;
              FUN_80242178((uint)DAT_803def98,(uint)DAT_803def9c);
              uVar3 = DAT_803defac;
            }
            DAT_803defac = uVar3;
            DAT_803def94 = DAT_803defa8;
            DAT_803defa8 = DAT_803defa4;
            DAT_803def98 = DAT_803defa0;
            DAT_803defa0 = DAT_803defa4;
            DAT_803def9c = uVar1;
            DAT_803defa4 = DAT_803defa4 + 0xc0;
          }
          *DAT_803defa8 = 9;
          DAT_803defa8[1] = (short)((uint)local_7c[DAT_803defff + 10] >> 0x10);
          DAT_803defa8[2] = (short)local_7c[DAT_803defff + 10];
          DAT_803defa8 = DAT_803defa8 + 3;
        }
        local_7c = local_7c + 0x2f;
      }
      if (DAT_803defa4 + -4 < DAT_803defa8 + 5) {
        *DAT_803defa8 = 0xd;
        DAT_803defa8[1] = (short)((uint)DAT_803defa4 >> 0x10);
        DAT_803defa8[2] = (short)DAT_803defa4;
        uVar1 = ((short)DAT_803defa8 - (short)DAT_803defa0) + 0xbU & 0xfffc;
        uVar3 = uVar1;
        if (DAT_803def94 != (undefined2 *)0x0) {
          DAT_803def94[3] = uVar1;
          FUN_80242178((uint)DAT_803def98,(uint)DAT_803def9c);
          uVar3 = DAT_803defac;
        }
        DAT_803defac = uVar3;
        DAT_803def94 = DAT_803defa8;
        DAT_803defa8 = DAT_803defa4;
        DAT_803def98 = DAT_803defa0;
        DAT_803defa0 = DAT_803defa4;
        DAT_803def9c = uVar1;
        DAT_803defa4 = DAT_803defa4 + 0xc0;
      }
      *DAT_803defa8 = 0xe;
      DAT_803defa8[1] = (short)((uint)DAT_803defbc >> 0x10);
      DAT_803defa8[2] = (short)DAT_803defbc;
      DAT_803defa8[3] = (short)((uint)local_94 >> 0x10);
      DAT_803defa8[4] = (short)local_94;
      puVar22 = DAT_803defa8 + 5;
      DAT_803defa8 = DAT_803defa8 + 6;
      *puVar22 = 0xf;
      uVar1 = ((short)DAT_803defa8 - (short)DAT_803defa0) + 3U & 0xfffc;
      if (DAT_803def94 != (undefined2 *)0x0) {
        DAT_803def94[3] = uVar1;
        FUN_80242178((uint)DAT_803def98,(uint)DAT_803def9c);
        uVar1 = DAT_803defac;
      }
      DAT_803defac = uVar1;
      FUN_80242178((uint)DAT_803defa0,(int)DAT_803defa8 - (int)DAT_803defa0);
      return;
    }
    if (*(char *)(puVar14 + 0x14) == '\x01') break;
LAB_8027f2a0:
    puVar14 = puVar14 + 0x2f;
    local_80 = local_80 + 1;
  }
  piVar17 = (int *)puVar14[0x12];
  while (piVar19 = piVar17, piVar19 != (int *)0x0) {
    piVar17 = (int *)piVar19[3];
    if ((*(char *)((int)piVar19 + 0xed) != '\0') || ((piVar19[9] & 0x20U) != 0)) {
      FUN_8027c83c((int)puVar14,piVar19);
      if (piVar19[0x3a] != -1) {
        FUN_8027f63c((int)piVar19,3);
      }
      if ((*(char *)(piVar19 + 0x3b) != '\x01') || (*(char *)((int)piVar19 + 0xee) != '\0')) {
        FUN_8027f724((int)piVar19);
        *(undefined *)((int)piVar19 + 0xee) = 0;
      }
    }
  }
  for (piVar17 = (int *)puVar14[0x13]; piVar17 != (int *)0x0; piVar17 = (int *)piVar17[5]) {
    FUN_8027c83c((int)puVar14,piVar17);
  }
  puVar14[0x13] = 0;
  if (DAT_803defa4 + -4 < DAT_803defa8 + 3) {
    *DAT_803defa8 = 0xd;
    DAT_803defa8[1] = (short)((uint)DAT_803defa4 >> 0x10);
    DAT_803defa8[2] = (short)DAT_803defa4;
    uVar1 = ((short)DAT_803defa8 - (short)DAT_803defa0) + 0xbU & 0xfffc;
    uVar3 = uVar1;
    if (DAT_803def94 != (undefined2 *)0x0) {
      DAT_803def94[3] = uVar1;
      FUN_80242178((uint)DAT_803def98,(uint)DAT_803def9c);
      uVar3 = DAT_803defac;
    }
    DAT_803defac = uVar3;
    DAT_803def94 = DAT_803defa8;
    DAT_803defa8 = DAT_803defa4;
    DAT_803def98 = DAT_803defa0;
    DAT_803defa0 = DAT_803defa4;
    DAT_803def9c = uVar1;
    DAT_803defa4 = DAT_803defa4 + 0xc0;
  }
  *DAT_803defa8 = 0;
  uVar16 = uVar16 + 0x2c62;
  DAT_803defa8[1] = (short)((uint)*puVar14 >> 0x10);
  DAT_803defa8[2] = (short)*puVar14;
  DAT_803defa8 = DAT_803defa8 + 3;
  puVar8 = puVar14;
  for (uVar15 = 0; uVar15 < *(byte *)((int)puVar14 + 0x52); uVar15 = uVar15 + 1) {
    if (DAT_803defa4 + -4 < DAT_803defa8 + 6) {
      *DAT_803defa8 = 0xd;
      DAT_803defa8[1] = (short)((uint)DAT_803defa4 >> 0x10);
      DAT_803defa8[2] = (short)DAT_803defa4;
      uVar1 = ((short)DAT_803defa8 - (short)DAT_803defa0) + 0xbU & 0xfffc;
      uVar3 = uVar1;
      if (DAT_803def94 != (undefined2 *)0x0) {
        DAT_803def94[3] = uVar1;
        FUN_80242178((uint)DAT_803def98,(uint)DAT_803def9c);
        uVar3 = DAT_803defac;
      }
      DAT_803defac = uVar3;
      DAT_803def94 = DAT_803defa8;
      DAT_803defa8 = DAT_803defa4;
      DAT_803def98 = DAT_803defa0;
      DAT_803defa0 = DAT_803defa4;
      DAT_803def9c = uVar1;
      DAT_803defa4 = DAT_803defa4 + 0xc0;
    }
    uVar16 = uVar16 + 0x294d;
    *DAT_803defa8 = 1;
    DAT_803defa8[1] =
         (short)((uint)local_7c[(DAT_803defff ^ 1) + (uint)*(byte *)(puVar8 + 0x16) * 0x2f + 10] >>
                0x10);
    DAT_803defa8[2] =
         (short)local_7c[(DAT_803defff ^ 1) + (uint)*(byte *)(puVar8 + 0x16) * 0x2f + 10];
    DAT_803defa8[3] = *(undefined2 *)((int)puVar8 + 0x5a);
    DAT_803defa8[4] = *(undefined2 *)(puVar8 + 0x17);
    puVar22 = (undefined2 *)((int)puVar8 + 0x5e);
    puVar8 = puVar8 + 3;
    DAT_803defa8[5] = *puVar22;
    DAT_803defa8 = DAT_803defa8 + 6;
  }
  iVar9 = puVar14[0x12];
  iVar12 = 0;
  local_4c = (undefined2 *)0x0;
  piVar17 = local_7c + 0x178;
  for (; iVar9 != 0; iVar9 = *(int *)(iVar9 + 0xc)) {
    *piVar17 = iVar9;
    piVar17 = piVar17 + 1;
    iVar12 = iVar12 + 1;
  }
  FUN_8027caf4((int)(local_7c + 0x178),0,iVar12 + -1);
  local_8c = 0;
  local_68 = local_7c + iVar12 + 0x178;
LAB_8027e764:
  if (0 < iVar12) {
    piVar17 = (int *)local_68[-1];
    if (*(char *)(piVar17 + 0x3b) == '\0') goto LAB_8027e754;
    puVar22 = (undefined2 *)*piVar17;
    local_a0[1] = 0;
    local_a0[2] = 0;
    local_a0[3] = 0;
    local_a0[4] = 0;
    if (*(char *)(piVar17 + 0x3b) != '\x01') {
      if ((((*(char *)(piVar17 + 0x24) == '\x04') || (*(char *)(piVar17 + 0x24) == '\x05')) &&
          (puVar22[0x5a] = (ushort)*(byte *)(piVar17 + 0x28), *(char *)(piVar17 + 0x24) == '\x05'))
         && ((*(char *)(piVar17 + 0x27) == '\0' && (puVar22[0x5d] != 0)))) {
        uVar6 = piVar17[0x26] - 1;
        piVar17[0x1e] = piVar17[0x25];
        iVar9 = (int)((ulonglong)local_60 * (ulonglong)uVar6 >> 0x20);
        uVar15 = (uVar6 - iVar9 >> 1) + iVar9;
        unaff_r18 = piVar17[0x25] * 2 + (uVar15 * 2 & 0xfffffff0) + 2 + uVar6 + (uVar15 >> 3) * -0xe
        ;
        *(int *)(puVar22 + 0x3b) = unaff_r18;
        *(undefined *)(piVar17 + 0x27) = 1;
      }
      if ((piVar17[0x23] == 0) && ((uint)piVar17[0x21] <= (uint)piVar17[0x36])) {
        FUN_8027f63c((int)piVar17,0);
        FUN_8027f724((int)piVar17);
      }
      else {
        if (((piVar17[9] & 0x10U) == 0) ||
           (iVar9 = FUN_8027b038((char *)(piVar17 + 0x29)), iVar9 == 0)) {
          if ((piVar17[9] & 1U) == 0) {
            uVar15 = FUN_8027c748(puVar22 + 9,puVar22 + 10,(short *)((int)piVar17 + 0x5e),
                                  *(short *)(piVar17 + 0x13),(int)local_a0,1);
            uVar6 = FUN_8027c748(puVar22 + 0xb,puVar22 + 0xc,(short *)(piVar17 + 0x18),
                                 *(short *)((int)piVar17 + 0x4e),(int)local_a0,2);
            uVar5 = FUN_8027c748(puVar22 + 0x17,puVar22 + 0x18,(short *)((int)piVar17 + 0x62),
                                 *(short *)(piVar17 + 0x14),(int)local_a0,4);
            uVar5 = uVar15 | uVar6 | uVar5;
          }
          else {
            uVar5 = 1;
            iVar9 = (int)*(short *)(piVar17 + 0x13) - (int)*(short *)((int)piVar17 + 0x5e);
            iVar9 = iVar9 / 0xa0 + (iVar9 >> 0x1f);
            puVar22[10] = (short)iVar9 - (short)(iVar9 >> 0x1f);
            *(short *)((int)piVar17 + 0x5e) = *(short *)((int)piVar17 + 0x5e) + puVar22[10] * 0xa0;
            iVar9 = (int)*(short *)((int)piVar17 + 0x4e) - (int)*(short *)(piVar17 + 0x18);
            iVar9 = iVar9 / 0xa0 + (iVar9 >> 0x1f);
            puVar22[0xc] = (short)iVar9 - (short)(iVar9 >> 0x1f);
            *(short *)(piVar17 + 0x18) = *(short *)(piVar17 + 0x18) + puVar22[0xc] * 0xa0;
            iVar9 = (int)*(short *)(piVar17 + 0x14) - (int)*(short *)((int)piVar17 + 0x62);
            iVar9 = iVar9 / 0xa0 + (iVar9 >> 0x1f);
            puVar22[0x18] = (short)iVar9 - (short)(iVar9 >> 0x1f);
            *(short *)((int)piVar17 + 0x62) = *(short *)((int)piVar17 + 0x62) + puVar22[0x18] * 0xa0
            ;
          }
          if ((piVar17[9] & 2U) == 0) {
            if ((puVar22[6] & 1) == 0) {
              puVar22[0xe] = 0;
              puVar22[0x10] = 0;
              puVar22[0x1a] = 0;
            }
            else {
              iVar9 = FUN_8027c748(puVar22 + 0xd,puVar22 + 0xe,(short *)(piVar17 + 0x19),
                                   *(short *)((int)piVar17 + 0x52),(int)local_a0,8);
              iVar10 = FUN_8027c748(puVar22 + 0xf,puVar22 + 0x10,(short *)((int)piVar17 + 0x66),
                                    *(short *)(piVar17 + 0x15),(int)local_a0,0x10);
              iVar21 = FUN_8027c748(puVar22 + 0x19,puVar22 + 0x1a,(short *)(piVar17 + 0x1a),
                                    *(short *)((int)piVar17 + 0x56),(int)local_a0,0x20);
              if (((iVar9 == 0 && iVar10 == 0) && iVar21 == 0) &&
                  (puVar22[0x19] == 0 && (puVar22[0xd] == 0 && puVar22[0xf] == 0))) {
                puVar22[6] = puVar22[6] & 0xfffe;
              }
              else {
                uVar5 = 1;
              }
            }
          }
          else {
            iVar9 = (int)*(short *)((int)piVar17 + 0x52) - (int)*(short *)(piVar17 + 0x19);
            iVar9 = iVar9 / 0xa0 + (iVar9 >> 0x1f);
            puVar22[0xe] = (short)iVar9 - (short)(iVar9 >> 0x1f);
            *(short *)(piVar17 + 0x19) = *(short *)(piVar17 + 0x19) + puVar22[0xe] * 0xa0;
            iVar9 = (int)*(short *)(piVar17 + 0x15) - (int)*(short *)((int)piVar17 + 0x66);
            iVar9 = iVar9 / 0xa0 + (iVar9 >> 0x1f);
            puVar22[0x10] = (short)iVar9 - (short)(iVar9 >> 0x1f);
            *(short *)((int)piVar17 + 0x66) = *(short *)((int)piVar17 + 0x66) + puVar22[0x10] * 0xa0
            ;
            iVar9 = (int)*(short *)((int)piVar17 + 0x56) - (int)*(short *)(piVar17 + 0x1a);
            iVar9 = iVar9 / 0xa0 + (iVar9 >> 0x1f);
            puVar22[0x1a] = (short)iVar9 - (short)(iVar9 >> 0x1f);
            *(short *)(piVar17 + 0x1a) = *(short *)(piVar17 + 0x1a) + puVar22[0x1a] * 0xa0;
            if (puVar22[0x1a] == 0 && (puVar22[0xe] == 0 && puVar22[0x10] == 0)) {
              if (puVar22[0x19] == 0 && (puVar22[0xd] == 0 && puVar22[0xf] == 0)) {
                puVar22[6] = puVar22[6] & 0xfffe;
              }
              else {
                puVar22[6] = puVar22[6] | 1;
              }
            }
            else {
              uVar5 = 1;
              puVar22[6] = puVar22[6] | 1;
            }
          }
          if ((piVar17[9] & 4U) == 0) {
            if (puVar14[0x15] == 0) {
              if ((puVar22[6] & 2) == 0) {
                puVar22[0x12] = 0;
                puVar22[0x14] = 0;
                puVar22[0x16] = 0;
              }
              else {
                iVar9 = FUN_8027c748(puVar22 + 0x11,puVar22 + 0x12,(short *)((int)piVar17 + 0x6a),
                                     *(short *)(piVar17 + 0x16),(int)local_a0,0x40);
                iVar10 = FUN_8027c748(puVar22 + 0x13,puVar22 + 0x14,(short *)(piVar17 + 0x1b),
                                      *(short *)((int)piVar17 + 0x5a),(int)local_a0,0x80);
                iVar21 = FUN_8027c748(puVar22 + 0x15,puVar22 + 0x16,(short *)((int)piVar17 + 0x6e),
                                      *(short *)(piVar17 + 0x17),(int)local_a0,0x100);
                if (((iVar9 == 0 && iVar10 == 0) && iVar21 == 0) &&
                    (puVar22[0x15] == 0 && (puVar22[0x11] == 0 && puVar22[0x13] == 0))) {
                  puVar22[6] = puVar22[6] & 0xfffd;
                }
                else {
                  uVar5 = 1;
                }
              }
            }
            else if ((puVar22[6] & 0x10) == 0) {
              puVar22[0x12] = 0;
              puVar22[0x14] = 0;
              if (puVar22[0x19] != 0 || puVar22[0x1a] != 0) {
                puVar22[6] = puVar22[6] | 0x10;
              }
            }
            else {
              iVar9 = FUN_8027c748(puVar22 + 0x11,puVar22 + 0x12,(short *)((int)piVar17 + 0x6a),
                                   *(short *)(piVar17 + 0x16),(int)local_a0,0x40);
              iVar10 = FUN_8027c748(puVar22 + 0x13,puVar22 + 0x14,(short *)(piVar17 + 0x1b),
                                    *(short *)((int)piVar17 + 0x5a),(int)local_a0,0x80);
              if ((iVar9 == 0 && iVar10 == 0) && (puVar22[0x11] == 0 && puVar22[0x13] == 0)) {
                if (puVar22[0x19] == 0 && puVar22[0x1a] == 0) {
                  puVar22[6] = puVar22[6] & 0xffef;
                }
              }
              else {
                uVar5 = 1;
              }
            }
          }
          else if (puVar14[0x15] == 0) {
            iVar9 = (int)*(short *)(piVar17 + 0x16) - (int)*(short *)((int)piVar17 + 0x6a);
            iVar9 = iVar9 / 0xa0 + (iVar9 >> 0x1f);
            puVar22[0x12] = (short)iVar9 - (short)(iVar9 >> 0x1f);
            *(short *)((int)piVar17 + 0x6a) = *(short *)((int)piVar17 + 0x6a) + puVar22[0x12] * 0xa0
            ;
            iVar9 = (int)*(short *)((int)piVar17 + 0x5a) - (int)*(short *)(piVar17 + 0x1b);
            iVar9 = iVar9 / 0xa0 + (iVar9 >> 0x1f);
            puVar22[0x14] = (short)iVar9 - (short)(iVar9 >> 0x1f);
            *(short *)(piVar17 + 0x1b) = *(short *)(piVar17 + 0x1b) + puVar22[0x14] * 0xa0;
            iVar9 = (int)*(short *)(piVar17 + 0x17) - (int)*(short *)((int)piVar17 + 0x6e);
            iVar9 = iVar9 / 0xa0 + (iVar9 >> 0x1f);
            puVar22[0x16] = (short)iVar9 - (short)(iVar9 >> 0x1f);
            *(short *)((int)piVar17 + 0x6e) = *(short *)((int)piVar17 + 0x6e) + puVar22[0x16] * 0xa0
            ;
            if (puVar22[0x16] == 0 && (puVar22[0x12] == 0 && puVar22[0x14] == 0)) {
              if (puVar22[0x15] == 0 && (puVar22[0x11] == 0 && puVar22[0x13] == 0)) {
                puVar22[6] = puVar22[6] & 0xfffd;
              }
              else {
                puVar22[6] = puVar22[6] | 2;
              }
            }
            else {
              uVar5 = 1;
              puVar22[6] = puVar22[6] | 2;
            }
          }
          else {
            iVar9 = (int)*(short *)(piVar17 + 0x16) - (int)*(short *)((int)piVar17 + 0x6a);
            iVar9 = iVar9 / 0xa0 + (iVar9 >> 0x1f);
            puVar22[0x12] = (short)iVar9 - (short)(iVar9 >> 0x1f);
            *(short *)((int)piVar17 + 0x6a) = *(short *)((int)piVar17 + 0x6a) + puVar22[0x12] * 0xa0
            ;
            iVar9 = (int)*(short *)((int)piVar17 + 0x5a) - (int)*(short *)(piVar17 + 0x1b);
            iVar9 = iVar9 / 0xa0 + (iVar9 >> 0x1f);
            puVar22[0x14] = (short)iVar9 - (short)(iVar9 >> 0x1f);
            *(short *)(piVar17 + 0x1b) = *(short *)(piVar17 + 0x1b) + puVar22[0x14] * 0xa0;
            if (puVar22[0x12] == 0 && puVar22[0x14] == 0) {
              if (puVar22[0x1a] == 0 &&
                  (puVar22[0x19] == 0 && (puVar22[0x11] == 0 && puVar22[0x13] == 0))) {
                puVar22[6] = puVar22[6] & 0xffef;
              }
              else {
                puVar22[6] = puVar22[6] | 0x10;
              }
            }
            else {
              uVar5 = 1;
              puVar22[6] = puVar22[6] | 0x10;
            }
          }
          if (uVar5 == 0) {
            puVar22[6] = puVar22[6] & 0xfff7;
          }
          else {
            puVar22[6] = puVar22[6] | 8;
          }
          if (puVar14[0x15] == 0) {
            if ((((puVar22[0x17] == 0) && (puVar22[0x18] == 0)) && (puVar22[0x19] == 0)) &&
               (((puVar22[0x1a] == 0 && (puVar22[0x15] == 0)) && (puVar22[0x16] == 0)))) {
              puVar22[6] = puVar22[6] & 0xfffb;
            }
            else {
              puVar22[6] = puVar22[6] | 4;
            }
          }
          if ((piVar17[9] & 0x200U) != 0) {
            puVar22[0x20] = *(undefined2 *)(piVar17 + 0x34);
            puVar22[0x21] = *(undefined2 *)((int)piVar17 + 0xd2);
          }
          if ((piVar17[9] & 0x100U) != 0) {
            puVar22[4] = *(undefined2 *)(piVar17 + 0x33);
          }
          if ((piVar17[9] & 0x80U) != 0) {
            puVar22[5] = *(undefined2 *)((int)piVar17 + 0xce);
          }
          uVar15 = 0;
          local_88 = 0;
          piVar17[8] = *(int *)(puVar22 + 0x3d);
          goto LAB_8027e080;
        }
        FUN_8027f63c((int)piVar17,0);
        FUN_8027f724((int)piVar17);
      }
      goto LAB_8027e754;
    }
    piVar17[0x3a] = -1;
    *(short *)(*piVar17 + 0x66) = (short)local_64;
    iVar9 = FUN_8027b038((char *)(piVar17 + 0x29));
    if (iVar9 != 0) {
      FUN_8027f63c((int)piVar17,0);
      FUN_8027f724((int)piVar17);
      goto LAB_8027e754;
    }
    piVar17[0x3a] = -1;
    if (*(char *)(piVar17 + 0x24) == '\x05') {
      piVar17[0x26] = 0;
      iVar9 = FUN_8027f63c((int)piVar17,2);
      piVar17[0x3a] = iVar9;
      if (piVar17[0x26] == 0) {
        FUN_8027f63c((int)piVar17,1);
        FUN_8027f724((int)piVar17);
        goto LAB_8027e754;
      }
    }
    puVar22[0x55] = 0;
    puVar22[0x56] = 0;
    puVar22[0x57] = 0;
    puVar22[0x58] = 0;
    puVar22[0x59] = 0;
    if ((piVar17[0x3c] & 0x80000000U) == 0) {
      puVar22[0x1b] = 0;
    }
    else {
      FUN_800033a8(piVar17[2],0,0x40);
      FUN_802420e0(piVar17[2],0x40);
      puVar22[0x20] = *(undefined2 *)(piVar17 + 0x34);
      puVar22[0x1e] = *(undefined2 *)(piVar17 + 0x34);
      puVar22[0x21] = *(undefined2 *)((int)piVar17 + 0xd2);
      puVar22[0x1f] = *(undefined2 *)((int)piVar17 + 0xd2);
      puVar22[0x1b] = 1;
    }
    bVar11 = *(byte *)(piVar17 + 0x24);
    if (bVar11 == 2) {
      puVar22[0x38] = 10;
      puVar22[0x4f] = 0x800;
      puVar22[0x3f] = 0;
      puVar22[0x40] = 0;
      puVar22[0x41] = 0;
      puVar22[0x42] = 0;
      puVar22[0x43] = 0;
      puVar22[0x44] = 0;
      puVar22[0x45] = 0;
      puVar22[0x46] = 0;
      puVar22[0x47] = 0;
      puVar22[0x48] = 0;
      puVar22[0x49] = 0;
      puVar22[0x4a] = 0;
      puVar22[0x4b] = 0;
      puVar22[0x4c] = 0;
      puVar22[0x4d] = 0;
      puVar22[0x4e] = 0;
      unaff_r19 = (uint)piVar17[0x1e] >> 1;
      piVar17[0x36] = piVar17[0x20];
      local_84 = piVar17[0x20] + unaff_r19;
      piVar17[0x37] = 0;
    }
    else if (bVar11 < 2) {
      if (bVar11 == 0) {
LAB_8027d1d8:
        puVar22[0x38] = 0;
        puVar22[0x4f] = 0;
        iVar9 = piVar17[0x1f];
        puVar22[0x52] = 0;
        puVar22[0x51] = 0;
        puVar22[0x50] = (ushort)*(byte *)(iVar9 + 2);
        puVar22[0x3f] = *(undefined2 *)(iVar9 + 8);
        puVar22[0x40] = *(undefined2 *)(iVar9 + 10);
        puVar22[0x41] = *(undefined2 *)(iVar9 + 0xc);
        puVar22[0x42] = *(undefined2 *)(iVar9 + 0xe);
        puVar22[0x43] = *(undefined2 *)(iVar9 + 0x10);
        puVar22[0x44] = *(undefined2 *)(iVar9 + 0x12);
        puVar22[0x45] = *(undefined2 *)(iVar9 + 0x14);
        puVar22[0x46] = *(undefined2 *)(iVar9 + 0x16);
        puVar22[0x47] = *(undefined2 *)(iVar9 + 0x18);
        puVar22[0x48] = *(undefined2 *)(iVar9 + 0x1a);
        puVar22[0x49] = *(undefined2 *)(iVar9 + 0x1c);
        puVar22[0x4a] = *(undefined2 *)(iVar9 + 0x1e);
        puVar22[0x4b] = *(undefined2 *)(iVar9 + 0x20);
        puVar22[0x4c] = *(undefined2 *)(iVar9 + 0x22);
        puVar22[0x4d] = *(undefined2 *)(iVar9 + 0x24);
        puVar22[0x4e] = *(undefined2 *)(iVar9 + 0x26);
        piVar17[0x37] = 0;
        unaff_r19 = piVar17[0x1e] * 2;
        local_84 = unaff_r19 + 2;
        piVar17[0x36] = 0;
        if ((*(char *)(piVar17 + 0x24) == '\x04') || (*(char *)(piVar17 + 0x24) == '\x05')) {
          puVar22[8] = 1;
        }
        else {
          puVar22[0x5c] = *(undefined2 *)(iVar9 + 4);
          puVar22[0x5b] = *(undefined2 *)(iVar9 + 6);
          puVar22[0x5a] = (ushort)*(byte *)(iVar9 + 3);
          puVar22[8] = 0;
        }
      }
      else {
        puVar22[0x38] = 0;
        puVar22[0x4f] = 0;
        iVar10 = piVar17[0x1f];
        iVar9 = (int)((ulonglong)local_60 * (ulonglong)(piVar17[0x20] + 0xdU) >> 0x20);
        uVar6 = ((piVar17[0x20] + 0xdU) - iVar9 >> 1) + iVar9;
        uVar15 = uVar6 >> 3;
        iVar9 = iVar10 + uVar15 * 6;
        puVar22[0x52] = *(undefined2 *)(iVar9 + 0x28);
        puVar22[0x51] = *(undefined2 *)(iVar9 + 0x2a);
        puVar22[0x50] = (ushort)*(byte *)(iVar9 + 0x2c);
        puVar22[0x5c] = *(undefined2 *)(iVar10 + 4);
        puVar22[0x5b] = *(undefined2 *)(iVar10 + 6);
        puVar22[0x5a] = (ushort)*(byte *)(iVar10 + 3);
        puVar22[0x3f] = *(undefined2 *)(iVar10 + 8);
        puVar22[0x40] = *(undefined2 *)(iVar10 + 10);
        puVar22[0x41] = *(undefined2 *)(iVar10 + 0xc);
        puVar22[0x42] = *(undefined2 *)(iVar10 + 0xe);
        puVar22[0x43] = *(undefined2 *)(iVar10 + 0x10);
        puVar22[0x44] = *(undefined2 *)(iVar10 + 0x12);
        puVar22[0x45] = *(undefined2 *)(iVar10 + 0x14);
        puVar22[0x46] = *(undefined2 *)(iVar10 + 0x16);
        puVar22[0x47] = *(undefined2 *)(iVar10 + 0x18);
        puVar22[0x48] = *(undefined2 *)(iVar10 + 0x1a);
        puVar22[0x49] = *(undefined2 *)(iVar10 + 0x1c);
        puVar22[0x4a] = *(undefined2 *)(iVar10 + 0x1e);
        puVar22[0x4b] = *(undefined2 *)(iVar10 + 0x20);
        puVar22[0x4c] = *(undefined2 *)(iVar10 + 0x22);
        puVar22[0x4d] = *(undefined2 *)(iVar10 + 0x24);
        puVar22[0x4e] = *(undefined2 *)(iVar10 + 0x26);
        unaff_r19 = piVar17[0x1e] * 2;
        piVar17[0x36] = uVar15 * 0xe;
        local_84 = unaff_r19 + (uVar6 * 2 & 0xfffffff0) + 2;
        piVar17[0x37] = 0;
      }
    }
    else if (bVar11 < 6) {
      if (3 < bVar11) goto LAB_8027d1d8;
      puVar22[0x38] = 0x19;
      puVar22[0x4f] = 0x100;
      puVar22[0x3f] = 0;
      puVar22[0x40] = 0;
      puVar22[0x41] = 0;
      puVar22[0x42] = 0;
      puVar22[0x43] = 0;
      puVar22[0x44] = 0;
      puVar22[0x45] = 0;
      puVar22[0x46] = 0;
      puVar22[0x47] = 0;
      puVar22[0x48] = 0;
      puVar22[0x49] = 0;
      puVar22[0x4a] = 0;
      puVar22[0x4b] = 0;
      puVar22[0x4c] = 0;
      puVar22[0x4d] = 0;
      puVar22[0x4e] = 0;
      unaff_r19 = piVar17[0x1e];
      piVar17[0x36] = piVar17[0x20];
      local_84 = piVar17[0x20] + unaff_r19;
      piVar17[0x37] = 0;
    }
    puVar22[0x3d] = (short)((uint)local_84 >> 0x10);
    puVar22[0x3e] = (short)local_84;
    piVar17[8] = local_84;
    if (piVar17[0x23] == 0) {
      puVar22[0x37] = 0;
      bVar11 = *(byte *)(piVar17 + 0x24);
      if (bVar11 == 3) {
        local_90 = DAT_803def90;
        unaff_r18 = unaff_r19 + piVar17[0x21];
      }
      else if (bVar11 < 3) {
        if (bVar11 < 2) {
LAB_8027d664:
          uVar6 = piVar17[0x21];
          iVar9 = (int)((ulonglong)local_60 * (ulonglong)uVar6 >> 0x20);
          uVar15 = (uVar6 - iVar9 >> 1) + iVar9;
          local_90 = DAT_803def90 * 2 + 2;
          unaff_r18 = unaff_r19 + (uVar15 * 2 & 0xfffffff0) + 2 + uVar6 + (uVar15 >> 3) * -0xe;
        }
        else {
          local_90 = DAT_803def90 >> 1;
          unaff_r18 = unaff_r19 + piVar17[0x21];
        }
      }
      else if (bVar11 < 6) goto LAB_8027d664;
      puVar22[0x39] = (short)(local_90 >> 0x10);
      puVar22[0x3a] = (short)local_90;
      puVar22[0x3b] = (short)((uint)unaff_r18 >> 0x10);
      puVar22[0x3c] = (short)unaff_r18;
    }
    else {
      puVar22[0x37] = 1;
      bVar11 = *(byte *)(piVar17 + 0x24);
      if (bVar11 == 4) {
LAB_8027d528:
        uVar6 = piVar17[0x22];
        uVar5 = uVar6 + piVar17[0x23] + -1;
        iVar9 = (int)((ulonglong)local_60 * (ulonglong)uVar6 >> 0x20);
        iVar10 = (int)((ulonglong)local_60 * (ulonglong)uVar5 >> 0x20);
        uVar15 = (uVar6 - iVar9 >> 1) + iVar9;
        uVar13 = (uVar5 - iVar10 >> 1) + iVar10;
        iVar9 = unaff_r19 + (uVar15 * 2 & 0xfffffff0) + 2 + uVar6 + (uVar15 >> 3) * -0xe;
        iVar10 = unaff_r19 + (uVar13 * 2 & 0xfffffff0) + 2 + uVar5 + (uVar13 >> 3) * -0xe;
      }
      else {
        if (bVar11 < 4) {
          if (bVar11 < 2) goto LAB_8027d528;
        }
        else if (bVar11 < 6) {
          uVar15 = piVar17[0x22] + piVar17[0x23] + -1;
          *(undefined *)(piVar17 + 0x27) = 0;
          iVar9 = (int)((ulonglong)local_60 * (ulonglong)uVar15 >> 0x20);
          uVar6 = (uVar15 - iVar9 >> 1) + iVar9;
          iVar9 = piVar17[0x25] * 2 + 2;
          iVar10 = unaff_r19 + (uVar6 * 2 & 0xfffffff0) + 2 + uVar15 + (uVar6 >> 3) * -0xe;
          goto LAB_8027d60c;
        }
        iVar9 = unaff_r19 + piVar17[0x22];
        iVar10 = piVar17[0x23] + iVar9 + -1;
      }
LAB_8027d60c:
      puVar22[0x39] = (short)((uint)iVar9 >> 0x10);
      puVar22[0x3a] = (short)iVar9;
      puVar22[0x3b] = (short)((uint)iVar10 >> 0x10);
      puVar22[0x3c] = (short)iVar10;
      puVar22[0x5d] = 0;
    }
    puVar22[4] = *(undefined2 *)(piVar17 + 0x33);
    puVar22[5] = *(undefined2 *)((int)piVar17 + 0xce);
    uVar15 = (uint)*(byte *)(piVar17 + 0x35);
    puVar22[7] = (ushort)(uVar15 == 0);
    *(undefined2 *)((int)piVar17 + 0x5e) = *(undefined2 *)(piVar17 + 0x13);
    puVar22[9] = *(undefined2 *)(piVar17 + 0x13);
    *(undefined2 *)(piVar17 + 0x18) = *(undefined2 *)((int)piVar17 + 0x4e);
    puVar22[0xb] = *(undefined2 *)((int)piVar17 + 0x4e);
    *(undefined2 *)((int)piVar17 + 0x62) = *(undefined2 *)(piVar17 + 0x14);
    puVar22[0x17] = *(undefined2 *)(piVar17 + 0x14);
    *(undefined2 *)(piVar17 + 0x19) = *(undefined2 *)((int)piVar17 + 0x52);
    puVar22[0xd] = *(undefined2 *)((int)piVar17 + 0x52);
    *(undefined2 *)((int)piVar17 + 0x66) = *(undefined2 *)(piVar17 + 0x15);
    puVar22[0xf] = *(undefined2 *)(piVar17 + 0x15);
    *(undefined2 *)(piVar17 + 0x1a) = *(undefined2 *)((int)piVar17 + 0x56);
    puVar22[0x19] = *(undefined2 *)((int)piVar17 + 0x56);
    puVar22[6] = (ushort)(puVar22[0x19] != 0 || (puVar22[0xd] != 0 || puVar22[0xf] != 0));
    *(undefined2 *)((int)piVar17 + 0x6a) = *(undefined2 *)(piVar17 + 0x16);
    puVar22[0x11] = *(undefined2 *)(piVar17 + 0x16);
    *(undefined2 *)(piVar17 + 0x1b) = *(undefined2 *)((int)piVar17 + 0x5a);
    puVar22[0x13] = *(undefined2 *)((int)piVar17 + 0x5a);
    *(undefined2 *)((int)piVar17 + 0x6e) = *(undefined2 *)(piVar17 + 0x17);
    puVar22[0x15] = *(undefined2 *)(piVar17 + 0x17);
    puVar22[10] = 0;
    puVar22[0xc] = 0;
    puVar22[0x18] = 0;
    puVar22[0xe] = 0;
    puVar22[0x10] = 0;
    puVar22[0x1a] = 0;
    puVar22[0x12] = 0;
    puVar22[0x14] = 0;
    puVar22[0x16] = 0;
    if (puVar14[0x15] == 0) {
      if (puVar22[0x15] != 0 || (puVar22[0x11] != 0 || puVar22[0x13] != 0)) {
        puVar22[6] = puVar22[6] | 2;
      }
      if (puVar22[0x15] != 0 || (puVar22[0x17] != 0 || puVar22[0x19] != 0)) {
        puVar22[6] = puVar22[6] | 4;
      }
    }
    else if (puVar22[0x19] != 0 || (puVar22[0x11] != 0 || puVar22[0x13] != 0)) {
      puVar22[6] = puVar22[6] | 0x10;
    }
    *(undefined *)(piVar17 + 0x3b) = 2;
    local_88 = 1;
LAB_8027e080:
    if ((piVar17[uVar15 + 9] & 0x40U) != 0) {
      FUN_8027b1b4((byte *)(piVar17 + 0x29));
    }
    if ((piVar17[uVar15 + 9] & 8U) != 0) {
      puVar22[0x53] = (short)((uint)piVar17[uVar15 + 0xe] >> 0x10);
      puVar22[0x54] = (short)piVar17[uVar15 + 0xe];
      piVar17[0x38] = piVar17[uVar15 + 0xe];
    }
    iVar9 = FUN_8027b1f8((char *)(piVar17 + 0x29),puVar22 + 0x32,puVar22 + 0x33);
    sVar4 = puVar22[0x33];
    local_6c = puVar22 + 0x23;
    puVar22[0x22] = 0;
    puVar22[0x23] = 0;
    local_70 = puVar22 + 0x24;
    local_74 = puVar22 + 0x25;
    puVar22[0x24] = 0;
    local_78 = puVar22 + 0x26;
    puVar22[0x25] = 0;
    puVar22[0x26] = 0;
    puVar23 = (undefined2 *)piVar17[1];
    if (uVar15 != 0) {
      *puVar23 = 7;
      puVar23[1] = 1;
      puVar23 = puVar23 + 2;
      puVar22[uVar15 + 0x22] = puVar22[uVar15 + 0x22] + 1;
    }
    if (piVar17[0x23] == 0) {
      if (*(short *)(*piVar17 + 8) == 2) {
        uVar6 = 0x200000;
      }
      else {
        uVar6 = piVar17[0x38] << 5;
      }
      uVar5 = piVar17[0x37];
      piVar17[0x37] = uVar5 + uVar6 * 0x10000;
      if ((uint)piVar17[0x37] < uVar5) {
        piVar17[0x36] = (uVar6 >> 0x10) + piVar17[0x36] + 1;
      }
      else {
        piVar17[0x36] = piVar17[0x36] + (uVar6 >> 0x10);
      }
    }
    uVar15 = uVar15 + 1;
    uVar6 = uVar15 * 2 & 0x1fe;
    puVar20 = (ushort *)((int)local_a0 + uVar6);
    iVar21 = (int)puVar22 + uVar6;
    iVar10 = (int)piVar17 + (uVar15 * 4 & 0x3fc);
    for (uVar15 = uVar15 & 0xff; (uVar15 & 0xff) < 5; uVar15 = uVar15 + 1) {
      if (iVar9 != 0) {
        *puVar23 = 7;
        puVar23[1] = 0;
        puVar23 = puVar23 + 2;
        puVar22[(uVar15 & 0xff) + 0x22] = puVar22[(uVar15 & 0xff) + 0x22] + 1;
        FUN_8027f63c((int)piVar17,0);
        FUN_8027f724((int)piVar17);
        break;
      }
      if (*puVar20 != 0) {
        puVar7 = &DAT_802c2e78;
        for (bVar11 = 0; bVar11 < 9; bVar11 = bVar11 + 1) {
          if ((1 << (uint)bVar11 & (uint)*puVar20) != 0) {
            *puVar23 = *puVar7;
            puVar23[1] = 0;
            puVar23 = puVar23 + 2;
            *(short *)(iVar21 + 0x44) = *(short *)(iVar21 + 0x44) + 1;
          }
          puVar7 = puVar7 + 1;
        }
      }
      if ((*(uint *)(iVar10 + 0x24) & 0x20) == 0) {
        if (*(char *)((int)piVar17 + 0xed) == '\0') {
          if ((*(uint *)(iVar10 + 0x24) & 0x40) != 0) {
            FUN_8027b1b4((byte *)(piVar17 + 0x29));
          }
          if ((*(uint *)(iVar10 + 0x24) & 8) != 0) {
            *puVar23 = 0x53;
            puVar23[1] = (short)((uint)*(undefined4 *)(iVar10 + 0x38) >> 0x10);
            puVar23[2] = 0x54;
            puVar23[3] = (short)*(undefined4 *)(iVar10 + 0x38);
            puVar23 = puVar23 + 4;
            *(short *)(iVar21 + 0x44) = *(short *)(iVar21 + 0x44) + 2;
            piVar17[0x38] = *(int *)(iVar10 + 0x38);
          }
        }
      }
      else {
        FUN_8027b060((char *)(piVar17 + 0x29),10);
        *(undefined *)((int)piVar17 + 0xed) = 1;
      }
      iVar18 = piVar17[0x2d];
      iVar9 = FUN_8027b1f8((char *)(piVar17 + 0x29),local_a6,&local_a8);
      if (sVar4 == local_a8) {
        if (iVar18 != 0) {
          *puVar23 = 0x32;
          puVar23[1] = local_a6[0];
          puVar23 = puVar23 + 2;
          *(short *)(iVar21 + 0x44) = *(short *)(iVar21 + 0x44) + 1;
        }
      }
      else {
        *puVar23 = 0x32;
        puVar23[1] = local_a6[0];
        puVar23[2] = 0x33;
        puVar23[3] = local_a8;
        puVar23 = puVar23 + 4;
        *(short *)(iVar21 + 0x44) = *(short *)(iVar21 + 0x44) + 2;
        sVar4 = local_a8;
      }
      if (piVar17[0x23] == 0) {
        if (*(short *)(*piVar17 + 8) == 2) {
          uVar6 = 0x200000;
        }
        else {
          uVar6 = piVar17[0x38] << 5;
        }
        uVar5 = piVar17[0x37];
        piVar17[0x37] = uVar5 + uVar6 * 0x10000;
        if ((uint)piVar17[0x37] < uVar5) {
          piVar17[0x36] = (uVar6 >> 0x10) + piVar17[0x36] + 1;
        }
        else {
          piVar17[0x36] = piVar17[0x36] + (uVar6 >> 0x10);
        }
      }
      puVar20 = puVar20 + 1;
      iVar21 = iVar21 + 2;
      iVar10 = iVar10 + 4;
    }
    if (iVar9 != 0) {
      FUN_8027f63c((int)piVar17,0);
      FUN_8027f724((int)piVar17);
    }
    FUN_80242178(piVar17[1],(int)puVar23 - piVar17[1]);
    if ((ushort)puVar22[0x53] < 2) {
      uVar1 = *(ushort *)(local_58 + (uint)(ushort)puVar22[4] * 2 + (uint)(ushort)puVar22[0x53] * 6)
      ;
    }
    else {
      uVar1 = *(ushort *)(local_58 + (uint)(ushort)puVar22[4] * 2 + 0xc);
    }
    uVar16 = *(ushort *)(local_5c + (uint)(ushort)puVar22[6] * 2) + uVar16 + 0x4fe + (uint)uVar1 +
             (uint)(ushort)puVar22[0x22] * 4 + (uint)*local_6c * 4 + (uint)*local_70 * 4 +
             (uint)*local_74 * 4 + (uint)*local_78 * 4;
    if (uVar16 <= local_54) {
      uVar2 = (undefined2)((uint)puVar22 >> 0x10);
      if (local_4c == (undefined2 *)0x0) {
        if (DAT_803defa4 + -4 < DAT_803defa8 + 3) {
          *DAT_803defa8 = 0xd;
          DAT_803defa8[1] = (short)((uint)DAT_803defa4 >> 0x10);
          DAT_803defa8[2] = (short)DAT_803defa4;
          uVar1 = ((short)DAT_803defa8 - (short)DAT_803defa0) + 0xbU & 0xfffc;
          uVar3 = uVar1;
          if (DAT_803def94 != (undefined2 *)0x0) {
            DAT_803def94[3] = uVar1;
            FUN_80242178((uint)DAT_803def98,(uint)DAT_803def9c);
            uVar3 = DAT_803defac;
          }
          DAT_803defac = uVar3;
          DAT_803def94 = DAT_803defa8;
          DAT_803defa8 = DAT_803defa4;
          DAT_803def98 = DAT_803defa0;
          DAT_803defa0 = DAT_803defa4;
          DAT_803def9c = uVar1;
          DAT_803defa4 = DAT_803defa4 + 0xc0;
        }
        *DAT_803defa8 = 2;
        local_8c = 1;
        DAT_803defa8[1] = uVar2;
        DAT_803defa8[2] = (short)puVar22;
        DAT_803defa8 = DAT_803defa8 + 3;
        local_4c = puVar22;
      }
      else {
        *local_4c = uVar2;
        local_4c[1] = (short)puVar22;
        local_8c = 1;
        FUN_80242148((uint)local_4c,0xbc);
        local_4c = puVar22;
      }
      goto LAB_8027e754;
    }
    if ((local_88 == 0) && (iVar9 == 0)) {
      FUN_8027c83c((int)puVar14,piVar17);
    }
    FUN_8027f724((int)piVar17);
    FUN_8027f63c((int)piVar17,1);
    puVar8 = local_7c + iVar12 + 0x177;
    while (iVar12 = iVar12 + -1, 0 < iVar12) {
      if (*(char *)((int *)puVar8[-1] + 0x3b) == '\x02') {
        FUN_8027c83c((int)puVar14,(int *)puVar8[-1]);
      }
      FUN_8027f724(puVar8[-1]);
      FUN_8027f63c(puVar8[-1],1);
      puVar8 = puVar8 + -1;
    }
    uVar15 = local_80 + 1 & 0xff;
    puVar8 = local_7c + uVar15 * 0x2f;
    for (; (uVar15 & 0xff) < (uint)DAT_803deffc; uVar15 = uVar15 + 1) {
      if (*(char *)(puVar8 + 0x14) == '\x01') {
        piVar17 = (int *)puVar8[0x12];
        while (piVar17 != (int *)0x0) {
          piVar19 = (int *)piVar17[3];
          if (*(char *)(piVar17 + 0x3b) == '\x02') {
            FUN_8027c83c((int)puVar8,piVar17);
          }
          FUN_8027f724((int)piVar17);
          FUN_8027f63c((int)piVar17,1);
          piVar17 = piVar19;
        }
      }
      puVar8 = puVar8 + 0x2f;
    }
  }
  if (local_8c != 0) {
    if (DAT_803defa4 + -4 < DAT_803defa8 + 1) {
      *DAT_803defa8 = 0xd;
      DAT_803defa8[1] = (short)((uint)DAT_803defa4 >> 0x10);
      DAT_803defa8[2] = (short)DAT_803defa4;
      uVar1 = ((short)DAT_803defa8 - (short)DAT_803defa0) + 0xbU & 0xfffc;
      uVar3 = uVar1;
      if (DAT_803def94 != (undefined2 *)0x0) {
        DAT_803def94[3] = uVar1;
        FUN_80242178((uint)DAT_803def98,(uint)DAT_803def9c);
        uVar3 = DAT_803defac;
      }
      DAT_803defac = uVar3;
      DAT_803def94 = DAT_803defa8;
      DAT_803defa8 = DAT_803defa4;
      DAT_803def98 = DAT_803defa0;
      DAT_803defa0 = DAT_803defa4;
      DAT_803def9c = uVar1;
      DAT_803defa4 = DAT_803defa4 + 0xc0;
    }
    puVar22 = DAT_803defa8 + 1;
    *DAT_803defa8 = 3;
    DAT_803defa8 = puVar22;
  }
  if (local_4c != (undefined2 *)0x0) {
    *local_4c = 0;
    local_4c[1] = 0;
    FUN_80242148((uint)local_4c,0xbc);
  }
  iVar9 = (int)((ulonglong)((longlong)local_50 * (longlong)(int)(DAT_803deffe + 1)) >> 0x20);
  uVar15 = DAT_803deffe + 1 + (iVar9 - (iVar9 >> 0x1f)) * -3 & 0xff;
  if (puVar14[0x2b] != 0) {
    if (DAT_803defa4 + -4 < DAT_803defa8 + 5) {
      *DAT_803defa8 = 0xd;
      DAT_803defa8[1] = (short)((uint)DAT_803defa4 >> 0x10);
      DAT_803defa8[2] = (short)DAT_803defa4;
      uVar1 = ((short)DAT_803defa8 - (short)DAT_803defa0) + 0xbU & 0xfffc;
      uVar3 = uVar1;
      if (DAT_803def94 != (undefined2 *)0x0) {
        DAT_803def94[3] = uVar1;
        FUN_80242178((uint)DAT_803def98,(uint)DAT_803def9c);
        uVar3 = DAT_803defac;
      }
      DAT_803defac = uVar3;
      DAT_803def94 = DAT_803defa8;
      DAT_803defa8 = DAT_803defa4;
      DAT_803def98 = DAT_803defa0;
      DAT_803defa0 = DAT_803defa4;
      DAT_803def9c = uVar1;
      DAT_803defa4 = DAT_803defa4 + 0xc0;
    }
    *DAT_803defa8 = 4;
    DAT_803defa8[1] = (short)((uint)puVar14[DAT_803deffe + 0xc] >> 0x10);
    DAT_803defa8[2] = (short)puVar14[DAT_803deffe + 0xc];
    DAT_803defa8[3] = (short)((uint)puVar14[uVar15 + 0xc] >> 0x10);
    DAT_803defa8[4] = (short)puVar14[uVar15 + 0xc];
    DAT_803defa8 = DAT_803defa8 + 5;
  }
  if (puVar14[0x15] == 0) {
    if (puVar14[0x2c] != 0) {
      if (DAT_803defa4 + -4 < DAT_803defa8 + 5) {
        *DAT_803defa8 = 0xd;
        DAT_803defa8[1] = (short)((uint)DAT_803defa4 >> 0x10);
        DAT_803defa8[2] = (short)DAT_803defa4;
        uVar1 = ((short)DAT_803defa8 - (short)DAT_803defa0) + 0xbU & 0xfffc;
        uVar3 = uVar1;
        if (DAT_803def94 != (undefined2 *)0x0) {
          DAT_803def94[3] = uVar1;
          FUN_80242178((uint)DAT_803def98,(uint)DAT_803def9c);
          uVar3 = DAT_803defac;
        }
        DAT_803defac = uVar3;
        DAT_803def94 = DAT_803defa8;
        DAT_803defa8 = DAT_803defa4;
        DAT_803def98 = DAT_803defa0;
        DAT_803defa0 = DAT_803defa4;
        DAT_803def9c = uVar1;
        DAT_803defa4 = DAT_803defa4 + 0xc0;
      }
      *DAT_803defa8 = 5;
      DAT_803defa8[1] = (short)((uint)puVar14[DAT_803deffe + 0xf] >> 0x10);
      DAT_803defa8[2] = (short)puVar14[DAT_803deffe + 0xf];
      DAT_803defa8[3] = (short)((uint)puVar14[uVar15 + 0xf] >> 0x10);
      DAT_803defa8[4] = (short)puVar14[uVar15 + 0xf];
      DAT_803defa8 = DAT_803defa8 + 5;
    }
  }
  else {
    if (DAT_803defa4 + -4 < DAT_803defa8 + 5) {
      *DAT_803defa8 = 0xd;
      DAT_803defa8[1] = (short)((uint)DAT_803defa4 >> 0x10);
      DAT_803defa8[2] = (short)DAT_803defa4;
      uVar1 = ((short)DAT_803defa8 - (short)DAT_803defa0) + 0xbU & 0xfffc;
      uVar3 = uVar1;
      if (DAT_803def94 != (undefined2 *)0x0) {
        DAT_803def94[3] = uVar1;
        FUN_80242178((uint)DAT_803def98,(uint)DAT_803def9c);
        uVar3 = DAT_803defac;
      }
      DAT_803defac = uVar3;
      DAT_803def94 = DAT_803defa8;
      DAT_803defa8 = DAT_803defa4;
      DAT_803def98 = DAT_803defa0;
      DAT_803defa0 = DAT_803defa4;
      DAT_803def9c = uVar1;
      DAT_803defa4 = DAT_803defa4 + 0xc0;
    }
    *DAT_803defa8 = 0x10;
    DAT_803defa8[1] = (short)((uint)puVar14[DAT_803defff + 0xf] >> 0x10);
    DAT_803defa8[2] = (short)puVar14[DAT_803defff + 0xf];
    DAT_803defa8[3] = (short)((uint)puVar14[(DAT_803defff ^ 1) + 0xf] >> 0x10);
    DAT_803defa8[4] = (short)puVar14[(DAT_803defff ^ 1) + 0xf];
    DAT_803defa8 = DAT_803defa8 + 5;
  }
  if (DAT_803defa4 + -4 < DAT_803defa8 + 3) {
    *DAT_803defa8 = 0xd;
    DAT_803defa8[1] = (short)((uint)DAT_803defa4 >> 0x10);
    DAT_803defa8[2] = (short)DAT_803defa4;
    uVar1 = ((short)DAT_803defa8 - (short)DAT_803defa0) + 0xbU & 0xfffc;
    uVar3 = uVar1;
    if (DAT_803def94 != (undefined2 *)0x0) {
      DAT_803def94[3] = uVar1;
      FUN_80242178((uint)DAT_803def98,(uint)DAT_803def9c);
      uVar3 = DAT_803defac;
    }
    DAT_803defac = uVar3;
    DAT_803def94 = DAT_803defa8;
    DAT_803defa8 = DAT_803defa4;
    DAT_803def98 = DAT_803defa0;
    DAT_803defa0 = DAT_803defa4;
    DAT_803def9c = uVar1;
    DAT_803defa4 = DAT_803defa4 + 0xc0;
  }
  *DAT_803defa8 = 6;
  DAT_803defa8[1] = (short)((uint)puVar14[DAT_803defff + 10] >> 0x10);
  DAT_803defa8[2] = (short)puVar14[DAT_803defff + 10];
  DAT_803defa8 = DAT_803defa8 + 3;
  iVar9 = puVar14[1];
  puVar8 = (undefined4 *)*puVar14;
  if (iVar9 < -0x9f) {
    if (iVar9 < -0xc7f) {
      sVar4 = 0x14;
    }
    else {
      iVar9 = -iVar9 / 0xa0 + (-iVar9 >> 0x1f);
      sVar4 = (short)iVar9 - (short)(iVar9 >> 0x1f);
    }
    *(short *)(puVar8 + 1) = sVar4;
  }
  else if (iVar9 < 0xa0) {
    *(undefined2 *)(puVar8 + 1) = 0;
  }
  else {
    if (iVar9 < 0xc80) {
      iVar9 = -iVar9 / 0xa0 + (-iVar9 >> 0x1f);
      sVar4 = (short)iVar9 - (short)(iVar9 >> 0x1f);
    }
    else {
      sVar4 = -0x14;
    }
    *(short *)(puVar8 + 1) = sVar4;
  }
  *puVar8 = puVar14[1];
  puVar14[1] = puVar14[1] + *(short *)(puVar8 + 1) * 0xa0;
  iVar9 = puVar14[2];
  if (iVar9 < -0x9f) {
    if (iVar9 < -0xc7f) {
      sVar4 = 0x14;
    }
    else {
      iVar9 = -iVar9 / 0xa0 + (-iVar9 >> 0x1f);
      sVar4 = (short)iVar9 - (short)(iVar9 >> 0x1f);
    }
    *(short *)((int)puVar8 + 10) = sVar4;
  }
  else if (iVar9 < 0xa0) {
    *(undefined2 *)((int)puVar8 + 10) = 0;
  }
  else {
    if (iVar9 < 0xc80) {
      iVar9 = -iVar9 / 0xa0 + (-iVar9 >> 0x1f);
      sVar4 = (short)iVar9 - (short)(iVar9 >> 0x1f);
    }
    else {
      sVar4 = -0x14;
    }
    *(short *)((int)puVar8 + 10) = sVar4;
  }
  *(undefined4 *)((int)puVar8 + 6) = puVar14[2];
  puVar14[2] = puVar14[2] + *(short *)((int)puVar8 + 10) * 0xa0;
  iVar9 = puVar14[3];
  if (iVar9 < -0x9f) {
    if (iVar9 < -0xc7f) {
      sVar4 = 0x14;
    }
    else {
      iVar9 = -iVar9 / 0xa0 + (-iVar9 >> 0x1f);
      sVar4 = (short)iVar9 - (short)(iVar9 >> 0x1f);
    }
    *(short *)(puVar8 + 4) = sVar4;
  }
  else if (iVar9 < 0xa0) {
    *(undefined2 *)(puVar8 + 4) = 0;
  }
  else {
    if (iVar9 < 0xc80) {
      iVar9 = -iVar9 / 0xa0 + (-iVar9 >> 0x1f);
      sVar4 = (short)iVar9 - (short)(iVar9 >> 0x1f);
    }
    else {
      sVar4 = -0x14;
    }
    *(short *)(puVar8 + 4) = sVar4;
  }
  puVar8[3] = puVar14[3];
  puVar14[3] = puVar14[3] + *(short *)(puVar8 + 4) * 0xa0;
  iVar9 = puVar14[4];
  if (iVar9 < -0x9f) {
    if (iVar9 < -0xc7f) {
      sVar4 = 0x14;
    }
    else {
      iVar9 = -iVar9 / 0xa0 + (-iVar9 >> 0x1f);
      sVar4 = (short)iVar9 - (short)(iVar9 >> 0x1f);
    }
    *(short *)((int)puVar8 + 0x16) = sVar4;
  }
  else if (iVar9 < 0xa0) {
    *(undefined2 *)((int)puVar8 + 0x16) = 0;
  }
  else {
    if (iVar9 < 0xc80) {
      iVar9 = -iVar9 / 0xa0 + (-iVar9 >> 0x1f);
      sVar4 = (short)iVar9 - (short)(iVar9 >> 0x1f);
    }
    else {
      sVar4 = -0x14;
    }
    *(short *)((int)puVar8 + 0x16) = sVar4;
  }
  *(undefined4 *)((int)puVar8 + 0x12) = puVar14[4];
  puVar14[4] = puVar14[4] + *(short *)((int)puVar8 + 0x16) * 0xa0;
  iVar9 = puVar14[5];
  if (iVar9 < -0x9f) {
    if (iVar9 < -0xc7f) {
      sVar4 = 0x14;
    }
    else {
      iVar9 = -iVar9 / 0xa0 + (-iVar9 >> 0x1f);
      sVar4 = (short)iVar9 - (short)(iVar9 >> 0x1f);
    }
    *(short *)(puVar8 + 7) = sVar4;
  }
  else if (iVar9 < 0xa0) {
    *(undefined2 *)(puVar8 + 7) = 0;
  }
  else {
    if (iVar9 < 0xc80) {
      iVar9 = -iVar9 / 0xa0 + (-iVar9 >> 0x1f);
      sVar4 = (short)iVar9 - (short)(iVar9 >> 0x1f);
    }
    else {
      sVar4 = -0x14;
    }
    *(short *)(puVar8 + 7) = sVar4;
  }
  puVar8[6] = puVar14[5];
  puVar14[5] = puVar14[5] + *(short *)(puVar8 + 7) * 0xa0;
  iVar9 = puVar14[6];
  if (iVar9 < -0x9f) {
    if (iVar9 < -0xc7f) {
      sVar4 = 0x14;
    }
    else {
      iVar9 = -iVar9 / 0xa0 + (-iVar9 >> 0x1f);
      sVar4 = (short)iVar9 - (short)(iVar9 >> 0x1f);
    }
    *(short *)((int)puVar8 + 0x22) = sVar4;
  }
  else if (iVar9 < 0xa0) {
    *(undefined2 *)((int)puVar8 + 0x22) = 0;
  }
  else {
    if (iVar9 < 0xc80) {
      iVar9 = -iVar9 / 0xa0 + (-iVar9 >> 0x1f);
      sVar4 = (short)iVar9 - (short)(iVar9 >> 0x1f);
    }
    else {
      sVar4 = -0x14;
    }
    *(short *)((int)puVar8 + 0x22) = sVar4;
  }
  *(undefined4 *)((int)puVar8 + 0x1e) = puVar14[6];
  puVar14[6] = puVar14[6] + *(short *)((int)puVar8 + 0x22) * 0xa0;
  iVar9 = puVar14[7];
  if (iVar9 < -0x9f) {
    if (iVar9 < -0xc7f) {
      sVar4 = 0x14;
    }
    else {
      iVar9 = -iVar9 / 0xa0 + (-iVar9 >> 0x1f);
      sVar4 = (short)iVar9 - (short)(iVar9 >> 0x1f);
    }
    *(short *)(puVar8 + 10) = sVar4;
  }
  else if (iVar9 < 0xa0) {
    *(undefined2 *)(puVar8 + 10) = 0;
  }
  else {
    if (iVar9 < 0xc80) {
      iVar9 = -iVar9 / 0xa0 + (-iVar9 >> 0x1f);
      sVar4 = (short)iVar9 - (short)(iVar9 >> 0x1f);
    }
    else {
      sVar4 = -0x14;
    }
    *(short *)(puVar8 + 10) = sVar4;
  }
  puVar8[9] = puVar14[7];
  puVar14[7] = puVar14[7] + *(short *)(puVar8 + 10) * 0xa0;
  iVar9 = puVar14[8];
  if (iVar9 < -0x9f) {
    if (iVar9 < -0xc7f) {
      sVar4 = 0x14;
    }
    else {
      iVar9 = -iVar9 / 0xa0 + (-iVar9 >> 0x1f);
      sVar4 = (short)iVar9 - (short)(iVar9 >> 0x1f);
    }
    *(short *)((int)puVar8 + 0x2e) = sVar4;
  }
  else if (iVar9 < 0xa0) {
    *(undefined2 *)((int)puVar8 + 0x2e) = 0;
  }
  else {
    if (iVar9 < 0xc80) {
      iVar9 = -iVar9 / 0xa0 + (-iVar9 >> 0x1f);
      sVar4 = (short)iVar9 - (short)(iVar9 >> 0x1f);
    }
    else {
      sVar4 = -0x14;
    }
    *(short *)((int)puVar8 + 0x2e) = sVar4;
  }
  *(undefined4 *)((int)puVar8 + 0x2a) = puVar14[8];
  puVar14[8] = puVar14[8] + *(short *)((int)puVar8 + 0x2e) * 0xa0;
  iVar9 = puVar14[9];
  if (iVar9 < -0x9f) {
    if (iVar9 < -0xc7f) {
      sVar4 = 0x14;
    }
    else {
      iVar9 = -iVar9 / 0xa0 + (-iVar9 >> 0x1f);
      sVar4 = (short)iVar9 - (short)(iVar9 >> 0x1f);
    }
    *(short *)(puVar8 + 0xd) = sVar4;
  }
  else if (iVar9 < 0xa0) {
    *(undefined2 *)(puVar8 + 0xd) = 0;
  }
  else {
    if (iVar9 < 0xc80) {
      iVar9 = -iVar9 / 0xa0 + (-iVar9 >> 0x1f);
      sVar4 = (short)iVar9 - (short)(iVar9 >> 0x1f);
    }
    else {
      sVar4 = -0x14;
    }
    *(short *)(puVar8 + 0xd) = sVar4;
  }
  puVar8[0xc] = puVar14[9];
  puVar14[9] = puVar14[9] + *(short *)(puVar8 + 0xd) * 0xa0;
  FUN_80242148((uint)puVar8,0x36);
  goto LAB_8027f2a0;
LAB_8027e754:
  iVar12 = iVar12 + -1;
  local_68 = local_68 + -1;
  goto LAB_8027e764;
}

