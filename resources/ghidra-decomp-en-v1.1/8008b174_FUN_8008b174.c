// Function: FUN_8008b174
// Entry: 8008b174
// Size: 2100 bytes

/* WARNING: Removing unreachable block (ram,0x8008b988) */
/* WARNING: Removing unreachable block (ram,0x8008b980) */
/* WARNING: Removing unreachable block (ram,0x8008b18c) */
/* WARNING: Removing unreachable block (ram,0x8008b184) */

void FUN_8008b174(void)

{
  int iVar1;
  undefined4 uVar2;
  undefined2 *puVar3;
  undefined4 extraout_r4;
  undefined4 extraout_r4_00;
  uint uVar4;
  undefined4 in_r6;
  int iVar5;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar6;
  double dVar7;
  undefined8 uVar8;
  double dVar9;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  double dVar10;
  uint3 local_e8;
  undefined4 local_e4;
  undefined4 local_e0;
  uint uStack_dc;
  undefined4 local_d8;
  uint uStack_d4;
  longlong local_d0;
  undefined4 local_c8;
  uint uStack_c4;
  undefined4 local_c0;
  uint uStack_bc;
  longlong local_b8;
  undefined4 local_b0;
  uint uStack_ac;
  undefined4 local_a8;
  uint uStack_a4;
  longlong local_a0;
  undefined4 local_98;
  uint uStack_94;
  undefined4 local_90;
  uint uStack_8c;
  longlong local_88;
  undefined4 local_80;
  uint uStack_7c;
  undefined4 local_78;
  uint uStack_74;
  longlong local_70;
  undefined4 local_68;
  uint uStack_64;
  undefined4 local_60;
  uint uStack_5c;
  longlong local_58;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  
  local_e4 = DAT_803e90d8;
  if ((DAT_803dddac != (undefined4 *)0x0) &&
     ((iVar1 = FUN_8002bac4(), iVar1 == 0 ||
      ((iVar1 = FUN_8005b128(), iVar1 != 0x30 && (iVar1 != 0x2b)))))) {
    dVar7 = (double)((float)DAT_803dddac[0x83] / FLOAT_803dfcf8);
    dVar9 = (double)FLOAT_803dfcd8;
    if ((dVar9 <= dVar7) && (dVar9 = dVar7, (double)FLOAT_803dfcdc < dVar7)) {
      dVar9 = (double)FLOAT_803dfcdc;
    }
    dVar7 = (double)FLOAT_803dfcd8;
    if ((dVar9 < dVar7) || ((double)FLOAT_803dfd48 <= dVar9)) {
      dVar10 = (double)FLOAT_803dfd48;
      if ((dVar9 < dVar10) || ((double)FLOAT_803dfcfc <= dVar9)) {
        if ((dVar9 < (double)FLOAT_803dfcfc) || ((double)FLOAT_803dfd4c <= dVar9)) {
          if ((dVar9 < (double)FLOAT_803dfd4c) || ((double)FLOAT_803dfce8 <= dVar9)) {
            if ((dVar9 < (double)FLOAT_803dfce8) || ((double)FLOAT_803dfd50 <= dVar9)) {
              if ((dVar9 < (double)FLOAT_803dfd50) || ((double)FLOAT_803dfd00 <= dVar9)) {
                if ((dVar9 < (double)FLOAT_803dfd00) || ((double)FLOAT_803dfd54 <= dVar9)) {
                  if (((double)FLOAT_803dfd54 <= dVar9) && (dVar9 <= (double)FLOAT_803dfcdc)) {
                    dVar7 = (double)((float)(dVar9 - (double)FLOAT_803dfd54) / FLOAT_803dfd48);
                    *(undefined *)((int)DAT_803dddac + 0x24f) = 7;
                  }
                }
                else {
                  dVar7 = (double)((float)(dVar9 - (double)FLOAT_803dfd00) / FLOAT_803dfd48);
                  *(undefined *)((int)DAT_803dddac + 0x24f) = 6;
                }
              }
              else {
                dVar7 = (double)((float)(dVar9 - (double)FLOAT_803dfd50) / FLOAT_803dfd48);
                *(undefined *)((int)DAT_803dddac + 0x24f) = 5;
              }
            }
            else {
              dVar7 = (double)((float)(dVar9 - (double)FLOAT_803dfce8) / FLOAT_803dfd48);
              *(undefined *)((int)DAT_803dddac + 0x24f) = 4;
            }
          }
          else {
            dVar7 = (double)((float)(dVar9 - (double)FLOAT_803dfd4c) / FLOAT_803dfd48);
            *(undefined *)((int)DAT_803dddac + 0x24f) = 3;
          }
        }
        else {
          dVar7 = (double)((float)(dVar9 - (double)FLOAT_803dfcfc) / FLOAT_803dfd48);
          *(undefined *)((int)DAT_803dddac + 0x24f) = 2;
        }
      }
      else {
        dVar7 = (double)(float)((double)(float)(dVar9 - dVar10) / dVar10);
        *(undefined *)((int)DAT_803dddac + 0x24f) = 1;
      }
    }
    else {
      dVar7 = (double)(float)(dVar9 / (double)FLOAT_803dfd48);
      *(undefined *)((int)DAT_803dddac + 0x24f) = 0;
    }
    dVar10 = (double)FLOAT_803dfcd8;
    if ((dVar10 <= dVar7) && (dVar10 = dVar7, (double)FLOAT_803dfcdc < dVar7)) {
      dVar10 = (double)FLOAT_803dfcdc;
    }
    uVar4 = (uint)*(byte *)((int)DAT_803dddac + 0x24f);
    if (uVar4 != (int)*(char *)(DAT_803dddac + 0x94)) {
      iVar6 = DAT_803dddac[uVar4 + 0x87];
      iVar1 = DAT_803dddac[(uVar4 + 1 & 7) + 0x87];
      if (DAT_803dddac[5] != iVar6) {
        uVar8 = FUN_80054484();
        uVar2 = FUN_80054ed0(uVar8,dVar9,dVar7,in_f4,in_f5,in_f6,in_f7,in_f8,iVar6,extraout_r4,uVar4
                             ,in_r6,in_r7,in_r8,in_r9,in_r10);
        *DAT_803dddac = uVar2;
        DAT_803dddac[5] = iVar6;
      }
      if (DAT_803dddac[6] != iVar1) {
        uVar8 = FUN_80054484();
        uVar2 = FUN_80054ed0(uVar8,dVar9,dVar7,in_f4,in_f5,in_f6,in_f7,in_f8,iVar1,extraout_r4_00,
                             uVar4,in_r6,in_r7,in_r8,in_r9,in_r10);
        DAT_803dddac[1] = uVar2;
        DAT_803dddac[6] = iVar1;
      }
      *(undefined *)(DAT_803dddac + 0x94) = *(undefined *)((int)DAT_803dddac + 0x24f);
    }
    FUN_80069c98(DAT_803dddac[1],*DAT_803dddac,
                 DAT_803dddac[*(byte *)((int)DAT_803dddac + 0x251) + 2]);
    *(byte *)((int)DAT_803dddac + 0x255) = *(byte *)((int)DAT_803dddac + 0x255) & 0x7f | 0x80;
    if ((float)DAT_803dddac[0x8f] != FLOAT_803dfcd8) {
      FUN_80069c98(DAT_803dddac[4],DAT_803dddac[*(byte *)((int)DAT_803dddac + 0x251) + 2],
                   DAT_803dddac[*(byte *)((int)DAT_803dddac + 0x251) + 2]);
    }
    iVar6 = (short)((short)DAT_803dddac[*(byte *)((int)DAT_803dddac + 0x24f) + 0x87] + -0xc38) * 6;
    uStack_d4 = (uint)(byte)(&DAT_8030fedc)[iVar6];
    iVar5 = (short)((short)DAT_803dddac[(*(byte *)((int)DAT_803dddac + 0x24f) + 1 & 7) + 0x87] +
                   -0xc38) * 6;
    uStack_dc = (byte)(&DAT_8030fedc)[iVar5] - uStack_d4 ^ 0x80000000;
    local_e0 = 0x43300000;
    local_d8 = 0x43300000;
    iVar1 = (int)(dVar10 * (double)(float)((double)CONCAT44(0x43300000,uStack_dc) - DOUBLE_803dfd10)
                 + (double)(float)((double)CONCAT44(0x43300000,uStack_d4) - DOUBLE_803dfcf0));
    local_d0 = (longlong)iVar1;
    DAT_803dddf0 = (undefined)iVar1;
    uStack_bc = (uint)(byte)(&DAT_8030fedd)[iVar6];
    uStack_c4 = (byte)(&DAT_8030fedd)[iVar5] - uStack_bc ^ 0x80000000;
    local_c8 = 0x43300000;
    local_c0 = 0x43300000;
    iVar1 = (int)(dVar10 * (double)(float)((double)CONCAT44(0x43300000,uStack_c4) - DOUBLE_803dfd10)
                 + (double)(float)((double)CONCAT44(0x43300000,uStack_bc) - DOUBLE_803dfcf0));
    local_b8 = (longlong)iVar1;
    uRam803dddf1 = (undefined)iVar1;
    uStack_a4 = (uint)(byte)(&DAT_8030fede)[iVar6];
    uStack_ac = (byte)(&DAT_8030fede)[iVar5] - uStack_a4 ^ 0x80000000;
    local_b0 = 0x43300000;
    local_a8 = 0x43300000;
    iVar1 = (int)(dVar10 * (double)(float)((double)CONCAT44(0x43300000,uStack_ac) - DOUBLE_803dfd10)
                 + (double)(float)((double)CONCAT44(0x43300000,uStack_a4) - DOUBLE_803dfcf0));
    local_a0 = (longlong)iVar1;
    uRam803dddf2 = (undefined)iVar1;
    uStack_8c = (uint)(byte)(&DAT_8030fedf)[iVar6];
    uStack_94 = (byte)(&DAT_8030fedf)[iVar5] - uStack_8c ^ 0x80000000;
    local_98 = 0x43300000;
    local_90 = 0x43300000;
    iVar1 = (int)(dVar10 * (double)(float)((double)CONCAT44(0x43300000,uStack_94) - DOUBLE_803dfd10)
                 + (double)(float)((double)CONCAT44(0x43300000,uStack_8c) - DOUBLE_803dfcf0));
    local_88 = (longlong)iVar1;
    DAT_803dddf4 = (undefined)iVar1;
    uStack_74 = (uint)(byte)(&DAT_8030fee0)[iVar6];
    uStack_7c = (byte)(&DAT_8030fee0)[iVar5] - uStack_74 ^ 0x80000000;
    local_80 = 0x43300000;
    local_78 = 0x43300000;
    iVar1 = (int)(dVar10 * (double)(float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803dfd10)
                 + (double)(float)((double)CONCAT44(0x43300000,uStack_74) - DOUBLE_803dfcf0));
    local_70 = (longlong)iVar1;
    uRam803dddf5 = (undefined)iVar1;
    uStack_5c = (uint)(byte)(&DAT_8030fee1)[iVar6];
    uStack_64 = (byte)(&DAT_8030fee1)[iVar5] - uStack_5c ^ 0x80000000;
    local_68 = 0x43300000;
    local_60 = 0x43300000;
    iVar1 = (int)(dVar10 * (double)(float)((double)CONCAT44(0x43300000,uStack_64) - DOUBLE_803dfd10)
                 + (double)(float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803dfcf0));
    local_58 = (longlong)iVar1;
    uRam803dddf6 = (undefined)iVar1;
    iVar1 = DAT_803dddac[*(byte *)((int)DAT_803dddac + 0x251) + 2];
    puVar3 = FUN_8000facc();
    dVar9 = FUN_8000fc54();
    uStack_4c = (uint)*(ushort *)(iVar1 + 0xc);
    local_50 = 0x43300000;
    dVar7 = (double)(float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803dfcf0);
    dVar10 = (double)(((float)(dVar7 * (double)(float)(dVar9 * (double)FLOAT_803dfce8)) /
                      FLOAT_803dfd58) * FLOAT_803dfd5c);
    uStack_44 = -(int)(short)puVar3[0x2a] ^ 0x80000000;
    local_48 = 0x43300000;
    dVar9 = (double)FUN_80294964();
    dVar10 = (double)(float)(dVar10 * dVar9);
    uStack_3c = (int)(short)puVar3[0x29] ^ 0x80000000;
    local_40 = 0x43300000;
    dVar7 = (double)((float)((double)((float)(dVar7 * (double)FLOAT_803dfce8 -
                                             (double)FLOAT_803dfd68) -
                                     (FLOAT_803dfd5c *
                                     (float)(dVar7 * (double)(float)((double)CONCAT44(0x43300000,
                                                                                      uStack_3c) -
                                                                    DOUBLE_803dfd10))) /
                                     FLOAT_803dfd64) + dVar10) * FLOAT_803dfd6c);
    (**(code **)(*DAT_803dd6dc + 0x18))(0);
    _local_e8 = local_e4;
    dVar9 = (double)FLOAT_803dfcd8;
    FUN_8025ca38(dVar9,dVar9,dVar9,dVar9,0,&local_e8);
    FUN_8004c460(iVar1,0);
    FUN_80078988();
    FUN_8025c828(0,0,0,0xff);
    FUN_8025be80(0);
    FUN_8025c1a4(0,8,4,5,0xf);
    FUN_8025c224(0,7,7,7,4);
    FUN_8025c65c(0,0,0);
    FUN_8025c2a8(0,0,0,0,1,0);
    FUN_8025c368(0,0,0,0,1,0);
    FUN_80258674(0,1,4,0x3c,0,0x7d);
    FUN_8025be54(0);
    FUN_8025a5bc(0);
    FUN_80258944(1);
    FUN_8025ca04(1);
    uVar4 = FUN_80070050();
    uStack_34 = (uint)*(ushort *)(iVar1 + 0xc);
    local_38 = 0x43300000;
    dVar9 = (double)(float)(dVar7 / (double)(FLOAT_803dfd6c *
                                            (float)((double)CONCAT44(0x43300000,uStack_34) -
                                                   DOUBLE_803dfcf0)));
    local_30 = 0x43300000;
    uStack_2c = uStack_34;
    FUN_80075ed8((double)FLOAT_803dfcd8,dVar9,(double)FLOAT_803dfcdc,
                 (double)(float)(dVar9 - (double)((float)(dVar10 * (double)FLOAT_803dfd38) /
                                                 (float)((double)CONCAT44(0x43300000,uStack_34) -
                                                        DOUBLE_803dfcf0))),0,0,
                 (short)((uVar4 & 0xffff) << 2),(short)((uVar4 >> 0x10) << 2),0xfe71);
  }
  return;
}

