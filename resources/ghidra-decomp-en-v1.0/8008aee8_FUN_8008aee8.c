// Function: FUN_8008aee8
// Entry: 8008aee8
// Size: 2100 bytes

/* WARNING: Removing unreachable block (ram,0x8008b6f4) */
/* WARNING: Removing unreachable block (ram,0x8008b6fc) */

void FUN_8008aee8(void)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  double dVar7;
  double dVar8;
  undefined8 in_f30;
  double dVar9;
  undefined8 in_f31;
  double dVar10;
  undefined4 local_e8;
  undefined4 local_e4;
  undefined4 local_e0;
  uint uStack220;
  undefined4 local_d8;
  uint uStack212;
  longlong local_d0;
  undefined4 local_c8;
  uint uStack196;
  undefined4 local_c0;
  uint uStack188;
  longlong local_b8;
  undefined4 local_b0;
  uint uStack172;
  undefined4 local_a8;
  uint uStack164;
  longlong local_a0;
  undefined4 local_98;
  uint uStack148;
  undefined4 local_90;
  uint uStack140;
  longlong local_88;
  undefined4 local_80;
  uint uStack124;
  undefined4 local_78;
  uint uStack116;
  longlong local_70;
  undefined4 local_68;
  uint uStack100;
  undefined4 local_60;
  uint uStack92;
  longlong local_58;
  undefined4 local_50;
  uint uStack76;
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  undefined4 local_30;
  uint uStack44;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  local_e4 = DAT_803e8458;
  if ((DAT_803dd12c != (undefined4 *)0x0) &&
     ((iVar1 = FUN_8002b9ec(), iVar1 == 0 ||
      ((iVar1 = FUN_8005afac((double)*(float *)(iVar1 + 0xc),(double)*(float *)(iVar1 + 0x14)),
       iVar1 != 0x30 && (iVar1 != 0x2b)))))) {
    dVar7 = (double)((float)DAT_803dd12c[0x83] / FLOAT_803df078);
    dVar8 = (double)FLOAT_803df058;
    if ((dVar8 <= dVar7) && (dVar8 = dVar7, (double)FLOAT_803df05c < dVar7)) {
      dVar8 = (double)FLOAT_803df05c;
    }
    dVar7 = (double)FLOAT_803df058;
    if ((dVar8 < dVar7) || ((double)FLOAT_803df0c8 <= dVar8)) {
      dVar9 = (double)FLOAT_803df0c8;
      if ((dVar8 < dVar9) || ((double)FLOAT_803df07c <= dVar8)) {
        if ((dVar8 < (double)FLOAT_803df07c) || ((double)FLOAT_803df0cc <= dVar8)) {
          if ((dVar8 < (double)FLOAT_803df0cc) || ((double)FLOAT_803df068 <= dVar8)) {
            if ((dVar8 < (double)FLOAT_803df068) || ((double)FLOAT_803df0d0 <= dVar8)) {
              if ((dVar8 < (double)FLOAT_803df0d0) || ((double)FLOAT_803df080 <= dVar8)) {
                if ((dVar8 < (double)FLOAT_803df080) || ((double)FLOAT_803df0d4 <= dVar8)) {
                  if (((double)FLOAT_803df0d4 <= dVar8) && (dVar8 <= (double)FLOAT_803df05c)) {
                    dVar7 = (double)((float)(dVar8 - (double)FLOAT_803df0d4) / FLOAT_803df0c8);
                    *(undefined *)((int)DAT_803dd12c + 0x24f) = 7;
                  }
                }
                else {
                  dVar7 = (double)((float)(dVar8 - (double)FLOAT_803df080) / FLOAT_803df0c8);
                  *(undefined *)((int)DAT_803dd12c + 0x24f) = 6;
                }
              }
              else {
                dVar7 = (double)((float)(dVar8 - (double)FLOAT_803df0d0) / FLOAT_803df0c8);
                *(undefined *)((int)DAT_803dd12c + 0x24f) = 5;
              }
            }
            else {
              dVar7 = (double)((float)(dVar8 - (double)FLOAT_803df068) / FLOAT_803df0c8);
              *(undefined *)((int)DAT_803dd12c + 0x24f) = 4;
            }
          }
          else {
            dVar7 = (double)((float)(dVar8 - (double)FLOAT_803df0cc) / FLOAT_803df0c8);
            *(undefined *)((int)DAT_803dd12c + 0x24f) = 3;
          }
        }
        else {
          dVar7 = (double)((float)(dVar8 - (double)FLOAT_803df07c) / FLOAT_803df0c8);
          *(undefined *)((int)DAT_803dd12c + 0x24f) = 2;
        }
      }
      else {
        dVar7 = (double)(float)((double)(float)(dVar8 - dVar9) / dVar9);
        *(undefined *)((int)DAT_803dd12c + 0x24f) = 1;
      }
    }
    else {
      dVar7 = (double)(float)(dVar8 / (double)FLOAT_803df0c8);
      *(undefined *)((int)DAT_803dd12c + 0x24f) = 0;
    }
    dVar8 = (double)FLOAT_803df058;
    if ((dVar8 <= dVar7) && (dVar8 = dVar7, (double)FLOAT_803df05c < dVar7)) {
      dVar8 = (double)FLOAT_803df05c;
    }
    uVar3 = (uint)*(byte *)((int)DAT_803dd12c + 0x24f);
    if (uVar3 != (int)*(char *)(DAT_803dd12c + 0x94)) {
      iVar5 = DAT_803dd12c[uVar3 + 0x87];
      iVar1 = DAT_803dd12c[(uVar3 + 1 & 7) + 0x87];
      if (DAT_803dd12c[5] != iVar5) {
        FUN_80054308(*DAT_803dd12c);
        uVar2 = FUN_80054d54(iVar5);
        *DAT_803dd12c = uVar2;
        DAT_803dd12c[5] = iVar5;
      }
      if (DAT_803dd12c[6] != iVar1) {
        FUN_80054308(DAT_803dd12c[1]);
        uVar2 = FUN_80054d54(iVar1);
        DAT_803dd12c[1] = uVar2;
        DAT_803dd12c[6] = iVar1;
      }
      *(undefined *)(DAT_803dd12c + 0x94) = *(undefined *)((int)DAT_803dd12c + 0x24f);
    }
    FUN_80069b1c(dVar8,DAT_803dd12c[1],*DAT_803dd12c,
                 DAT_803dd12c[*(byte *)((int)DAT_803dd12c + 0x251) + 2]);
    *(byte *)((int)DAT_803dd12c + 0x255) = *(byte *)((int)DAT_803dd12c + 0x255) & 0x7f | 0x80;
    if ((float)DAT_803dd12c[0x8f] != FLOAT_803df058) {
      FUN_80069b1c(DAT_803dd12c[4],DAT_803dd12c[*(byte *)((int)DAT_803dd12c + 0x251) + 2],
                   DAT_803dd12c[*(byte *)((int)DAT_803dd12c + 0x251) + 2]);
    }
    iVar5 = (short)((short)DAT_803dd12c[*(byte *)((int)DAT_803dd12c + 0x24f) + 0x87] + -0xc38) * 6;
    uStack212 = (uint)(byte)(&DAT_8030f31c)[iVar5];
    iVar4 = (short)((short)DAT_803dd12c[(*(byte *)((int)DAT_803dd12c + 0x24f) + 1 & 7) + 0x87] +
                   -0xc38) * 6;
    uStack220 = (byte)(&DAT_8030f31c)[iVar4] - uStack212 ^ 0x80000000;
    local_e0 = 0x43300000;
    local_d8 = 0x43300000;
    iVar1 = (int)(dVar8 * (double)(float)((double)CONCAT44(0x43300000,uStack220) - DOUBLE_803df090)
                 + (double)(float)((double)CONCAT44(0x43300000,uStack212) - DOUBLE_803df070));
    local_d0 = (longlong)iVar1;
    DAT_803dd170 = (undefined)iVar1;
    uStack188 = (uint)(byte)(&DAT_8030f31d)[iVar5];
    uStack196 = (byte)(&DAT_8030f31d)[iVar4] - uStack188 ^ 0x80000000;
    local_c8 = 0x43300000;
    local_c0 = 0x43300000;
    iVar1 = (int)(dVar8 * (double)(float)((double)CONCAT44(0x43300000,uStack196) - DOUBLE_803df090)
                 + (double)(float)((double)CONCAT44(0x43300000,uStack188) - DOUBLE_803df070));
    local_b8 = (longlong)iVar1;
    uRam803dd171 = (undefined)iVar1;
    uStack164 = (uint)(byte)(&DAT_8030f31e)[iVar5];
    uStack172 = (byte)(&DAT_8030f31e)[iVar4] - uStack164 ^ 0x80000000;
    local_b0 = 0x43300000;
    local_a8 = 0x43300000;
    iVar1 = (int)(dVar8 * (double)(float)((double)CONCAT44(0x43300000,uStack172) - DOUBLE_803df090)
                 + (double)(float)((double)CONCAT44(0x43300000,uStack164) - DOUBLE_803df070));
    local_a0 = (longlong)iVar1;
    uRam803dd172 = (undefined)iVar1;
    uStack140 = (uint)(byte)(&DAT_8030f31f)[iVar5];
    uStack148 = (byte)(&DAT_8030f31f)[iVar4] - uStack140 ^ 0x80000000;
    local_98 = 0x43300000;
    local_90 = 0x43300000;
    iVar1 = (int)(dVar8 * (double)(float)((double)CONCAT44(0x43300000,uStack148) - DOUBLE_803df090)
                 + (double)(float)((double)CONCAT44(0x43300000,uStack140) - DOUBLE_803df070));
    local_88 = (longlong)iVar1;
    DAT_803dd174 = (undefined)iVar1;
    uStack116 = (uint)(byte)(&DAT_8030f320)[iVar5];
    uStack124 = (byte)(&DAT_8030f320)[iVar4] - uStack116 ^ 0x80000000;
    local_80 = 0x43300000;
    local_78 = 0x43300000;
    iVar1 = (int)(dVar8 * (double)(float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803df090)
                 + (double)(float)((double)CONCAT44(0x43300000,uStack116) - DOUBLE_803df070));
    local_70 = (longlong)iVar1;
    uRam803dd175 = (undefined)iVar1;
    uStack92 = (uint)(byte)(&DAT_8030f321)[iVar5];
    uStack100 = (byte)(&DAT_8030f321)[iVar4] - uStack92 ^ 0x80000000;
    local_68 = 0x43300000;
    local_60 = 0x43300000;
    iVar1 = (int)(dVar8 * (double)(float)((double)CONCAT44(0x43300000,uStack100) - DOUBLE_803df090)
                 + (double)(float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803df070));
    local_58 = (longlong)iVar1;
    uRam803dd176 = (undefined)iVar1;
    iVar5 = DAT_803dd12c[*(byte *)((int)DAT_803dd12c + 0x251) + 2];
    iVar1 = FUN_8000faac();
    dVar8 = (double)FUN_8000fc34();
    uStack76 = (uint)*(ushort *)(iVar5 + 0xc);
    local_50 = 0x43300000;
    dVar9 = (double)(float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803df070);
    dVar7 = (double)(((float)(dVar9 * (double)(float)(dVar8 * (double)FLOAT_803df068)) /
                     FLOAT_803df0d8) * FLOAT_803df0dc);
    uStack68 = -(int)*(short *)(iVar1 + 0x54) ^ 0x80000000;
    local_48 = 0x43300000;
    dVar8 = (double)FUN_80294204((double)((FLOAT_803df0e0 *
                                          (float)((double)CONCAT44(0x43300000,uStack68) -
                                                 DOUBLE_803df090)) / FLOAT_803df0e4));
    dVar10 = (double)(float)(dVar7 * dVar8);
    dVar7 = (double)(float)(dVar9 * (double)FLOAT_803df068 - (double)FLOAT_803df0e8);
    uStack60 = (int)*(short *)(iVar1 + 0x52) ^ 0x80000000;
    local_40 = 0x43300000;
    dVar8 = (double)(float)((double)FLOAT_803df0dc *
                           (double)(float)(dVar9 * (double)(float)((double)CONCAT44(0x43300000,
                                                                                    uStack60) -
                                                                  DOUBLE_803df090)));
    dVar9 = (double)((float)((double)(float)(dVar7 - (double)(float)(dVar8 / (double)FLOAT_803df0e4)
                                            ) + dVar10) * FLOAT_803df0ec);
    (**(code **)(*DAT_803dca5c + 0x18))(dVar8,(double)FLOAT_803df0dc,dVar7,0);
    local_e8 = local_e4;
    dVar8 = (double)FLOAT_803df058;
    FUN_8025c2d4(dVar8,dVar8,dVar8,dVar8,0,&local_e8);
    FUN_8004c2e4(iVar5,0);
    FUN_8007880c();
    FUN_8025c0c4(0,0,0,0xff);
    FUN_8025b71c(0);
    FUN_8025ba40(0,8,4,5,0xf);
    FUN_8025bac0(0,7,7,7,4);
    FUN_8025bef8(0,0,0);
    FUN_8025bb44(0,0,0,0,1,0);
    FUN_8025bc04(0,0,0,0,1,0);
    FUN_80257f10(0,1,4,0x3c,0,0x7d);
    FUN_8025b6f0(0);
    FUN_80259e58(0);
    FUN_802581e0(1);
    FUN_8025c2a0(1);
    uVar3 = FUN_8006fed4();
    uStack52 = (uint)*(ushort *)(iVar5 + 0xc);
    local_38 = 0x43300000;
    dVar8 = (double)(float)(dVar9 / (double)(FLOAT_803df0ec *
                                            (float)((double)CONCAT44(0x43300000,uStack52) -
                                                   DOUBLE_803df070)));
    local_30 = 0x43300000;
    uStack44 = uStack52;
    FUN_80075d5c((double)FLOAT_803df058,dVar8,(double)FLOAT_803df05c,
                 (double)(float)(dVar8 - (double)((float)(dVar10 * (double)FLOAT_803df0b8) /
                                                 (float)((double)CONCAT44(0x43300000,uStack52) -
                                                        DOUBLE_803df070))),0,0,(uVar3 & 0xffff) << 2
                 ,(uVar3 >> 0x10) << 2,0xfffffe71);
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  return;
}

