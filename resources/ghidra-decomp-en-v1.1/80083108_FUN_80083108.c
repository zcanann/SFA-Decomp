// Function: FUN_80083108
// Entry: 80083108
// Size: 2176 bytes

void FUN_80083108(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,uint param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  int iVar6;
  byte *pbVar7;
  int iVar8;
  char cVar9;
  uint uVar10;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  double dVar11;
  double dVar12;
  undefined8 uVar13;
  undefined4 local_38;
  undefined4 local_34;
  undefined8 local_30;
  
  uVar13 = FUN_80286834();
  iVar8 = (int)((ulonglong)uVar13 >> 0x20);
  iVar6 = (int)uVar13;
  uVar10 = param_12 >> 8 & 0xff;
  cVar9 = (char)param_13;
  uVar13 = extraout_f1;
  switch(param_12 & 0xff) {
  case 2:
    if (cVar9 == '\0') {
      local_38 = 0x19;
      local_34 = 0x15;
      if (*(int *)(param_11 + 0x28) < 0) {
        param_2 = (double)*(float *)(iVar8 + 0x10);
        param_3 = (double)*(float *)(iVar8 + 0x14);
        uVar4 = (**(code **)(*DAT_803dd71c + 0x14))
                          ((double)*(float *)(iVar8 + 0xc),&local_38,2,uVar10);
        *(undefined4 *)(param_11 + 0x28) = uVar4;
        uVar13 = extraout_f1_00;
        if (-1 < *(int *)(param_11 + 0x28)) {
          if (*(uint *)(param_11 + 0x2c) != 0) {
            uVar13 = FUN_800238c4(*(uint *)(param_11 + 0x2c));
            *(undefined4 *)(param_11 + 0x2c) = 0;
          }
          iVar3 = FUN_80023d8c(0x2c,0x11);
          *(int *)(param_11 + 0x2c) = iVar3;
          if (*(undefined4 **)(param_11 + 0x2c) == (undefined4 *)0x0) {
            *(undefined4 *)(param_11 + 0x28) = 0xffffffff;
          }
          else {
            uVar13 = FUN_80084650(*(undefined4 **)(param_11 + 0x2c),*(undefined4 *)(param_11 + 0x28)
                                 );
          }
        }
      }
    }
    break;
  case 9:
    if (cVar9 == '\0') {
      *(byte *)(param_11 + 0x7f) = *(byte *)(param_11 + 0x7f) | 1;
    }
    break;
  case 0xe:
    if ((cVar9 == '\0') && ((&DAT_8039afb8)[*(char *)(param_11 + 0x57)] == '\0')) {
      uVar13 = (**(code **)(*DAT_803dd6cc + 8))(uVar10,1);
    }
    break;
  case 0xf:
    if ((cVar9 == '\0') && ((&DAT_8039afb8)[*(char *)(param_11 + 0x57)] == '\0')) {
      uVar13 = (**(code **)(*DAT_803dd6cc + 0xc))(uVar10,1);
    }
    break;
  case 0x12:
    if (cVar9 == '\0') {
      pbVar7 = &DAT_8039aab0 + *(char *)(param_11 + 0x57);
      bVar1 = *pbVar7;
      if ((bVar1 & 0x10) == 0) {
        *pbVar7 = bVar1 | 0x10;
      }
      else {
        *pbVar7 = bVar1 & 0xef;
      }
    }
    break;
  case 0x14:
    DAT_803ddd8c = 0x47;
    DAT_803ddd88 = param_12 >> 8 & 0x7f;
    DAT_803ddd84 = 1;
    DAT_803ddd80 = 0x78;
    break;
  case 0x17:
    if ((cVar9 == '\0') && ((int)uVar10 < (int)*(char *)(*(int *)(iVar6 + 0x50) + 0x55))) {
      if (*(short *)(iVar6 + 0x44) == 1) {
        if ((&DAT_8039b010)[*(char *)(param_11 + 0x57)] == 0x46) {
          if (uVar10 == 1) {
            uVar10 = 0;
          }
          uVar13 = FUN_802965f0();
        }
      }
      else {
        uVar13 = FUN_8002b95c(iVar6,uVar10);
      }
    }
    break;
  case 0x18:
    if (*(short *)(iVar6 + 0x44) == 1) {
      uVar13 = FUN_80296f40(iVar6,uVar10);
    }
    break;
  case 0x19:
    if (*(short *)(iVar6 + 0x44) == 1) {
      uVar13 = FUN_80296e8c(iVar6,uVar10);
    }
    break;
  case 0x1a:
    DAT_803ddd8c = 0x42;
    DAT_803ddd88 = 4;
    DAT_803ddd84 = 0;
    DAT_803ddd80 = 0;
    break;
  case 0x21:
    *(ushort *)(param_11 + 0x6e) = *(ushort *)(param_11 + 0x6e) | 0x400;
    *(byte *)(param_11 + 0x136) = (byte)(uVar10 << 4) | *(byte *)(param_11 + 0x136) & 0xf;
    break;
  case 0x22:
    *(ushort *)(param_11 + 0x6e) = *(ushort *)(param_11 + 0x6e) & 0xfbff;
    *(byte *)(param_11 + 0x136) = *(byte *)(param_11 + 0x136) & 0xf;
    break;
  case 0x23:
    *(byte *)(param_11 + 0x136) = *(byte *)(param_11 + 0x136) & 0xfb | 4;
    break;
  case 0x24:
    iVar3 = FUN_80057360();
    uVar13 = (**(code **)(*DAT_803dd72c + 0x1c))(0,0,1,iVar3);
    break;
  case 0x26:
    iVar3 = FUN_8002bac4();
    uVar13 = FUN_80297354(iVar3,uVar10);
    break;
  case 0x2c:
    local_30 = (double)CONCAT44(0x43300000,uVar10 ^ 0x80000000);
    uVar13 = FUN_80055240((double)((float)(local_30 - DOUBLE_803dfc38) / FLOAT_803dfc84),1);
    break;
  case 0x2d:
    uVar13 = FUN_80055240((double)FLOAT_803dfc30,0);
    break;
  case 0x2e:
    uVar13 = FUN_80055230(1);
    break;
  case 0x2f:
    uVar13 = FUN_80055230(0);
    break;
  case 0x30:
    uVar13 = FUN_800201ac(0x3b0,1);
    uVar4 = FUN_8002bac4();
    uVar5 = FUN_8002bac4();
    uVar13 = FUN_80008cbc(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar5,uVar4
                          ,0x134,0,param_13,param_14,param_15,param_16);
    uVar4 = FUN_8002bac4();
    uVar5 = FUN_8002bac4();
    uVar13 = FUN_80008cbc(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar5,uVar4
                          ,0x135,0,param_13,param_14,param_15,param_16);
    uVar4 = FUN_8002bac4();
    uVar5 = FUN_8002bac4();
    uVar13 = FUN_80008cbc(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar5,uVar4
                          ,0x142,0,param_13,param_14,param_15,param_16);
    break;
  case 0x31:
    uVar13 = FUN_800201ac(0x3b0,1);
    uVar4 = FUN_8002bac4();
    uVar5 = FUN_8002bac4();
    uVar13 = FUN_80008cbc(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar5,uVar4
                          ,0x136,0,param_13,param_14,param_15,param_16);
    uVar4 = FUN_8002bac4();
    uVar5 = FUN_8002bac4();
    uVar13 = FUN_80008cbc(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar5,uVar4
                          ,0x137,0,param_13,param_14,param_15,param_16);
    uVar4 = FUN_8002bac4();
    uVar5 = FUN_8002bac4();
    uVar13 = FUN_80008cbc(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar5,uVar4
                          ,0x143,0,param_13,param_14,param_15,param_16);
    break;
  case 0x32:
    uVar13 = FUN_800201ac(0x3b0,0);
    uVar4 = FUN_8002bac4();
    uVar5 = FUN_8002bac4();
    uVar13 = FUN_80008cbc(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar5,uVar4
                          ,0x134,0,param_13,param_14,param_15,param_16);
    uVar4 = FUN_8002bac4();
    uVar5 = FUN_8002bac4();
    uVar13 = FUN_80008cbc(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar5,uVar4
                          ,0x135,0,param_13,param_14,param_15,param_16);
    uVar4 = FUN_8002bac4();
    uVar5 = FUN_8002bac4();
    uVar13 = FUN_80008cbc(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar5,uVar4
                          ,0x142,0,param_13,param_14,param_15,param_16);
    uVar13 = FUN_80088a58(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  switch(param_12 & 0xff) {
  case 0:
    DAT_803ddd5a = 1;
    goto LAB_80083970;
  case 7:
    if (cVar9 == '\0') {
      FUN_8000faf8();
      iVar6 = FUN_8002bac4();
      if (iVar6 != 0) {
        dVar11 = (double)FUN_80021754((float *)(iVar6 + 0x18),(float *)(iVar8 + 0x18));
        local_30 = (double)CONCAT44(0x43300000,uVar10 - 7 ^ 0x80000000);
        dVar12 = (double)(FLOAT_803dfc88 * (float)(local_30 - DOUBLE_803dfc38) + FLOAT_803dfc48);
        if (dVar11 < (double)FLOAT_803dfc8c) {
          if ((double)FLOAT_803dfc90 < dVar11) {
            dVar12 = (double)(float)(dVar12 * (double)(FLOAT_803dfc48 -
                                                      (float)(dVar11 - (double)FLOAT_803dfc90) /
                                                      FLOAT_803dfc94));
          }
          dVar11 = (double)(float)((double)FLOAT_803dc390 * dVar12);
          FUN_8000e670(dVar11,dVar11,(double)FLOAT_803dc390);
        }
      }
    }
    break;
  case 10:
    FUN_800146e8(0x12,uVar10);
    break;
  case 0xb:
    FUN_800146e8(0x11,uVar10);
    break;
  case 0xc:
    FUN_800146c8();
    break;
  case 0xd:
    FUN_8000b7dc(iVar6,0x7f);
    break;
  case 0x10:
    *(char *)(param_11 + 0x7d) = (char)uVar10;
    break;
  case 0x13:
    if (cVar9 == '\0') {
      (&DAT_8039aab0)[*(char *)(param_11 + 0x57)] =
           (&DAT_8039aab0)[*(char *)(param_11 + 0x57)] & 0xef;
    }
    break;
  case 0x15:
    DAT_803ddd8c = 0x48;
    DAT_803ddd88 = uVar10 & 0x7f;
    DAT_803ddd84 = 1;
    DAT_803ddd80 = 0x78;
    break;
  case 0x17:
    if (((cVar9 == '\0') && (*(short *)(iVar6 + 0x44) != 1)) &&
       ((int)uVar10 < (int)*(char *)(*(int *)(iVar6 + 0x50) + 0x55))) {
      FUN_8002b95c(iVar6,uVar10);
    }
    break;
  case 0x1b:
    (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(iVar6 + 0xac),uVar10,1);
    break;
  case 0x1c:
    (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(iVar6 + 0xac),uVar10,0);
    break;
  case 0x1d:
    (**(code **)(*DAT_803dd72c + 0x44))((int)*(char *)(iVar6 + 0xac),uVar10);
    break;
  case 0x1e:
    if (cVar9 == '\0') {
      (&DAT_8039aab0)[*(char *)(param_11 + 0x57)] =
           (&DAT_8039aab0)[*(char *)(param_11 + 0x57)] | 0x10;
    }
    break;
  case 0x1f:
    (**(code **)(*DAT_803dd72c + 0x2c))();
    break;
  case 0x20:
    (**(code **)(*DAT_803dd72c + 0x28))();
    break;
  case 0x25:
    FUN_800146a8();
    break;
  case 0x27:
    if (DAT_803dc380 == *(char *)(param_11 + 0x57)) {
      DAT_803dc388 = (int)(float)(&DAT_8039ae0c)[*(char *)(param_11 + 0x57)];
      local_30 = (double)(longlong)DAT_803dc388;
      uVar4 = FUN_800804c8((int)*(char *)(param_11 + 0x57));
      uVar10 = countLeadingZeros(uVar4);
      DAT_803ddcf0 = (undefined2)(uVar10 >> 5);
    }
    break;
  case 0x28:
    iVar8 = (int)*(char *)(param_11 + 0x57);
    if ((&DAT_8039a8ac)[iVar8] == '\0') {
      uVar2 = (int)(short)(&DAT_8039b010)[iVar8] - 1U & 0x3fff;
      DAT_803ddce8 = uVar2;
      iVar6 = FUN_80080284((int *)&DAT_8030f868,5,uVar2);
      if (iVar6 != 0) {
        iVar6 = FUN_8000d220(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        if (iVar6 != 0) {
          DAT_803dc380 = iVar8;
        }
        iVar8 = FUN_80080284((int *)&DAT_8030f890,5,uVar2);
        if (iVar8 != 0) {
          DAT_803dc378 = *(undefined4 *)(iVar8 + uVar10 * 4);
        }
      }
    }
    break;
  case 0x33:
    DAT_803ddd80 = uVar10;
  }
LAB_80083970:
  FUN_80286880();
  return;
}

