// Function: FUN_8019df6c
// Entry: 8019df6c
// Size: 2112 bytes

void FUN_8019df6c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  float fVar1;
  short *psVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  float *pfVar6;
  bool bVar7;
  undefined4 in_r7;
  float *in_r8;
  int in_r9;
  undefined4 in_r10;
  int iVar8;
  float *pfVar9;
  int iVar10;
  short sVar11;
  float *pfVar12;
  float *pfVar13;
  undefined8 uVar14;
  uint local_58;
  uint local_54;
  uint local_50;
  float local_4c;
  float local_48;
  float local_44;
  undefined auStack_40 [4];
  short local_3c;
  short local_3a;
  float local_34;
  float local_30;
  float local_2c;
  undefined4 local_28;
  uint uStack_24;
  
  psVar2 = (short *)FUN_80286838();
  pfVar9 = *(float **)(psVar2 + 0x5c);
  local_58 = 0;
  FUN_8002bac4();
  uVar14 = FUN_8000faf8();
  while (iVar3 = FUN_800375e4((int)psVar2,&local_54,&local_50,&local_58), iVar3 != 0) {
    if (local_54 == 0x110003) {
      pfVar9[2] = *(float *)(local_50 + 0xc);
      pfVar9[6] = FLOAT_803e4e70;
      pfVar9[10] = *(float *)(local_50 + 0x14);
      *(undefined2 *)(pfVar9 + 0xd) = 1;
    }
    else if ((int)local_54 < 0x110003) {
      if (local_54 == 0x110001) {
        *pfVar9 = *(float *)(local_50 + 0xc);
        pfVar9[4] = FLOAT_803e4e70;
        pfVar9[8] = *(float *)(local_50 + 0x14);
        *(undefined2 *)(pfVar9 + 0xc) = 1;
      }
      else if (0x110000 < (int)local_54) {
        pfVar9[1] = *(float *)(local_50 + 0xc);
        pfVar9[5] = FLOAT_803e4e70;
        pfVar9[9] = *(float *)(local_50 + 0x14);
        *(undefined2 *)((int)pfVar9 + 0x32) = 1;
      }
    }
    else if ((int)local_54 < 0x110005) {
      pfVar9[3] = *(float *)(local_50 + 0xc);
      pfVar9[7] = *(float *)(local_50 + 0x10);
      pfVar9[0xb] = *(float *)(local_50 + 0x14);
      *(undefined2 *)((int)pfVar9 + 0x36) = 1;
    }
  }
  if (*(short *)((int)pfVar9 + 0x36) == 0) {
    in_r7 = 0;
    uVar14 = FUN_800377d0(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xdc,5,
                          (uint)psVar2,0x110004,0,in_r8,in_r9,in_r10);
  }
  uVar4 = FUN_80020078(0x54);
  if ((uVar4 != 0) && (*(short *)(pfVar9 + 0xc) == 0)) {
    in_r7 = 0;
    uVar14 = FUN_800377d0(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xda,4,
                          (uint)psVar2,0x110001,0,in_r8,in_r9,in_r10);
  }
  uVar4 = FUN_80020078(0x55);
  if ((uVar4 != 0) && (*(short *)((int)pfVar9 + 0x32) == 0)) {
    in_r7 = 0;
    uVar14 = FUN_800377d0(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xda,4,
                          (uint)psVar2,0x110002,0,in_r8,in_r9,in_r10);
  }
  uVar4 = FUN_80020078(0x56);
  if ((uVar4 != 0) && (*(short *)(pfVar9 + 0xd) == 0)) {
    in_r7 = 0;
    FUN_800377d0(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xda,4,(uint)psVar2,
                 0x110003,0,in_r8,in_r9,in_r10);
  }
  *(undefined *)((int)pfVar9 + 0x53) = 0;
  *(undefined *)((int)pfVar9 + 0x6f) = 0;
  *(undefined *)((int)pfVar9 + 0x8b) = 0;
  *(undefined *)((int)pfVar9 + 0xa7) = 0;
  *(undefined *)((int)pfVar9 + 0xc3) = 0;
  *(undefined *)((int)pfVar9 + 0xdf) = 0;
  *(undefined *)((int)pfVar9 + 0xfb) = 0;
  *(undefined *)((int)pfVar9 + 0x117) = 0;
  *(undefined *)((int)pfVar9 + 0x133) = 0;
  *(undefined *)((int)pfVar9 + 0x14f) = 0;
  uVar4 = 0;
  iVar3 = 0;
  if (*(short *)((int)pfVar9 + 0x36) != 0) {
    uVar5 = FUN_80020078(0x57);
    if (uVar5 != 0) {
      if (*(short *)(pfVar9 + 0xc) != 0) {
        *(undefined2 *)(pfVar9 + 0xc) = 0x78;
      }
      if (*(short *)((int)pfVar9 + 0x32) != 0) {
        *(undefined2 *)((int)pfVar9 + 0x32) = 0x78;
      }
      if (*(short *)(pfVar9 + 0xd) != 0) {
        *(undefined2 *)(pfVar9 + 0xd) = 0x78;
      }
      *(undefined2 *)(pfVar9 + 0x54) = 0x5a;
    }
    iVar10 = 0;
    pfVar12 = pfVar9;
    pfVar13 = pfVar9;
    do {
      if ((iVar10 < 3) && (*(short *)(pfVar13 + 0xc) != 0)) {
        iVar8 = iVar3 + 1;
        pfVar6 = pfVar9 + iVar3 * 7 + 0xe;
        *(undefined *)((int)pfVar6 + 0x1b) = 1;
        *(undefined *)(pfVar6 + 6) = 0x7f;
        *(undefined *)((int)pfVar6 + 0x19) = 0x7f;
        *(undefined *)((int)pfVar6 + 0x1a) = 0xff;
        *pfVar6 = pfVar9[3];
        pfVar6[2] = FLOAT_803e4e74 + pfVar9[7];
        pfVar6[4] = pfVar9[0xb];
        local_4c = *pfVar12 - *pfVar6;
        local_48 = (FLOAT_803e4e78 + pfVar12[4]) - pfVar6[2];
        local_44 = pfVar12[8] - pfVar6[4];
        FUN_80247ef8(&local_4c,&local_4c);
        local_34 = *pfVar12 - pfVar9[3];
        local_30 = (FLOAT_803e4e78 + pfVar12[4]) - pfVar9[7];
        local_2c = pfVar12[8] - pfVar9[0xb];
        local_4c = -local_4c;
        local_48 = -local_48;
        local_44 = -local_44;
        sVar11 = (short)iVar10;
        local_3a = sVar11;
        (**(code **)(*DAT_803dd708 + 8))(psVar2,0x7f4,auStack_40,2,0xffffffff,&local_4c);
        local_4c = *pfVar12 - *(float *)(DAT_803de790 + 0xc);
        local_48 = FLOAT_803e4e7c;
        local_44 = pfVar12[8] - *(float *)(DAT_803de790 + 0x14);
        FUN_80247ef8(&local_4c,&local_4c);
        local_34 = FLOAT_803e4e80;
        local_30 = FLOAT_803e4e74;
        local_2c = FLOAT_803e4e80;
        local_3a = sVar11 + 3;
        in_r7 = 0xffffffff;
        in_r8 = &local_4c;
        in_r9 = *DAT_803dd708;
        (**(code **)(in_r9 + 8))(DAT_803de790,0x7f4,auStack_40,2);
        param_2 = (double)*pfVar12;
        local_34 = *pfVar12;
        local_30 = pfVar12[4];
        local_2c = pfVar12[8];
        iVar3 = iVar3 + 2;
        *(undefined *)((int)pfVar9 + iVar8 * 0x1c + 0x53) = 1;
        uVar4 = uVar4 + 1;
        local_3c = sVar11;
      }
      pfVar13 = (float *)((int)pfVar13 + 2);
      pfVar12 = pfVar12 + 1;
      iVar10 = iVar10 + 1;
    } while (iVar10 < 3);
    if (((int)*(short *)(pfVar9 + 0xc) +
         (int)*(short *)((int)pfVar9 + 0x32) + (int)*(short *)(pfVar9 + 0xd) < 300) &&
       (uVar5 = FUN_80022264(0,3), uVar5 == 0)) {
      in_r7 = 0xffffffff;
      in_r8 = (float *)0x0;
      in_r9 = *DAT_803dd708;
      (**(code **)(in_r9 + 8))(psVar2,0x81,0,0);
    }
    if (((*(short *)(pfVar9 + 0xc) != 0) || (*(short *)((int)pfVar9 + 0x32) != 0)) ||
       (*(short *)(pfVar9 + 0xd) != 0)) {
      if (100 < *(byte *)(pfVar9 + 0x57)) {
        *(undefined *)(pfVar9 + 0x57) = 0;
      }
      if (100 < *(byte *)((int)pfVar9 + 0x15d)) {
        *(undefined *)((int)pfVar9 + 0x15d) = 0;
      }
      if (100 < *(byte *)((int)pfVar9 + 0x15e)) {
        *(undefined *)((int)pfVar9 + 0x15e) = 0;
      }
      if (0x14 < *(byte *)((int)pfVar9 + 0x15f)) {
        *(undefined *)((int)pfVar9 + 0x15f) = 0;
      }
      *(byte *)(pfVar9 + 0x57) = *(char *)(pfVar9 + 0x57) + DAT_803dc070;
      *(byte *)((int)pfVar9 + 0x15d) = *(char *)((int)pfVar9 + 0x15d) + DAT_803dc070;
      *(byte *)((int)pfVar9 + 0x15e) = *(char *)((int)pfVar9 + 0x15e) + DAT_803dc070;
      *(byte *)((int)pfVar9 + 0x15f) = *(char *)((int)pfVar9 + 0x15f) + DAT_803dc070;
    }
    if (uVar4 == 3) {
      if (*(short *)(pfVar9 + 0x54) == 0) {
        uVar14 = FUN_8000bb38(0,0x7e);
        FUN_80008cbc(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,0x7f,0,in_r7
                     ,in_r8,in_r9,in_r10);
      }
      *(ushort *)(pfVar9 + 0x54) = *(short *)(pfVar9 + 0x54) + (ushort)DAT_803dc070;
    }
    if (0x3b < *(short *)(pfVar9 + 0x54)) {
      uStack_24 = (int)*(short *)(pfVar9 + 0x54) - 0x3cU ^ 0x80000000;
      local_28 = 0x43300000;
      fVar1 = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e4ea0) / FLOAT_803e4e84;
      pfVar12 = pfVar9 + iVar3 * 7 + 0xe;
      *(undefined *)((int)pfVar12 + 0x1b) = 1;
      *(undefined *)(pfVar12 + 6) = 0;
      *(undefined *)((int)pfVar12 + 0x19) = 0;
      *(undefined *)((int)pfVar12 + 0x1a) = 0;
      *pfVar12 = *(float *)(psVar2 + 6);
      pfVar12[2] = FLOAT_803e4e88 + *(float *)(psVar2 + 8);
      pfVar12[4] = *(float *)(psVar2 + 10);
      pfVar12[1] = *pfVar12;
      pfVar12[3] = -(FLOAT_803e4e8c * fVar1 - pfVar12[2]);
      pfVar12[5] = pfVar12[4];
    }
    *psVar2 = *psVar2 + (ushort)DAT_803dc070 * (short)uVar4 * 0x7e;
  }
  if (uVar4 != 0) {
    bVar7 = FUN_8000b598((int)psVar2,0x40);
    if (bVar7) {
      uStack_24 = uVar4 ^ 0x80000000;
      local_28 = 0x43300000;
      fVar1 = FLOAT_803e4e94 +
              (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e4ea0) / FLOAT_803e4e98;
      pfVar9[0x55] = (fVar1 - pfVar9[0x55]) * FLOAT_803e4e9c + pfVar9[0x55];
      if (0x3b < *(short *)(pfVar9 + 0x54)) {
        pfVar9[0x55] = fVar1;
      }
      FUN_8000b8a8((double)pfVar9[0x55],(int)psVar2,0x40,100);
    }
    else {
      FUN_8000bb38((uint)psVar2,0xd5);
      pfVar9[0x55] = FLOAT_803e4e90;
    }
  }
  iVar3 = 0;
  do {
    sVar11 = *(short *)(pfVar9 + 0xc);
    if ((sVar11 != 0) && (sVar11 < 0x80)) {
      *(ushort *)(pfVar9 + 0xc) = sVar11 + (ushort)DAT_803dc070;
      if ((sVar11 == 1) && (1 < *(short *)(pfVar9 + 0xc))) {
        FUN_8000bb38((uint)psVar2,0xd6);
      }
      if ((sVar11 < 0x1e) && (0x1d < *(short *)(pfVar9 + 0xc))) {
        FUN_8000bb38((uint)psVar2,0xd7);
      }
    }
    pfVar9 = (float *)((int)pfVar9 + 2);
    iVar3 = iVar3 + 1;
  } while (iVar3 < 3);
  *psVar2 = *psVar2 + (ushort)DAT_803dc070 * 0x2a;
  FUN_80286884();
  return;
}

