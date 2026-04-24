// Function: FUN_8019d9f0
// Entry: 8019d9f0
// Size: 2112 bytes

void FUN_8019d9f0(void)

{
  float fVar1;
  short *psVar2;
  int iVar3;
  int iVar4;
  float *pfVar5;
  uint uVar6;
  int iVar7;
  float *pfVar8;
  short sVar9;
  float *pfVar10;
  float *pfVar11;
  undefined4 local_58;
  int local_54;
  int local_50;
  float local_4c;
  float local_48;
  float local_44;
  undefined auStack64 [4];
  short local_3c;
  short local_3a;
  float local_34;
  float local_30;
  float local_2c;
  undefined4 local_28;
  uint uStack36;
  
  psVar2 = (short *)FUN_802860d4();
  pfVar8 = *(float **)(psVar2 + 0x5c);
  local_58 = 0;
  FUN_8002b9ec();
  FUN_8000fad8();
  while (iVar3 = FUN_800374ec(psVar2,&local_54,&local_50,&local_58), iVar3 != 0) {
    if (local_54 == 0x110003) {
      pfVar8[2] = *(float *)(local_50 + 0xc);
      pfVar8[6] = FLOAT_803e41d8;
      pfVar8[10] = *(float *)(local_50 + 0x14);
      *(undefined2 *)(pfVar8 + 0xd) = 1;
    }
    else if (local_54 < 0x110003) {
      if (local_54 == 0x110001) {
        *pfVar8 = *(float *)(local_50 + 0xc);
        pfVar8[4] = FLOAT_803e41d8;
        pfVar8[8] = *(float *)(local_50 + 0x14);
        *(undefined2 *)(pfVar8 + 0xc) = 1;
      }
      else if (0x110000 < local_54) {
        pfVar8[1] = *(float *)(local_50 + 0xc);
        pfVar8[5] = FLOAT_803e41d8;
        pfVar8[9] = *(float *)(local_50 + 0x14);
        *(undefined2 *)((int)pfVar8 + 0x32) = 1;
      }
    }
    else if (local_54 < 0x110005) {
      pfVar8[3] = *(float *)(local_50 + 0xc);
      pfVar8[7] = *(float *)(local_50 + 0x10);
      pfVar8[0xb] = *(float *)(local_50 + 0x14);
      *(undefined2 *)((int)pfVar8 + 0x36) = 1;
    }
  }
  if (*(short *)((int)pfVar8 + 0x36) == 0) {
    FUN_800376d8(0xdc,5,psVar2,0x110004,0);
  }
  iVar3 = FUN_8001ffb4(0x54);
  if ((iVar3 != 0) && (*(short *)(pfVar8 + 0xc) == 0)) {
    FUN_800376d8(0xda,4,psVar2,0x110001,0);
  }
  iVar3 = FUN_8001ffb4(0x55);
  if ((iVar3 != 0) && (*(short *)((int)pfVar8 + 0x32) == 0)) {
    FUN_800376d8(0xda,4,psVar2,0x110002,0);
  }
  iVar3 = FUN_8001ffb4(0x56);
  if ((iVar3 != 0) && (*(short *)(pfVar8 + 0xd) == 0)) {
    FUN_800376d8(0xda,4,psVar2,0x110003,0);
  }
  *(undefined *)((int)pfVar8 + 0x53) = 0;
  *(undefined *)((int)pfVar8 + 0x6f) = 0;
  *(undefined *)((int)pfVar8 + 0x8b) = 0;
  *(undefined *)((int)pfVar8 + 0xa7) = 0;
  *(undefined *)((int)pfVar8 + 0xc3) = 0;
  *(undefined *)((int)pfVar8 + 0xdf) = 0;
  *(undefined *)((int)pfVar8 + 0xfb) = 0;
  *(undefined *)((int)pfVar8 + 0x117) = 0;
  *(undefined *)((int)pfVar8 + 0x133) = 0;
  *(undefined *)((int)pfVar8 + 0x14f) = 0;
  uVar6 = 0;
  iVar3 = 0;
  if (*(short *)((int)pfVar8 + 0x36) != 0) {
    iVar4 = FUN_8001ffb4(0x57);
    if (iVar4 != 0) {
      if (*(short *)(pfVar8 + 0xc) != 0) {
        *(undefined2 *)(pfVar8 + 0xc) = 0x78;
      }
      if (*(short *)((int)pfVar8 + 0x32) != 0) {
        *(undefined2 *)((int)pfVar8 + 0x32) = 0x78;
      }
      if (*(short *)(pfVar8 + 0xd) != 0) {
        *(undefined2 *)(pfVar8 + 0xd) = 0x78;
      }
      *(undefined2 *)(pfVar8 + 0x54) = 0x5a;
    }
    iVar4 = 0;
    pfVar10 = pfVar8;
    pfVar11 = pfVar8;
    do {
      if ((iVar4 < 3) && (*(short *)(pfVar11 + 0xc) != 0)) {
        iVar7 = iVar3 + 1;
        pfVar5 = pfVar8 + iVar3 * 7 + 0xe;
        *(undefined *)((int)pfVar5 + 0x1b) = 1;
        *(undefined *)(pfVar5 + 6) = 0x7f;
        *(undefined *)((int)pfVar5 + 0x19) = 0x7f;
        *(undefined *)((int)pfVar5 + 0x1a) = 0xff;
        *pfVar5 = pfVar8[3];
        pfVar5[2] = FLOAT_803e41dc + pfVar8[7];
        pfVar5[4] = pfVar8[0xb];
        local_4c = *pfVar10 - *pfVar5;
        local_48 = (FLOAT_803e41e0 + pfVar10[4]) - pfVar5[2];
        local_44 = pfVar10[8] - pfVar5[4];
        FUN_80247794(&local_4c,&local_4c);
        local_34 = *pfVar10 - pfVar8[3];
        local_30 = (FLOAT_803e41e0 + pfVar10[4]) - pfVar8[7];
        local_2c = pfVar10[8] - pfVar8[0xb];
        local_4c = -local_4c;
        local_48 = -local_48;
        local_44 = -local_44;
        sVar9 = (short)iVar4;
        local_3a = sVar9;
        (**(code **)(*DAT_803dca88 + 8))(psVar2,0x7f4,auStack64,2,0xffffffff,&local_4c);
        local_4c = *pfVar10 - *(float *)(DAT_803ddb10 + 0xc);
        local_48 = FLOAT_803e41e4;
        local_44 = pfVar10[8] - *(float *)(DAT_803ddb10 + 0x14);
        FUN_80247794(&local_4c,&local_4c);
        local_34 = FLOAT_803e41e8;
        local_30 = FLOAT_803e41dc;
        local_2c = FLOAT_803e41e8;
        local_3a = sVar9 + 3;
        (**(code **)(*DAT_803dca88 + 8))(DAT_803ddb10,0x7f4,auStack64,2,0xffffffff,&local_4c);
        local_34 = *pfVar10;
        local_30 = pfVar10[4];
        local_2c = pfVar10[8];
        iVar3 = iVar3 + 2;
        *(undefined *)((int)pfVar8 + iVar7 * 0x1c + 0x53) = 1;
        uVar6 = uVar6 + 1;
        local_3c = sVar9;
      }
      pfVar11 = (float *)((int)pfVar11 + 2);
      pfVar10 = pfVar10 + 1;
      iVar4 = iVar4 + 1;
    } while (iVar4 < 3);
    if (((int)*(short *)(pfVar8 + 0xc) +
         (int)*(short *)((int)pfVar8 + 0x32) + (int)*(short *)(pfVar8 + 0xd) < 300) &&
       (iVar4 = FUN_800221a0(0,3), iVar4 == 0)) {
      (**(code **)(*DAT_803dca88 + 8))(psVar2,0x81,0,0,0xffffffff,0);
    }
    if (((*(short *)(pfVar8 + 0xc) != 0) || (*(short *)((int)pfVar8 + 0x32) != 0)) ||
       (*(short *)(pfVar8 + 0xd) != 0)) {
      if (100 < *(byte *)(pfVar8 + 0x57)) {
        *(undefined *)(pfVar8 + 0x57) = 0;
      }
      if (100 < *(byte *)((int)pfVar8 + 0x15d)) {
        *(undefined *)((int)pfVar8 + 0x15d) = 0;
      }
      if (100 < *(byte *)((int)pfVar8 + 0x15e)) {
        *(undefined *)((int)pfVar8 + 0x15e) = 0;
      }
      if (0x14 < *(byte *)((int)pfVar8 + 0x15f)) {
        *(undefined *)((int)pfVar8 + 0x15f) = 0;
      }
      *(byte *)(pfVar8 + 0x57) = *(char *)(pfVar8 + 0x57) + DAT_803db410;
      *(byte *)((int)pfVar8 + 0x15d) = *(char *)((int)pfVar8 + 0x15d) + DAT_803db410;
      *(byte *)((int)pfVar8 + 0x15e) = *(char *)((int)pfVar8 + 0x15e) + DAT_803db410;
      *(byte *)((int)pfVar8 + 0x15f) = *(char *)((int)pfVar8 + 0x15f) + DAT_803db410;
    }
    if (uVar6 == 3) {
      if (*(short *)(pfVar8 + 0x54) == 0) {
        FUN_8000bb18(0,0x7e);
        FUN_80008cbc(0,0,0x7f,0);
      }
      *(ushort *)(pfVar8 + 0x54) = *(short *)(pfVar8 + 0x54) + (ushort)DAT_803db410;
    }
    if (0x3b < *(short *)(pfVar8 + 0x54)) {
      uStack36 = (int)*(short *)(pfVar8 + 0x54) - 0x3cU ^ 0x80000000;
      local_28 = 0x43300000;
      fVar1 = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e4208) / FLOAT_803e41ec;
      pfVar10 = pfVar8 + iVar3 * 7 + 0xe;
      *(undefined *)((int)pfVar10 + 0x1b) = 1;
      *(undefined *)(pfVar10 + 6) = 0;
      *(undefined *)((int)pfVar10 + 0x19) = 0;
      *(undefined *)((int)pfVar10 + 0x1a) = 0;
      *pfVar10 = *(float *)(psVar2 + 6);
      pfVar10[2] = FLOAT_803e41f0 + *(float *)(psVar2 + 8);
      pfVar10[4] = *(float *)(psVar2 + 10);
      pfVar10[1] = *pfVar10;
      pfVar10[3] = -(FLOAT_803e41f4 * fVar1 - pfVar10[2]);
      pfVar10[5] = pfVar10[4];
    }
    *psVar2 = *psVar2 + (ushort)DAT_803db410 * (short)uVar6 * 0x7e;
  }
  if (uVar6 != 0) {
    iVar3 = FUN_8000b578(psVar2,0x40);
    if (iVar3 == 0) {
      FUN_8000bb18(psVar2,0xd5);
      pfVar8[0x55] = FLOAT_803e41f8;
    }
    else {
      uStack36 = uVar6 ^ 0x80000000;
      local_28 = 0x43300000;
      fVar1 = FLOAT_803e41fc +
              (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e4208) / FLOAT_803e4200;
      pfVar8[0x55] = (fVar1 - pfVar8[0x55]) * FLOAT_803e4204 + pfVar8[0x55];
      if (0x3b < *(short *)(pfVar8 + 0x54)) {
        pfVar8[0x55] = fVar1;
      }
      FUN_8000b888((double)pfVar8[0x55],psVar2,0x40,100);
    }
  }
  iVar3 = 0;
  do {
    sVar9 = *(short *)(pfVar8 + 0xc);
    if ((sVar9 != 0) && (sVar9 < 0x80)) {
      *(ushort *)(pfVar8 + 0xc) = sVar9 + (ushort)DAT_803db410;
      if ((sVar9 == 1) && (1 < *(short *)(pfVar8 + 0xc))) {
        FUN_8000bb18(psVar2,0xd6);
      }
      if ((sVar9 < 0x1e) && (0x1d < *(short *)(pfVar8 + 0xc))) {
        FUN_8000bb18(psVar2,0xd7);
      }
    }
    pfVar8 = (float *)((int)pfVar8 + 2);
    iVar3 = iVar3 + 1;
  } while (iVar3 < 3);
  *psVar2 = *psVar2 + (ushort)DAT_803db410 * 0x2a;
  FUN_80286120();
  return;
}

