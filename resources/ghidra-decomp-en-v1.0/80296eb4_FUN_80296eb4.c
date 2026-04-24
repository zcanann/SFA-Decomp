// Function: FUN_80296eb4
// Entry: 80296eb4
// Size: 928 bytes

void FUN_80296eb4(void)

{
  short *psVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined4 uVar7;
  short sVar8;
  undefined2 uVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  undefined8 uVar13;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  undefined auStack72 [4];
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c [11];
  
  uVar13 = FUN_802860c8();
  psVar1 = (short *)((ulonglong)uVar13 >> 0x20);
  iVar10 = (int)uVar13;
  iVar11 = *(int *)(psVar1 + 0x18);
  iVar12 = *(int *)(psVar1 + 0x5c);
  if (iVar11 != iVar10) {
    if (iVar11 == 0) {
      local_34 = *(float *)(psVar1 + 6);
      local_30 = *(float *)(psVar1 + 8);
      local_2c[0] = *(float *)(psVar1 + 10);
      local_40 = *(float *)(psVar1 + 0x40);
      local_3c = *(float *)(psVar1 + 0x42);
      local_38 = *(float *)(psVar1 + 0x44);
      local_4c = *(float *)(psVar1 + 0x12);
      local_44 = *(float *)(psVar1 + 0x16);
      iVar2 = (int)*psVar1;
      iVar3 = (int)*(short *)(iVar12 + 0x478);
      iVar4 = (int)*(short *)(iVar12 + 0x484);
      iVar5 = (int)*(short *)(iVar12 + 0x492);
      iVar6 = (int)*(short *)(iVar12 + 0x490);
      uVar7 = *(undefined4 *)(iVar12 + 0x494);
      local_58 = *(float *)(iVar12 + 0x118);
      local_54 = *(float *)(iVar12 + 0x11c);
      local_50 = *(float *)(iVar12 + 0x120);
    }
    else {
      FUN_8000e0a0((double)*(float *)(psVar1 + 6),(double)*(float *)(psVar1 + 8),
                   (double)*(float *)(psVar1 + 10),&local_34,&local_30,local_2c,iVar11);
      FUN_8000e0a0((double)*(float *)(psVar1 + 0x40),(double)*(float *)(psVar1 + 0x42),
                   (double)*(float *)(psVar1 + 0x44),&local_40,&local_3c,&local_38,iVar11);
      FUN_8000df1c((double)*(float *)(psVar1 + 0x12),(double)FLOAT_803e7ea4,
                   (double)*(float *)(psVar1 + 0x16),&local_4c,auStack72,&local_44,iVar11);
      iVar2 = FUN_8000deb4((int)*psVar1,iVar11);
      iVar3 = FUN_8000deb4((int)*(short *)(iVar12 + 0x478),iVar11);
      iVar4 = FUN_8000deb4((int)*(short *)(iVar12 + 0x484),iVar11);
      iVar5 = FUN_8000deb4((int)*(short *)(iVar12 + 0x492),iVar11);
      iVar6 = FUN_8000deb4((int)*(short *)(iVar12 + 0x490),iVar11);
      uVar7 = FUN_8000deb4(*(undefined4 *)(iVar12 + 0x494),iVar11);
      FUN_8000e0a0((double)*(float *)(iVar12 + 0x118),(double)*(float *)(iVar12 + 0x11c),
                   (double)*(float *)(iVar12 + 0x120),&local_58,&local_54,&local_50,iVar11);
    }
    if (iVar10 == 0) {
      *(float *)(psVar1 + 6) = local_34;
      *(float *)(psVar1 + 8) = local_30;
      *(float *)(psVar1 + 10) = local_2c[0];
      *(float *)(psVar1 + 0x40) = local_40;
      *(float *)(psVar1 + 0x42) = local_3c;
      *(float *)(psVar1 + 0x44) = local_38;
      *(float *)(psVar1 + 0x12) = local_4c;
      *(float *)(psVar1 + 0x16) = local_44;
      *psVar1 = (short)iVar2;
      *(short *)(iVar12 + 0x478) = (short)iVar3;
      *(short *)(iVar12 + 0x484) = (short)iVar4;
      *(short *)(iVar12 + 0x492) = (short)iVar5;
      *(short *)(iVar12 + 0x490) = (short)iVar6;
      *(undefined4 *)(iVar12 + 0x494) = uVar7;
      *(float *)(iVar12 + 0x118) = local_58;
      *(float *)(iVar12 + 0x11c) = local_54;
      *(float *)(iVar12 + 0x120) = local_50;
    }
    else {
      FUN_8000e034((double)local_34,(double)local_30,(double)local_2c[0],psVar1 + 6,psVar1 + 8,
                   psVar1 + 10,iVar10);
      FUN_8000e034((double)local_40,(double)local_3c,(double)local_38,psVar1 + 0x40,psVar1 + 0x42,
                   psVar1 + 0x44,iVar10);
      FUN_8000dfa8((double)local_4c,(double)FLOAT_803e7ea4,(double)local_44,psVar1 + 0x12,auStack72,
                   psVar1 + 0x16,iVar10);
      sVar8 = FUN_8000dee8(iVar2,iVar10);
      *psVar1 = sVar8;
      uVar9 = FUN_8000dee8(iVar3,iVar10);
      *(undefined2 *)(iVar12 + 0x478) = uVar9;
      uVar9 = FUN_8000dee8(iVar4,iVar10);
      *(undefined2 *)(iVar12 + 0x484) = uVar9;
      uVar9 = FUN_8000dee8(iVar5,iVar10);
      *(undefined2 *)(iVar12 + 0x492) = uVar9;
      uVar9 = FUN_8000dee8(iVar6,iVar10);
      *(undefined2 *)(iVar12 + 0x490) = uVar9;
      uVar7 = FUN_8000dee8(uVar7,iVar10);
      *(undefined4 *)(iVar12 + 0x494) = uVar7;
      FUN_8000e034((double)local_58,(double)local_54,(double)local_50,iVar12 + 0x118,iVar12 + 0x11c,
                   iVar12 + 0x120,iVar10);
    }
    *(float *)(psVar1 + 0xc) = local_34;
    *(float *)(psVar1 + 0xe) = local_30;
    *(float *)(psVar1 + 0x10) = local_2c[0];
    *(float *)(psVar1 + 0x46) = local_40;
    *(float *)(psVar1 + 0x48) = local_3c;
    *(float *)(psVar1 + 0x4a) = local_38;
    *(undefined4 *)(*(int *)(psVar1 + 0x2a) + 0x10) = *(undefined4 *)(psVar1 + 6);
    *(undefined4 *)(*(int *)(psVar1 + 0x2a) + 0x14) = *(undefined4 *)(psVar1 + 8);
    *(undefined4 *)(*(int *)(psVar1 + 0x2a) + 0x18) = *(undefined4 *)(psVar1 + 10);
    *(undefined4 *)(*(int *)(psVar1 + 0x2a) + 0x1c) = *(undefined4 *)(psVar1 + 0xc);
    *(undefined4 *)(*(int *)(psVar1 + 0x2a) + 0x20) = *(undefined4 *)(psVar1 + 0xe);
    *(undefined4 *)(*(int *)(psVar1 + 0x2a) + 0x24) = *(undefined4 *)(psVar1 + 0x10);
    *(int *)(psVar1 + 0x18) = iVar10;
  }
  FUN_80286114();
  return;
}

