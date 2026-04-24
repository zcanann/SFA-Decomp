// Function: FUN_80025ae4
// Entry: 80025ae4
// Size: 1108 bytes

void FUN_80025ae4(void)

{
  byte bVar1;
  ushort uVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  float *pfVar7;
  int *in_r6;
  int iVar8;
  ulonglong uVar9;
  undefined auStack56 [4];
  int local_34;
  int local_24;
  int local_20;
  
  uVar9 = FUN_802860dc();
  iVar4 = (int)(uVar9 >> 0x20);
  if (iVar4 == 0) {
    in_r6 = (int *)0x0;
  }
  else {
    FUN_80025880(iVar4,(int)uVar9,auStack56,0);
    iVar5 = FUN_80022e6c(in_r6 + 0x19);
    in_r6[3] = iVar5;
    iVar5 = iVar5 + (local_20 >> 1);
    in_r6[4] = iVar5;
    iVar5 = iVar5 + (local_20 >> 1);
    in_r6[0x17] = in_r6[3];
    if (((*(char *)(iVar4 + 0xf9) == '\0') && (*(int *)(iVar4 + 0xa4) == 0)) &&
       ((*(ushort *)(iVar4 + 2) & 0x10) == 0)) {
      iVar8 = *(int *)(iVar4 + 0x28);
      in_r6[8] = iVar8;
      in_r6[7] = iVar8;
    }
    else {
      iVar5 = FUN_80022e6c(iVar5);
      in_r6[7] = iVar5;
      iVar5 = FUN_80022e6c(iVar5 + (uint)*(ushort *)(iVar4 + 0xe4) * 6);
      in_r6[8] = iVar5;
      uVar2 = *(ushort *)(iVar4 + 0xe4);
      FUN_80003494(in_r6[7],*(undefined4 *)(iVar4 + 0x28));
      FUN_802419e8(in_r6[7],(uint)*(ushort *)(iVar4 + 0xe4) * 6);
      FUN_80003494(in_r6[8],*(undefined4 *)(iVar4 + 0x28),(uint)*(ushort *)(iVar4 + 0xe4) * 6);
      FUN_802419e8(in_r6[8],(uint)*(ushort *)(iVar4 + 0xe4) * 6);
      iVar5 = FUN_80022e6c(iVar5 + (uint)uVar2 * 6);
    }
    if (*(int *)(iVar4 + 200) == 0) {
      in_r6[9] = *(int *)(iVar4 + 0x2c);
    }
    else {
      if ((*(byte *)(iVar4 + 0x24) & 8) == 0) {
        iVar8 = 3;
      }
      else {
        iVar8 = 9;
      }
      iVar5 = FUN_80022e6c(iVar5);
      in_r6[9] = iVar5;
      uVar2 = *(ushort *)(iVar4 + 0xe6);
      FUN_80003494(in_r6[9],*(undefined4 *)(iVar4 + 0x2c));
      FUN_802419e8(in_r6[9],iVar8 * (uint)*(ushort *)(iVar4 + 0xe6));
      FUN_80022e6c(iVar5 + (uint)uVar2 * iVar8);
    }
    iVar5 = FUN_80022e24();
    in_r6[0xb] = iVar5;
    iVar8 = iVar5 + 0x68;
    if ((uVar9 & 0x80) != 0) {
      in_r6[0xc] = iVar8;
      iVar8 = iVar5 + 0xd0;
    }
    if ((*(ushort *)(iVar4 + 2) & 0x40) != 0) {
      iVar5 = FUN_80022e3c(iVar8);
      iVar6 = in_r6[0xb];
      *(int *)(iVar6 + 0x1c) = iVar5;
      *(int *)(iVar6 + 0x20) = iVar5 + local_24;
      iVar8 = iVar5 + local_24 + local_24;
      *(int *)(iVar6 + 0x24) = iVar8;
      iVar8 = iVar8 + local_24;
      *(int *)(iVar6 + 0x28) = iVar8;
      iVar8 = iVar8 + local_24;
      iVar5 = in_r6[0xc];
      if (iVar5 != 0) {
        *(int *)(iVar5 + 0x1c) = iVar8;
        *(int *)(iVar5 + 0x20) = iVar8 + local_24;
        iVar8 = iVar8 + local_24 + local_24;
        *(int *)(iVar5 + 0x24) = iVar8;
        iVar8 = iVar8 + local_24;
        *(int *)(iVar5 + 0x28) = iVar8;
        iVar8 = iVar8 + local_24;
      }
    }
    if (*(char *)(iVar4 + 0xf9) != '\0') {
      iVar8 = FUN_80022e24(iVar8);
      in_r6[10] = iVar8;
      iVar8 = iVar8 + 0x30;
      pfVar7 = (float *)in_r6[10];
      *(undefined *)(pfVar7 + 3) = 0xff;
      *(undefined *)((int)pfVar7 + 0xd) = 0xff;
      fVar3 = FLOAT_803de828;
      *pfVar7 = FLOAT_803de828;
      pfVar7[1] = fVar3;
      pfVar7[2] = fVar3;
      iVar5 = in_r6[10];
      *(undefined *)(iVar5 + 0x1c) = 0xff;
      *(undefined *)(iVar5 + 0x1d) = 0xff;
      *(float *)(iVar5 + 0x10) = fVar3;
      *(float *)(iVar5 + 0x14) = fVar3;
      *(float *)(iVar5 + 0x18) = fVar3;
      iVar5 = in_r6[10];
      *(undefined *)(iVar5 + 0x2c) = 0xff;
      *(undefined *)(iVar5 + 0x2d) = 0xff;
      *(float *)(iVar5 + 0x20) = fVar3;
      *(float *)(iVar5 + 0x24) = fVar3;
      *(float *)(iVar5 + 0x28) = fVar3;
    }
    if (0 < local_34) {
      iVar8 = FUN_80022e24(iVar8);
      in_r6[0x12] = iVar8;
      iVar8 = iVar8 + (uint)*(byte *)(iVar4 + 0xf7) * 0x10;
      in_r6[0x13] = iVar8;
      iVar8 = iVar8 + (uint)*(byte *)(iVar4 + 0xf7) * 0x10;
      in_r6[0x14] = in_r6[0x12];
    }
    if (((*(int *)(iVar4 + 0x3c) == 0) || (*(char *)(iVar4 + 0xf3) == '\0')) ||
       ((*(int *)(iVar4 + 0x18) == 0 || (*(int *)(iVar4 + 0x1c) == 0)))) {
      in_r6[5] = 0;
    }
    else {
      iVar5 = FUN_80022e24(iVar8);
      in_r6[5] = iVar5;
      *(int *)in_r6[5] = iVar5 + 0x1c;
      iVar8 = iVar5 + 0x1c + (uint)*(byte *)(iVar4 + 0xf3) * 0xc;
      *(int *)(in_r6[5] + 4) = iVar8;
      iVar8 = iVar8 + (uint)*(byte *)(iVar4 + 0xf3) * 4;
      *(int *)(in_r6[5] + 8) = iVar8;
      iVar8 = iVar8 + (uint)*(byte *)(iVar4 + 0xf3) * 4;
      *(int *)(in_r6[5] + 0xc) = iVar8;
      iVar8 = iVar8 + (uint)*(byte *)(iVar4 + 0xf3) * 4;
      *(int *)(in_r6[5] + 0x10) = iVar8;
      iVar8 = iVar8 + (uint)*(byte *)(iVar4 + 0xf3) * 4;
      *(int *)(in_r6[5] + 0x18) = iVar8;
      iVar8 = iVar8 + (uint)*(byte *)(iVar4 + 0xf3);
    }
    if (*(int *)(iVar4 + 0xa4) != 0) {
      iVar8 = FUN_80022e24(iVar8);
      in_r6[0x10] = iVar8;
      iVar8 = iVar8 + (uint)*(ushort *)(iVar4 + 0x8a) * 4;
    }
    if (*(int *)(iVar4 + 200) != 0) {
      iVar8 = FUN_80022e24(iVar8);
      in_r6[0x11] = iVar8;
      iVar8 = iVar8 + (uint)*(ushort *)(iVar4 + 0xae) * 4;
    }
    iVar5 = FUN_80022e24(iVar8);
    in_r6[0xd] = iVar5;
    bVar1 = *(byte *)(iVar4 + 0xf8);
    iVar8 = 0;
    for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(iVar4 + 0xf8); iVar6 = iVar6 + 1) {
      *(undefined *)(in_r6[0xd] + iVar8 + 8) = 0;
      iVar8 = iVar8 + 0xc;
    }
    if ((uVar9 & 0x8000) != 0) {
      iVar5 = FUN_80022e0c(iVar5 + (uint)bVar1 * 0xc);
      in_r6[0x15] = iVar5;
      *(undefined *)(in_r6[0x15] + 0x18) = 0;
    }
    in_r6[0x16] = 0;
    *in_r6 = iVar4;
    *(undefined *)(in_r6 + 0x18) = 0;
  }
  FUN_80286128(in_r6);
  return;
}

