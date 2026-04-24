// Function: FUN_80025ba8
// Entry: 80025ba8
// Size: 1108 bytes

void FUN_80025ba8(void)

{
  byte bVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  float *pfVar7;
  int iVar8;
  int *in_r6;
  ulonglong uVar9;
  int iStack_38;
  int local_34;
  int local_24;
  int local_20;
  
  uVar9 = FUN_80286840();
  iVar3 = (int)(uVar9 >> 0x20);
  if (iVar3 != 0) {
    FUN_80025944(iVar3,(uint)uVar9,&iStack_38,0);
    uVar4 = FUN_80022f30((uint)(in_r6 + 0x19));
    in_r6[3] = uVar4;
    iVar5 = uVar4 + (local_20 >> 1);
    in_r6[4] = iVar5;
    uVar4 = iVar5 + (local_20 >> 1);
    in_r6[0x17] = in_r6[3];
    if (((*(char *)(iVar3 + 0xf9) == '\0') && (*(int *)(iVar3 + 0xa4) == 0)) &&
       ((*(ushort *)(iVar3 + 2) & 0x10) == 0)) {
      iVar5 = *(int *)(iVar3 + 0x28);
      in_r6[8] = iVar5;
      in_r6[7] = iVar5;
    }
    else {
      uVar4 = FUN_80022f30(uVar4);
      in_r6[7] = uVar4;
      uVar4 = FUN_80022f30(uVar4 + (uint)*(ushort *)(iVar3 + 0xe4) * 6);
      in_r6[8] = uVar4;
      iVar5 = (uint)*(ushort *)(iVar3 + 0xe4) * 6;
      FUN_80003494(in_r6[7],*(uint *)(iVar3 + 0x28),iVar5);
      FUN_802420e0(in_r6[7],(uint)*(ushort *)(iVar3 + 0xe4) * 6);
      FUN_80003494(in_r6[8],*(uint *)(iVar3 + 0x28),(uint)*(ushort *)(iVar3 + 0xe4) * 6);
      FUN_802420e0(in_r6[8],(uint)*(ushort *)(iVar3 + 0xe4) * 6);
      uVar4 = FUN_80022f30(uVar4 + iVar5);
    }
    if (*(int *)(iVar3 + 200) == 0) {
      in_r6[9] = *(int *)(iVar3 + 0x2c);
    }
    else {
      if ((*(byte *)(iVar3 + 0x24) & 8) == 0) {
        iVar5 = 3;
      }
      else {
        iVar5 = 9;
      }
      uVar4 = FUN_80022f30(uVar4);
      in_r6[9] = uVar4;
      iVar8 = (uint)*(ushort *)(iVar3 + 0xe6) * iVar5;
      FUN_80003494(in_r6[9],*(uint *)(iVar3 + 0x2c),iVar8);
      FUN_802420e0(in_r6[9],iVar5 * (uint)*(ushort *)(iVar3 + 0xe6));
      uVar4 = FUN_80022f30(uVar4 + iVar8);
    }
    uVar4 = FUN_80022ee8(uVar4);
    in_r6[0xb] = uVar4;
    uVar6 = uVar4 + 0x68;
    if ((uVar9 & 0x80) != 0) {
      in_r6[0xc] = uVar6;
      uVar6 = uVar4 + 0xd0;
    }
    if ((*(ushort *)(iVar3 + 2) & 0x40) != 0) {
      uVar4 = FUN_80022f00(uVar6);
      iVar8 = in_r6[0xb];
      *(uint *)(iVar8 + 0x1c) = uVar4;
      *(uint *)(iVar8 + 0x20) = uVar4 + local_24;
      iVar5 = uVar4 + local_24 + local_24;
      *(int *)(iVar8 + 0x24) = iVar5;
      iVar5 = iVar5 + local_24;
      *(int *)(iVar8 + 0x28) = iVar5;
      uVar6 = iVar5 + local_24;
      iVar5 = in_r6[0xc];
      if (iVar5 != 0) {
        *(uint *)(iVar5 + 0x1c) = uVar6;
        *(uint *)(iVar5 + 0x20) = uVar6 + local_24;
        iVar8 = uVar6 + local_24 + local_24;
        *(int *)(iVar5 + 0x24) = iVar8;
        iVar8 = iVar8 + local_24;
        *(int *)(iVar5 + 0x28) = iVar8;
        uVar6 = iVar8 + local_24;
      }
    }
    if (*(char *)(iVar3 + 0xf9) != '\0') {
      uVar6 = FUN_80022ee8(uVar6);
      in_r6[10] = uVar6;
      uVar6 = uVar6 + 0x30;
      pfVar7 = (float *)in_r6[10];
      *(undefined *)(pfVar7 + 3) = 0xff;
      *(undefined *)((int)pfVar7 + 0xd) = 0xff;
      fVar2 = FLOAT_803df4a8;
      *pfVar7 = FLOAT_803df4a8;
      pfVar7[1] = fVar2;
      pfVar7[2] = fVar2;
      iVar5 = in_r6[10];
      *(undefined *)(iVar5 + 0x1c) = 0xff;
      *(undefined *)(iVar5 + 0x1d) = 0xff;
      *(float *)(iVar5 + 0x10) = fVar2;
      *(float *)(iVar5 + 0x14) = fVar2;
      *(float *)(iVar5 + 0x18) = fVar2;
      iVar5 = in_r6[10];
      *(undefined *)(iVar5 + 0x2c) = 0xff;
      *(undefined *)(iVar5 + 0x2d) = 0xff;
      *(float *)(iVar5 + 0x20) = fVar2;
      *(float *)(iVar5 + 0x24) = fVar2;
      *(float *)(iVar5 + 0x28) = fVar2;
    }
    if (0 < local_34) {
      uVar4 = FUN_80022ee8(uVar6);
      in_r6[0x12] = uVar4;
      iVar5 = uVar4 + (uint)*(byte *)(iVar3 + 0xf7) * 0x10;
      in_r6[0x13] = iVar5;
      uVar6 = iVar5 + (uint)*(byte *)(iVar3 + 0xf7) * 0x10;
      in_r6[0x14] = in_r6[0x12];
    }
    if (((*(int *)(iVar3 + 0x3c) == 0) || (*(char *)(iVar3 + 0xf3) == '\0')) ||
       ((*(int *)(iVar3 + 0x18) == 0 || (*(int *)(iVar3 + 0x1c) == 0)))) {
      in_r6[5] = 0;
    }
    else {
      uVar4 = FUN_80022ee8(uVar6);
      in_r6[5] = uVar4;
      *(uint *)in_r6[5] = uVar4 + 0x1c;
      iVar5 = uVar4 + 0x1c + (uint)*(byte *)(iVar3 + 0xf3) * 0xc;
      *(int *)(in_r6[5] + 4) = iVar5;
      iVar5 = iVar5 + (uint)*(byte *)(iVar3 + 0xf3) * 4;
      *(int *)(in_r6[5] + 8) = iVar5;
      iVar5 = iVar5 + (uint)*(byte *)(iVar3 + 0xf3) * 4;
      *(int *)(in_r6[5] + 0xc) = iVar5;
      iVar5 = iVar5 + (uint)*(byte *)(iVar3 + 0xf3) * 4;
      *(int *)(in_r6[5] + 0x10) = iVar5;
      iVar5 = iVar5 + (uint)*(byte *)(iVar3 + 0xf3) * 4;
      *(int *)(in_r6[5] + 0x18) = iVar5;
      uVar6 = iVar5 + (uint)*(byte *)(iVar3 + 0xf3);
    }
    if (*(int *)(iVar3 + 0xa4) != 0) {
      uVar6 = FUN_80022ee8(uVar6);
      in_r6[0x10] = uVar6;
      uVar6 = uVar6 + (uint)*(ushort *)(iVar3 + 0x8a) * 4;
    }
    if (*(int *)(iVar3 + 200) != 0) {
      uVar6 = FUN_80022ee8(uVar6);
      in_r6[0x11] = uVar6;
      uVar6 = uVar6 + (uint)*(ushort *)(iVar3 + 0xae) * 4;
    }
    uVar4 = FUN_80022ee8(uVar6);
    in_r6[0xd] = uVar4;
    bVar1 = *(byte *)(iVar3 + 0xf8);
    iVar5 = 0;
    for (iVar8 = 0; iVar8 < (int)(uint)*(byte *)(iVar3 + 0xf8); iVar8 = iVar8 + 1) {
      *(undefined *)(in_r6[0xd] + iVar5 + 8) = 0;
      iVar5 = iVar5 + 0xc;
    }
    if ((uVar9 & 0x8000) != 0) {
      uVar4 = FUN_80022ed0(uVar4 + (uint)bVar1 * 0xc);
      in_r6[0x15] = uVar4;
      *(undefined *)(in_r6[0x15] + 0x18) = 0;
    }
    in_r6[0x16] = 0;
    *in_r6 = iVar3;
    *(undefined *)(in_r6 + 0x18) = 0;
  }
  FUN_8028688c();
  return;
}

