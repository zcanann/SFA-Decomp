// Function: FUN_8008e980
// Entry: 8008e980
// Size: 928 bytes

void FUN_8008e980(undefined4 param_1,undefined4 param_2,int param_3)

{
  bool bVar1;
  ushort uVar2;
  uint uVar3;
  double dVar4;
  int iVar5;
  byte bVar6;
  undefined4 uVar7;
  
  uVar7 = 0;
  iVar5 = FUN_800e84f8();
  if (param_3 != 0) {
    DAT_803db610 = *(short *)(param_3 + 0x24) + -1;
    iRam803db614 = DAT_803db610;
    *(short *)(iVar5 + 0xc) = *(short *)(param_3 + 0x24) + -1;
    bVar6 = *(byte *)(param_3 + 0x58);
    bVar1 = (bVar6 & 0x80) != 0;
    if (*(char *)((&DAT_803dd184)[bVar1] + 0x317) == '\0') {
      if ((bVar6 & 0x40) != 0) {
        uVar7 = 0x40;
      }
      FUN_8008c9f4(param_3,uVar7);
      if ((*(byte *)(param_3 + 0x58) & 0x40) != 0) {
        *(undefined *)((&DAT_803dd184)[bVar1] + 0x316) = 1;
      }
      *(ushort *)((&DAT_803dd184)[bVar1] + 4) = *(byte *)(param_3 + 0x58) | 0x100;
      *(undefined *)((&DAT_803dd184)[bVar1] + 0x315) = 1;
      *(float *)((&DAT_803dd184)[bVar1] + 0x304) = FLOAT_803df108;
    }
    else if ((bVar6 & 0x20) == 0) {
      *(ushort *)((&DAT_803dd184)[bVar1] + 4) = bVar6 | 0x100;
      *(undefined *)((&DAT_803dd184)[bVar1] + 0x315) = 1;
      *(float *)((&DAT_803dd184)[bVar1] + 0x304) = FLOAT_803df108;
      dVar4 = DOUBLE_803df128;
      for (bVar6 = 0; bVar6 < 0xb; bVar6 = bVar6 + 1) {
        uVar3 = (uint)bVar6;
        iVar5 = uVar3 * 4;
        *(float *)((&DAT_803dd184)[bVar1] + iVar5 + 0xf4) =
             (float)((double)CONCAT44(0x43300000,
                                      (uint)*(byte *)(param_3 + (byte)(&DAT_8030f4a0)[uVar3] + 0xc))
                    - dVar4);
        *(float *)((&DAT_803dd184)[bVar1] + iVar5 + 0x120) =
             (float)((double)CONCAT44(0x43300000,
                                      (uint)*(byte *)(param_3 + (byte)(&DAT_8030f4a0)[uVar3] + 0x14)
                                     ) - dVar4);
        *(float *)((&DAT_803dd184)[bVar1] + iVar5 + 0x14c) =
             (float)((double)CONCAT44(0x43300000,
                                      (uint)*(byte *)(param_3 + (byte)(&DAT_8030f4a0)[uVar3] + 0x1c)
                                     ) - dVar4);
        *(float *)((&DAT_803dd184)[bVar1] + iVar5 + 0x254) =
             (float)((double)CONCAT44(0x43300000,
                                      (uint)*(ushort *)
                                             (param_3 +
                                             (uint)(byte)(&DAT_8030f4a0)[uVar3] * 2 + 0x3e)) - dVar4
                    );
        *(float *)((&DAT_803dd184)[bVar1] + iVar5 + 0x280) =
             (float)((double)CONCAT44(0x43300000,
                                      (uint)*(ushort *)
                                             (param_3 +
                                             (uint)(byte)(&DAT_8030f4a0)[uVar3] * 2 + 0x2e)) - dVar4
                    );
      }
      *(uint *)((&DAT_803dd184)[bVar1] + 0x3c) = (uint)*(ushort *)(param_3 + 0x2a);
      *(uint *)((&DAT_803dd184)[bVar1] + 0x40) = (uint)*(ushort *)(param_3 + 0x2c);
      *(undefined *)((&DAT_803dd184)[bVar1] + 0x314) = 0xff;
      if ((*(byte *)(param_3 + 0x59) & 0x20) != 0) {
        uVar2 = *(ushort *)((&DAT_803dd184)[bVar1] + 6);
        if ((uVar2 & 0x20) == 0) {
          *(ushort *)((&DAT_803dd184)[bVar1] + 6) = uVar2 | 0x20;
        }
      }
      if ((*(byte *)(param_3 + 0x59) & 0x20) == 0) {
        uVar2 = *(ushort *)((&DAT_803dd184)[bVar1] + 6);
        if ((uVar2 & 0x20) != 0) {
          *(ushort *)((&DAT_803dd184)[bVar1] + 6) = uVar2 ^ 0x20;
        }
      }
      if ((*(byte *)(param_3 + 0x58) & 0x40) == 0) {
        uVar2 = *(ushort *)((&DAT_803dd184)[bVar1] + 6);
        if ((uVar2 & 0x40) != 0) {
          *(ushort *)((&DAT_803dd184)[bVar1] + 6) = uVar2 ^ 0x40;
        }
      }
      else {
        *(ushort *)((&DAT_803dd184)[bVar1] + 6) = *(ushort *)((&DAT_803dd184)[bVar1] + 6) | 0x40;
        *(undefined *)((&DAT_803dd184)[bVar1] + 0x316) = 1;
      }
      if ((*(byte *)(param_3 + 0x59) & 0x40) != 0) {
        uVar2 = *(ushort *)((&DAT_803dd184)[bVar1] + 6);
        if ((uVar2 & 0x40) == 0) {
          *(ushort *)((&DAT_803dd184)[bVar1] + 6) = uVar2 | 0x40;
          return;
        }
      }
      if ((*(byte *)(param_3 + 0x59) & 0x40) == 0) {
        uVar2 = *(ushort *)((&DAT_803dd184)[bVar1] + 6);
        if ((uVar2 & 0x40) != 0) {
          *(ushort *)((&DAT_803dd184)[bVar1] + 6) = uVar2 ^ 0x40;
        }
      }
    }
    else {
      FUN_80008cbc(0,0,9,0);
    }
  }
  return;
}

