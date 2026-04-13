// Function: FUN_8008ec0c
// Entry: 8008ec0c
// Size: 928 bytes

void FUN_8008ec0c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  ushort uVar1;
  bool bVar2;
  uint uVar3;
  int iVar4;
  double dVar5;
  undefined4 *puVar6;
  byte bVar7;
  
  puVar6 = FUN_800e877c();
  if (param_11 != 0) {
    DAT_803dc270 = *(short *)(param_11 + 0x24) + -1;
    iRam803dc274 = DAT_803dc270;
    *(short *)(puVar6 + 3) = *(short *)(param_11 + 0x24) + -1;
    bVar7 = *(byte *)(param_11 + 0x58);
    bVar2 = (bVar7 & 0x80) != 0;
    if (*(char *)((&DAT_803dde04)[bVar2] + 0x317) == '\0') {
      FUN_8008cc80(param_11);
      if ((*(byte *)(param_11 + 0x58) & 0x40) != 0) {
        *(undefined *)((&DAT_803dde04)[bVar2] + 0x316) = 1;
      }
      *(ushort *)((&DAT_803dde04)[bVar2] + 4) = *(byte *)(param_11 + 0x58) | 0x100;
      *(undefined *)((&DAT_803dde04)[bVar2] + 0x315) = 1;
      *(float *)((&DAT_803dde04)[bVar2] + 0x304) = FLOAT_803dfd88;
    }
    else if ((bVar7 & 0x20) == 0) {
      *(ushort *)((&DAT_803dde04)[bVar2] + 4) = bVar7 | 0x100;
      *(undefined *)((&DAT_803dde04)[bVar2] + 0x315) = 1;
      *(float *)((&DAT_803dde04)[bVar2] + 0x304) = FLOAT_803dfd88;
      dVar5 = DOUBLE_803dfda8;
      for (bVar7 = 0; bVar7 < 0xb; bVar7 = bVar7 + 1) {
        uVar3 = (uint)bVar7;
        iVar4 = uVar3 * 4;
        *(float *)((&DAT_803dde04)[bVar2] + iVar4 + 0xf4) =
             (float)((double)CONCAT44(0x43300000,
                                      (uint)*(byte *)(param_11 + (byte)(&DAT_80310060)[uVar3] + 0xc)
                                     ) - dVar5);
        *(float *)((&DAT_803dde04)[bVar2] + iVar4 + 0x120) =
             (float)((double)CONCAT44(0x43300000,
                                      (uint)*(byte *)(param_11 + (byte)(&DAT_80310060)[uVar3] + 0x14
                                                     )) - dVar5);
        *(float *)((&DAT_803dde04)[bVar2] + iVar4 + 0x14c) =
             (float)((double)CONCAT44(0x43300000,
                                      (uint)*(byte *)(param_11 + (byte)(&DAT_80310060)[uVar3] + 0x1c
                                                     )) - dVar5);
        *(float *)((&DAT_803dde04)[bVar2] + iVar4 + 0x254) =
             (float)((double)CONCAT44(0x43300000,
                                      (uint)*(ushort *)
                                             (param_11 +
                                             (uint)(byte)(&DAT_80310060)[uVar3] * 2 + 0x3e)) - dVar5
                    );
        *(float *)((&DAT_803dde04)[bVar2] + iVar4 + 0x280) =
             (float)((double)CONCAT44(0x43300000,
                                      (uint)*(ushort *)
                                             (param_11 +
                                             (uint)(byte)(&DAT_80310060)[uVar3] * 2 + 0x2e)) - dVar5
                    );
      }
      *(uint *)((&DAT_803dde04)[bVar2] + 0x3c) = (uint)*(ushort *)(param_11 + 0x2a);
      *(uint *)((&DAT_803dde04)[bVar2] + 0x40) = (uint)*(ushort *)(param_11 + 0x2c);
      *(undefined *)((&DAT_803dde04)[bVar2] + 0x314) = 0xff;
      if ((*(byte *)(param_11 + 0x59) & 0x20) != 0) {
        uVar1 = *(ushort *)((&DAT_803dde04)[bVar2] + 6);
        if ((uVar1 & 0x20) == 0) {
          *(ushort *)((&DAT_803dde04)[bVar2] + 6) = uVar1 | 0x20;
        }
      }
      if ((*(byte *)(param_11 + 0x59) & 0x20) == 0) {
        uVar1 = *(ushort *)((&DAT_803dde04)[bVar2] + 6);
        if ((uVar1 & 0x20) != 0) {
          *(ushort *)((&DAT_803dde04)[bVar2] + 6) = uVar1 ^ 0x20;
        }
      }
      if ((*(byte *)(param_11 + 0x58) & 0x40) == 0) {
        uVar1 = *(ushort *)((&DAT_803dde04)[bVar2] + 6);
        if ((uVar1 & 0x40) != 0) {
          *(ushort *)((&DAT_803dde04)[bVar2] + 6) = uVar1 ^ 0x40;
        }
      }
      else {
        *(ushort *)((&DAT_803dde04)[bVar2] + 6) = *(ushort *)((&DAT_803dde04)[bVar2] + 6) | 0x40;
        *(undefined *)((&DAT_803dde04)[bVar2] + 0x316) = 1;
      }
      if ((*(byte *)(param_11 + 0x59) & 0x40) != 0) {
        uVar1 = *(ushort *)((&DAT_803dde04)[bVar2] + 6);
        if ((uVar1 & 0x40) == 0) {
          *(ushort *)((&DAT_803dde04)[bVar2] + 6) = uVar1 | 0x40;
          return;
        }
      }
      if ((*(byte *)(param_11 + 0x59) & 0x40) == 0) {
        uVar1 = *(ushort *)((&DAT_803dde04)[bVar2] + 6);
        if ((uVar1 & 0x40) != 0) {
          *(ushort *)((&DAT_803dde04)[bVar2] + 6) = uVar1 ^ 0x40;
        }
      }
    }
    else {
      FUN_80008cbc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,9,0,param_13,
                   param_14,param_15,param_16);
    }
  }
  return;
}

