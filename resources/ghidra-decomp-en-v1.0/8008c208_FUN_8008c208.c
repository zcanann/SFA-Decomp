// Function: FUN_8008c208
// Entry: 8008c208
// Size: 1900 bytes

void FUN_8008c208(undefined4 param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  float fVar2;
  double dVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  undefined4 uVar9;
  int iVar10;
  int iVar11;
  
  iVar5 = FUN_800e84f8();
  if ((param_3 != 0) && ((*(byte *)(param_3 + 0x58) & 2) != 0)) {
    switch(*(undefined2 *)(param_3 + 0x54)) {
    default:
      uVar4 = 0xf;
      break;
    case 1:
      uVar4 = 1;
      break;
    case 2:
      uVar4 = 2;
      break;
    case 3:
      uVar4 = 4;
      break;
    case 4:
      uVar4 = 5;
      break;
    case 5:
      uVar4 = 3;
      break;
    case 6:
      uVar4 = 6;
    }
    iVar8 = 0;
    iVar6 = 0;
    iVar11 = 2;
    do {
      if ((uVar4 & 1 << iVar8) != 0) {
        *(short *)(iVar5 + 4) = *(short *)(param_3 + 0x24) + -1;
        dVar3 = DOUBLE_803df070;
        *(float *)(DAT_803dd12c + iVar6 + 0x20) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0xc)) - DOUBLE_803df070);
        *(float *)(DAT_803dd12c + iVar6 + 0x24) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0xc)) - dVar3);
        *(float *)(DAT_803dd12c + iVar6 + 0x28) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0xd)) - dVar3);
        *(float *)(DAT_803dd12c + iVar6 + 0x2c) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0xe)) - dVar3);
        *(float *)(DAT_803dd12c + iVar6 + 0x30) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0xf)) - dVar3);
        *(float *)(DAT_803dd12c + iVar6 + 0x34) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0xc)) - dVar3);
        *(float *)(DAT_803dd12c + iVar6 + 0x38) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0xc)) - dVar3);
        *(float *)(DAT_803dd12c + iVar6 + 0x3c) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0x14)) - dVar3);
        *(float *)(DAT_803dd12c + iVar6 + 0x40) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0x14)) - dVar3);
        *(float *)(DAT_803dd12c + iVar6 + 0x44) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0x15)) - dVar3);
        *(float *)(DAT_803dd12c + iVar6 + 0x48) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0x16)) - dVar3);
        *(float *)(DAT_803dd12c + iVar6 + 0x4c) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0x17)) - dVar3);
        *(float *)(DAT_803dd12c + iVar6 + 0x50) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0x14)) - dVar3);
        *(float *)(DAT_803dd12c + iVar6 + 0x54) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0x14)) - dVar3);
        *(float *)(DAT_803dd12c + iVar6 + 0x58) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0x1c)) - dVar3);
        *(float *)(DAT_803dd12c + iVar6 + 0x5c) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0x1c)) - dVar3);
        *(float *)(DAT_803dd12c + iVar6 + 0x60) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0x1d)) - dVar3);
        *(float *)(DAT_803dd12c + iVar6 + 100) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0x1e)) - dVar3);
        *(float *)(DAT_803dd12c + iVar6 + 0x68) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0x1f)) - dVar3);
        *(float *)(DAT_803dd12c + iVar6 + 0x6c) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0x1c)) - dVar3);
        *(float *)(DAT_803dd12c + iVar6 + 0x70) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0x1c)) - dVar3);
        fVar2 = FLOAT_803df05c;
        *(float *)(DAT_803dd12c + iVar6 + 0xb8) = FLOAT_803df05c;
        if (*(ushort *)(param_3 + 0x2a) == 0) {
          *(float *)(DAT_803dd12c + iVar6 + 0xb4) = fVar2;
        }
        else {
          *(float *)(DAT_803dd12c + iVar6 + 0xb4) =
               fVar2 / (FLOAT_803df104 *
                       (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_3 + 0x2a)) -
                              dVar3));
        }
        iVar10 = DAT_803dd12c + iVar6;
        if (DAT_803dd12c == 0) {
          *(undefined *)(iVar10 + 0x76) = 0xff;
          *(undefined *)(iVar10 + 0x75) = 0xff;
          *(undefined *)(iVar10 + 0x74) = 0xff;
        }
        else {
          *(undefined *)(iVar10 + 0x74) = *(undefined *)(iVar10 + 0x78);
          *(undefined *)(iVar10 + 0x75) = *(undefined *)(DAT_803dd12c + iVar6 + 0x79);
          *(undefined *)(iVar10 + 0x76) = *(undefined *)(DAT_803dd12c + iVar6 + 0x7a);
        }
        if (*(byte *)(param_3 + 0x5d) == 0) {
          *(byte *)(DAT_803dd12c + iVar6 + 0xc1) = *(byte *)(DAT_803dd12c + iVar6 + 0xc1) & 0xe7;
        }
        else {
          *(byte *)(DAT_803dd12c + iVar6 + 0xc1) =
               ((*(byte *)(param_3 + 0x5d) & 1) + 1) * '\b' & 0x18 |
               *(byte *)(DAT_803dd12c + iVar6 + 0xc1) & 0xe7;
        }
      }
      iVar5 = iVar5 + 2;
      iVar6 = iVar6 + 0xa4;
      iVar8 = iVar8 + 1;
      iVar11 = iVar11 + -1;
    } while (iVar11 != 0);
    if (*(byte *)(param_3 + 0x5d) != 0) {
      FUN_80088c94(uVar4,2 < *(byte *)(param_3 + 0x5d));
    }
    uVar7 = *(ushort *)(param_3 + 0x56) & 0xff;
    if ((uVar4 & 1) != 0) {
      *(byte *)(DAT_803dd12c + 0xc1) =
           (byte)(uVar7 << 5) & 0x20 | *(byte *)(DAT_803dd12c + 0xc1) & 0xdf;
    }
    if ((uVar4 & 2) != 0) {
      *(byte *)(DAT_803dd12c + 0x165) =
           (byte)(uVar7 << 5) & 0x20 | *(byte *)(DAT_803dd12c + 0x165) & 0xdf;
    }
    *(byte *)(DAT_803dd12c + 0x209) =
         (byte)((*(byte *)(DAT_803dd12c + (uint)*(byte *)(DAT_803dd12c + 0x24c) * 0xa4 + 0xc1) >> 5
                & 1) << 5) | *(byte *)(DAT_803dd12c + 0x209) & 0xdf;
    if ((*(byte *)(param_3 + 0x58) & 1) == 0) {
      *(uint *)(DAT_803dd12c + 0x21c) = *(ushort *)(param_3 + 0x2e) + 0xc38;
      *(uint *)(DAT_803dd12c + 0x220) = *(ushort *)(param_3 + 0x30) + 0xc38;
      *(uint *)(DAT_803dd12c + 0x224) = *(ushort *)(param_3 + 0x32) + 0xc38;
      *(uint *)(DAT_803dd12c + 0x228) = *(ushort *)(param_3 + 0x34) + 0xc38;
      *(uint *)(DAT_803dd12c + 0x22c) = *(ushort *)(param_3 + 0x3e) + 0xc38;
      *(uint *)(DAT_803dd12c + 0x230) = *(ushort *)(param_3 + 0x40) + 0xc38;
      *(uint *)(DAT_803dd12c + 0x234) = *(ushort *)(param_3 + 0x42) + 0xc38;
      *(uint *)(DAT_803dd12c + 0x238) = *(ushort *)(param_3 + 0x44) + 0xc38;
      uVar9 = *(undefined4 *)(DAT_803dd12c + 0x10);
      *(undefined4 *)(DAT_803dd12c + 0x10) =
           *(undefined4 *)(DAT_803dd12c + (uint)*(byte *)(DAT_803dd12c + 0x251) * 4 + 8);
      *(undefined4 *)(DAT_803dd12c + (uint)*(byte *)(DAT_803dd12c + 0x251) * 4 + 8) = uVar9;
      *(undefined *)(DAT_803dd12c + 0x250) = 0xff;
      fVar2 = FLOAT_803df05c;
      if (*(char *)(DAT_803dd12c + 0x255) < '\0') {
        *(float *)(DAT_803dd12c + 0x23c) = FLOAT_803df05c;
        if (*(ushort *)(param_3 + 0x2a) == 0) {
          *(float *)(DAT_803dd12c + 0x240) = fVar2;
        }
        else {
          *(float *)(DAT_803dd12c + 0x240) =
               fVar2 / (FLOAT_803df104 *
                       (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_3 + 0x2a)) -
                              DOUBLE_803df070));
        }
      }
      else {
        *(float *)(DAT_803dd12c + 0x23c) = FLOAT_803df058;
      }
    }
    bVar1 = *(byte *)(DAT_803dd12c + (uint)*(byte *)(DAT_803dd12c + 0x24c) * 0xa4 + 0xc1) >> 3;
    if ((bVar1 & 3) != 0) {
      FUN_8005cef0((bVar1 & 3) - 1);
    }
    *(byte *)(DAT_803dd12c + 0x209) =
         *(byte *)(DAT_803dd12c + (uint)*(byte *)(DAT_803dd12c + 0x24c) * 0xa4 + 0xc1) & 0x80 |
         *(byte *)(DAT_803dd12c + 0x209) & 0x7f;
    *(byte *)(DAT_803dd12c + 0x209) =
         (byte)((*(byte *)(DAT_803dd12c + (uint)*(byte *)(DAT_803dd12c + 0x24c) * 0xa4 + 0xc1) >> 5
                & 1) << 5) | *(byte *)(DAT_803dd12c + 0x209) & 0xdf;
    iVar5 = FUN_800e84f8();
    iVar6 = FUN_800e87c4();
    if (iVar6 == 0) {
      if (*(char *)(DAT_803dd12c + 0xc1) < '\0') {
        *(byte *)(iVar5 + 0x40) = *(byte *)(iVar5 + 0x40) | 2;
      }
      else {
        *(byte *)(iVar5 + 0x40) = *(byte *)(iVar5 + 0x40) & 0xfd;
      }
      if (*(char *)(DAT_803dd12c + 0x165) < '\0') {
        *(byte *)(iVar5 + 0x40) = *(byte *)(iVar5 + 0x40) | 4;
      }
      else {
        *(byte *)(iVar5 + 0x40) = *(byte *)(iVar5 + 0x40) & 0xfb;
      }
    }
  }
  return;
}

