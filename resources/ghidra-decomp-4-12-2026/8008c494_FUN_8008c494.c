// Function: FUN_8008c494
// Entry: 8008c494
// Size: 1900 bytes

void FUN_8008c494(undefined4 param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  float fVar2;
  double dVar3;
  uint uVar4;
  undefined4 *puVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  undefined4 uVar9;
  int iVar10;
  int iVar11;
  
  puVar5 = FUN_800e877c();
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
        *(short *)(puVar5 + 1) = *(short *)(param_3 + 0x24) + -1;
        dVar3 = DOUBLE_803dfcf0;
        *(float *)(DAT_803dddac + iVar6 + 0x20) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0xc)) - DOUBLE_803dfcf0);
        *(float *)(DAT_803dddac + iVar6 + 0x24) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0xc)) - dVar3);
        *(float *)(DAT_803dddac + iVar6 + 0x28) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0xd)) - dVar3);
        *(float *)(DAT_803dddac + iVar6 + 0x2c) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0xe)) - dVar3);
        *(float *)(DAT_803dddac + iVar6 + 0x30) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0xf)) - dVar3);
        *(float *)(DAT_803dddac + iVar6 + 0x34) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0xc)) - dVar3);
        *(float *)(DAT_803dddac + iVar6 + 0x38) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0xc)) - dVar3);
        *(float *)(DAT_803dddac + iVar6 + 0x3c) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0x14)) - dVar3);
        *(float *)(DAT_803dddac + iVar6 + 0x40) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0x14)) - dVar3);
        *(float *)(DAT_803dddac + iVar6 + 0x44) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0x15)) - dVar3);
        *(float *)(DAT_803dddac + iVar6 + 0x48) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0x16)) - dVar3);
        *(float *)(DAT_803dddac + iVar6 + 0x4c) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0x17)) - dVar3);
        *(float *)(DAT_803dddac + iVar6 + 0x50) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0x14)) - dVar3);
        *(float *)(DAT_803dddac + iVar6 + 0x54) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0x14)) - dVar3);
        *(float *)(DAT_803dddac + iVar6 + 0x58) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0x1c)) - dVar3);
        *(float *)(DAT_803dddac + iVar6 + 0x5c) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0x1c)) - dVar3);
        *(float *)(DAT_803dddac + iVar6 + 0x60) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0x1d)) - dVar3);
        *(float *)(DAT_803dddac + iVar6 + 100) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0x1e)) - dVar3);
        *(float *)(DAT_803dddac + iVar6 + 0x68) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0x1f)) - dVar3);
        *(float *)(DAT_803dddac + iVar6 + 0x6c) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0x1c)) - dVar3);
        *(float *)(DAT_803dddac + iVar6 + 0x70) =
             (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0x1c)) - dVar3);
        fVar2 = FLOAT_803dfcdc;
        *(float *)(DAT_803dddac + iVar6 + 0xb8) = FLOAT_803dfcdc;
        if (*(ushort *)(param_3 + 0x2a) == 0) {
          *(float *)(DAT_803dddac + iVar6 + 0xb4) = fVar2;
        }
        else {
          *(float *)(DAT_803dddac + iVar6 + 0xb4) =
               fVar2 / (FLOAT_803dfd84 *
                       (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_3 + 0x2a)) -
                              dVar3));
        }
        iVar10 = DAT_803dddac + iVar6;
        if (DAT_803dddac == 0) {
          *(undefined *)(iVar10 + 0x76) = 0xff;
          *(undefined *)(iVar10 + 0x75) = 0xff;
          *(undefined *)(iVar10 + 0x74) = 0xff;
        }
        else {
          *(undefined *)(iVar10 + 0x74) = *(undefined *)(iVar10 + 0x78);
          *(undefined *)(iVar10 + 0x75) = *(undefined *)(DAT_803dddac + iVar6 + 0x79);
          *(undefined *)(iVar10 + 0x76) = *(undefined *)(DAT_803dddac + iVar6 + 0x7a);
        }
        if (*(byte *)(param_3 + 0x5d) == 0) {
          *(byte *)(DAT_803dddac + iVar6 + 0xc1) = *(byte *)(DAT_803dddac + iVar6 + 0xc1) & 0xe7;
        }
        else {
          *(byte *)(DAT_803dddac + iVar6 + 0xc1) =
               ((*(byte *)(param_3 + 0x5d) & 1) + 1) * '\b' |
               *(byte *)(DAT_803dddac + iVar6 + 0xc1) & 0xe7;
        }
      }
      puVar5 = (undefined4 *)((int)puVar5 + 2);
      iVar6 = iVar6 + 0xa4;
      iVar8 = iVar8 + 1;
      iVar11 = iVar11 + -1;
    } while (iVar11 != 0);
    if (*(byte *)(param_3 + 0x5d) != 0) {
      FUN_80088f20(uVar4,2 < *(byte *)(param_3 + 0x5d));
    }
    uVar7 = *(ushort *)(param_3 + 0x56) & 0xff;
    if ((uVar4 & 1) != 0) {
      *(byte *)(DAT_803dddac + 0xc1) =
           (byte)(uVar7 << 5) & 0x20 | *(byte *)(DAT_803dddac + 0xc1) & 0xdf;
    }
    if ((uVar4 & 2) != 0) {
      *(byte *)(DAT_803dddac + 0x165) =
           (byte)(uVar7 << 5) & 0x20 | *(byte *)(DAT_803dddac + 0x165) & 0xdf;
    }
    *(byte *)(DAT_803dddac + 0x209) =
         (byte)((*(byte *)(DAT_803dddac + (uint)*(byte *)(DAT_803dddac + 0x24c) * 0xa4 + 0xc1) >> 5
                & 1) << 5) | *(byte *)(DAT_803dddac + 0x209) & 0xdf;
    if ((*(byte *)(param_3 + 0x58) & 1) == 0) {
      *(uint *)(DAT_803dddac + 0x21c) = *(ushort *)(param_3 + 0x2e) + 0xc38;
      *(uint *)(DAT_803dddac + 0x220) = *(ushort *)(param_3 + 0x30) + 0xc38;
      *(uint *)(DAT_803dddac + 0x224) = *(ushort *)(param_3 + 0x32) + 0xc38;
      *(uint *)(DAT_803dddac + 0x228) = *(ushort *)(param_3 + 0x34) + 0xc38;
      *(uint *)(DAT_803dddac + 0x22c) = *(ushort *)(param_3 + 0x3e) + 0xc38;
      *(uint *)(DAT_803dddac + 0x230) = *(ushort *)(param_3 + 0x40) + 0xc38;
      *(uint *)(DAT_803dddac + 0x234) = *(ushort *)(param_3 + 0x42) + 0xc38;
      *(uint *)(DAT_803dddac + 0x238) = *(ushort *)(param_3 + 0x44) + 0xc38;
      uVar9 = *(undefined4 *)(DAT_803dddac + 0x10);
      *(undefined4 *)(DAT_803dddac + 0x10) =
           *(undefined4 *)(DAT_803dddac + (uint)*(byte *)(DAT_803dddac + 0x251) * 4 + 8);
      *(undefined4 *)(DAT_803dddac + (uint)*(byte *)(DAT_803dddac + 0x251) * 4 + 8) = uVar9;
      *(undefined *)(DAT_803dddac + 0x250) = 0xff;
      fVar2 = FLOAT_803dfcdc;
      if (*(char *)(DAT_803dddac + 0x255) < '\0') {
        *(float *)(DAT_803dddac + 0x23c) = FLOAT_803dfcdc;
        if (*(ushort *)(param_3 + 0x2a) == 0) {
          *(float *)(DAT_803dddac + 0x240) = fVar2;
        }
        else {
          *(float *)(DAT_803dddac + 0x240) =
               fVar2 / (FLOAT_803dfd84 *
                       (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_3 + 0x2a)) -
                              DOUBLE_803dfcf0));
        }
      }
      else {
        *(float *)(DAT_803dddac + 0x23c) = FLOAT_803dfcd8;
      }
    }
    bVar1 = *(byte *)(DAT_803dddac + (uint)*(byte *)(DAT_803dddac + 0x24c) * 0xa4 + 0xc1) >> 3;
    if ((bVar1 & 3) != 0) {
      FUN_8005d06c((bVar1 & 3) - 1);
    }
    *(byte *)(DAT_803dddac + 0x209) =
         *(byte *)(DAT_803dddac + (uint)*(byte *)(DAT_803dddac + 0x24c) * 0xa4 + 0xc1) & 0x80 |
         *(byte *)(DAT_803dddac + 0x209) & 0x7f;
    *(byte *)(DAT_803dddac + 0x209) =
         (byte)((*(byte *)(DAT_803dddac + (uint)*(byte *)(DAT_803dddac + 0x24c) * 0xa4 + 0xc1) >> 5
                & 1) << 5) | *(byte *)(DAT_803dddac + 0x209) & 0xdf;
    puVar5 = FUN_800e877c();
    iVar6 = FUN_800e8a48();
    if (iVar6 == 0) {
      if (*(char *)(DAT_803dddac + 0xc1) < '\0') {
        *(byte *)(puVar5 + 0x10) = *(byte *)(puVar5 + 0x10) | 2;
      }
      else {
        *(byte *)(puVar5 + 0x10) = *(byte *)(puVar5 + 0x10) & 0xfd;
      }
      if (*(char *)(DAT_803dddac + 0x165) < '\0') {
        *(byte *)(puVar5 + 0x10) = *(byte *)(puVar5 + 0x10) | 4;
      }
      else {
        *(byte *)(puVar5 + 0x10) = *(byte *)(puVar5 + 0x10) & 0xfb;
      }
    }
  }
  return;
}

