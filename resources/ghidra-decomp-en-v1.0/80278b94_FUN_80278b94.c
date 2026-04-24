// Function: FUN_80278b94
// Entry: 80278b94
// Size: 784 bytes

int FUN_80278b94(ushort param_1,uint param_2,undefined4 param_3,undefined4 param_4,byte param_5,
                undefined param_6,undefined param_7,undefined4 param_8,undefined param_9,
                undefined param_10,ushort param_11,undefined param_12,undefined param_13,
                undefined param_14,undefined param_15,int param_16)

{
  bool bVar1;
  byte bVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  
  iVar3 = FUN_80274e7c();
  if (iVar3 != 0) {
    bVar2 = param_5 & 0x80;
    if ((bVar2 == 0) && (uVar4 = FUN_80272788(param_9,param_8), (uVar4 & 0xffff) != 0xffff)) {
      param_2 = uVar4 & 0xff;
    }
    uVar4 = FUN_8027975c(param_2,param_3,param_4,bVar2 != 0);
    if (uVar4 != 0xffffffff) {
      iVar6 = DAT_803de268 + uVar4 * 0x404;
      FUN_80279038(iVar6);
      if (*(int *)(iVar6 + 0x4c) != 2) {
        if (*(int *)(iVar6 + 0x4c) == 0) {
          if (*(int *)(iVar6 + 0x40) == 0) {
            DAT_803de2d4 = *(int *)(iVar6 + 0x3c);
          }
          else {
            *(undefined4 *)(*(int *)(iVar6 + 0x40) + 0x3c) = *(undefined4 *)(iVar6 + 0x3c);
          }
          if (*(int *)(iVar6 + 0x3c) != 0) {
            *(undefined4 *)(*(int *)(iVar6 + 0x3c) + 0x40) = *(undefined4 *)(iVar6 + 0x40);
          }
        }
        FUN_802788b4(iVar6,1);
        *(undefined4 *)(iVar6 + 0x4c) = 2;
      }
      *(uint *)(iVar6 + 0x118) = *(uint *)(iVar6 + 0x118) & 0x10 | 2;
      *(undefined4 *)(iVar6 + 0x114) = 0;
      iVar5 = FUN_80283254(uVar4);
      if (iVar5 != 0) {
        *(uint *)(iVar6 + 0x118) = *(uint *)(iVar6 + 0x118) | 1;
      }
      *(undefined4 *)(iVar6 + 0x9c) = 0;
      *(undefined4 *)(iVar6 + 0x98) = 0;
      if (bVar2 == 0) {
        *(undefined *)(iVar6 + 0x11d) = 0;
        *(char *)(iVar6 + 0x20a) = (char)param_8;
        *(undefined *)(iVar6 + 0x20b) = param_9;
        *(undefined *)(iVar6 + 0x20c) = param_10;
      }
      else {
        *(undefined *)(iVar6 + 0x11d) = 1;
        param_5 = param_5 & 0x7f;
        FUN_80281a30(uVar4 & 0xff,0xff,1);
        FUN_80281dec(uVar4 & 0xff,0xff);
        *(char *)(iVar6 + 0x20a) = (char)uVar4;
        *(undefined *)(iVar6 + 0x20b) = 0xff;
        *(undefined *)(iVar6 + 0x20c) = 0;
      }
      *(ushort *)(iVar6 + 0x102) = param_1;
      *(short *)(iVar6 + 0x100) = (short)param_4;
      *(undefined4 *)(iVar6 + 0x110) = 0x75300000;
      *(undefined2 *)(iVar6 + 0x10e) = 0x400;
      *(int *)(iVar6 + 0x34) = iVar3;
      *(uint *)(iVar6 + 0x38) = iVar3 + (uint)param_11 * 8;
      *(byte *)(iVar6 + 0x12f) = param_5;
      *(ushort *)(iVar6 + 300) = (ushort)param_5;
      *(undefined *)(iVar6 + 0x12e) = 0;
      *(undefined *)(iVar6 + 0x208) = param_6;
      *(undefined *)(iVar6 + 0x209) = param_7;
      *(undefined *)(iVar6 + 0x20d) = param_12;
      *(undefined *)(iVar6 + 0x8c) = 0;
      *(undefined *)(iVar6 + 0x8d) = 0;
      *(undefined4 *)(iVar6 + 0xec) = 0xffffffff;
      *(undefined4 *)(iVar6 + 0xf0) = 0xffffffff;
      *(undefined4 *)(iVar6 + 0x108) = 0xffffffff;
      *(undefined *)(iVar6 + 0x20e) = param_14;
      *(undefined *)(iVar6 + 0x20f) = param_15;
      *(bool *)(iVar6 + 0x210) = param_16 == 0;
      *(undefined *)(iVar6 + 0x3ee) = 0;
      *(undefined *)(iVar6 + 0x3ed) = 0;
      *(undefined *)(iVar6 + 0x3ec) = 0;
      *(uint *)(iVar6 + 0xf4) = uVar4 | (uint)param_1 << 0x10 | (uint)param_5 << 8;
      FUN_802795cc(iVar6,param_2);
      iVar3 = FUN_802793a0(iVar6,param_13);
      if (iVar3 != -1) {
        if (*(int *)(iVar6 + 0x4c) == 0) {
          return iVar3;
        }
        FUN_802788b4(iVar6,0);
        bVar1 = DAT_803de2d4 != 0;
        *(int *)(iVar6 + 0x3c) = DAT_803de2d4;
        if (bVar1) {
          *(int *)(DAT_803de2d4 + 0x40) = iVar6;
        }
        *(undefined4 *)(iVar6 + 0x40) = 0;
        DAT_803de2d4 = iVar6;
        *(undefined4 *)(iVar6 + 0x4c) = 0;
        return iVar3;
      }
      iVar3 = FUN_80283254(uVar4);
      if (iVar3 != 0) {
        FUN_8028343c(uVar4);
      }
      FUN_80279b98(iVar6);
    }
  }
  return -1;
}

