// Function: FUN_802792f8
// Entry: 802792f8
// Size: 784 bytes

uint FUN_802792f8(uint param_1,byte param_2,byte param_3,short param_4,byte param_5,
                 undefined param_6,undefined param_7,uint param_8,byte param_9,undefined param_10,
                 ushort param_11,undefined param_12,byte param_13,undefined param_14,
                 undefined param_15,int param_16)

{
  int iVar1;
  short sVar4;
  uint uVar2;
  bool bVar5;
  uint uVar3;
  int *piVar6;
  
  iVar1 = FUN_802755e0(param_1);
  if (iVar1 != 0) {
    if (((param_5 & 0x80) == 0) && (sVar4 = FUN_80272eec((uint)param_9,param_8), sVar4 != -1)) {
      param_2 = (byte)sVar4;
    }
    uVar2 = FUN_80279ec0(param_2,param_3,param_4,(param_5 & 0x80) != 0);
    if (uVar2 != 0xffffffff) {
      piVar6 = (int *)(DAT_803deee8 + uVar2 * 0x404);
      FUN_8027979c((int)piVar6);
      if (piVar6[0x13] != 2) {
        if (piVar6[0x13] == 0) {
          if (piVar6[0x10] == 0) {
            DAT_803def54 = (int *)piVar6[0xf];
          }
          else {
            *(int *)(piVar6[0x10] + 0x3c) = piVar6[0xf];
          }
          if (piVar6[0xf] != 0) {
            *(int *)(piVar6[0xf] + 0x40) = piVar6[0x10];
          }
        }
        FUN_80279018(piVar6,1);
        piVar6[0x13] = 2;
      }
      piVar6[0x46] = piVar6[0x46] & 0x10U | 2;
      piVar6[0x45] = 0;
      bVar5 = FUN_802839b8(uVar2);
      if (bVar5) {
        piVar6[0x46] = piVar6[0x46] | 1;
      }
      piVar6[0x27] = 0;
      piVar6[0x26] = 0;
      if ((param_5 & 0x80) == 0) {
        *(undefined *)((int)piVar6 + 0x11d) = 0;
        *(char *)((int)piVar6 + 0x20a) = (char)param_8;
        *(byte *)((int)piVar6 + 0x20b) = param_9;
        *(undefined *)(piVar6 + 0x83) = param_10;
      }
      else {
        *(undefined *)((int)piVar6 + 0x11d) = 1;
        param_5 = param_5 & 0x7f;
        FUN_80282194(uVar2 & 0xff,0xff,1);
        FUN_80282550(uVar2 & 0xff,0xff);
        *(char *)((int)piVar6 + 0x20a) = (char)uVar2;
        *(undefined *)((int)piVar6 + 0x20b) = 0xff;
        *(undefined *)(piVar6 + 0x83) = 0;
      }
      *(short *)((int)piVar6 + 0x102) = (short)param_1;
      *(short *)(piVar6 + 0x40) = param_4;
      piVar6[0x44] = 0x75300000;
      *(undefined2 *)((int)piVar6 + 0x10e) = 0x400;
      piVar6[0xd] = iVar1;
      piVar6[0xe] = iVar1 + (uint)param_11 * 8;
      *(byte *)((int)piVar6 + 0x12f) = param_5;
      *(ushort *)(piVar6 + 0x4b) = (ushort)param_5;
      *(undefined *)((int)piVar6 + 0x12e) = 0;
      *(undefined *)(piVar6 + 0x82) = param_6;
      *(undefined *)((int)piVar6 + 0x209) = param_7;
      *(undefined *)((int)piVar6 + 0x20d) = param_12;
      *(undefined *)(piVar6 + 0x23) = 0;
      *(undefined *)((int)piVar6 + 0x8d) = 0;
      piVar6[0x3b] = -1;
      piVar6[0x3c] = -1;
      piVar6[0x42] = -1;
      *(undefined *)((int)piVar6 + 0x20e) = param_14;
      *(undefined *)((int)piVar6 + 0x20f) = param_15;
      *(bool *)(piVar6 + 0x84) = param_16 == 0;
      *(undefined *)((int)piVar6 + 0x3ee) = 0;
      *(undefined *)((int)piVar6 + 0x3ed) = 0;
      *(undefined *)(piVar6 + 0xfb) = 0;
      piVar6[0x3d] = uVar2 | param_1 << 0x10 | (uint)param_5 << 8;
      FUN_80279d30((int)piVar6,param_2);
      uVar3 = FUN_80279b04((int)piVar6,(uint)param_13);
      if (uVar3 != 0xffffffff) {
        if (piVar6[0x13] == 0) {
          return uVar3;
        }
        FUN_80279018(piVar6,0);
        bVar5 = DAT_803def54 != (int *)0x0;
        piVar6[0xf] = (int)DAT_803def54;
        if (bVar5) {
          *(int **)((int)DAT_803def54 + 0x40) = piVar6;
        }
        piVar6[0x10] = 0;
        DAT_803def54 = piVar6;
        piVar6[0x13] = 0;
        return uVar3;
      }
      bVar5 = FUN_802839b8(uVar2);
      if (bVar5) {
        FUN_80283ba0(uVar2);
      }
      FUN_8027a2fc((int)piVar6);
    }
  }
  return 0xffffffff;
}

