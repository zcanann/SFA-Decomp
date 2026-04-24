// Function: FUN_802622ac
// Entry: 802622ac
// Size: 380 bytes

undefined4 FUN_802622ac(int param_1,uint *param_2,undefined4 *param_3)

{
  int iVar1;
  uint uVar2;
  undefined4 uVar3;
  undefined1 *local_1c [2];
  
  if ((-1 < param_1) && (param_1 < 2)) {
    if ((DAT_800030e3 & 0x80) != 0) {
      return 0xfffffffd;
    }
    FUN_80243e74();
    iVar1 = FUN_802542b8(param_1);
    if (iVar1 == -1) {
      uVar3 = 0xfffffffd;
    }
    else if (iVar1 == 0) {
      uVar3 = 0xffffffff;
    }
    else if ((&DAT_803afe40)[param_1 * 0x44] == 0) {
      uVar2 = FUN_80254e04(param_1);
      if ((uVar2 & 8) == 0) {
        iVar1 = FUN_80254e44(param_1,0,(byte *)local_1c);
        if (iVar1 == 0) {
          uVar3 = 0xffffffff;
        }
        else {
          iVar1 = FUN_802621e0(local_1c[0]);
          if (iVar1 == 0) {
            uVar3 = 0xfffffffe;
          }
          else {
            if (param_2 != (uint *)0x0) {
              *param_2 = (uint)local_1c[0] & 0xfc;
            }
            if (param_3 != (undefined4 *)0x0) {
              *param_3 = *(undefined4 *)(&DAT_8032f9a0 + ((uint)local_1c[0] >> 9 & 0x1c));
            }
            uVar3 = 0;
          }
        }
      }
      else {
        uVar3 = 0xfffffffe;
      }
    }
    else if ((int)(&DAT_803afe64)[param_1 * 0x44] < 1) {
      uVar3 = 0xffffffff;
    }
    else {
      if (param_2 != (uint *)0x0) {
        *param_2 = (uint)*(ushort *)(&DAT_803afe48 + param_1 * 0x110);
      }
      if (param_3 != (undefined4 *)0x0) {
        *param_3 = *(undefined4 *)(&DAT_803afe4c + param_1 * 0x110);
      }
      uVar3 = 0;
    }
    FUN_80243e9c();
    return uVar3;
  }
  return 0xffffff80;
}

