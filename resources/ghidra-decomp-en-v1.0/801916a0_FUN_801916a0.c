// Function: FUN_801916a0
// Entry: 801916a0
// Size: 976 bytes

void FUN_801916a0(short *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x5c);
  *(undefined2 *)(iVar2 + 8) = 400;
  *(undefined *)(iVar2 + 0xe) = 0;
  *param_1 = (ushort)*(byte *)(param_2 + 0x18) << 8;
  *(undefined4 *)(param_1 + 0x7a) = 0;
  *(code **)(param_1 + 0x5e) = FUN_80190bd4;
  *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
  iVar1 = *(int *)(param_2 + 0x14);
  if (iVar1 == 0x48506) goto LAB_80191868;
  if (iVar1 < 0x48506) {
    if (iVar1 != 0x4670d) {
      if (iVar1 < 0x4670d) {
        if (iVar1 != 0x45753) {
          if (iVar1 < 0x45753) {
            if (iVar1 == 0x43f83) {
              iVar1 = FUN_8001ffb4(0xba8);
              if (((iVar1 != 0) || (iVar1 = FUN_8001ffb4(0x316), iVar1 != 0)) ||
                 (iVar1 = FUN_8001ffb4(0x511), iVar1 != 0)) {
                *(byte *)(iVar2 + 0xe) = *(byte *)(iVar2 + 0xe) | 0x20;
              }
            }
            else if (((iVar1 < 0x43f83) && (iVar1 == 0x2ba7)) &&
                    ((iVar1 = FUN_8001ffb4(0xbfd), iVar1 != 0 ||
                     ((iVar1 = FUN_8001ffb4(0x29a), iVar1 != 0 ||
                      (iVar1 = FUN_8001ffb4(0x29b), iVar1 != 0)))))) {
              *(byte *)(iVar2 + 0xe) = *(byte *)(iVar2 + 0xe) | 0x20;
            }
            goto LAB_80191a38;
          }
          if ((iVar1 != 0x463c0) && ((0x463bf < iVar1 || (iVar1 != 0x45dd6)))) goto LAB_80191a38;
        }
        goto LAB_80191868;
      }
      if (iVar1 == 0x4800c) {
        iVar1 = FUN_8001ffb4(0xc85);
        if (((iVar1 != 0) || (iVar1 = FUN_8001ffb4(0xcb5), iVar1 != 0)) ||
           (iVar1 = FUN_8001ffb4(0xcb6), iVar1 != 0)) {
          *(byte *)(iVar2 + 0xe) = *(byte *)(iVar2 + 0xe) | 0x20;
        }
        goto LAB_80191a38;
      }
      if (iVar1 < 0x4800c) {
        if (iVar1 == 0x47064) {
          *(byte *)(iVar2 + 0xe) = *(byte *)(iVar2 + 0xe) | 0x10;
        }
        else if (((iVar1 < 0x47064) && (iVar1 == 0x46a40)) &&
                ((iVar1 = FUN_8001ffb4(0xff), iVar1 != 0 ||
                 ((iVar1 = FUN_8001ffb4(0x8a0), iVar1 != 0 ||
                  (iVar1 = FUN_8001ffb4(0x8a2), iVar1 != 0)))))) {
          *(byte *)(iVar2 + 0xe) = *(byte *)(iVar2 + 0xe) | 0x20;
        }
        goto LAB_80191a38;
      }
      if (iVar1 != 0x4827e) goto LAB_80191a38;
    }
    goto LAB_80191854;
  }
  if (iVar1 == 0x4a533) {
    iVar1 = FUN_8001ffb4(0x174);
    if (((iVar1 != 0) || (iVar1 = FUN_8001ffb4(0xcb7), iVar1 != 0)) ||
       (iVar1 = FUN_8001ffb4(0xcb8), iVar1 != 0)) {
      *(byte *)(iVar2 + 0xe) = *(byte *)(iVar2 + 0xe) | 0x20;
    }
    goto LAB_80191a38;
  }
  if (iVar1 < 0x4a533) {
    if (iVar1 == 0x497f4) {
      iVar1 = FUN_8001ffb4(0xc6e);
      if (((iVar1 != 0) || (iVar1 = FUN_8001ffb4(0xc70), iVar1 != 0)) ||
         (iVar1 = FUN_8001ffb4(0xc71), iVar1 != 0)) {
        *(byte *)(iVar2 + 0xe) = *(byte *)(iVar2 + 0xe) | 0x20;
      }
      goto LAB_80191a38;
    }
    if (iVar1 < 0x497f4) {
      if (iVar1 != 0x4977d) {
        if ((0x4977c < iVar1) || (iVar1 != 0x49267)) goto LAB_80191a38;
        goto LAB_80191854;
      }
    }
    else if (iVar1 != 0x49c33) goto LAB_80191a38;
LAB_80191868:
    *(byte *)(iVar2 + 0xe) = *(byte *)(iVar2 + 0xe) | 8;
  }
  else {
    if (iVar1 != 0x4cb6a) {
      if (iVar1 < 0x4cb6a) {
        if (iVar1 == 0x4c986) {
          *(byte *)(iVar2 + 0xe) = *(byte *)(iVar2 + 0xe) | 0x30;
          goto LAB_80191a38;
        }
        if (((0x4c985 < iVar1) || (0x4b667 < iVar1)) || (iVar1 < 0x4b666)) goto LAB_80191a38;
        goto LAB_80191868;
      }
      if (iVar1 != 0x4cb84) goto LAB_80191a38;
    }
LAB_80191854:
    *(byte *)(iVar2 + 0xe) = *(byte *)(iVar2 + 0xe) | 0x68;
  }
LAB_80191a38:
  if ((*(byte *)(iVar2 + 0xe) & 0x40) != 0) {
    *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
  }
  return;
}

