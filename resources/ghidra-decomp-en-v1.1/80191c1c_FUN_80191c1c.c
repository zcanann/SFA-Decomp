// Function: FUN_80191c1c
// Entry: 80191c1c
// Size: 976 bytes

void FUN_80191c1c(short *param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x5c);
  *(undefined2 *)(iVar3 + 8) = 400;
  *(undefined *)(iVar3 + 0xe) = 0;
  *param_1 = (ushort)*(byte *)(param_2 + 0x18) << 8;
  param_1[0x7a] = 0;
  param_1[0x7b] = 0;
  *(code **)(param_1 + 0x5e) = FUN_80191150;
  *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
  iVar2 = *(int *)(param_2 + 0x14);
  if (iVar2 == 0x48506) goto LAB_80191de4;
  if (iVar2 < 0x48506) {
    if (iVar2 != 0x4670d) {
      if (iVar2 < 0x4670d) {
        if (iVar2 != 0x45753) {
          if (iVar2 < 0x45753) {
            if (iVar2 == 0x43f83) {
              uVar1 = FUN_80020078(0xba8);
              if (((uVar1 != 0) || (uVar1 = FUN_80020078(0x316), uVar1 != 0)) ||
                 (uVar1 = FUN_80020078(0x511), uVar1 != 0)) {
                *(byte *)(iVar3 + 0xe) = *(byte *)(iVar3 + 0xe) | 0x20;
              }
            }
            else if (((iVar2 < 0x43f83) && (iVar2 == 0x2ba7)) &&
                    ((uVar1 = FUN_80020078(0xbfd), uVar1 != 0 ||
                     ((uVar1 = FUN_80020078(0x29a), uVar1 != 0 ||
                      (uVar1 = FUN_80020078(0x29b), uVar1 != 0)))))) {
              *(byte *)(iVar3 + 0xe) = *(byte *)(iVar3 + 0xe) | 0x20;
            }
            goto LAB_80191fb4;
          }
          if ((iVar2 != 0x463c0) && ((0x463bf < iVar2 || (iVar2 != 0x45dd6)))) goto LAB_80191fb4;
        }
        goto LAB_80191de4;
      }
      if (iVar2 == 0x4800c) {
        uVar1 = FUN_80020078(0xc85);
        if (((uVar1 != 0) || (uVar1 = FUN_80020078(0xcb5), uVar1 != 0)) ||
           (uVar1 = FUN_80020078(0xcb6), uVar1 != 0)) {
          *(byte *)(iVar3 + 0xe) = *(byte *)(iVar3 + 0xe) | 0x20;
        }
        goto LAB_80191fb4;
      }
      if (iVar2 < 0x4800c) {
        if (iVar2 == 0x47064) {
          *(byte *)(iVar3 + 0xe) = *(byte *)(iVar3 + 0xe) | 0x10;
        }
        else if (((iVar2 < 0x47064) && (iVar2 == 0x46a40)) &&
                ((uVar1 = FUN_80020078(0xff), uVar1 != 0 ||
                 ((uVar1 = FUN_80020078(0x8a0), uVar1 != 0 ||
                  (uVar1 = FUN_80020078(0x8a2), uVar1 != 0)))))) {
          *(byte *)(iVar3 + 0xe) = *(byte *)(iVar3 + 0xe) | 0x20;
        }
        goto LAB_80191fb4;
      }
      if (iVar2 != 0x4827e) goto LAB_80191fb4;
    }
    goto LAB_80191dd0;
  }
  if (iVar2 == 0x4a533) {
    uVar1 = FUN_80020078(0x174);
    if (((uVar1 != 0) || (uVar1 = FUN_80020078(0xcb7), uVar1 != 0)) ||
       (uVar1 = FUN_80020078(0xcb8), uVar1 != 0)) {
      *(byte *)(iVar3 + 0xe) = *(byte *)(iVar3 + 0xe) | 0x20;
    }
    goto LAB_80191fb4;
  }
  if (iVar2 < 0x4a533) {
    if (iVar2 == 0x497f4) {
      uVar1 = FUN_80020078(0xc6e);
      if (((uVar1 != 0) || (uVar1 = FUN_80020078(0xc70), uVar1 != 0)) ||
         (uVar1 = FUN_80020078(0xc71), uVar1 != 0)) {
        *(byte *)(iVar3 + 0xe) = *(byte *)(iVar3 + 0xe) | 0x20;
      }
      goto LAB_80191fb4;
    }
    if (iVar2 < 0x497f4) {
      if (iVar2 != 0x4977d) {
        if ((0x4977c < iVar2) || (iVar2 != 0x49267)) goto LAB_80191fb4;
        goto LAB_80191dd0;
      }
    }
    else if (iVar2 != 0x49c33) goto LAB_80191fb4;
LAB_80191de4:
    *(byte *)(iVar3 + 0xe) = *(byte *)(iVar3 + 0xe) | 8;
  }
  else {
    if (iVar2 != 0x4cb6a) {
      if (iVar2 < 0x4cb6a) {
        if (iVar2 == 0x4c986) {
          *(byte *)(iVar3 + 0xe) = *(byte *)(iVar3 + 0xe) | 0x30;
          goto LAB_80191fb4;
        }
        if (((0x4c985 < iVar2) || (0x4b667 < iVar2)) || (iVar2 < 0x4b666)) goto LAB_80191fb4;
        goto LAB_80191de4;
      }
      if (iVar2 != 0x4cb84) goto LAB_80191fb4;
    }
LAB_80191dd0:
    *(byte *)(iVar3 + 0xe) = *(byte *)(iVar3 + 0xe) | 0x68;
  }
LAB_80191fb4:
  if ((*(byte *)(iVar3 + 0xe) & 0x40) != 0) {
    *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
  }
  return;
}

