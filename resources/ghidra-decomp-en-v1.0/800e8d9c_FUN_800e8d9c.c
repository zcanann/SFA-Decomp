// Function: FUN_800e8d9c
// Entry: 800e8d9c
// Size: 604 bytes

void FUN_800e8d9c(void)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  byte *pbVar5;
  uint uVar6;
  undefined auStack1800 [28];
  undefined auStack1772 [5];
  char local_6e7;
  byte local_1b0 [5];
  byte local_1ab;
  byte local_1aa;
  float local_1a8;
  
  iVar1 = FUN_802860d8();
  uVar6 = 0;
  do {
    iVar2 = FUN_8007dc5c(uVar6 & 0xff,auStack1800);
    if (iVar2 == 0) {
      uVar3 = 0;
      goto LAB_800e8fe0;
    }
    *(char *)(iVar1 + 0x20) = local_6e7;
    if (local_6e7 == '\0') {
      FUN_800033a8(iVar1,0,0x24);
    }
    else {
      FUN_80003494(iVar1,auStack1772,4);
      *(char *)(iVar1 + 4) = (char)(((uint)local_1ab * 100) / 0xbb);
      if (local_1ab < 0xb4) {
        if (local_1ab < 0xb1) {
          if (local_1ab < 0xa2) {
            if (local_1ab < 0x8b) {
              if (local_1ab < 0x82) {
                if (local_1ab < 0x72) {
                  if (local_1ab < 99) {
                    if (local_1ab < 0x49) {
                      if (local_1ab < 0x3e) {
                        if (local_1ab < 9) {
                          *(undefined *)(iVar1 + 5) = 0;
                          *(undefined *)(iVar1 + 6) = 0;
                        }
                        else {
                          *(undefined *)(iVar1 + 5) = 1;
                          *(undefined *)(iVar1 + 6) = 0;
                        }
                      }
                      else {
                        *(undefined *)(iVar1 + 5) = 1;
                        *(undefined *)(iVar1 + 6) = 1;
                      }
                    }
                    else {
                      *(undefined *)(iVar1 + 5) = 2;
                      *(undefined *)(iVar1 + 6) = 1;
                    }
                  }
                  else {
                    *(undefined *)(iVar1 + 5) = 2;
                    *(undefined *)(iVar1 + 6) = 2;
                  }
                }
                else {
                  *(undefined *)(iVar1 + 5) = 3;
                  *(undefined *)(iVar1 + 6) = 2;
                }
              }
              else {
                *(undefined *)(iVar1 + 5) = 3;
                *(undefined *)(iVar1 + 6) = 3;
              }
            }
            else {
              *(undefined *)(iVar1 + 5) = 4;
              *(undefined *)(iVar1 + 6) = 3;
            }
          }
          else {
            *(undefined *)(iVar1 + 5) = 4;
            *(undefined *)(iVar1 + 6) = 4;
          }
        }
        else {
          *(undefined *)(iVar1 + 5) = 5;
          *(undefined *)(iVar1 + 6) = 4;
        }
      }
      else {
        *(undefined *)(iVar1 + 5) = 6;
        *(undefined *)(iVar1 + 6) = 4;
      }
      uVar3 = FUN_80285fb4((double)(local_1a8 / FLOAT_803e06cc));
      *(undefined4 *)(iVar1 + 8) = uVar3;
      *(undefined4 *)(iVar1 + 0xc) = 0;
      *(undefined4 *)(iVar1 + 0x10) = 0;
      *(undefined4 *)(iVar1 + 0x14) = 0;
      *(undefined4 *)(iVar1 + 0x18) = 0;
      *(undefined4 *)(iVar1 + 0x1c) = 0;
      pbVar5 = local_1b0;
      iVar2 = iVar1;
      for (iVar4 = 0; iVar4 < (int)(uint)local_1aa; iVar4 = iVar4 + 1) {
        uVar3 = FUN_800191c4(*pbVar5 + 0xf4,0);
        *(undefined4 *)(iVar2 + 0xc) = uVar3;
        iVar2 = iVar2 + 4;
        pbVar5 = pbVar5 + 1;
      }
      *(undefined *)(iVar1 + 0x21) = 0;
      *(char *)(iVar1 + 0x20) = local_6e7;
    }
    iVar1 = iVar1 + 0x24;
    uVar6 = uVar6 + 1;
  } while ((int)uVar6 < 3);
  uVar3 = 1;
LAB_800e8fe0:
  FUN_80286124(uVar3);
  return;
}

