// Function: FUN_8000bb64
// Entry: 8000bb64
// Size: 624 bytes

void FUN_8000bb64(void)

{
  bool bVar1;
  uint *puVar2;
  uint uVar3;
  int iVar4;
  
  puVar2 = &DAT_80336c60;
  iVar4 = 0x37;
  do {
    if ((*puVar2 != 0xffffffff) && (uVar3 = FUN_80273090(*puVar2), uVar3 == 0xffffffff)) {
      *puVar2 = 0xffffffff;
    }
    puVar2 = puVar2 + 0xe;
    bVar1 = iVar4 != 0;
    iVar4 = iVar4 + -1;
  } while (bVar1);
  uVar3 = FUN_80020078(0xcbb);
  if (uVar3 == 0) {
    uVar3 = FUN_80020078(0xefa);
    if (uVar3 == 0) {
      uVar3 = FUN_80020078(0xefb);
      if (uVar3 == 0) {
        uVar3 = FUN_80020078(0xefd);
        if (uVar3 == 0) {
          uVar3 = FUN_80020078(0xa7f);
          if (uVar3 == 0) {
            uVar3 = FUN_80020078(0xefc);
            if (uVar3 == 0) {
              uVar3 = FUN_80020078(0xefe);
              if (uVar3 == 0) {
                uVar3 = FUN_80020078(0xdcf);
                if (uVar3 == 0) {
                  iVar4 = FUN_8000aea8();
                  if (iVar4 < 0x29) {
                    uVar3 = 0xc;
                  }
                  else {
                    uVar3 = 0;
                  }
                }
                else {
                  uVar3 = 0xb;
                }
              }
              else {
                uVar3 = 0xc;
              }
            }
            else {
              uVar3 = 0xc;
            }
          }
          else {
            uVar3 = 0xc;
          }
        }
        else {
          uVar3 = 0xc;
        }
      }
      else {
        uVar3 = 0xd;
      }
    }
    else {
      uVar3 = 0xc;
    }
  }
  else {
    uVar3 = 0xe;
  }
  if (uVar3 != DAT_803dd4b8 / 5) {
    puVar2 = &DAT_80336c60;
    DAT_803dd4b8 = (char)uVar3 * '\x05';
    iVar4 = 0x37;
    do {
      if ((*puVar2 != 0xffffffff) && (*(char *)(puVar2 + 10) == '\0')) {
        FUN_80272f0c(*puVar2,0x5b,DAT_803dd4b8);
      }
      puVar2 = puVar2 + 0xe;
      bVar1 = iVar4 != 0;
      iVar4 = iVar4 + -1;
    } while (bVar1);
  }
  puVar2 = &DAT_80336c60;
  iVar4 = 0x37;
  do {
    if ((*puVar2 != 0xffffffff) && (*(char *)(puVar2 + 1) != '\0')) {
      if (*(char *)((int)puVar2 + 5) != '\0') {
        if ((*(ushort *)(puVar2[6] + 0xb0) & 0x40) == 0) {
          puVar2[3] = *(uint *)(puVar2[6] + 0x18);
          puVar2[4] = *(uint *)(puVar2[6] + 0x1c);
          puVar2[5] = *(uint *)(puVar2[6] + 0x20);
        }
        else {
          *(undefined *)((int)puVar2 + 5) = 0;
        }
      }
      if ((*(char *)((int)puVar2 + 5) != '\0') || (*(char *)(puVar2 + 10) != '\0')) {
        FUN_8000c6e0(puVar2);
      }
    }
    puVar2 = puVar2 + 0xe;
    bVar1 = iVar4 != 0;
    iVar4 = iVar4 + -1;
  } while (bVar1);
  return;
}

