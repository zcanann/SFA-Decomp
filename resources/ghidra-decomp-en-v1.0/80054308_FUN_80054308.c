// Function: FUN_80054308
// Entry: 80054308
// Size: 412 bytes

void FUN_80054308(void)

{
  undefined4 *puVar1;
  int iVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  int iVar6;
  
  puVar1 = (undefined4 *)FUN_802860dc();
  if (puVar1 != *(undefined4 **)(DAT_803dcdc4 + 4)) {
    if (puVar1 == (undefined4 *)0x0) {
      uRam0000004b = 10;
    }
    else if (*(ushort *)((int)puVar1 + 0xe) == 0) {
      *(undefined *)((int)puVar1 + 0x4b) = 10;
    }
    else {
      if ((*(char *)((int)puVar1 + 0x49) != '\0') && (*(ushort *)((int)puVar1 + 0xe) < 2)) {
        *(undefined *)((int)puVar1 + 0x4b) = 10;
      }
      *(short *)((int)puVar1 + 0xe) = *(short *)((int)puVar1 + 0xe) + -1;
      if ((*(short *)((int)puVar1 + 0xe) == 0) &&
         (iVar3 = 0, iVar2 = DAT_803dcdc4, iVar6 = DAT_803dcdbc, 0 < DAT_803dcdbc)) {
        do {
          if (*(undefined4 **)(iVar2 + 4) == puVar1) {
            puVar4 = (undefined4 *)*puVar1;
            while (puVar4 != (undefined4 *)0x0) {
              if ((puVar4 < &DAT_80000000) || (puVar5 = puVar4, (undefined4 *)0x81800000 < puVar4))
              {
                puVar5 = (undefined4 *)0x0;
              }
              if ((puVar5 < &DAT_80000000) || ((undefined4 *)0x9fffffff < puVar5)) {
                puVar4 = (undefined4 *)0x0;
              }
              else {
                puVar4 = puVar5;
                if (puVar5 != (undefined4 *)0x0) {
                  puVar4 = (undefined4 *)*puVar5;
                  if (*(char *)(puVar5 + 0x12) != '\0') {
                    FUN_8006cad0(puVar5[0x10]);
                  }
                  if (*(char *)((int)puVar5 + 0x49) == '\0') {
                    FUN_80023800(puVar5);
                  }
                }
              }
            }
            if (*(char *)(puVar1 + 0x12) != '\0') {
              FUN_8006cad0(puVar1[0x10]);
            }
            if (*(char *)((int)puVar1 + 0x49) == '\0') {
              FUN_80023800(puVar1);
            }
            *(undefined4 *)(DAT_803dcdc4 + iVar3 * 0x10) = 0xffffffff;
            *(undefined4 *)(DAT_803dcdc4 + iVar3 * 0x10 + 4) = 0;
            break;
          }
          iVar2 = iVar2 + 0x10;
          iVar3 = iVar3 + 1;
          iVar6 = iVar6 + -1;
        } while (iVar6 != 0);
      }
    }
  }
  FUN_80286128();
  return;
}

