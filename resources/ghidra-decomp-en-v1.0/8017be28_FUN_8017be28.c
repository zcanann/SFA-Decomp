// Function: FUN_8017be28
// Entry: 8017be28
// Size: 848 bytes

void FUN_8017be28(int param_1)

{
  byte bVar1;
  int iVar2;
  char cVar3;
  uint uVar4;
  int iVar5;
  char *pcVar6;
  
  pcVar6 = *(char **)(param_1 + 0xb8);
  iVar5 = *(int *)(param_1 + 0x4c);
  if (((*(byte *)(param_1 + 0xaf) & 4) == 0) || (iVar2 = FUN_8001ffb4(0x930), iVar2 != 0)) {
    cVar3 = FUN_8001ffb4((int)*(short *)(iVar5 + 0x1c));
    *pcVar6 = cVar3;
    if ((*(byte *)(iVar5 + 0x1b) & 1) == 0) {
      if ((*(ushort *)(iVar5 + 0x26) & 1) != 0) {
        if (*pcVar6 == '\0') {
          *(undefined4 *)(param_1 + 0xf8) = 1;
        }
        else {
          *(undefined4 *)(param_1 + 0xf8) = 0;
        }
      }
    }
    else if (*pcVar6 != '\0') {
      *(undefined *)(param_1 + 0x36) = 0;
    }
    if (*pcVar6 == '\0') {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
      if (((*(short *)(iVar5 + 0x22) != -1) && (iVar2 = FUN_8001ffb4(), iVar2 == 0)) &&
         (*(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10,
         (*(byte *)(iVar5 + 0x1b) & 0x10) != 0)) {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
      }
      if ((*(short *)(iVar5 + 0x1e) != -1) && (iVar2 = FUN_8001ffb4(), iVar2 == 0)) {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
      }
      if (((*(short *)(iVar5 + 0x1e) != -1) && (iVar2 = FUN_80037fa4(param_1), iVar2 != 0)) ||
         ((*(short *)(iVar5 + 0x1e) == -1 && (iVar2 = FUN_80038024(param_1), iVar2 != 0)))) {
        if (*(char *)(iVar5 + 0x20) != -1) {
          (**(code **)(*DAT_803dca54 + 0x48))((int)*(char *)(iVar5 + 0x20),param_1,0xffffffff);
        }
        if ((*(byte *)(iVar5 + 0x1b) & 4) == 0) {
          FUN_800200e8((int)*(short *)(iVar5 + 0x1c),1);
        }
        if ((*(byte *)(iVar5 + 0x1b) & 8) == 0) {
          *pcVar6 = '\x01';
          *(undefined4 *)(param_1 + 0xf4) = 1;
        }
        else {
          FUN_800200e8((int)*(short *)(iVar5 + 0x22),0);
        }
        FUN_80014b3c(0,0x100);
      }
    }
    else {
      if (*(int *)(param_1 + 0xf4) == 0) {
        if ((*(char *)(iVar5 + 0x20) != -1) && (*(short *)(iVar5 + 0x24) != 0)) {
          (**(code **)(*DAT_803dca54 + 0x54))(param_1);
          uVar4 = 1;
          bVar1 = *(byte *)(iVar5 + 0x1b);
          if ((bVar1 & 0x20) != 0) {
            uVar4 = 3;
          }
          if ((bVar1 & 0x40) != 0) {
            uVar4 = uVar4 | 4;
          }
          if ((bVar1 & 0x80) != 0) {
            uVar4 = uVar4 | 8;
          }
          (**(code **)(*DAT_803dca54 + 0x48))((int)*(char *)(iVar5 + 0x20),param_1,uVar4);
        }
        *(undefined4 *)(param_1 + 0xf4) = 1;
      }
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    }
    if (((*(uint *)(*(int *)(param_1 + 0x50) + 0x44) & 1) != 0) && (*(int *)(param_1 + 0x74) != 0))
    {
      FUN_80041018(param_1);
    }
  }
  else {
    FUN_80014b3c(0,0x100);
    (**(code **)(*DAT_803dca54 + 0x84))(param_1,0);
    (**(code **)(*DAT_803dca54 + 0x48))(1,param_1,0xffffffff);
    FUN_800200e8(0x930,1);
  }
  return;
}

