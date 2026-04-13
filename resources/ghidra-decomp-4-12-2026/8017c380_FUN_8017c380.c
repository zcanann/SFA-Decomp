// Function: FUN_8017c380
// Entry: 8017c380
// Size: 848 bytes

void FUN_8017c380(int param_1)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  char *pcVar5;
  
  pcVar5 = *(char **)(param_1 + 0xb8);
  iVar4 = *(int *)(param_1 + 0x4c);
  if (((*(byte *)(param_1 + 0xaf) & 4) == 0) || (uVar2 = FUN_80020078(0x930), uVar2 != 0)) {
    uVar2 = FUN_80020078((int)*(short *)(iVar4 + 0x1c));
    *pcVar5 = (char)uVar2;
    if ((*(byte *)(iVar4 + 0x1b) & 1) == 0) {
      if ((*(ushort *)(iVar4 + 0x26) & 1) != 0) {
        if (*pcVar5 == '\0') {
          *(undefined4 *)(param_1 + 0xf8) = 1;
        }
        else {
          *(undefined4 *)(param_1 + 0xf8) = 0;
        }
      }
    }
    else if (*pcVar5 != '\0') {
      *(undefined *)(param_1 + 0x36) = 0;
    }
    if (*pcVar5 == '\0') {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
      if ((((int)*(short *)(iVar4 + 0x22) != 0xffffffff) &&
          (uVar2 = FUN_80020078((int)*(short *)(iVar4 + 0x22)), uVar2 == 0)) &&
         (*(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10,
         (*(byte *)(iVar4 + 0x1b) & 0x10) != 0)) {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
      }
      if (((int)*(short *)(iVar4 + 0x1e) != 0xffffffff) &&
         (uVar2 = FUN_80020078((int)*(short *)(iVar4 + 0x1e)), uVar2 == 0)) {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
      }
      if (((*(short *)(iVar4 + 0x1e) != -1) &&
          (iVar3 = FUN_8003809c(param_1,*(short *)(iVar4 + 0x1e)), iVar3 != 0)) ||
         ((*(short *)(iVar4 + 0x1e) == -1 && (iVar3 = FUN_8003811c(param_1), iVar3 != 0)))) {
        if (*(char *)(iVar4 + 0x20) != -1) {
          (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar4 + 0x20),param_1,0xffffffff);
        }
        if ((*(byte *)(iVar4 + 0x1b) & 4) == 0) {
          FUN_800201ac((int)*(short *)(iVar4 + 0x1c),1);
        }
        if ((*(byte *)(iVar4 + 0x1b) & 8) == 0) {
          *pcVar5 = '\x01';
          *(undefined4 *)(param_1 + 0xf4) = 1;
        }
        else {
          FUN_800201ac((int)*(short *)(iVar4 + 0x22),0);
        }
        FUN_80014b68(0,0x100);
      }
    }
    else {
      if (*(int *)(param_1 + 0xf4) == 0) {
        if ((*(char *)(iVar4 + 0x20) != -1) && (*(short *)(iVar4 + 0x24) != 0)) {
          (**(code **)(*DAT_803dd6d4 + 0x54))(param_1);
          uVar2 = 1;
          bVar1 = *(byte *)(iVar4 + 0x1b);
          if ((bVar1 & 0x20) != 0) {
            uVar2 = 3;
          }
          if ((bVar1 & 0x40) != 0) {
            uVar2 = uVar2 | 4;
          }
          if ((bVar1 & 0x80) != 0) {
            uVar2 = uVar2 | 8;
          }
          (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar4 + 0x20),param_1,uVar2);
        }
        *(undefined4 *)(param_1 + 0xf4) = 1;
      }
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    }
    if (((*(uint *)(*(int *)(param_1 + 0x50) + 0x44) & 1) != 0) && (*(int *)(param_1 + 0x74) != 0))
    {
      FUN_80041110();
    }
  }
  else {
    FUN_80014b68(0,0x100);
    (**(code **)(*DAT_803dd6d4 + 0x84))(param_1,0);
    (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_1,0xffffffff);
    FUN_800201ac(0x930,1);
  }
  return;
}

