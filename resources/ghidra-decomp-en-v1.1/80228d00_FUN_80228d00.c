// Function: FUN_80228d00
// Entry: 80228d00
// Size: 972 bytes

void FUN_80228d00(int param_1)

{
  uint uVar1;
  undefined4 *puVar2;
  byte bVar4;
  int iVar3;
  int iVar5;
  char *pcVar6;
  
  pcVar6 = *(char **)(param_1 + 0xb8);
  iVar5 = *(int *)(param_1 + 0x4c);
  uVar1 = FUN_80020078((int)*(short *)(iVar5 + 0x1c));
  *pcVar6 = (char)uVar1;
  if (*pcVar6 == '\0') {
    puVar2 = (undefined4 *)FUN_800395a4(param_1,0);
    if (puVar2 != (undefined4 *)0x0) {
      *puVar2 = 0;
    }
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar5 + 8);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar5 + 0xc);
    *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(iVar5 + 0x10);
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    if ((int)*(short *)(iVar5 + 0x22) == 0xffffffff) {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
    }
    else {
      uVar1 = FUN_80020078((int)*(short *)(iVar5 + 0x22));
      if (uVar1 == 0) {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
        if ((*(byte *)(iVar5 + 0x1b) & 0x10) != 0) {
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
        }
      }
      else {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
      }
    }
    if (*(short *)(param_1 + 0x46) == 0x830) {
      bVar4 = FUN_80014074();
      if (bVar4 == 0) {
        if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
          FUN_8011f6d0(0xf);
        }
      }
      else {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
      }
    }
    if (((*(byte *)(param_1 + 0xaf) & 1) != 0) &&
       ((*(short *)(iVar5 + 0x1e) == -1 ||
        (iVar3 = (**(code **)(*DAT_803dd6e8 + 0x20))(), iVar3 != 0)))) {
      if (*(char *)(iVar5 + 0x20) != -1) {
        if (*(short *)(param_1 + 0x46) == 0x526) {
          if ((pcVar6[1] == '\x01') &&
             ((uVar1 = FUN_80020078(0x25a), uVar1 != 0 || (uVar1 = FUN_80020078(0x25b), uVar1 != 0))
             )) {
            (**(code **)(*DAT_803dd6d4 + 0x48))(*(char *)(iVar5 + 0x20) + 2,param_1,0xffffffff);
          }
          else if ((pcVar6[1] == '\x02') &&
                  ((uVar1 = FUN_80020078(0x202), uVar1 != 0 ||
                   (uVar1 = FUN_80020078(0x243), uVar1 != 0)))) {
            (**(code **)(*DAT_803dd6d4 + 0x48))(*(char *)(iVar5 + 0x20) + 2,param_1,0xffffffff);
          }
          else {
            (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar5 + 0x20),param_1,0xffffffff);
          }
        }
        else {
          (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar5 + 0x20),param_1,0xffffffff);
        }
      }
      if ((*(byte *)(iVar5 + 0x1b) & 4) == 0) {
        FUN_800201ac((int)*(short *)(iVar5 + 0x1c),1);
        puVar2 = (undefined4 *)FUN_800395a4(param_1,0);
        if (puVar2 != (undefined4 *)0x0) {
          *puVar2 = 0x100;
        }
      }
      if ((*(byte *)(iVar5 + 0x1b) & 8) == 0) {
        *pcVar6 = '\x01';
        *(undefined4 *)(param_1 + 0xf4) = 1;
      }
      else {
        FUN_800201ac((int)*(short *)(iVar5 + 0x22),0);
      }
      FUN_80014b68(0,0x100);
    }
  }
  else {
    if (((*(int *)(param_1 + 0xf4) == 0) && (*(char *)(iVar5 + 0x20) != -1)) &&
       (*(short *)(iVar5 + 0x24) != 0)) {
      (**(code **)(*DAT_803dd6d4 + 0x54))(param_1);
      uVar1 = 1;
      bVar4 = *(byte *)(iVar5 + 0x1b);
      if ((bVar4 & 0x20) != 0) {
        uVar1 = 3;
      }
      if ((bVar4 & 0x40) != 0) {
        uVar1 = 3;
      }
      if ((bVar4 & 0x80) != 0) {
        uVar1 = uVar1 | 4;
      }
      (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar5 + 0x20),param_1,uVar1);
    }
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  }
  *(undefined4 *)(param_1 + 0xf4) = 1;
  return;
}

