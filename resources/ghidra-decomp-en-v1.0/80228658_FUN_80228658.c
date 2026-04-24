// Function: FUN_80228658
// Entry: 80228658
// Size: 944 bytes

void FUN_80228658(int param_1)

{
  byte bVar1;
  char cVar4;
  undefined4 *puVar2;
  int iVar3;
  uint uVar5;
  int iVar6;
  char *pcVar7;
  
  pcVar7 = *(char **)(param_1 + 0xb8);
  iVar6 = *(int *)(param_1 + 0x4c);
  cVar4 = FUN_8001ffb4((int)*(short *)(iVar6 + 0x1c));
  *pcVar7 = cVar4;
  if (*pcVar7 == '\0') {
    puVar2 = (undefined4 *)FUN_800394ac(param_1,0,0);
    if (puVar2 != (undefined4 *)0x0) {
      *puVar2 = 0;
    }
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar6 + 8);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar6 + 0xc);
    *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(iVar6 + 0x10);
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    if (*(short *)(iVar6 + 0x22) == -1) {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
    }
    else {
      iVar3 = FUN_8001ffb4();
      if (iVar3 == 0) {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
        if ((*(byte *)(iVar6 + 0x1b) & 0x10) != 0) {
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
        }
      }
      else {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
      }
    }
    if ((*(short *)(param_1 + 0x46) == 0x830) && (cVar4 = FUN_80014054(), cVar4 != '\0')) {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
    }
    if (((*(byte *)(param_1 + 0xaf) & 1) != 0) &&
       ((*(short *)(iVar6 + 0x1e) == -1 ||
        (iVar3 = (**(code **)(*DAT_803dca68 + 0x20))(), iVar3 != 0)))) {
      if (*(char *)(iVar6 + 0x20) != -1) {
        if (*(short *)(param_1 + 0x46) == 0x526) {
          if ((pcVar7[1] == '\x01') &&
             ((iVar3 = FUN_8001ffb4(0x25a), iVar3 != 0 || (iVar3 = FUN_8001ffb4(0x25b), iVar3 != 0))
             )) {
            (**(code **)(*DAT_803dca54 + 0x48))(*(char *)(iVar6 + 0x20) + 2,param_1,0xffffffff);
          }
          else if ((pcVar7[1] == '\x02') &&
                  ((iVar3 = FUN_8001ffb4(0x202), iVar3 != 0 ||
                   (iVar3 = FUN_8001ffb4(0x243), iVar3 != 0)))) {
            (**(code **)(*DAT_803dca54 + 0x48))(*(char *)(iVar6 + 0x20) + 2,param_1,0xffffffff);
          }
          else {
            (**(code **)(*DAT_803dca54 + 0x48))((int)*(char *)(iVar6 + 0x20),param_1,0xffffffff);
          }
        }
        else {
          (**(code **)(*DAT_803dca54 + 0x48))((int)*(char *)(iVar6 + 0x20),param_1,0xffffffff);
        }
      }
      if ((*(byte *)(iVar6 + 0x1b) & 4) == 0) {
        FUN_800200e8((int)*(short *)(iVar6 + 0x1c),1);
        puVar2 = (undefined4 *)FUN_800394ac(param_1,0,0);
        if (puVar2 != (undefined4 *)0x0) {
          *puVar2 = 0x100;
        }
      }
      if ((*(byte *)(iVar6 + 0x1b) & 8) == 0) {
        *pcVar7 = '\x01';
        *(undefined4 *)(param_1 + 0xf4) = 1;
      }
      else {
        FUN_800200e8((int)*(short *)(iVar6 + 0x22),0);
      }
      FUN_80014b3c(0,0x100);
    }
  }
  else {
    if (((*(int *)(param_1 + 0xf4) == 0) && (*(char *)(iVar6 + 0x20) != -1)) &&
       (*(short *)(iVar6 + 0x24) != 0)) {
      (**(code **)(*DAT_803dca54 + 0x54))(param_1);
      uVar5 = 1;
      bVar1 = *(byte *)(iVar6 + 0x1b);
      if ((bVar1 & 0x20) != 0) {
        uVar5 = 3;
      }
      if ((bVar1 & 0x40) != 0) {
        uVar5 = 3;
      }
      if ((bVar1 & 0x80) != 0) {
        uVar5 = uVar5 | 4;
      }
      (**(code **)(*DAT_803dca54 + 0x48))((int)*(char *)(iVar6 + 0x20),param_1,uVar5);
    }
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  }
  *(undefined4 *)(param_1 + 0xf4) = 1;
  return;
}

