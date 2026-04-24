// Function: FUN_801892d0
// Entry: 801892d0
// Size: 720 bytes

/* WARNING: Removing unreachable block (ram,0x801893d4) */

void FUN_801892d0(int param_1)

{
  byte bVar1;
  int iVar2;
  char cVar5;
  undefined4 uVar3;
  int iVar4;
  int iVar6;
  
  iVar6 = *(int *)(param_1 + 0xb8);
  iVar2 = FUN_8002b9ec();
  if ((*(int *)(iVar6 + 0x10) == 0) && (cVar5 = FUN_8002e04c(), cVar5 != '\0')) {
    uVar3 = FUN_8002bdf4(0x24,0x606);
    uVar3 = FUN_8002df90(uVar3,4,0xffffffff,0xffffffff,0);
    *(undefined4 *)(iVar6 + 0x10) = uVar3;
    if (*(int *)(iVar6 + 0x10) != 0) {
      FUN_80037d2c(param_1,*(int *)(iVar6 + 0x10),0);
      FUN_8022f270(*(undefined4 *)(iVar6 + 0x10),0xaf);
      *(ushort *)(*(int *)(iVar6 + 0x10) + 6) = *(ushort *)(*(int *)(iVar6 + 0x10) + 6) | 0x4000;
    }
  }
  if (*(int *)(iVar6 + 0x10) != 0) {
    FUN_8022f27c();
  }
  if ((iVar2 == 0) || (iVar2 = FUN_802972a8(iVar2), iVar2 == 0)) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
  }
  bVar1 = *(byte *)(iVar6 + 0x16);
  if (bVar1 == 1) {
    iVar2 = FUN_80038024(param_1);
    if (iVar2 != 0) {
      *(undefined *)(iVar6 + 0x16) = 2;
      FUN_8011dd30();
    }
    FUN_80037b40(param_1,8,0xb4,0xf0,0xff,0x6f,iVar6);
  }
  else if (bVar1 == 0) {
    iVar2 = FUN_80038024(param_1);
    if (iVar2 != 0) {
      iVar6 = *(int *)(param_1 + 0x4c);
      iVar2 = FUN_80036e58(0xf,param_1,0);
      if ((*(char *)(param_1 + 0xac) == '\r') && (iVar4 = FUN_8001ffb4(0xc92), iVar4 != 0)) {
        *(float *)(iVar2 + 0x10) = *(float *)(iVar2 + 0x10) + FLOAT_803e3ba0;
        (**(code **)(*DAT_803dca54 + 0x48))(2,iVar2,0xffffffff);
      }
      else {
        (**(code **)(*DAT_803dca54 + 0x48))(1,iVar2,0xffffffff);
      }
      FUN_800200e8((int)*(short *)(iVar6 + 0x1c),0);
    }
  }
  else if (bVar1 < 3) {
    cVar5 = FUN_8012dda4();
    if (cVar5 == '\0') {
      *(undefined *)(iVar6 + 0x16) = 1;
    }
    else {
      iVar6 = *(int *)(param_1 + 0x4c);
      iVar2 = FUN_80036e58(0xf,param_1,0);
      if ((*(char *)(param_1 + 0xac) == '\r') && (iVar4 = FUN_8001ffb4(0xc92), iVar4 != 0)) {
        *(float *)(iVar2 + 0x10) = *(float *)(iVar2 + 0x10) + FLOAT_803e3ba0;
        (**(code **)(*DAT_803dca54 + 0x48))(2,iVar2,0xffffffff);
      }
      else {
        (**(code **)(*DAT_803dca54 + 0x48))(1,iVar2,0xffffffff);
      }
      FUN_800200e8((int)*(short *)(iVar6 + 0x1c),0);
    }
  }
  return;
}

