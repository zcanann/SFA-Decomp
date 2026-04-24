// Function: FUN_801ca9c0
// Entry: 801ca9c0
// Size: 788 bytes

void FUN_801ca9c0(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  
  iVar1 = FUN_802860dc();
  iVar4 = *(int *)(iVar1 + 0xb8);
  *(undefined2 *)(param_3 + 0x70) = 0xffff;
  *(undefined *)(param_3 + 0x56) = 0;
  if (*(short *)(iVar4 + 10) != 0) {
    *(short *)(iVar4 + 8) = *(short *)(iVar4 + 8) + *(short *)(iVar4 + 10);
    if ((*(short *)(iVar4 + 8) < 2) && (*(short *)(iVar4 + 10) < 1)) {
      *(undefined2 *)(iVar4 + 8) = 1;
      *(undefined2 *)(iVar4 + 10) = 0;
    }
    else if ((0x45 < *(short *)(iVar4 + 8)) && (-1 < *(short *)(iVar4 + 10))) {
      *(undefined2 *)(iVar4 + 8) = 0x46;
      *(undefined2 *)(iVar4 + 10) = 0;
    }
    (**(code **)(*DAT_803dca70 + 0x38))(3,*(ushort *)(iVar4 + 8) & 0xff);
  }
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar3 = iVar3 + 1) {
    switch(*(undefined *)(param_3 + iVar3 + 0x81)) {
    case 1:
      FUN_80008cbc(iVar1,iVar1,0xc3,0);
      break;
    case 2:
      if (DAT_803db610 == 0xffffffff) {
        FUN_80008cbc(iVar1,iVar1,0x14,0);
      }
      else {
        FUN_80008cbc(iVar1,iVar1,DAT_803db610 & 0xffff,0);
      }
      break;
    case 3:
      *(undefined *)(iVar4 + 0x10) = 1;
      break;
    case 4:
      *(undefined *)(iVar4 + 0xf) = 4;
      *(undefined *)(iVar4 + 0x10) = 2;
      FUN_800200e8(0x129,1);
      FUN_800200e8(0x1cf,0);
      FUN_800200e8(0x126,1);
      *(undefined2 *)(iVar4 + 10) = 0xfffd;
      break;
    case 5:
      *(undefined *)(iVar4 + 0x10) = 3;
      *(undefined2 *)(iVar4 + 10) = 0xfffd;
      FUN_800200e8(0x129,1);
      break;
    case 6:
      FUN_800200e8(0x1cf,1);
      break;
    case 7:
      FUN_800200e8(0x1cf,0);
      *(undefined2 *)(iVar4 + 10) = 0xfffd;
      break;
    case 8:
      FUN_800200e8(0x127,1);
      break;
    case 9:
      FUN_800200e8(0x128,1);
      if (DAT_803ddbd8 == 0) {
        DAT_803ddbd8 = FUN_8005669c(1);
      }
      break;
    case 10:
      *(undefined2 *)(iVar4 + 8) = 100;
      (**(code **)(*DAT_803dca70 + 0x18))(3,0x2d,0x50,*(ushort *)(iVar4 + 8) & 0xff,0);
      break;
    case 0xb:
      *(undefined *)(iVar4 + 0xf) = 7;
    }
    *(undefined *)(param_3 + iVar3 + 0x81) = 0;
  }
  if (*(char *)(iVar4 + 0xf) == '\a') {
    uVar2 = FUN_80014ee8(0);
    if ((uVar2 & 0x100) == 0) {
      uVar2 = FUN_80014ee8(0);
      if ((uVar2 & 0x200) != 0) {
        (**(code **)(*DAT_803dca54 + 0x4c))((int)*(char *)(param_3 + 0x57));
        *(undefined *)(iVar4 + 0xf) = 7;
        *(undefined2 *)(iVar4 + 2) = 0;
      }
    }
    else {
      (**(code **)(*DAT_803dca54 + 0x4c))((int)*(char *)(param_3 + 0x57));
      *(undefined *)(iVar4 + 0xf) = 8;
      *(undefined2 *)(iVar4 + 2) = 0;
    }
  }
  FUN_80286128(0);
  return;
}

