// Function: FUN_801cba98
// Entry: 801cba98
// Size: 636 bytes

void FUN_801cba98(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar1 = FUN_802860dc();
  iVar3 = *(int *)(iVar1 + 0xb8);
  *(undefined2 *)(param_3 + 0x6e) = 0xffff;
  *(undefined *)(param_3 + 0x56) = 0;
  if (*(short *)(iVar3 + 10) != 0) {
    *(short *)(iVar3 + 8) = *(short *)(iVar3 + 8) + *(short *)(iVar3 + 10);
    if ((*(short *)(iVar3 + 8) < 2) && (*(short *)(iVar3 + 10) < 1)) {
      *(undefined2 *)(iVar3 + 8) = 1;
      *(undefined2 *)(iVar3 + 10) = 0;
    }
    else if ((0x45 < *(short *)(iVar3 + 8)) && (-1 < *(short *)(iVar3 + 10))) {
      *(undefined2 *)(iVar3 + 8) = 0x46;
      *(undefined2 *)(iVar3 + 10) = 0;
    }
    (**(code **)(*DAT_803dca70 + 0x38))(3,*(ushort *)(iVar3 + 8) & 0xff);
  }
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar2 = iVar2 + 1) {
    switch(*(undefined *)(param_3 + iVar2 + 0x81)) {
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
      *(undefined *)(iVar3 + 0x14) = 1;
      break;
    case 4:
      *(undefined *)(iVar3 + 0x13) = 4;
      *(undefined *)(iVar3 + 0x14) = 2;
      FUN_800200e8(0x129,1);
      FUN_800200e8(0x1d2,0);
      FUN_800200e8(0x126,1);
      *(undefined2 *)(iVar3 + 10) = 0xfffd;
      break;
    case 5:
      *(undefined *)(iVar3 + 0x13) = 6;
      *(undefined *)(iVar3 + 0x14) = 3;
      *(undefined2 *)(iVar3 + 10) = 0xfffd;
      FUN_800200e8(0x129,1);
      break;
    case 6:
      FUN_800200e8(0x1d2,1);
      break;
    case 7:
      FUN_800200e8(0x1d2,0);
      *(undefined2 *)(iVar3 + 10) = 0xfffd;
      break;
    case 8:
      FUN_800200e8(0x127,1);
      break;
    case 9:
      FUN_800200e8(0x128,1);
      if (DAT_803ddbe0 == 0) {
        DAT_803ddbe0 = FUN_8005669c(1);
      }
      break;
    case 0xb:
      *(undefined2 *)(iVar3 + 8) = 100;
      (**(code **)(*DAT_803dca70 + 0x18))(3,0x2d,0x50,*(ushort *)(iVar3 + 8) & 0xff,0);
    }
    *(undefined *)(param_3 + iVar2 + 0x81) = 0;
  }
  FUN_80286128(0);
  return;
}

