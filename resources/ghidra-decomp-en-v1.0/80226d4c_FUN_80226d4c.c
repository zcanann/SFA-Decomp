// Function: FUN_80226d4c
// Entry: 80226d4c
// Size: 424 bytes

void FUN_80226d4c(int param_1)

{
  int iVar1;
  char cVar2;
  undefined4 uVar3;
  
  iVar1 = (**(code **)(*DAT_803dca58 + 0x24))(0);
  if (iVar1 == 0) {
    if (*(short *)(param_1 + 0x16) != 0x39) {
      *(undefined2 *)(param_1 + 0x16) = 0x39;
      FUN_8000a518(0x39,1);
    }
    if (*(short *)(param_1 + 0x18) != 0x22) {
      *(undefined2 *)(param_1 + 0x18) = 0x22;
      FUN_8000a518(0x22,1);
    }
  }
  else {
    if (*(short *)(param_1 + 0x16) != 0x2d) {
      *(undefined2 *)(param_1 + 0x16) = 0x2d;
      FUN_8000a518(0x2d,1);
    }
    if (*(ushort *)(param_1 + 0x18) != 0xffffffff) {
      *(undefined2 *)(param_1 + 0x18) = 0xffff;
      FUN_8000a518(0x22,0);
    }
  }
  FUN_801d7ed4(param_1 + 0x10,8,0xffffffff,0xffffffff,0xba6,0xd2);
  FUN_801d7ed4(param_1 + 0x10,4,0xffffffff,0xffffffff,0xcce,0x36);
  FUN_801d7ed4(param_1 + 0x10,0x10,0xffffffff,0xffffffff,0xcd0,0xd4);
  FUN_801d7ed4(param_1 + 0x10,0x40,0xffffffff,0xffffffff,0xcbb,0xc4);
  uVar3 = 0;
  iVar1 = FUN_8001ffb4(0xba6);
  if ((iVar1 == 0) &&
     ((iVar1 = FUN_8001ffb4(0xda9), iVar1 != 0 || (cVar2 = FUN_80014054(), cVar2 != '\0')))) {
    uVar3 = 1;
  }
  FUN_800200e8(0xf31,uVar3);
  FUN_801d7ed4(param_1 + 0x10,0x80,0xffffffff,0xffffffff,0xf31,0xaf);
  return;
}

