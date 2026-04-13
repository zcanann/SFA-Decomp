// Function: FUN_8022739c
// Entry: 8022739c
// Size: 424 bytes

void FUN_8022739c(int param_1)

{
  int iVar1;
  uint uVar2;
  byte bVar3;
  uint uVar4;
  
  iVar1 = (**(code **)(*DAT_803dd6d8 + 0x24))(0);
  if (iVar1 == 0) {
    if (*(short *)(param_1 + 0x1a) != 0x39) {
      *(undefined2 *)(param_1 + 0x1a) = 0x39;
      FUN_8000a538((int *)0x39,1);
    }
    if (*(short *)(param_1 + 0x1c) != 0x22) {
      *(undefined2 *)(param_1 + 0x1c) = 0x22;
      FUN_8000a538((int *)0x22,1);
    }
  }
  else {
    if (*(short *)(param_1 + 0x1a) != 0x2d) {
      *(undefined2 *)(param_1 + 0x1a) = 0x2d;
      FUN_8000a538((int *)0x2d,1);
    }
    if (*(ushort *)(param_1 + 0x1c) != 0xffffffff) {
      *(undefined2 *)(param_1 + 0x1c) = 0xffff;
      FUN_8000a538((int *)0x22,0);
    }
  }
  FUN_801d84c4(param_1 + 0x14,8,-1,-1,0xba6,(int *)0xd2);
  FUN_801d84c4(param_1 + 0x14,4,-1,-1,0xcce,(int *)0x36);
  FUN_801d84c4(param_1 + 0x14,0x10,-1,-1,0xcd0,(int *)0xd4);
  FUN_801d84c4(param_1 + 0x14,0x40,-1,-1,0xcbb,(int *)0xc4);
  uVar4 = 0;
  uVar2 = FUN_80020078(0xba6);
  if ((uVar2 == 0) &&
     ((uVar2 = FUN_80020078(0xda9), uVar2 != 0 || (bVar3 = FUN_80014074(), bVar3 != 0)))) {
    uVar4 = 1;
  }
  FUN_800201ac(0xf31,uVar4);
  FUN_801d84c4(param_1 + 0x14,0x80,-1,-1,0xf31,(int *)0xaf);
  return;
}

