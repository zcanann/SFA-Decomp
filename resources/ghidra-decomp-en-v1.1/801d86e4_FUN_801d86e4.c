// Function: FUN_801d86e4
// Entry: 801d86e4
// Size: 532 bytes

void FUN_801d86e4(uint *param_1)

{
  int iVar1;
  uint uVar2;
  
  iVar1 = (**(code **)(*DAT_803dd6d8 + 0x24))(0);
  if (iVar1 == 0) {
    if (((*(short *)(param_1 + 4) == 0x2d) || (*(short *)(param_1 + 4) == -1)) &&
       (*(undefined2 *)(param_1 + 4) = 0x39, (*param_1 & 1) != 0)) {
      FUN_8000a538((int *)0x2d,0);
      FUN_8000a538((int *)0x39,1);
    }
    if (((*(short *)((int)param_1 + 0x12) == 0xce) || (*(short *)((int)param_1 + 0x12) == -1)) &&
       (*(undefined2 *)((int)param_1 + 0x12) = 0xc2, (*param_1 & 2) != 0)) {
      FUN_8000a538((int *)0xce,0);
      FUN_8000a538((int *)0xc2,1);
    }
  }
  else {
    if (((*(short *)(param_1 + 4) == 0x39) || (*(short *)(param_1 + 4) == -1)) &&
       (*(undefined2 *)(param_1 + 4) = 0x2d, (*param_1 & 1) != 0)) {
      FUN_8000a538((int *)0x39,0);
      FUN_8000a538((int *)0x2d,1);
    }
    if (((*(short *)((int)param_1 + 0x12) == 0xc2) || (*(short *)((int)param_1 + 0x12) == -1)) &&
       (*(undefined2 *)((int)param_1 + 0x12) = 0xce, (*param_1 & 2) != 0)) {
      FUN_8000a538((int *)0xc2,0);
      FUN_8000a538((int *)0xce,1);
    }
  }
  uVar2 = FUN_80020078(0xb);
  if (uVar2 != 0) {
    uVar2 = FUN_80020078(0x64b);
    if (uVar2 != 0) {
      FUN_800201ac(0x390,1);
    }
    FUN_801d84c4(param_1,1,0x1a7,0x64b,0x372,(int *)(int)*(short *)(param_1 + 4));
    FUN_801d84c4(param_1,2,0x1a8,0xc0,0x390,(int *)(int)*(short *)((int)param_1 + 0x12));
    FUN_801d84c4(param_1,4,-1,-1,0x393,(int *)0x36);
    FUN_801d84c4(param_1,8,-1,-1,0xa32,(int *)0x98);
    FUN_801d84c4(param_1,0x10,-1,-1,0xbfe,(int *)0xc3);
  }
  return;
}

