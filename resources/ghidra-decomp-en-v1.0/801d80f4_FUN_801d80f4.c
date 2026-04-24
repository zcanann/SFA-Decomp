// Function: FUN_801d80f4
// Entry: 801d80f4
// Size: 532 bytes

void FUN_801d80f4(uint *param_1)

{
  int iVar1;
  
  iVar1 = (**(code **)(*DAT_803dca58 + 0x24))(0);
  if (iVar1 == 0) {
    if (((*(short *)(param_1 + 4) == 0x2d) || (*(short *)(param_1 + 4) == -1)) &&
       (*(undefined2 *)(param_1 + 4) = 0x39, (*param_1 & 1) != 0)) {
      FUN_8000a518(0x2d,0);
      FUN_8000a518(0x39,1);
    }
    if (((*(short *)((int)param_1 + 0x12) == 0xce) || (*(short *)((int)param_1 + 0x12) == -1)) &&
       (*(undefined2 *)((int)param_1 + 0x12) = 0xc2, (*param_1 & 2) != 0)) {
      FUN_8000a518(0xce,0);
      FUN_8000a518(0xc2,1);
    }
  }
  else {
    if (((*(short *)(param_1 + 4) == 0x39) || (*(short *)(param_1 + 4) == -1)) &&
       (*(undefined2 *)(param_1 + 4) = 0x2d, (*param_1 & 1) != 0)) {
      FUN_8000a518(0x39,0);
      FUN_8000a518(0x2d,1);
    }
    if (((*(short *)((int)param_1 + 0x12) == 0xc2) || (*(short *)((int)param_1 + 0x12) == -1)) &&
       (*(undefined2 *)((int)param_1 + 0x12) = 0xce, (*param_1 & 2) != 0)) {
      FUN_8000a518(0xc2,0);
      FUN_8000a518(0xce,1);
    }
  }
  iVar1 = FUN_8001ffb4(0xb);
  if (iVar1 != 0) {
    iVar1 = FUN_8001ffb4(0x64b);
    if (iVar1 != 0) {
      FUN_800200e8(0x390,1);
    }
    FUN_801d7ed4(param_1,1,0x1a7,0x64b,0x372,(int)*(short *)(param_1 + 4));
    FUN_801d7ed4(param_1,2,0x1a8,0xc0,0x390,(int)*(short *)((int)param_1 + 0x12));
    FUN_801d7ed4(param_1,4,0xffffffff,0xffffffff,0x393,0x36);
    FUN_801d7ed4(param_1,8,0xffffffff,0xffffffff,0xa32,0x98);
    FUN_801d7ed4(param_1,0x10,0xffffffff,0xffffffff,0xbfe,0xc3);
  }
  return;
}

