// Function: FUN_801ac790
// Entry: 801ac790
// Size: 560 bytes

void FUN_801ac790(int param_1)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if (*(int *)(param_1 + 0xf4) == 0) {
    FUN_80008cbc(param_1,param_1,0xa3,0);
    FUN_80008cbc(param_1,param_1,0x9e,0);
    FUN_80008cbc(param_1,param_1,0x104,0);
    (**(code **)(*DAT_803dca64 + 0x1c))(1);
    *(undefined4 *)(param_1 + 0xf4) = 1;
  }
  bVar1 = *(byte *)(iVar3 + 0xc);
  if (bVar1 == 2) {
    iVar2 = FUN_8001ffb4(0x3a3);
    if (iVar2 != 0) {
      FUN_801ac01c(param_1);
    }
  }
  else if ((bVar1 < 2) && (bVar1 != 0)) {
    FUN_801ac248(param_1);
  }
  *(uint *)(iVar3 + 4) = *(uint *)(iVar3 + 4) & 0xfffffffe;
  if (FLOAT_803e46dc < *(float *)(iVar3 + 0x10)) {
    FUN_80019908(0xff,0xff,0xff,0xff);
    FUN_80016870(0x351);
    *(float *)(iVar3 + 0x10) = *(float *)(iVar3 + 0x10) - FLOAT_803db414;
    if (*(float *)(iVar3 + 0x10) < FLOAT_803e46dc) {
      *(float *)(iVar3 + 0x10) = FLOAT_803e46dc;
    }
  }
  iVar2 = (**(code **)(*DAT_803dca58 + 0x24))(0);
  if (iVar2 == 0) {
    if ((*(short *)(iVar3 + 10) != 0x1a) &&
       (*(undefined2 *)(iVar3 + 10) = 0x1a, (*(uint *)(iVar3 + 4) & 8) != 0)) {
      FUN_8000a518(0x1a,1);
    }
  }
  else if ((*(short *)(iVar3 + 10) != -1) &&
          (*(undefined2 *)(iVar3 + 10) = 0xffff, (*(uint *)(iVar3 + 4) & 8) != 0)) {
    FUN_8000a518(0x1a,0);
  }
  FUN_801d7ed4(iVar3 + 4,2,0x2c1,0x238,0x1ed,0xb2);
  FUN_801d7ed4(iVar3 + 4,0x10,0x1ba,0x1b9,0x1d6,0xb4);
  FUN_801d7ed4(iVar3 + 4,4,0xffffffff,0xffffffff,0x3a0,0xe9);
  FUN_801d7ed4(iVar3 + 4,8,0xffffffff,0xffffffff,0x3a1,(int)*(short *)(iVar3 + 10));
  return;
}

