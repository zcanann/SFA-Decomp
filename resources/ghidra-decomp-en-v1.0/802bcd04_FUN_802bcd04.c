// Function: FUN_802bcd04
// Entry: 802bcd04
// Size: 272 bytes

int FUN_802bcd04(int param_1,int param_2)

{
  float fVar1;
  undefined4 uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  fVar1 = FLOAT_803e8304;
  *(float *)(param_2 + 0x294) = FLOAT_803e8304;
  *(float *)(param_2 + 0x284) = fVar1;
  *(float *)(param_2 + 0x280) = fVar1;
  *(float *)(param_1 + 0x24) = fVar1;
  *(float *)(param_1 + 0x28) = fVar1;
  *(float *)(param_1 + 0x2c) = fVar1;
  if (*(char *)(param_2 + 0x27a) != '\0') {
    if (*(char *)(iVar3 + 0x14ec) < '\0') {
      FUN_80030334(param_1,7,0);
    }
    else {
      FUN_80030334(param_1,8,0);
    }
    *(float *)(param_2 + 0x2a0) = FLOAT_803e8310;
  }
  if ((*(char *)(param_2 + 0x346) == '\0') || (*(char *)(iVar3 + 0x14e6) != '\x02')) {
    iVar3 = 0;
  }
  else {
    *(short *)(iVar3 + 0x14e2) = *(short *)(iVar3 + 0x14e2) + -1;
    if (*(short *)(iVar3 + 0x14e2) < 1) {
      *(float *)(iVar3 + 0x1444) = FLOAT_803dc76c;
      FUN_8000fad8();
      FUN_8000e67c((double)FLOAT_803e8338);
      uVar2 = FUN_8002b9ec();
      FUN_80296afc(uVar2,0xffffffff);
      *(undefined2 *)(iVar3 + 0x14e2) = 0;
    }
    iVar3 = *(int *)(iVar3 + 0x14d8) + 1;
  }
  return iVar3;
}

