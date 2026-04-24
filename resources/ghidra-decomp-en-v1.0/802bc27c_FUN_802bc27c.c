// Function: FUN_802bc27c
// Entry: 802bc27c
// Size: 240 bytes

undefined4 FUN_802bc27c(int param_1,uint *param_2)

{
  float fVar1;
  undefined2 uVar2;
  int iVar3;
  
  fVar1 = FLOAT_803e82c0;
  iVar3 = *(int *)(param_1 + 0xb8);
  param_2[0xa5] = (uint)FLOAT_803e82c0;
  param_2[0xa1] = (uint)fVar1;
  param_2[0xa0] = (uint)fVar1;
  *(float *)(param_1 + 0x24) = fVar1;
  *(float *)(param_1 + 0x28) = fVar1;
  *(float *)(param_1 + 0x2c) = fVar1;
  *param_2 = *param_2 | 0x200000;
  if (*(char *)((int)param_2 + 0x27a) != '\0') {
    param_2[0xa8] = (uint)FLOAT_803e82c4;
    if (*(short *)(param_1 + 0xa0) != 5) {
      FUN_80030334(param_1,5,0);
    }
    uVar2 = FUN_800221a0(0x4b0,0x960);
    *(undefined2 *)(iVar3 + 0x38c) = uVar2;
  }
  if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
    FUN_800200e8(0x223,1);
    FUN_80014b3c(0,0x100);
  }
  iVar3 = FUN_8002208c((double)FLOAT_803e82c8,(double)FLOAT_803e82cc,iVar3 + 0x600);
  if (iVar3 != 0) {
    FUN_8000bb18(param_1,0x43a);
  }
  return 0;
}

