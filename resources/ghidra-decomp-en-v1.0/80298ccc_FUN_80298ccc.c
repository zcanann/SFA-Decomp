// Function: FUN_80298ccc
// Entry: 80298ccc
// Size: 392 bytes

undefined4 FUN_80298ccc(int param_1,int param_2)

{
  float fVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80035e8c();
  }
  fVar1 = FLOAT_803e7ea4;
  *(float *)(param_2 + 0x294) = FLOAT_803e7ea4;
  *(float *)(param_2 + 0x284) = fVar1;
  *(float *)(param_2 + 0x280) = fVar1;
  *(float *)(param_1 + 0x24) = fVar1;
  *(float *)(param_1 + 0x28) = fVar1;
  *(float *)(param_1 + 0x2c) = fVar1;
  if (*(short *)(param_1 + 0xa0) == 0xdd) {
    if (FLOAT_803e7f44 < *(float *)(param_1 + 0x98)) {
      FUN_8018a20c(DAT_803de434,0);
    }
    if ((FLOAT_803e7f48 < *(float *)(param_1 + 0x98)) && ((*(byte *)(param_2 + 0x356) & 1) == 0)) {
      FUN_8000bb18(param_1,0x2c3);
      *(byte *)(param_2 + 0x356) = *(byte *)(param_2 + 0x356) | 1;
    }
    if (*(char *)(param_2 + 0x346) != '\0') {
      *(uint *)(iVar2 + 0x360) = *(uint *)(iVar2 + 0x360) | 0x800000;
      *(code **)(param_2 + 0x308) = FUN_802a514c;
      return 2;
    }
  }
  else {
    FUN_80030334(param_1,0xdd,0);
    FUN_80189f5c(DAT_803de434,param_1 + 0xc,param_1 + 0x14);
    *(float *)(param_2 + 0x2a0) = FLOAT_803e7ef8;
    *(undefined *)(param_2 + 0x356) = 0;
    *(undefined2 *)(iVar2 + 0x478) = *DAT_803de434;
    *(undefined2 *)(iVar2 + 0x484) = *(undefined2 *)(iVar2 + 0x478);
    if ((DAT_803de44c != 0) && ((*(byte *)(iVar2 + 0x3f4) >> 6 & 1) != 0)) {
      *(undefined *)(iVar2 + 0x8b4) = 4;
      *(byte *)(iVar2 + 0x3f4) = *(byte *)(iVar2 + 0x3f4) & 0xf7 | 8;
    }
  }
  return 0;
}

