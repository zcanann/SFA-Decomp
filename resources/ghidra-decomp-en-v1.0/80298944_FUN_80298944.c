// Function: FUN_80298944
// Entry: 80298944
// Size: 904 bytes

undefined4 FUN_80298944(int param_1,int param_2)

{
  short sVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80035e8c();
  }
  fVar2 = FLOAT_803e7ea4;
  *(float *)(param_2 + 0x294) = FLOAT_803e7ea4;
  *(float *)(param_2 + 0x284) = fVar2;
  *(float *)(param_2 + 0x280) = fVar2;
  *(float *)(param_1 + 0x24) = fVar2;
  *(float *)(param_1 + 0x28) = fVar2;
  *(float *)(param_1 + 0x2c) = fVar2;
  FUN_8011f3ec(0xe);
  FUN_8011f3c8(10);
  sVar1 = *(short *)(param_1 + 0xa0);
  if (sVar1 == 0xe1) {
    if ((FLOAT_803e7e98 < *(float *)(param_1 + 0x98)) && ((*(byte *)(param_2 + 0x356) & 1) == 0)) {
      *(byte *)(param_2 + 0x356) = *(byte *)(param_2 + 0x356) | 1;
      FUN_8000bb18(param_1,0x376);
    }
    if (*(char *)(param_2 + 0x346) == '\0') {
      return 0;
    }
    FUN_80030334((double)FLOAT_803e7ea4,param_1,0xde,0);
    *(float *)(param_2 + 0x2a0) = FLOAT_803e7f40;
    *(undefined *)(param_2 + 0x356) = 0;
    return 0;
  }
  if (sVar1 < 0xe1) {
    if (sVar1 == 0xdf) {
      if ((FLOAT_803e7e9c < *(float *)(param_1 + 0x98)) && ((*(byte *)(param_2 + 0x356) & 1) == 0))
      {
        *(byte *)(param_2 + 0x356) = *(byte *)(param_2 + 0x356) | 1;
        FUN_80014aa0((double)FLOAT_803e7f10);
        FUN_8000bb18(param_1,0x377);
        FUN_80189be4(DAT_803de434,1);
      }
      if (*(char *)(param_2 + 0x346) == '\0') {
        return 0;
      }
      FUN_80030334((double)FLOAT_803e7ea4,param_1,0xe5,0);
      *(float *)(param_2 + 0x2a0) = FLOAT_803e7f40;
      FUN_8000bb18(param_1,0x3c3);
      return 0;
    }
    if (0xde < sVar1) {
      if ((FLOAT_803e7e98 < *(float *)(param_1 + 0x98)) && ((*(byte *)(param_2 + 0x356) & 1) == 0))
      {
        *(byte *)(param_2 + 0x356) = *(byte *)(param_2 + 0x356) | 1;
        FUN_8000bb18(param_1,0x376);
      }
      if (*(char *)(param_2 + 0x346) == '\0') {
        return 0;
      }
      FUN_80030334((double)FLOAT_803e7ea4,param_1,0xdf,0);
      *(float *)(param_2 + 0x2a0) = FLOAT_803e7f40;
      *(undefined *)(param_2 + 0x356) = 0;
      return 0;
    }
    if (0xdd < sVar1) {
      if ((FLOAT_803e7e9c < *(float *)(param_1 + 0x98)) && ((*(byte *)(param_2 + 0x356) & 1) == 0))
      {
        *(byte *)(param_2 + 0x356) = *(byte *)(param_2 + 0x356) | 1;
        FUN_80014aa0((double)FLOAT_803e7f10);
        FUN_8000bb18(param_1,0x377);
        FUN_80189be4(DAT_803de434,0);
      }
      if (*(char *)(param_2 + 0x346) == '\0') {
        return 0;
      }
      FUN_80030334((double)FLOAT_803e7ea4,param_1,0xe4,0);
      *(float *)(param_2 + 0x2a0) = FLOAT_803e7f40;
      FUN_8000bb18(param_1,0x3c3);
      return 0;
    }
  }
  else if ((sVar1 < 0xe6) && (0xe3 < sVar1)) {
    if (*(char *)(param_2 + 0x346) == '\0') {
      return 0;
    }
    *(uint *)(iVar4 + 0x360) = *(uint *)(iVar4 + 0x360) | 0x800000;
    *(code **)(param_2 + 0x308) = FUN_802a514c;
    return 2;
  }
  iVar3 = FUN_80189c58(DAT_803de434);
  if (iVar3 == 0) {
    FUN_80030334((double)FLOAT_803e7ea4,param_1,0xe0,0);
  }
  else {
    FUN_80030334((double)FLOAT_803e7ea4,param_1,0xe1,0);
  }
  FUN_80189f5c(DAT_803de434,param_1 + 0xc,param_1 + 0x14);
  *(float *)(param_2 + 0x2a0) = FLOAT_803e7f40;
  *(undefined *)(param_2 + 0x356) = 0;
  *(undefined2 *)(iVar4 + 0x478) = *DAT_803de434;
  *(undefined2 *)(iVar4 + 0x484) = *(undefined2 *)(iVar4 + 0x478);
  if ((DAT_803de44c != 0) && ((*(byte *)(iVar4 + 0x3f4) >> 6 & 1) != 0)) {
    *(undefined *)(iVar4 + 0x8b4) = 4;
    *(byte *)(iVar4 + 0x3f4) = *(byte *)(iVar4 + 0x3f4) & 0xf7 | 8;
  }
  return 0;
}

