// Function: FUN_8029b7b0
// Entry: 8029b7b0
// Size: 484 bytes

int FUN_8029b7b0(int param_1,int param_2)

{
  short sVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  iVar3 = FUN_802ac7dc(param_1,param_2,iVar4);
  fVar2 = FLOAT_803e7ea4;
  if (iVar3 == 0) {
    *(float *)(param_2 + 0x294) = FLOAT_803e7ea4;
    *(float *)(param_2 + 0x284) = fVar2;
    *(float *)(param_2 + 0x280) = fVar2;
    *(float *)(param_1 + 0x24) = fVar2;
    *(float *)(param_1 + 0x28) = fVar2;
    *(float *)(param_1 + 0x2c) = fVar2;
    FUN_8011f3ec(6);
    FUN_8011f3c8(10);
    sVar1 = *(short *)(param_1 + 0xa0);
    if (sVar1 == 0x448) {
      if ((((FLOAT_803e7e9c < *(float *)(param_1 + 0x98)) && (*(char *)(iVar4 + 0x8b3) == '\0')) &&
          (FUN_8000bb18(param_1,0x2c), DAT_803de44c != 0)) &&
         ((*(byte *)(iVar4 + 0x3f4) >> 6 & 1) != 0)) {
        *(undefined *)(iVar4 + 0x8b4) = 2;
        *(byte *)(iVar4 + 0x3f4) = *(byte *)(iVar4 + 0x3f4) & 0xf7;
      }
      if (*(char *)(param_2 + 0x346) != '\0') {
        *(code **)(param_2 + 0x308) = FUN_8029a4a8;
        return 0x2d;
      }
    }
    else if ((sVar1 < 0x448) && (sVar1 == 0x43d)) {
      if (*(char *)(param_2 + 0x346) != '\0') {
        *(code **)(param_2 + 0x308) = FUN_8029a4a8;
        return 0x2d;
      }
    }
    else {
      FUN_80030334((double)FLOAT_803e7ea4,param_1,0x43d,0);
      *(float *)(param_2 + 0x2a0) = FLOAT_803e7f4c;
      if ((DAT_803de44c != 0) && ((*(byte *)(iVar4 + 0x3f4) >> 6 & 1) != 0)) {
        *(undefined *)(iVar4 + 0x8b4) = 4;
        *(byte *)(iVar4 + 0x3f4) = *(byte *)(iVar4 + 0x3f4) & 0xf7 | 8;
      }
      fVar2 = FLOAT_803e7ea4;
      FLOAT_803de460 = FLOAT_803e7ea4;
      FLOAT_803de464 = FLOAT_803e7ea4;
      *(float *)(iVar4 + 0x7bc) = FLOAT_803e7ea4;
      *(float *)(iVar4 + 0x7b8) = fVar2;
    }
    if (((*(ushort *)(iVar4 + 0x6e2) & 0x200) == 0) && (*(char *)(iVar4 + 0x8c8) == 'R')) {
      iVar3 = 0;
    }
    else {
      FUN_80014b3c(0,0x200);
      *(code **)(param_2 + 0x308) = FUN_8029a420;
      iVar3 = 0x2c;
    }
  }
  return iVar3;
}

