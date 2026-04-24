// Function: FUN_802a49c8
// Entry: 802a49c8
// Size: 388 bytes

undefined4 FUN_802a49c8(int param_1,int param_2)

{
  short sVar1;
  float fVar2;
  undefined4 uVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27a) != '\0') {
    if (*(int *)(iVar4 + 0x7f8) != 0) {
      FUN_80035e8c();
    }
    FUN_80030334((double)FLOAT_803e7eac,param_1,0x443,0);
    *(undefined2 *)(param_2 + 0x278) = 1;
    *(code **)(iVar4 + 0x898) = FUN_802a514c;
  }
  fVar2 = FLOAT_803e7ea4;
  *(float *)(param_2 + 0x294) = FLOAT_803e7ea4;
  *(float *)(param_2 + 0x284) = fVar2;
  *(float *)(param_2 + 0x280) = fVar2;
  *(float *)(param_1 + 0x24) = fVar2;
  *(float *)(param_1 + 0x28) = fVar2;
  *(float *)(param_1 + 0x2c) = fVar2;
  *(float *)(param_2 + 0x2a0) = FLOAT_803e8058;
  if ((*(uint *)(param_2 + 0x314) & 1) != 0) {
    if (*(short *)(iVar4 + 0x81a) == 0) {
      uVar3 = 0x327;
    }
    else {
      uVar3 = 0x379;
    }
    FUN_8000bb18(param_1,uVar3);
  }
  if ((*(int *)(iVar4 + 0x7f8) == 0) && (*(char *)(param_2 + 0x346) != '\0')) {
    *(code **)(param_2 + 0x308) = FUN_802a514c;
    uVar3 = 2;
  }
  else {
    if ((*(int *)(iVar4 + 0x7f8) != 0) && (FLOAT_803e7e9c < *(float *)(param_1 + 0x98))) {
      *(undefined *)(iVar4 + 0x800) = 0;
      if (*(int *)(iVar4 + 0x7f8) != 0) {
        sVar1 = *(short *)(*(int *)(iVar4 + 0x7f8) + 0x46);
        if ((sVar1 == 0x3cf) || (sVar1 == 0x662)) {
          FUN_80182504();
        }
        else {
          FUN_800ea774();
        }
        *(ushort *)(*(int *)(iVar4 + 0x7f8) + 6) = *(ushort *)(*(int *)(iVar4 + 0x7f8) + 6) & 0xbfff
        ;
        *(undefined4 *)(*(int *)(iVar4 + 0x7f8) + 0xf8) = 0;
        *(undefined4 *)(iVar4 + 0x7f8) = 0;
      }
    }
    uVar3 = 0;
  }
  return uVar3;
}

