// Function: FUN_801e3dc4
// Entry: 801e3dc4
// Size: 312 bytes

void FUN_801e3dc4(int param_1)

{
  float fVar1;
  short sVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  
  fVar3 = FLOAT_803e58b4;
  iVar5 = *(int *)(param_1 + 0xb8);
  fVar1 = *(float *)(iVar5 + 0x1c);
  if (fVar1 <= FLOAT_803e58b4) {
    iVar4 = *(int *)(*(int *)(param_1 + 0x54) + 0x50);
    if ((((iVar4 != 0) && (sVar2 = *(short *)(iVar4 + 0x46), sVar2 != 0x119)) && (sVar2 != 0x113))
       && (FLOAT_803e58b4 == fVar1)) {
      FUN_8000bb18(param_1,0x31d);
      *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
           *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 0xfffe;
      *(float *)(iVar5 + 0x1c) = FLOAT_803e58b8;
      *(undefined *)(param_1 + 0x36) = 0x19;
      iVar5 = 0x32;
      do {
        (**(code **)(*DAT_803dca88 + 8))(param_1,0xa7,0,1,0xffffffff,0);
        iVar5 = iVar5 + -1;
      } while (iVar5 != 0);
      iVar5 = 10;
      do {
        (**(code **)(*DAT_803dca88 + 8))(param_1,0xab,0,1,0xffffffff,0);
        iVar5 = iVar5 + -1;
      } while (iVar5 != 0);
    }
  }
  else {
    *(float *)(iVar5 + 0x1c) = fVar1 - FLOAT_803db414;
    if (*(float *)(iVar5 + 0x1c) <= fVar3) {
      FUN_8002cbc4();
    }
  }
  return;
}

