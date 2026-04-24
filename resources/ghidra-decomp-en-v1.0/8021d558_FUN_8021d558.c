// Function: FUN_8021d558
// Entry: 8021d558
// Size: 400 bytes

undefined4 FUN_8021d558(int param_1,int param_2)

{
  short sVar1;
  float fVar2;
  undefined4 uVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27a) != '\0') {
    *(float *)(iVar4 + 0xc30) = FLOAT_803e6ab4;
    fVar2 = FLOAT_803e6aa8;
    *(float *)(param_2 + 0x294) = FLOAT_803e6aa8;
    *(float *)(param_2 + 0x284) = fVar2;
    *(float *)(param_2 + 0x280) = fVar2;
    *(float *)(param_1 + 0x24) = fVar2;
    *(float *)(param_1 + 0x28) = fVar2;
    *(float *)(param_1 + 0x2c) = fVar2;
  }
  if (*(char *)(param_2 + 0x346) != '\0') {
    sVar1 = *(short *)(param_1 + 0xa0);
    if (sVar1 == 10) {
      if (*(float *)(param_2 + 0x2a0) <= FLOAT_803e6aa8) {
        return 8;
      }
      FUN_80030334(param_1,5,0);
    }
    else if ((sVar1 < 10) && (sVar1 == 5)) {
      if (*(float *)(iVar4 + 0xc30) < FLOAT_803e6aa8) {
        FUN_80030334((double)FLOAT_803e6ab8,param_1,10,0);
        *(float *)(param_2 + 0x2a0) = FLOAT_803e6abc;
      }
    }
    else {
      FUN_80030334((double)FLOAT_803e6aa8,param_1,10,0);
      *(float *)(param_2 + 0x2a0) = FLOAT_803e6ac0;
    }
  }
  if (((*(short *)(param_1 + 0xa0) != 10) || (FLOAT_803e6aa8 <= *(float *)(param_2 + 0x2a0))) ||
     (FLOAT_803e6ac4 <= *(float *)(param_1 + 0x98))) {
    *(float *)(iVar4 + 0xc30) =
         *(float *)(iVar4 + 0xc30) -
         (float)((double)CONCAT44(0x43300000,(uint)DAT_803db410) - DOUBLE_803e6ad0);
    uVar3 = 0;
  }
  else {
    FUN_80030334(param_1,0,0);
    *(float *)(param_2 + 0x2a0) = FLOAT_803e6ac8;
    uVar3 = 8;
  }
  return uVar3;
}

