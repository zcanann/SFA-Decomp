// Function: FUN_80236a4c
// Entry: 80236a4c
// Size: 248 bytes

undefined4 FUN_80236a4c(undefined4 param_1,int *param_2,int param_3)

{
  float fVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  undefined auStack_18 [12];
  
  uVar4 = 0;
  if ((*param_2 == 0) || (iVar2 = FUN_8001dc28(*param_2), iVar2 == 0)) {
    if (((int)*(short *)(param_3 + 0x24) == 0xffffffff) ||
       (uVar3 = FUN_80020078((int)*(short *)(param_3 + 0x24)), uVar3 == 0)) {
      if (((*(byte *)((int)param_2 + 0x22) & 4) != 0) &&
         (iVar2 = (**(code **)(*DAT_803dd6d8 + 0x24))(auStack_18), iVar2 != 0)) {
        uVar4 = 1;
      }
    }
    else {
      uVar4 = 1;
    }
    fVar1 = FLOAT_803e7ff8;
    if ((((*(byte *)(param_3 + 0x2a) & 0x30) == 0x10) && ((float)param_2[5] != FLOAT_803e7ff8)) &&
       (param_2[5] = (int)((float)param_2[5] - FLOAT_803dc074), (float)param_2[5] <= fVar1)) {
      uVar4 = 1;
    }
  }
  else {
    uVar4 = 0;
  }
  return uVar4;
}

