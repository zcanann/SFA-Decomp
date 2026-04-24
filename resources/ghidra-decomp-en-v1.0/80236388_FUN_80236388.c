// Function: FUN_80236388
// Entry: 80236388
// Size: 248 bytes

undefined4 FUN_80236388(undefined4 param_1,int *param_2,int param_3)

{
  float fVar1;
  int iVar2;
  undefined4 uVar3;
  undefined auStack24 [12];
  
  uVar3 = 0;
  if ((*param_2 == 0) || (iVar2 = FUN_8001db64(), iVar2 == 0)) {
    if ((*(short *)(param_3 + 0x24) == -1) || (iVar2 = FUN_8001ffb4(), iVar2 == 0)) {
      if (((*(byte *)((int)param_2 + 0x22) & 4) != 0) &&
         (iVar2 = (**(code **)(*DAT_803dca58 + 0x24))(auStack24), iVar2 != 0)) {
        uVar3 = 1;
      }
    }
    else {
      uVar3 = 1;
    }
    fVar1 = FLOAT_803e7360;
    if ((((*(byte *)(param_3 + 0x2a) & 0x30) == 0x10) && ((float)param_2[5] != FLOAT_803e7360)) &&
       (param_2[5] = (int)((float)param_2[5] - FLOAT_803db414), (float)param_2[5] <= fVar1)) {
      uVar3 = 1;
    }
  }
  else {
    uVar3 = 0;
  }
  return uVar3;
}

