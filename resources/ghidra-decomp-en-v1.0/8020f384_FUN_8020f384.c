// Function: FUN_8020f384
// Entry: 8020f384
// Size: 528 bytes

void FUN_8020f384(int param_1,int param_2)

{
  undefined4 uVar1;
  short sVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  int local_28;
  float local_24;
  float local_20 [2];
  double local_18;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  dVar5 = (double)(**(code **)(**(int **)(param_2 + 0x68) + 0x44))(param_2,&local_24);
  local_24 = (float)((double)FLOAT_803e66e4 * (double)(float)(dVar5 * (double)FLOAT_803dc224) +
                    (double)FLOAT_803dc224);
  (**(code **)(**(int **)(param_2 + 0x68) + 0x40))(param_2,local_20,&local_28);
  iVar3 = (int)(FLOAT_803e66e8 * local_20[0]);
  local_18 = (double)(longlong)iVar3;
  if (iVar3 < 0) {
    iVar3 = -iVar3;
  }
  if ((local_28 == 0) || ((int)*(short *)(param_1 + 0xa0) != (uint)*(ushort *)(iVar4 + 0xa8))) {
    FUN_8002ed6c(param_1,*(ushort *)(iVar4 + 0xa8) + 2,iVar3);
  }
  else {
    FUN_8002ed6c(param_1,*(ushort *)(iVar4 + 0xa8) + 1,iVar3);
  }
  local_18 = (double)CONCAT44(0x43300000,(uint)DAT_803db410);
  iVar3 = FUN_8002fa48((double)local_24,(double)(float)(local_18 - DOUBLE_803e6700),param_1,0);
  if ((iVar3 != 0) && ((int)*(short *)(param_1 + 0xa0) != (uint)*(ushort *)(iVar4 + 0xa8))) {
    *(float *)(iVar4 + 0x30) = FLOAT_803e66ec;
    iVar3 = *(int *)(iVar4 + 0x9c);
    if (iVar3 < 1) {
      iVar3 = 1;
    }
    else if (400 < iVar3) {
      iVar3 = 400;
    }
    *(int *)(iVar4 + 0x9c) = iVar3;
    iVar3 = FUN_80080100(2);
    if (iVar3 == 0) {
      FUN_80030334((double)FLOAT_803e66f0,param_1,*(undefined2 *)(iVar4 + 0xa8),0);
    }
    else {
      uVar1 = FUN_8002b9ec();
      sVar2 = FUN_800385e8(param_1,uVar1,0);
      if (sVar2 < 0) {
        *(float *)(iVar4 + 0x30) = FLOAT_803e66f8;
        FUN_8000bb18(param_1,0x2e2);
        iVar3 = *(ushort *)(iVar4 + 0xa8) + 4;
      }
      else {
        *(float *)(iVar4 + 0x30) = FLOAT_803e66f4;
        FUN_8000bb18(param_1,0x2e3);
        iVar3 = *(ushort *)(iVar4 + 0xa8) + 8;
      }
      FUN_80030334((double)FLOAT_803e66f0,param_1,iVar3,0);
      *(int *)(iVar4 + 0x9c) = *(int *)(iVar4 + 0x9c) + 100;
    }
  }
  return;
}

