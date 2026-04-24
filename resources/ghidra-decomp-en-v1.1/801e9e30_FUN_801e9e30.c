// Function: FUN_801e9e30
// Entry: 801e9e30
// Size: 264 bytes

void FUN_801e9e30(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  float local_18 [3];
  
  iVar4 = *(int *)(param_1 + 0xf4);
  iVar3 = *(int *)(param_1 + 0x4c);
  local_18[0] = FLOAT_803e6770;
  if (iVar4 == 0) {
    uVar1 = FUN_80036f50(9,param_1,local_18);
    *(undefined4 *)(param_1 + 0xf4) = uVar1;
  }
  else {
    iVar2 = (**(code **)(**(int **)(iVar4 + 0x68) + 0x28))(iVar4,(int)*(short *)(iVar3 + 0x1a));
    if ((iVar2 == 0) ||
       (iVar3 = (**(code **)(**(int **)(iVar4 + 0x68) + 0x2c))(iVar4,(int)*(short *)(iVar3 + 0x1a)),
       iVar3 != 0)) {
      *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
      *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x8000;
    }
    iVar3 = FUN_800395a4(param_1,0);
    if (iVar3 != 0) {
      *(short *)(iVar3 + 8) = *(short *)(iVar3 + 8) + 8;
      if (0x400 < *(short *)(iVar3 + 8)) {
        *(short *)(iVar3 + 8) = *(short *)(iVar3 + 8) + -0x400;
      }
    }
  }
  return;
}

