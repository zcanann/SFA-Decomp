// Function: FUN_8023ef3c
// Entry: 8023ef3c
// Size: 288 bytes

void FUN_8023ef3c(undefined2 *param_1,int param_2)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar3 = *(int *)(param_1 + 0x5c);
  *(undefined4 *)(iVar3 + 0x58) = *(undefined4 *)(param_2 + 8);
  *(undefined4 *)(iVar3 + 0x5c) = *(undefined4 *)(param_2 + 0xc);
  *(undefined4 *)(iVar3 + 0x60) = *(undefined4 *)(param_2 + 0x10);
  *(undefined2 *)(iVar3 + 0x98) = 0;
  *(undefined4 *)(iVar3 + 0x88) = 0;
  *(undefined4 *)(iVar3 + 0x8c) = 0xffffffff;
  *(float *)(iVar3 + 100) = FLOAT_803e7590;
  *(undefined *)(iVar3 + 0xb6) = 5;
  *(undefined4 *)(iVar3 + 0x7c) = 1;
  *(undefined4 *)(iVar3 + 0x80) = 0xffffffff;
  *(undefined2 *)(iVar3 + 0xa0) = 0x8000;
  *param_1 = 0x8000;
  *(float *)(iVar3 + 0x6c) = FLOAT_803e7594;
  *(float *)(iVar3 + 0xa8) = FLOAT_803e74d4;
  *(float *)(iVar3 + 0x74) = FLOAT_803e7598;
  *(float *)(iVar3 + 0x78) = FLOAT_803e7530;
  *(undefined *)(iVar3 + 0xbc) = 1;
  FUN_80035960(param_1,4);
  *(code **)(param_1 + 0x5e) = FUN_8023a974;
  FUN_8006cb50();
  piVar1 = (int *)FUN_8002b588(param_1);
  iVar3 = *piVar1;
  for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(iVar3 + 0xf8); iVar4 = iVar4 + 1) {
    iVar2 = FUN_80028424(iVar3,iVar4);
    *(undefined *)(iVar2 + 0x43) = 0;
  }
  FUN_800200e8(0xd,0);
  FUN_8004350c(0,0,1);
  return;
}

