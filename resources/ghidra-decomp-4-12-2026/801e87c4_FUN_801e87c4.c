// Function: FUN_801e87c4
// Entry: 801e87c4
// Size: 220 bytes

void FUN_801e87c4(int param_1)

{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  *(code **)(param_1 + 0xbc) = FUN_801e7c90;
  *(uint *)(*(int *)(param_1 + 100) + 0x30) = *(uint *)(*(int *)(param_1 + 100) + 0x30) | 0x810;
  uVar1 = FUN_80022264(0xf,0x23);
  *(float *)(iVar3 + 0x9b8) =
       FLOAT_803e6688 * (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e6698);
  uVar2 = FUN_80013a08(4,4);
  *(undefined4 *)(iVar3 + 0x9b0) = uVar2;
  *(undefined *)(iVar3 + 0x9d6) = 0xff;
  *(float *)(iVar3 + 0x9c4) = FLOAT_803e66c0;
  FUN_80115200(param_1,(undefined4 *)(iVar3 + 0x35c),0xe38f,0x3555,2);
  *(byte *)(iVar3 + 0x96d) = *(byte *)(iVar3 + 0x96d) | 0x12;
  return;
}

