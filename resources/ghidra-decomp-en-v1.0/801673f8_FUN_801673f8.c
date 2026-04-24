// Function: FUN_801673f8
// Entry: 801673f8
// Size: 344 bytes

void FUN_801673f8(int param_1,int param_2,int param_3)

{
  float fVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  uVar2 = 6;
  if (param_3 != 0) {
    uVar2 = 7;
  }
  (**(code **)(*DAT_803dcab8 + 0x58))((double)FLOAT_803e3048,param_1,param_2,iVar4,5,1,0x108,uVar2);
  *(undefined4 *)(param_1 + 0xbc) = 0;
  iVar3 = *(int *)(iVar4 + 0x40c);
  FUN_800033a8(iVar3,0,0x94);
  *(undefined *)(iVar3 + 0x90) = 5;
  *(byte *)(iVar3 + 0x92) = *(byte *)(iVar3 + 0x92) & 0xf | 0x30;
  fVar1 = FLOAT_803e2fdc;
  *(float *)(iVar3 + 0x7c) = FLOAT_803e2fdc;
  *(float *)(iVar3 + 0x80) = FLOAT_803e2ff4;
  *(float *)(iVar3 + 0x84) = fVar1;
  *(float *)(iVar3 + 0x88) = -*(float *)(param_1 + 0x10);
  *(undefined4 *)(iVar3 + 0x70) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(iVar3 + 0x74) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(iVar3 + 0x78) = *(undefined4 *)(param_1 + 0x14);
  FUN_80030334(param_1,0,0);
  *(ushort *)(iVar4 + 0x274) = (ushort)(*(char *)(param_2 + 0x2b) != '\0');
  *(undefined2 *)(iVar4 + 0x270) = 0;
  *(undefined2 *)(iVar4 + 0x402) = 0;
  *(undefined *)(iVar4 + 0x405) = 0;
  *(undefined *)(iVar4 + 0x25f) = 0;
  FUN_80035f00(param_1);
  fVar1 = FLOAT_803e2ff4;
  *(float *)(iVar3 + 4) = FLOAT_803e2ff4;
  *(float *)(iVar3 + 0x18) = fVar1;
  *(float *)(iVar3 + 0x2c) = fVar1;
  *(float *)(iVar3 + 0x40) = fVar1;
  return;
}

