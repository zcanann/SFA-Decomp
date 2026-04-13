// Function: FUN_801678a4
// Entry: 801678a4
// Size: 344 bytes

void FUN_801678a4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10,int param_11)

{
  float fVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  double dVar9;
  
  iVar8 = *(int *)(param_9 + 0xb8);
  uVar5 = 6;
  if (param_11 != 0) {
    uVar5 = 7;
  }
  uVar2 = 5;
  uVar3 = 1;
  uVar4 = 0x108;
  iVar6 = *DAT_803dd738;
  (**(code **)(iVar6 + 0x58))((double)FLOAT_803e3ce0,param_9,param_10,iVar8);
  *(undefined4 *)(param_9 + 0xbc) = 0;
  iVar7 = *(int *)(iVar8 + 0x40c);
  FUN_800033a8(iVar7,0,0x94);
  *(undefined *)(iVar7 + 0x90) = 5;
  *(byte *)(iVar7 + 0x92) = *(byte *)(iVar7 + 0x92) & 0xf | 0x30;
  fVar1 = FLOAT_803e3c74;
  dVar9 = (double)FLOAT_803e3c74;
  *(float *)(iVar7 + 0x7c) = FLOAT_803e3c74;
  *(float *)(iVar7 + 0x80) = FLOAT_803e3c8c;
  *(float *)(iVar7 + 0x84) = fVar1;
  *(float *)(iVar7 + 0x88) = -*(float *)(param_9 + 0x10);
  *(undefined4 *)(iVar7 + 0x70) = *(undefined4 *)(param_9 + 0xc);
  *(undefined4 *)(iVar7 + 0x74) = *(undefined4 *)(param_9 + 0x10);
  *(undefined4 *)(iVar7 + 0x78) = *(undefined4 *)(param_9 + 0x14);
  FUN_8003042c(dVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,0,0,uVar2,uVar3
               ,uVar4,uVar5,iVar6);
  *(ushort *)(iVar8 + 0x274) = (ushort)(*(char *)(param_10 + 0x2b) != '\0');
  *(undefined2 *)(iVar8 + 0x270) = 0;
  *(undefined2 *)(iVar8 + 0x402) = 0;
  *(undefined *)(iVar8 + 0x405) = 0;
  *(undefined *)(iVar8 + 0x25f) = 0;
  FUN_80035ff8(param_9);
  fVar1 = FLOAT_803e3c8c;
  *(float *)(iVar7 + 4) = FLOAT_803e3c8c;
  *(float *)(iVar7 + 0x18) = fVar1;
  *(float *)(iVar7 + 0x2c) = fVar1;
  *(float *)(iVar7 + 0x40) = fVar1;
  return;
}

