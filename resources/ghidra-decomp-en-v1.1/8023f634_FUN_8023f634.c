// Function: FUN_8023f634
// Entry: 8023f634
// Size: 288 bytes

void FUN_8023f634(undefined2 *param_1,int param_2)

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
  *(float *)(iVar3 + 100) = FLOAT_803e8228;
  *(undefined *)(iVar3 + 0xb6) = 5;
  *(undefined4 *)(iVar3 + 0x7c) = 1;
  *(undefined4 *)(iVar3 + 0x80) = 0xffffffff;
  *(undefined2 *)(iVar3 + 0xa0) = 0x8000;
  *param_1 = 0x8000;
  *(float *)(iVar3 + 0x6c) = FLOAT_803e822c;
  *(float *)(iVar3 + 0xa8) = FLOAT_803e816c;
  *(float *)(iVar3 + 0x74) = FLOAT_803e8230;
  *(float *)(iVar3 + 0x78) = FLOAT_803e81c8;
  *(undefined *)(iVar3 + 0xbc) = 1;
  FUN_80035a58((int)param_1,4);
  *(code **)(param_1 + 0x5e) = FUN_8023b06c;
  FUN_8006cccc();
  piVar1 = (int *)FUN_8002b660((int)param_1);
  iVar3 = *piVar1;
  for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(iVar3 + 0xf8); iVar4 = iVar4 + 1) {
    iVar2 = FUN_800284e8(iVar3,iVar4);
    *(undefined *)(iVar2 + 0x43) = 0;
  }
  FUN_800201ac(0xd,0);
  FUN_80043604(0,0,1);
  return;
}

