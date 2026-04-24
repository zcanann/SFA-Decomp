// Function: FUN_801d39c4
// Entry: 801d39c4
// Size: 456 bytes

void FUN_801d39c4(int param_1,int param_2)

{
  ushort uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  uVar1 = *(ushort *)(iVar4 + 0x1c);
  uVar2 = FUN_80022264(0x1e,0x2d);
  *(float *)(param_2 + 0x298) =
       (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e6038);
  uVar2 = FUN_80022264(0x78,0xb4);
  *(float *)(param_2 + 0x284) =
       *(float *)(param_2 + 0x298) +
       (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e6038);
  uVar2 = FUN_80022264(0xfffff830,2000);
  *(short *)(param_2 + 0x2aa) = *(short *)(param_2 + 0x2a8) + (short)uVar2;
  iVar3 = (int)*(short *)(param_2 + 0x2aa) - (uint)uVar1;
  if (0x8000 < iVar3) {
    iVar3 = iVar3 + -0xffff;
  }
  if (iVar3 < -0x8000) {
    iVar3 = iVar3 + 0xffff;
  }
  if (*(short *)(iVar4 + 0x1a) < iVar3) {
    *(ushort *)(param_2 + 0x2aa) = uVar1 + *(short *)(iVar4 + 0x1a);
  }
  if (iVar3 < -(int)*(short *)(iVar4 + 0x1a)) {
    *(ushort *)(param_2 + 0x2aa) = uVar1 - *(short *)(iVar4 + 0x1a);
  }
  uVar2 = FUN_80022264(900,0x514);
  *(float *)(param_2 + 0x29c) =
       (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e6038) / FLOAT_803e6028;
  *(float *)(param_2 + 0x27c) = FLOAT_803e602c;
  dVar5 = (double)FUN_802945e0();
  *(float *)(param_2 + 0x290) = (float)dVar5;
  dVar5 = (double)FUN_80294964();
  *(float *)(param_2 + 0x294) = (float)dVar5;
  return;
}

