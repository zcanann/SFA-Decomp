// Function: FUN_802397e4
// Entry: 802397e4
// Size: 116 bytes

void FUN_802397e4(int param_1,int param_2)

{
  float fVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
  *(code **)(param_1 + 0xbc) = FUN_8023938c;
  FUN_80037200(param_1,0x48);
  *(byte *)(iVar2 + 0x1b) = *(byte *)(param_2 + 0x1a) & 0xf | *(byte *)(iVar2 + 0x1b) & 0xf0;
  fVar1 = FLOAT_803e745c;
  *(float *)(iVar2 + 0x10) = FLOAT_803e745c;
  *(float *)(iVar2 + 0x14) = fVar1;
  return;
}

