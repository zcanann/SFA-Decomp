// Function: FUN_802bc7c0
// Entry: 802bc7c0
// Size: 112 bytes

void FUN_802bc7c0(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (param_2 == 1) {
    *(short *)(iVar1 + 0x14e2) = *(short *)(iVar1 + 0x14e2) + 4;
    FUN_800393f8(param_1,iVar1 + 0x3bc,0x291,0x1000,0xffffffff,1);
    *(float *)(iVar1 + 0x1444) = FLOAT_803e82e8;
    DAT_803352a0 = *(undefined4 *)(iVar1 + 0x1444);
  }
  return;
}

