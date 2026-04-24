// Function: FUN_802bcf30
// Entry: 802bcf30
// Size: 112 bytes

void FUN_802bcf30(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (param_2 == 1) {
    *(short *)(iVar1 + 0x14e2) = *(short *)(iVar1 + 0x14e2) + 4;
    FUN_800394f0(param_1,iVar1 + 0x3bc,0x291,0x1000,0xffffffff,1);
    *(float *)(iVar1 + 0x1444) = FLOAT_803e8f80;
    DAT_80335f00 = *(undefined4 *)(iVar1 + 0x1444);
  }
  return;
}

