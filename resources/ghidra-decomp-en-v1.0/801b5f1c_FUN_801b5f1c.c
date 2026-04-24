// Function: FUN_801b5f1c
// Entry: 801b5f1c
// Size: 272 bytes

void FUN_801b5f1c(undefined4 param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  
  iVar1 = FUN_800394ac(param_1,0,0);
  *(short *)(iVar1 + 10) = *(short *)(iVar1 + 10) + 0x14;
  if (10000 < *(short *)(iVar1 + 10)) {
    *(short *)(iVar1 + 10) = *(short *)(iVar1 + 10) + -10000;
  }
  *(short *)(iVar1 + 8) = *(short *)(iVar1 + 8) + 10;
  if (10000 < *(short *)(iVar1 + 8)) {
    *(short *)(iVar1 + 8) = *(short *)(iVar1 + 8) + -10000;
  }
  iVar1 = FUN_800394ac(param_1,1,0);
  *(short *)(iVar1 + 10) = *(short *)(iVar1 + 10) + 0x1e;
  if (10000 < *(short *)(iVar1 + 10)) {
    *(short *)(iVar1 + 10) = *(short *)(iVar1 + 10) + -10000;
  }
  uVar2 = (uint)*(ushort *)(param_2 + 0x60) + (uint)DAT_803db410 * 0x100;
  if (0xffff < uVar2) {
    uVar2 = uVar2 - 0xffff;
  }
  *(short *)(param_2 + 0x60) = (short)uVar2;
  uVar2 = (uint)*(ushort *)(param_2 + 0x62) + (uint)DAT_803db410 * 0x80;
  if (0xffff < uVar2) {
    uVar2 = uVar2 - 0xffff;
  }
  *(short *)(param_2 + 0x62) = (short)uVar2;
  return;
}

