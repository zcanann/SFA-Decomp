// Function: FUN_802bde90
// Entry: 802bde90
// Size: 236 bytes

void FUN_802bde90(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(char *)(iVar1 + 0x14e6) = (char)param_2;
  if (param_2 == 0) {
    FUN_800200e8(0x7bc,0);
    FUN_800200e8(0x7d4,1);
    *(byte *)(iVar1 + 0x9fd) = *(byte *)(iVar1 + 0x9fd) & 0xfe;
    *(byte *)(iVar1 + 0x14ec) = *(byte *)(iVar1 + 0x14ec) & 0xfd;
    (**(code **)(*DAT_803dca68 + 0x60))();
  }
  else {
    iVar2 = *(int *)(param_1 + 0xb8);
    iVar1 = *(int *)(param_1 + 0x4c);
    *(byte *)(iVar2 + 0x14ec) = *(byte *)(iVar2 + 0x14ec) & 0xfd | 2;
    (**(code **)(*DAT_803dca68 + 0x58))((int)*(short *)(iVar1 + 0x1a),0x5cf);
    (**(code **)(*DAT_803dca68 + 0x5c))((int)*(short *)(iVar2 + 0x14e2));
    FUN_800200e8(0x7bc,1);
    FUN_800200e8(0x7d4,0);
  }
  return;
}

