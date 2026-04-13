// Function: FUN_801a43ec
// Entry: 801a43ec
// Size: 92 bytes

void FUN_801a43ec(undefined2 *param_1,int param_2)

{
  uint uVar1;
  byte *pbVar2;
  
  pbVar2 = *(byte **)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x20));
  *pbVar2 = (byte)((uVar1 & 0xff) << 7) | *pbVar2 & 0x7f;
  FUN_800803f8((undefined4 *)(pbVar2 + 4));
  return;
}

