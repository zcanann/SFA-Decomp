// Function: FUN_802817a8
// Entry: 802817a8
// Size: 284 bytes

int FUN_802817a8(byte param_1,undefined param_2,undefined param_3,byte param_4,uint param_5,
                int param_6)

{
  int iVar1;
  uint uVar2;
  undefined4 local_18 [3];
  
  DAT_803deeb8 = 0;
  DAT_803bdfc0 = param_1;
  if (0x40 < param_1) {
    DAT_803bdfc0 = 0x40;
  }
  DAT_803bdfc3 = param_4;
  if (8 < param_4) {
    DAT_803bdfc3 = 8;
  }
  local_18[0] = 32000;
  DAT_803bdfc1 = param_2;
  DAT_803bdfc2 = param_3;
  iVar1 = FUN_802838b0(local_18,DAT_803bdfc0,DAT_803bdfc3,param_5);
  if (iVar1 == 0) {
    uVar2 = (uint)DAT_803bdfc0;
    FUN_8027bb84();
    FUN_802759c4(0,param_6);
    FUN_8026fa70();
    DAT_803deef0 = 0;
    FUN_8027280c(32000,uVar2);
    FUN_80273608();
    FUN_8027b41c();
    FUN_80281760(param_5);
    DAT_803deeb8 = 1;
    iVar1 = 0;
  }
  return iVar1;
}

