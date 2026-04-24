// Function: FUN_801cdd90
// Entry: 801cdd90
// Size: 192 bytes

void FUN_801cdd90(int param_1)

{
  int iVar1;
  
  iVar1 = FUN_8001ffb4(10);
  if (iVar1 == 0) {
    FUN_8000dcbc(param_1,0x372);
    FUN_8000dcbc(param_1,0x373);
    (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
    FUN_80035f20(param_1);
  }
  else {
    *(undefined2 *)(param_1 + 6) = 0x4000;
    *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x8000;
    FUN_8000db90(param_1,0x372);
    FUN_8000db90(param_1,0x373);
    FUN_80035f00(param_1);
    FUN_800200e8(0x398,1);
  }
  return;
}

