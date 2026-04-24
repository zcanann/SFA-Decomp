// Function: FUN_801f20d4
// Entry: 801f20d4
// Size: 444 bytes

void FUN_801f20d4(int param_1)

{
  int iVar1;
  int iVar2;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_18;
  uint uStack20;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  FUN_8002b9ec();
  local_28 = DAT_802c247c;
  local_24 = DAT_802c2480;
  local_20 = DAT_802c2484;
  if ((*(byte *)(param_1 + 0xaf) & 8) != 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) ^ 8;
  }
  iVar1 = FUN_8001ffb4(0x2fb);
  if (iVar1 == 0) {
    if (*(short *)(param_1 + 0xa0) != 7) {
      FUN_80030334((double)FLOAT_803e5d98,param_1,7,0);
    }
    uStack20 = (uint)DAT_803db410;
    local_18 = 0x43300000;
    FUN_8002fa48((double)FLOAT_803e5d9c,
                 (double)(float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e5da0),param_1,0)
    ;
  }
  else {
    if (*(short *)(param_1 + 0xa0) != 2) {
      FUN_80030334((double)FLOAT_803e5d98,param_1,2,0);
    }
    uStack20 = (uint)DAT_803db410;
    local_18 = 0x43300000;
    FUN_8002fa48((double)FLOAT_803e5d9c,
                 (double)(float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e5da0),param_1,0)
    ;
  }
  if (((*(byte *)(param_1 + 0xaf) & 1) == 0) || (iVar1 = FUN_8001ffb4(0x2fb), iVar1 != 0)) {
    if (((*(byte *)(param_1 + 0xaf) & 1) != 0) &&
       (iVar1 = (**(code **)(*DAT_803dca68 + 0x24))(&local_28,3), -1 < iVar1)) {
      FUN_800200e8(0x310,1);
      *(char *)(iVar2 + 0x27) = *(char *)(iVar2 + 0x27) + '\x01';
      FUN_80014b3c(0,0x100);
    }
  }
  else {
    FUN_800200e8(0x2fb,1);
    *(undefined *)(iVar2 + 0x27) = 0;
    FUN_80014b3c(0,0x100);
  }
  return;
}

