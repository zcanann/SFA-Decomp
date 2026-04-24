// Function: FUN_8002df90
// Entry: 8002df90
// Size: 188 bytes

void FUN_8002df90(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5)

{
  uint uVar1;
  int iVar2;
  undefined8 uVar3;
  
  uVar3 = FUN_802860dc();
  uVar1 = FUN_800430ac(0);
  if ((uVar1 & 0x100000) == 0) {
    iVar2 = FUN_8002d55c((int)((ulonglong)uVar3 >> 0x20),(int)uVar3,param_3,param_4,param_5,0);
    if (iVar2 != 0) {
      FUN_8002d30c(iVar2,(int)uVar3);
      FUN_8007d6dc(s_LOADED_OBJECT__s_802cac54,*(int *)(iVar2 + 0x50) + 0x91);
    }
  }
  else {
    FUN_8007d6dc(s__objSetupObject__loading_is_lock_802cac18,param_4);
    iVar2 = 0;
  }
  FUN_80286128(iVar2);
  return;
}

