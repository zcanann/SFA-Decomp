// Function: FUN_8002b5a0
// Entry: 8002b5a0
// Size: 192 bytes

int FUN_8002b5a0(int param_1,undefined4 param_2)

{
  char cVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  
  uVar3 = *(undefined4 *)(param_1 + 0x30);
  cVar1 = *(char *)(param_1 + 0xac);
  uVar2 = FUN_800430ac(0);
  if ((uVar2 & 0x100000) == 0) {
    iVar4 = FUN_8002d55c(param_2,5,(int)cVar1,0xffffffff,uVar3,0);
    if (iVar4 != 0) {
      FUN_8002d30c(iVar4,5);
      FUN_8007d6dc(s_LOADED_OBJECT__s_802cac54,*(int *)(iVar4 + 0x50) + 0x91);
    }
  }
  else {
    FUN_8007d6dc(s__objSetupObject__loading_is_lock_802cac18,0xffffffff);
    iVar4 = 0;
  }
  return iVar4;
}

