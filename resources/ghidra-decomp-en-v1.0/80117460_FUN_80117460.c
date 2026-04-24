// Function: FUN_80117460
// Entry: 80117460
// Size: 172 bytes

void FUN_80117460(int *param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int *local_18;
  int local_14;
  
  iVar3 = 0;
  iVar1 = DAT_803a5e14;
  local_18 = param_1;
  do {
    local_14 = iVar3;
    FUN_80117380(&local_18);
    if ((iVar3 + DAT_803a5e18) - ((uint)(iVar3 + DAT_803a5e18) / DAT_803a5db0) * DAT_803a5db0 ==
        DAT_803a5db0 - 1) {
      if ((DAT_803a5dfe & 1) == 0) {
        FUN_802468f0(&DAT_803a54a0);
        iVar2 = iVar1;
      }
      else {
        iVar2 = *local_18;
        local_18 = DAT_803a5e0c;
      }
    }
    else {
      iVar2 = *local_18;
      local_18 = (int *)((int)local_18 + iVar1);
    }
    iVar3 = iVar3 + 1;
    iVar1 = iVar2;
  } while( true );
}

