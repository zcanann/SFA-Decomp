// Function: FUN_801198e0
// Entry: 801198e0
// Size: 316 bytes

void FUN_801198e0(int *param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int *local_18;
  int local_14;
  
  iVar1 = 0;
  iVar3 = DAT_803a5e14;
  local_18 = param_1;
  do {
    iVar2 = iVar3;
    if (DAT_803a5dff != '\0') {
      while (iVar2 = iVar3, DAT_803a5e30 < 0) {
        FUN_8024377c();
        DAT_803a5e30 = DAT_803a5e30 + 1;
        FUN_802437a4();
        if ((iVar1 + DAT_803a5e18) - ((uint)(iVar1 + DAT_803a5e18) / DAT_803a5db0) * DAT_803a5db0 ==
            DAT_803a5db0 - 1) {
          if ((DAT_803a5dfe & 1) == 0) break;
          iVar2 = *local_18;
          local_18 = DAT_803a5e0c;
        }
        else {
          iVar2 = *local_18;
          local_18 = (int *)((int)local_18 + iVar3);
        }
        iVar1 = iVar1 + 1;
        iVar3 = iVar2;
      }
    }
    local_14 = iVar1;
    FUN_80119798(&local_18);
    if ((iVar1 + DAT_803a5e18) - ((uint)(iVar1 + DAT_803a5e18) / DAT_803a5db0) * DAT_803a5db0 ==
        DAT_803a5db0 - 1) {
      if ((DAT_803a5dfe & 1) == 0) {
        FUN_802468f0(&DAT_803a8348);
        iVar3 = iVar2;
      }
      else {
        iVar3 = *local_18;
        local_18 = DAT_803a5e0c;
      }
    }
    else {
      iVar3 = *local_18;
      local_18 = (int *)((int)local_18 + iVar2);
    }
    iVar1 = iVar1 + 1;
  } while( true );
}

