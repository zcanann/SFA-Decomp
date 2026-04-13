// Function: FUN_8029215c
// Entry: 8029215c
// Size: 452 bytes

double FUN_8029215c(double param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  double dVar3;
  double local_18;
  uint local_10;
  int iStack_c;
  
  local_10 = (uint)((ulonglong)param_1 >> 0x20);
  iStack_c = SUB84(param_1,0);
  if ((local_10 & 0x7ff00000) == 0x7ff00000) {
    if ((((ulonglong)param_1 & 0xfffff00000000) == 0) && (iStack_c == 0)) {
      uVar1 = 2;
    }
    else {
      uVar1 = 1;
    }
  }
  else if (((local_10 & 0x7ff00000) < 0x7ff00000) &&
          (((ulonglong)param_1 & 0x7ff0000000000000) == 0)) {
    if ((((ulonglong)param_1 & 0xfffff00000000) == 0) && (iStack_c == 0)) {
      uVar1 = 3;
    }
    else {
      uVar1 = 5;
    }
  }
  else {
    uVar1 = 4;
  }
  if (uVar1 < 3) {
    return param_1;
  }
  if (DOUBLE_803e85e8 == param_1) {
    return param_1;
  }
  uVar1 = local_10 >> 0x14 & 0x7ff;
  local_18 = param_1;
  if (uVar1 == 0) {
    if (iStack_c == 0 && ((ulonglong)param_1 & 0x7fffffff00000000) == 0) {
      return param_1;
    }
    dVar3 = param_1 * DOUBLE_803e85f0;
    local_18._0_4_ = (uint)((ulonglong)dVar3 >> 0x20);
    uVar1 = (local_18._0_4_ >> 0x14 & 0x7ff) - 0x36;
    local_10 = local_18._0_4_;
    local_18 = dVar3;
    if (param_2 < -50000) {
      return DOUBLE_803e85f8 * dVar3;
    }
  }
  if (uVar1 == 0x7ff) {
    local_18 = local_18 + local_18;
  }
  else {
    iVar2 = uVar1 + param_2;
    if (iVar2 < 0x7ff) {
      if (iVar2 < 1) {
        if (iVar2 < -0x35) {
          if (param_2 < 0xc351) {
            local_18 = (double)FUN_802920a8(DOUBLE_803e85f8,local_18);
            local_18 = DOUBLE_803e85f8 * local_18;
          }
          else {
            local_18 = (double)FUN_802920a8(DOUBLE_803e8600,local_18);
            local_18 = DOUBLE_803e8600 * local_18;
          }
        }
        else {
          local_18 = (double)CONCAT44(local_10 & 0x800fffff | (iVar2 + 0x36) * 0x100000,
                                      local_18._4_4_);
          local_18 = DOUBLE_803e8608 * local_18;
        }
      }
      else {
        local_18 = (double)CONCAT44(local_10 & 0x800fffff | iVar2 * 0x100000,local_18._4_4_);
      }
    }
    else {
      local_18 = (double)FUN_802920a8(DOUBLE_803e8600,local_18);
      local_18 = DOUBLE_803e8600 * local_18;
    }
  }
  return local_18;
}

