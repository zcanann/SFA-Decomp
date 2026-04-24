// Function: FUN_802919fc
// Entry: 802919fc
// Size: 452 bytes

/* WARNING: Could not reconcile some variable overlaps */

double FUN_802919fc(double param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  double local_18;
  uint local_10;
  uint uStack12;
  
  local_10 = (uint)((ulonglong)param_1 >> 0x20);
  uStack12 = SUB84(param_1,0);
  if ((local_10 & 0x7ff00000) == 0x7ff00000) {
    if ((((ulonglong)param_1 & 0xfffff00000000) == 0) && (uStack12 == 0)) {
      uVar1 = 2;
    }
    else {
      uVar1 = 1;
    }
  }
  else if (((local_10 & 0x7ff00000) < 0x7ff00000) &&
          (((ulonglong)param_1 & 0x7ff0000000000000) == 0)) {
    if ((((ulonglong)param_1 & 0xfffff00000000) == 0) && (uStack12 == 0)) {
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
  if (DOUBLE_803e7950 == param_1) {
    return param_1;
  }
  uVar1 = local_10 >> 0x14 & 0x7ff;
  local_18 = param_1;
  if (uVar1 == 0) {
    if ((uStack12 | local_10 & 0x7fffffff) == 0) {
      return param_1;
    }
    local_18 = param_1 * DOUBLE_803e7958;
    local_18._0_4_ = (uint)((ulonglong)local_18 >> 0x20);
    uVar1 = (local_18._0_4_ >> 0x14 & 0x7ff) - 0x36;
    local_10 = local_18._0_4_;
    if (param_2 < -50000) {
      return DOUBLE_803e7960 * local_18;
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
            local_18 = (double)FUN_80291948(DOUBLE_803e7960,local_18);
            local_18 = DOUBLE_803e7960 * local_18;
          }
          else {
            local_18 = (double)FUN_80291948(DOUBLE_803e7968,local_18);
            local_18 = DOUBLE_803e7968 * local_18;
          }
        }
        else {
          local_18 = (double)((ulonglong)local_18 & 0xffffffff |
                             (ulonglong)(local_10 & 0x800fffff | (iVar2 + 0x36) * 0x100000) << 0x20)
          ;
          local_18 = DOUBLE_803e7970 * local_18;
        }
      }
      else {
        local_18 = (double)((ulonglong)local_18 & 0xffffffff |
                           (ulonglong)(local_10 & 0x800fffff | iVar2 * 0x100000) << 0x20);
      }
    }
    else {
      local_18 = (double)FUN_80291948(DOUBLE_803e7968,local_18);
      local_18 = DOUBLE_803e7968 * local_18;
    }
  }
  return local_18;
}

