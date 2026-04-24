// Function: FUN_80291970
// Entry: 80291970
// Size: 140 bytes

/* WARNING: Could not reconcile some variable overlaps */

double FUN_80291970(double param_1,int *param_2)

{
  double dVar1;
  uint uVar2;
  undefined8 local_8;
  
  local_8._0_4_ = (uint)((ulonglong)param_1 >> 0x20);
  *param_2 = 0;
  dVar1 = DOUBLE_803e7948;
  uVar2 = local_8._0_4_ & 0x7fffffff;
  local_8._4_4_ = SUB84(param_1,0);
  local_8 = param_1;
  if ((uVar2 < 0x7ff00000) && ((uVar2 | local_8._4_4_) != 0)) {
    if (uVar2 < 0x100000) {
      *param_2 = -0x36;
      local_8 = param_1 * dVar1;
      local_8._0_4_ = (uint)((ulonglong)local_8 >> 0x20);
      uVar2 = local_8._0_4_ & 0x7fffffff;
    }
    local_8 = (double)((ulonglong)local_8 & 0xffffffff |
                       ((ulonglong)local_8._0_4_ & 0x800fffff) << 0x20 | 0x3fe0000000000000);
    *param_2 = ((int)uVar2 >> 0x14) + *param_2 + -0x3fe;
  }
  return local_8;
}

