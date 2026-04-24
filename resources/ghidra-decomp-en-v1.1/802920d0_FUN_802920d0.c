// Function: FUN_802920d0
// Entry: 802920d0
// Size: 140 bytes

double FUN_802920d0(double param_1,int *param_2)

{
  double dVar1;
  uint uVar2;
  uint uVar3;
  undefined8 local_8;
  
  local_8._0_4_ = (uint)((ulonglong)param_1 >> 0x20);
  *param_2 = 0;
  dVar1 = DOUBLE_803e85e0;
  uVar2 = local_8._0_4_ & 0x7fffffff;
  local_8._4_4_ = SUB84(param_1,0);
  if ((uVar2 < 0x7ff00000) && (((ulonglong)param_1 & 0x7fffffff00000000) != 0 || local_8._4_4_ != 0)
     ) {
    uVar3 = local_8._0_4_;
    local_8 = param_1;
    if (uVar2 < 0x100000) {
      *param_2 = -0x36;
      local_8._0_4_ = (uint)((ulonglong)(param_1 * dVar1) >> 0x20);
      uVar2 = local_8._0_4_ & 0x7fffffff;
      uVar3 = local_8._0_4_;
      local_8 = param_1 * dVar1;
    }
    local_8 = (double)(CONCAT44(uVar3,local_8._4_4_) & 0x800fffffffffffff | 0x3fe0000000000000);
    *param_2 = ((int)uVar2 >> 0x14) + *param_2 + -0x3fe;
    param_1 = local_8;
  }
  return param_1;
}

