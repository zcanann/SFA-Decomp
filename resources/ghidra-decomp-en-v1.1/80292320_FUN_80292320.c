// Function: FUN_80292320
// Entry: 80292320
// Size: 252 bytes

double FUN_80292320(double param_1,double *param_2)

{
  uint uVar1;
  uint uVar2;
  undefined8 local_8;
  
  local_8._0_4_ = (uint)((ulonglong)param_1 >> 0x20);
  local_8._4_4_ = SUB84(param_1,0);
  uVar1 = local_8._0_4_ >> 0x14 & 0x7ff;
  uVar2 = uVar1 - 0x3ff;
  if ((int)uVar2 < 0x14) {
    if ((int)uVar2 < 0) {
      *(uint *)param_2 = local_8._0_4_ & 0x80000000;
      *(undefined4 *)((int)param_2 + 4) = 0;
    }
    else {
      uVar1 = 0xfffff >> (uVar2 & 0x3f);
      if (local_8._4_4_ == 0 && (local_8._0_4_ & uVar1) == 0) {
        local_8 = (double)((ulonglong)(local_8._0_4_ & 0x80000000) << 0x20);
        *param_2 = param_1;
        param_1 = local_8;
      }
      else {
        *(uint *)param_2 = local_8._0_4_ & ~uVar1;
        *(undefined4 *)((int)param_2 + 4) = 0;
        param_1 = param_1 - *param_2;
      }
    }
  }
  else if ((int)uVar2 < 0x34) {
    uVar1 = 0xffffffff >> uVar1 - 0x413;
    if ((local_8._4_4_ & uVar1) == 0) {
      local_8 = (double)((ulonglong)(local_8._0_4_ & 0x80000000) << 0x20);
      *param_2 = param_1;
      param_1 = local_8;
    }
    else {
      *(uint *)param_2 = local_8._0_4_;
      *(uint *)((int)param_2 + 4) = local_8._4_4_ & ~uVar1;
      param_1 = param_1 - *param_2;
    }
  }
  else {
    local_8 = (double)((ulonglong)(local_8._0_4_ & 0x80000000) << 0x20);
    *param_2 = param_1;
    param_1 = local_8;
  }
  return param_1;
}

