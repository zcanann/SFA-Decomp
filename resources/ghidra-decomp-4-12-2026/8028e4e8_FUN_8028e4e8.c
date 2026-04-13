// Function: FUN_8028e4e8
// Entry: 8028e4e8
// Size: 572 bytes

void FUN_8028e4e8(double param_1,char *param_2)

{
  uint uVar1;
  int iVar2;
  char cVar3;
  short sVar4;
  double dVar5;
  undefined8 uVar6;
  double local_a8;
  undefined4 local_a0;
  undefined8 local_98;
  undefined8 local_88;
  double local_80;
  undefined4 auStack_78 [11];
  undefined auStack_4c [56];
  
  local_a8._0_4_ = (uint)((ulonglong)param_1 >> 0x20);
  cVar3 = -(char)((longlong)param_1 >> 0x3f);
  if (DOUBLE_803e85c8 == param_1) {
    *param_2 = cVar3;
    param_2[2] = '\0';
    param_2[3] = '\0';
    param_2[4] = '\x01';
    param_2[5] = '\0';
  }
  else {
    local_88._4_4_ = SUB84(param_1,0);
    if ((local_a8._0_4_ & 0x7ff00000) == 0x7ff00000) {
      if ((((ulonglong)param_1 & 0xfffff00000000) == 0) && (local_88._4_4_ == 0)) {
        uVar1 = 2;
      }
      else {
        uVar1 = 1;
      }
    }
    else if (((local_a8._0_4_ & 0x7ff00000) < 0x7ff00000) &&
            (((ulonglong)param_1 & 0x7ff0000000000000) == 0)) {
      if ((((ulonglong)param_1 & 0xfffff00000000) == 0) && (local_88._4_4_ == 0)) {
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
      *param_2 = cVar3;
      param_2[2] = '\0';
      param_2[3] = '\0';
      param_2[4] = '\x01';
      if ((local_a8._0_4_ & 0x7ff00000) == 0x7ff00000) {
        if ((((ulonglong)param_1 & 0xfffff00000000) == 0) && (local_88._4_4_ == 0)) {
          iVar2 = 2;
        }
        else {
          iVar2 = 1;
        }
      }
      else if (((local_a8._0_4_ & 0x7ff00000) < 0x7ff00000) &&
              (((ulonglong)param_1 & 0x7ff0000000000000) == 0)) {
        if ((((ulonglong)param_1 & 0xfffff00000000) == 0) && (local_88._4_4_ == 0)) {
          iVar2 = 3;
        }
        else {
          iVar2 = 5;
        }
      }
      else {
        iVar2 = 4;
      }
      cVar3 = 'I';
      if (iVar2 == 1) {
        cVar3 = 'N';
      }
      param_2[5] = cVar3;
    }
    else {
      local_a8 = param_1;
      if (cVar3 != '\0') {
        local_a8 = -param_1;
      }
      local_88 = param_1;
      dVar5 = FUN_802920d0(local_a8,&local_a0);
      local_98._4_4_ = SUB84(dVar5,0);
      local_98 = dVar5;
      if (local_98._4_4_ == 0) {
        local_98._0_4_ = (uint)((ulonglong)dVar5 >> 0x20);
        uVar1 = local_98._0_4_ | 0x100000;
        iVar2 = FUN_8028eeec(uVar1);
        sVar4 = (short)iVar2 + 0x20;
      }
      else {
        uVar1 = local_98._4_4_;
        iVar2 = FUN_8028eeec(uVar1);
        sVar4 = (short)iVar2;
      }
      FUN_8028e724(auStack_78,local_a0._2_2_ - (0x35 - sVar4));
      dVar5 = FUN_8029215c(dVar5,(int)(short)(0x35 - sVar4));
      FUN_80292320(dVar5,&local_80);
      uVar6 = FUN_80286d70((ulonglong)local_80);
      FUN_8028eddc(auStack_4c,(int)uVar6,(int)((ulonglong)uVar6 >> 0x20),(int)uVar6);
      FUN_8028eb50(param_2,(int)auStack_4c,(int)auStack_78);
      *param_2 = cVar3;
    }
  }
  return;
}

