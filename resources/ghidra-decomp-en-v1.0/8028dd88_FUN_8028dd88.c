// Function: FUN_8028dd88
// Entry: 8028dd88
// Size: 572 bytes

/* WARNING: Could not reconcile some variable overlaps */

void FUN_8028dd88(double param_1,char *param_2)

{
  uint uVar1;
  int iVar2;
  char cVar3;
  short sVar4;
  undefined8 uVar5;
  double local_a8;
  undefined local_a0 [2];
  short sStack158;
  undefined8 local_98;
  undefined8 local_88;
  undefined8 local_80;
  undefined auStack120 [44];
  undefined auStack76 [56];
  
  local_a8._0_4_ = (uint)((ulonglong)param_1 >> 0x20);
  cVar3 = -(char)((longlong)param_1 >> 0x3f);
  if (DOUBLE_803e7930 == param_1) {
    *param_2 = cVar3;
    *(undefined2 *)(param_2 + 2) = 0;
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
      *(undefined2 *)(param_2 + 2) = 0;
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
      uVar5 = FUN_80291970(local_a8,local_a0);
      local_98._4_4_ = (int)uVar5;
      local_98 = uVar5;
      if (local_98._4_4_ == 0) {
        local_98._0_4_ = (uint)((ulonglong)uVar5 >> 0x20);
        sVar4 = FUN_8028e78c(local_98._0_4_ | 0x100000);
        sVar4 = sVar4 + 0x20;
      }
      else {
        sVar4 = FUN_8028e78c();
      }
      FUN_8028dfc4(auStack120,(int)(short)(sStack158 - (0x35 - sVar4)));
      FUN_802919fc(uVar5,(int)(short)(0x35 - sVar4));
      FUN_80291bc0(&local_80);
      uVar5 = FUN_8028660c(local_80);
      FUN_8028e67c(auStack76,(int)uVar5,(int)((ulonglong)uVar5 >> 0x20),(int)uVar5);
      FUN_8028e3f0(param_2,auStack76,auStack120);
      *param_2 = cVar3;
    }
  }
  return;
}

