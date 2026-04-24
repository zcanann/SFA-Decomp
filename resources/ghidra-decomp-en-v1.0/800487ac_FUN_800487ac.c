// Function: FUN_800487ac
// Entry: 800487ac
// Size: 440 bytes

void FUN_800487ac(undefined4 param_1,undefined4 param_2,undefined4 *param_3,undefined4 *param_4,
                 int param_5,int param_6,int param_7)

{
  uint uVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  
  uVar2 = FUN_802860d0();
  iVar4 = -1;
  if ((DAT_8035f474 != 0) || (DAT_8035f51c != 0)) {
    FUN_8024377c();
    uVar1 = DAT_803dcc80;
    FUN_802437a4();
    if (((uVar2 & 0x80000000) == 0) || ((uVar1 & 0x200) != 0)) {
      if (((uVar2 & 0x40000000) == 0) || ((uVar1 & 0x100) != 0)) {
        if ((DAT_8035f478 == 0) || ((uVar1 & 0x100) != 0)) {
          if ((DAT_8035f520 != 0) && ((uVar1 & 0x200) == 0)) {
            iVar4 = 0x4d;
          }
        }
        else {
          iVar4 = 0x23;
        }
      }
      else {
        iVar4 = 0x23;
      }
    }
    else {
      iVar4 = 0x4d;
    }
    if ((param_7 == 1) && (param_6 != 0)) {
      iVar4 = (&DAT_8035f3e8)[iVar4] + (uVar2 & 0xffffff) * 2 + *(int *)(param_6 + param_5 * 4) + 4;
      uVar3 = *(undefined4 *)(iVar4 + 8);
      *param_3 = *(undefined4 *)(iVar4 + 4);
      *param_4 = uVar3;
    }
    else if ((param_7 == 2) && (param_6 != 0)) {
      FUN_80003494(param_6,(&DAT_8035f3e8)[iVar4] + (uVar2 & 0xffffff) * 2,(param_5 + 1) * 4);
    }
    else {
      iVar4 = (&DAT_8035f3e8)[iVar4] + (uVar2 & 0xffffff) * 2 + 4;
      uVar3 = *(undefined4 *)(iVar4 + 8);
      *param_3 = *(undefined4 *)(iVar4 + 4);
      *param_4 = uVar3;
    }
  }
  FUN_8028611c();
  return;
}

