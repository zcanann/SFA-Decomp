// Function: FUN_80286fc0
// Entry: 80286fc0
// Size: 248 bytes

/* WARNING: Removing unreachable block (ram,0x80287010) */

void FUN_80286fc0(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  bool bVar1;
  bool bVar2;
  int iVar3;
  undefined *puVar4;
  undefined4 extraout_r4;
  undefined4 extraout_r4_00;
  byte local_18 [8];
  int local_10;
  
  bVar2 = false;
  bVar1 = false;
  while (!bVar2) {
    iVar3 = FUN_802871d4((int)local_18);
    if (iVar3 == 0) {
      if ((bVar1) && (*DAT_803d8f30 == '\0')) {
        iVar3 = FUN_8028be24();
        if (iVar3 == 0) {
          FUN_8028da78(0,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        }
        bVar1 = false;
      }
      else {
        bVar1 = true;
        FUN_802880e4();
        param_2 = extraout_r4_00;
      }
    }
    else {
      bVar1 = false;
      if (local_18[0] == 2) {
        puVar4 = FUN_80287f00(local_10);
        FUN_802884c0((int)puVar4);
      }
      else if (local_18[0] < 2) {
        if (local_18[0] != 0) {
          bVar2 = true;
        }
      }
      else if (local_18[0] == 5) {
        FUN_8028be70();
      }
      else if (local_18[0] < 5) {
        FUN_8028c338(local_18);
      }
      FUN_802870b8((int)local_18);
      param_2 = extraout_r4;
    }
  }
  return;
}

