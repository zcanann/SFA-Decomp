// Function: FUN_80048a58
// Entry: 80048a58
// Size: 332 bytes

void FUN_80048a58(undefined4 param_1,undefined4 param_2,undefined4 *param_3,undefined4 *param_4,
                 undefined4 *param_5)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  ulonglong uVar5;
  
  uVar5 = FUN_802860cc();
  iVar2 = -1;
  if ((DAT_8035f494 != 0) || (DAT_8035f500 != 0)) {
    FUN_8024377c();
    uVar1 = DAT_803dcc80;
    FUN_802437a4();
    iVar4 = 0;
    if (((uVar1 & 4) == 0) && ((uVar1 & 1) == 0)) {
      iVar4 = DAT_8035f490;
    }
    iVar3 = 0;
    if (((uVar1 & 8) == 0) && ((uVar1 & 2) == 0)) {
      iVar3 = DAT_8035f4fc;
    }
    if ((iVar3 == 0) || ((uVar5 & 0x2000000000000000) == 0)) {
      if ((iVar4 == 0) || ((uVar5 & 0x1000000000000000) == 0)) {
        if (iVar4 == 0) {
          if (iVar3 != 0) {
            iVar2 = 0x46;
          }
        }
        else {
          iVar2 = 0x2b;
        }
      }
      else {
        iVar2 = 0x2b;
      }
    }
    else {
      iVar2 = 0x46;
    }
    iVar2 = (&DAT_8035f3e8)[iVar2] + ((uint)(uVar5 >> 0x20) & 0xfffffff);
    *param_4 = *(undefined4 *)(iVar2 + 0x18);
    *(undefined4 *)uVar5 = *(undefined4 *)(iVar2 + 0x1c);
    *param_3 = *(undefined4 *)(iVar2 + 0x20);
    *param_5 = *(undefined4 *)(iVar2 + 4);
  }
  FUN_80286118();
  return;
}

