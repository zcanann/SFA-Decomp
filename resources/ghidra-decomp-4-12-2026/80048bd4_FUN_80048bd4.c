// Function: FUN_80048bd4
// Entry: 80048bd4
// Size: 332 bytes

void FUN_80048bd4(undefined4 param_1,undefined4 param_2,undefined4 *param_3,undefined4 *param_4,
                 undefined4 *param_5)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  ulonglong uVar5;
  
  uVar5 = FUN_80286830();
  iVar2 = -1;
  if ((DAT_803600f4 != 0) || (DAT_80360160 != 0)) {
    FUN_80243e74();
    uVar1 = DAT_803dd900;
    FUN_80243e9c();
    iVar4 = 0;
    if (((uVar1 & 4) == 0) && ((uVar1 & 1) == 0)) {
      iVar4 = DAT_803600f0;
    }
    iVar3 = 0;
    if (((uVar1 & 8) == 0) && ((uVar1 & 2) == 0)) {
      iVar3 = DAT_8036015c;
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
    iVar2 = (&DAT_80360048)[iVar2] + ((uint)(uVar5 >> 0x20) & 0xfffffff);
    *param_4 = *(undefined4 *)(iVar2 + 0x18);
    *(undefined4 *)uVar5 = *(undefined4 *)(iVar2 + 0x1c);
    *param_3 = *(undefined4 *)(iVar2 + 0x20);
    *param_5 = *(undefined4 *)(iVar2 + 4);
  }
  FUN_8028687c();
  return;
}

