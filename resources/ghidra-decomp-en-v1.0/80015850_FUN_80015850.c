// Function: FUN_80015850
// Entry: 80015850
// Size: 260 bytes

void FUN_80015850(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  bool bVar1;
  undefined8 uVar2;
  
  uVar2 = FUN_802860d8();
  bVar1 = false;
  DAT_803dc958 = 0;
  while (((DAT_803dc958 == 0 || (DAT_803dc958 == -1)) || (DAT_803dc958 == -3))) {
    FUN_80248eac((int)((ulonglong)uVar2 >> 0x20),(int)uVar2,param_3,param_4,&LAB_80015954,2);
    while ((DAT_803dc958 == 0 || (DAT_803dc958 == -1))) {
      FUN_80014f40();
      FUN_800202cc();
      if (bVar1) {
        FUN_8004a868();
      }
      FUN_80015624();
      if (bVar1) {
        FUN_800234ec(0);
        FUN_80019c24();
        FUN_8004a43c(1,0);
      }
      if (DAT_803dc950 != '\0') {
        bVar1 = true;
      }
    }
  }
  FUN_80286124(DAT_803dc958);
  return;
}

