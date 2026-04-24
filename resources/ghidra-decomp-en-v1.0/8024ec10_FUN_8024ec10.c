// Function: FUN_8024ec10
// Entry: 8024ec10
// Size: 164 bytes

void FUN_8024ec10(int param_1,uint param_2)

{
  undefined4 uVar1;
  uint uVar2;
  
  uVar1 = FUN_8024377c();
  if (((DAT_803ddfb4 & 0x80000000U >> param_1) != 0) &&
     (uVar2 = FUN_80252d80(param_1), (uVar2 & 0x20000000) == 0)) {
    if ((DAT_803dc594 < 2) && (param_2 == 2)) {
      param_2 = 0;
    }
    FUN_802525c0(param_1,DAT_803dc590 | 0x400000 | param_2 & 3);
    FUN_802525d4();
  }
  FUN_802437a4(uVar1);
  return;
}

