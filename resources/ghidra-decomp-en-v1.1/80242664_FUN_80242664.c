// Function: FUN_80242664
// Entry: 80242664
// Size: 244 bytes

void FUN_80242664(void)

{
  uint uVar1;
  
  uVar1 = FUN_80240a54();
  if ((uVar1 & 0x8000) == 0) {
    FUN_80242220();
    FUN_80247568();
  }
  uVar1 = FUN_80240a54();
  if ((uVar1 & 0x4000) == 0) {
    FUN_8024209c();
    FUN_80247568();
  }
  uVar1 = FUN_80240a64();
  if ((uVar1 & 0x80000000) == 0) {
    FUN_80240a44();
    sync(0);
    FUN_80240a4c();
    sync(0);
    sync(0);
    FUN_80240a64();
    FUN_80240a6c();
    sync(0);
    FUN_8024246c();
    FUN_80240a4c();
    FUN_80240a64();
    FUN_80240a6c();
    FUN_80247568();
  }
  FUN_802430ec(1,&LAB_80242504);
  FUN_80247568();
  return;
}

