// Function: FUN_8025eee4
// Entry: 8025eee4
// Size: 152 bytes

int FUN_8025eee4(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  
  uVar2 = FUN_8024377c();
  while( true ) {
    if ((param_1 < 0) || (1 < param_1)) {
      iVar1 = -0x80;
    }
    else {
      iVar1 = (&DAT_803af1e4)[param_1 * 0x44];
    }
    if (iVar1 != -1) break;
    FUN_80246a60(&DAT_803af26c + param_1 * 0x110);
  }
  FUN_802437a4(uVar2);
  return iVar1;
}

