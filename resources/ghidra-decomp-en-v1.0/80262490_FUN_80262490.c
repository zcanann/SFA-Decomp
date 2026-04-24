// Function: FUN_80262490
// Entry: 80262490
// Size: 172 bytes

int FUN_80262490(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  undefined auStack20 [8];
  
  iVar1 = FUN_8025edc8(param_1,auStack20);
  if (-1 < iVar1) {
    uVar2 = FUN_8024377c();
    if ((&DAT_803af1e0)[param_1 * 0x44] != 0) {
      FUN_802538e4(param_1,0);
      FUN_80253d14(param_1);
      FUN_80241044(&DAT_803af2c0 + param_1 * 0x110);
      (&DAT_803af1e0)[param_1 * 0x44] = 0;
      (&DAT_803af1e4)[param_1 * 0x44] = 0xfffffffd;
      (&DAT_803af204)[param_1 * 0x44] = 0;
    }
    FUN_802437a4(uVar2);
    iVar1 = 0;
  }
  return iVar1;
}

