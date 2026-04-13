// Function: FUN_80296454
// Entry: 80296454
// Size: 412 bytes

void FUN_80296454(int param_1,uint param_2)

{
  byte bVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if ((DAT_803df0cc != 0) && (bVar1 = *(byte *)(iVar2 + 0x3f4) >> 6, (bVar1 & 1) != param_2)) {
    if (param_2 == 0) {
      if (DAT_803df0cc != 0) {
        *(ushort *)(DAT_803df0cc + 6) = *(ushort *)(DAT_803df0cc + 6) | 0x4000;
        if ((DAT_803df0cc != 0) && ((*(byte *)(iVar2 + 0x3f4) >> 6 & 1) != 0)) {
          *(undefined *)(iVar2 + 0x8b4) = 1;
          *(byte *)(iVar2 + 0x3f4) = *(byte *)(iVar2 + 0x3f4) & 0xf7 | 8;
        }
        FUN_800201ac(0x96b,1);
        FUN_800201ac(0x961,1);
        FUN_800201ac(0x969,1);
        FUN_800201ac(0x964,1);
        FUN_800201ac(0x965,1);
        FUN_800201ac(0x986,1);
        FUN_800201ac(0x960,1);
      }
    }
    else if (DAT_803df0cc != 0) {
      if ((DAT_803df0cc != 0) && ((bVar1 & 1) != 0)) {
        *(undefined *)(iVar2 + 0x8b4) = 4;
        *(byte *)(iVar2 + 0x3f4) = *(byte *)(iVar2 + 0x3f4) & 0xf7 | 8;
      }
      *(ushort *)(DAT_803df0cc + 6) = *(ushort *)(DAT_803df0cc + 6) & 0xbfff;
      FUN_800201ac(0x96b,0);
      FUN_800201ac(0x961,0);
      FUN_800201ac(0x969,0);
      FUN_800201ac(0x964,0);
      FUN_800201ac(0x965,0);
      FUN_800201ac(0x986,0);
      FUN_800201ac(0x960,0);
    }
    *(byte *)(iVar2 + 0x3f4) =
         (byte)((param_2 & 0xff) << 6) & 0x40 | *(byte *)(iVar2 + 0x3f4) & 0xbf;
  }
  return;
}

