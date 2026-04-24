// Function: FUN_8024363c
// Entry: 8024363c
// Size: 320 bytes

byte * FUN_8024363c(byte *param_1,uint *param_2)

{
  byte bVar1;
  ushort uVar2;
  ushort uVar3;
  int iVar4;
  bool bVar5;
  bool bVar6;
  byte *pbVar7;
  
  bVar1 = *param_1;
  uVar3 = (ushort)bVar1;
  if (uVar3 != 0) {
    pbVar7 = param_1 + 1;
    if (1 < DAT_803dc548) {
      if (DAT_800000cc == 0) {
        uVar2 = read_volatile_2(DAT_cc00206e);
        DAT_803dc548 = (ushort)((uVar2 & 2) != 0);
      }
      else {
        DAT_803dc548 = 0;
      }
    }
    if (DAT_803dc548 == 1) {
      bVar5 = true;
      bVar6 = false;
      if ((0x80 < bVar1) && (bVar1 < 0xa0)) {
        bVar6 = true;
      }
      if (!bVar6) {
        bVar6 = false;
        if ((0xdf < bVar1) && (bVar1 < 0xfd)) {
          bVar6 = true;
        }
        if (!bVar6) {
          bVar5 = false;
        }
      }
      if ((bVar5) && (*pbVar7 != 0)) {
        uVar3 = CONCAT11(bVar1,*pbVar7);
        pbVar7 = param_1 + 2;
      }
    }
    param_1 = pbVar7;
    if (param_2 != (uint *)0x0) {
      iVar4 = FUN_80242c10(uVar3);
      *param_2 = (uint)*(byte *)(DAT_803dde30 + iVar4);
    }
  }
  return param_1;
}

