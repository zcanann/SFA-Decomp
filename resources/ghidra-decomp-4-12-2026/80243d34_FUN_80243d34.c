// Function: FUN_80243d34
// Entry: 80243d34
// Size: 320 bytes

byte * FUN_80243d34(byte *param_1,uint *param_2)

{
  byte bVar1;
  bool bVar2;
  bool bVar3;
  ushort uVar4;
  uint uVar5;
  byte *pbVar6;
  
  bVar1 = *param_1;
  uVar5 = (uint)bVar1;
  if (uVar5 != 0) {
    pbVar6 = param_1 + 1;
    if (1 < DAT_803dd1b0) {
      if (DAT_800000cc == 0) {
        uVar4 = DAT_cc00206e;
        DAT_803dd1b0 = (ushort)((uVar4 & 2) != 0);
      }
      else {
        DAT_803dd1b0 = 0;
      }
    }
    if (DAT_803dd1b0 == 1) {
      bVar3 = true;
      bVar2 = false;
      if ((0x80 < bVar1) && (bVar1 < 0xa0)) {
        bVar2 = true;
      }
      if (!bVar2) {
        bVar2 = false;
        if ((0xdf < bVar1) && (bVar1 < 0xfd)) {
          bVar2 = true;
        }
        if (!bVar2) {
          bVar3 = false;
        }
      }
      if ((bVar3) && (*pbVar6 != 0)) {
        uVar5 = (uint)CONCAT11(bVar1,*pbVar6);
        pbVar6 = param_1 + 2;
      }
    }
    param_1 = pbVar6;
    if (param_2 != (uint *)0x0) {
      uVar5 = FUN_80243308(uVar5);
      *param_2 = (uint)*(byte *)(DAT_803deab0 + uVar5);
    }
  }
  return param_1;
}

