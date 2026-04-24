// Function: FUN_8001bbd8
// Entry: 8001bbd8
// Size: 220 bytes

void FUN_8001bbd8(int param_1)

{
  bool bVar1;
  int iVar2;
  short *psVar3;
  int local_18;
  undefined4 local_14 [4];
  
  iVar2 = FUN_80015d70(param_1,local_14,&local_18);
  if (iVar2 != 0) {
    if (DAT_803dca00 == 0) {
      psVar3 = &DAT_802c9ee8;
      iVar2 = 0xb;
      do {
        if (param_1 == *psVar3) {
          bVar1 = true;
          goto LAB_8001bc3c;
        }
        psVar3 = psVar3 + 1;
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
      bVar1 = false;
LAB_8001bc3c:
      if (!bVar1) {
        return;
      }
    }
    DAT_803dc9fc = local_14[0];
    DAT_803dc9f8 = local_18;
    if (local_18 != 0x29) {
      DAT_803db3e0 = FUN_80019bf0();
      FUN_80019970(DAT_803dc9f8);
    }
    else {
      FUN_8001a420();
    }
    DAT_803dc9f0 = (uint)(local_18 == 0x29);
    DAT_803dca04 = 1;
    DAT_803dc9f7 = 0xff;
    DAT_803dc9f6 = 0xff;
    DAT_803dc9f5 = 0xff;
    DAT_803dc9f4 = 0xff;
  }
  return;
}

