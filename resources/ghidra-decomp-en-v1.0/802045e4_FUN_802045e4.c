// Function: FUN_802045e4
// Entry: 802045e4
// Size: 524 bytes

void FUN_802045e4(void)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  byte bVar7;
  int iVar8;
  
  iVar1 = FUN_802860d8();
  iVar8 = *(int *)(iVar1 + 0xb8);
  iVar2 = FUN_8002b9ec();
  uVar3 = FUN_8001ffb4(0xd5d);
  uVar4 = FUN_8001ffb4(0xd59);
  uVar5 = FUN_8001ffb4(0xd5a);
  if (((((uVar3 & 0xff) != 0) && (-1 < *(char *)(iVar8 + 7))) ||
      (((uVar4 & 0xff) != 0 && ((*(byte *)(iVar8 + 7) >> 6 & 1) == 0)))) ||
     (((uVar5 & 0xff) != 0 && ((*(byte *)(iVar8 + 7) >> 5 & 1) == 0)))) {
    FUN_8000bb18(0,0x109);
  }
  *(byte *)(iVar8 + 7) = (byte)((uVar3 & 0xff) << 7) | *(byte *)(iVar8 + 7) & 0x7f;
  *(byte *)(iVar8 + 7) = (byte)((uVar4 & 0xff) << 6) & 0x40 | *(byte *)(iVar8 + 7) & 0xbf;
  *(byte *)(iVar8 + 7) = (byte)((uVar5 & 0xff) << 5) & 0x20 | *(byte *)(iVar8 + 7) & 0xdf;
  iVar6 = FUN_8001ffb4(0x5e8);
  if (((iVar6 == 0) && (iVar6 = FUN_8001ffb4(0x5ee), iVar6 != 0)) &&
     (iVar6 = FUN_8001ffb4(0x5ef), iVar6 != 0)) {
    FUN_800200e8(0x5e8,1);
  }
  FUN_8005afac((double)*(float *)(iVar2 + 0xc),(double)*(float *)(iVar2 + 0x14));
  bVar7 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(iVar1 + 0xac));
  if (bVar7 == 2) {
    FUN_80204098(iVar1);
  }
  else if ((bVar7 < 2) && (bVar7 != 0)) {
    if ((DAT_803dc180 != 0) &&
       (DAT_803dc180 = DAT_803dc180 - (short)(int)FLOAT_803db414, DAT_803dc180 < 1)) {
      DAT_803dc180 = 0;
    }
    FUN_80204320(iVar1);
  }
  FUN_801d7ed4(iVar8 + 8,2,0xffffffff,0xffffffff,0xdce,0x95);
  FUN_801d8060(iVar8 + 8,4,0xffffffff,0xffffffff,0xdce,0x37);
  FUN_801d8060(iVar8 + 8,1,0xffffffff,0xffffffff,0xdce,0xe4);
  FUN_800200e8(0xdcf,0);
  FUN_80286124();
  return;
}

