// Function: FUN_80128e70
// Entry: 80128e70
// Size: 812 bytes

void FUN_80128e70(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined4 *puVar5;
  double dVar6;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined auStack76 [36];
  longlong local_28;
  
  FUN_802860d8();
  local_58 = DAT_802c21a0;
  local_54 = DAT_802c21a4;
  local_50 = DAT_802c21a8;
  if (DAT_803dd780 == '\0') {
    FUN_8007719c((double)FLOAT_803e2130,(double)FLOAT_803e1e40,DAT_803a89d8,0xff,0x100);
    FUN_8007681c((double)FLOAT_803e20bc,(double)FLOAT_803e1e40,DAT_803a89e4,0xff,0x100,600,5,0);
    FUN_8007681c((double)FLOAT_803e2130,(double)FLOAT_803e2090,DAT_803a89dc,0xff,0x100,5,400,0);
    FUN_8007681c((double)FLOAT_803e20bc,(double)FLOAT_803e2090,DAT_803a89e0,0xff,0x100,600,400,0);
    FUN_8007681c((double)FLOAT_803e20bc,(double)FLOAT_803e2134,DAT_803a89e4,0xff,0x100,600,5,2);
    FUN_8007681c((double)FLOAT_803e2138,(double)FLOAT_803e2090,DAT_803a89dc,0xff,0x100,5,400,1);
    FUN_8007681c((double)FLOAT_803e2138,(double)FLOAT_803e2134,DAT_803a89d8,0xff,0x100,5,5,3);
    FUN_8007681c((double)FLOAT_803e2138,(double)FLOAT_803e1e40,DAT_803a89d8,0xff,0x100,5,5,1);
    FUN_8007681c((double)FLOAT_803e2130,(double)FLOAT_803e2134,DAT_803a89d8,0xff,0x100,5,5,2);
    DAT_803dd7e6 = DAT_803dd7e6 + DAT_803dbab4;
    dVar6 = (double)FUN_80293464(DAT_803dd7e6);
    iVar4 = (int)((double)FLOAT_803dbab8 * dVar6 + (double)FLOAT_803dbabc);
    local_28 = (longlong)iVar4;
    if (DAT_803dd75b == '\x01') {
      iVar3 = iVar4;
      iVar4 = 0xff;
    }
    else {
      iVar3 = 0xff;
    }
    FUN_80016810(0x2f7,0,5);
    FUN_80019908(iVar3,iVar3,iVar3,0xff);
    FUN_80016870(0x2f8);
    FUN_80019908(iVar4,iVar4,iVar4,0xff);
    FUN_80016870(0x2fb);
    FUN_80019908(0xff,0xff,0xff,0xff);
    iVar4 = 0;
    puVar5 = &local_58;
    do {
      iVar3 = FUN_8001ffb4(*(undefined2 *)puVar5);
      if (iVar4 == 0) {
        FUN_800173e4(6);
        FUN_80016870(0x2fa);
      }
      else if (iVar4 == 3) {
        FUN_800173e4(7);
        FUN_80016870(0x2fa);
      }
      iVar1 = iVar3 / 6000 + (iVar3 >> 0x1f);
      iVar1 = iVar1 - (iVar1 >> 0x1f);
      iVar2 = iVar3 / 100 + (iVar3 >> 0x1f);
      FUN_8028f688(auStack76,s___02d__02d__02d_8031c120,iVar1,
                   (iVar2 - (iVar2 >> 0x1f)) + iVar1 * -0x3c,
                   iVar3 + (iVar2 - (iVar2 >> 0x1f)) * -100);
      FUN_80016220(auStack76);
      puVar5 = (undefined4 *)((int)puVar5 + 2);
      iVar4 = iVar4 + 1;
    } while (iVar4 < 6);
    FUN_800173e4(0xff);
  }
  FUN_80286124();
  return;
}

