// Function: FUN_80009920
// Entry: 80009920
// Size: 264 bytes

/* WARNING: Removing unreachable block (ram,0x80009978) */

void FUN_80009920(byte param_1,char param_2)

{
  uint uVar1;
  byte bVar2;
  bool bVar3;
  
  if ((param_2 != '\0') || (bVar3 = FUN_80245dbc(), bVar2 = DAT_803dbe48, bVar3)) {
    uVar1 = (uint)param_1;
    if (uVar1 != (int)(char)DAT_803dbe48) {
      if (uVar1 == 2) {
        FUN_802731c8(0);
      }
      else if (uVar1 < 2) {
        if (param_1 == 0) {
          FUN_802731c8(1);
        }
        else {
          FUN_802731c8(2);
        }
      }
      else if (uVar1 < 4) {
        FUN_802731c8(1);
      }
    }
    if (((param_1 == 2) && (DAT_803dbe48 != 2)) ||
       ((bVar2 = param_1, param_1 != 2 && (bVar2 = param_1, DAT_803dbe48 == 2)))) {
      if (param_1 == 2) {
        FUN_80245e3c(0);
        bVar2 = param_1;
      }
      else {
        FUN_80245e3c(1);
        bVar2 = param_1;
      }
    }
  }
  DAT_803dbe48 = bVar2;
  return;
}

