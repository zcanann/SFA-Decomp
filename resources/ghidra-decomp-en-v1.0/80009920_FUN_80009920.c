// Function: FUN_80009920
// Entry: 80009920
// Size: 264 bytes

/* WARNING: Removing unreachable block (ram,0x80009978) */

void FUN_80009920(byte param_1,char param_2)

{
  uint uVar1;
  byte bVar2;
  int iVar3;
  
  if ((param_2 != '\0') || (iVar3 = FUN_802456c4(), bVar2 = DAT_803db1e8, iVar3 == 1)) {
    uVar1 = (uint)param_1;
    if (uVar1 != (int)(char)DAT_803db1e8) {
      if (uVar1 == 2) {
        FUN_80272a64(0);
      }
      else if (uVar1 < 2) {
        if (uVar1 == 0) {
          FUN_80272a64(1);
        }
        else {
          FUN_80272a64(2);
        }
      }
      else if (uVar1 < 4) {
        FUN_80272a64(1);
      }
    }
    if (((param_1 == 2) && (DAT_803db1e8 != 2)) ||
       ((bVar2 = param_1, param_1 != 2 && (bVar2 = param_1, DAT_803db1e8 == 2)))) {
      if (param_1 == 2) {
        FUN_80245744(0);
        bVar2 = param_1;
      }
      else {
        FUN_80245744(1);
        bVar2 = param_1;
      }
    }
  }
  DAT_803db1e8 = bVar2;
  return;
}

