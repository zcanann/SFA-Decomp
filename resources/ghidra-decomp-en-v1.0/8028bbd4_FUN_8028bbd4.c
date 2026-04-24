// Function: FUN_8028bbd4
// Entry: 8028bbd4
// Size: 348 bytes

/* WARNING: Removing unreachable block (ram,0x8028bc54) */

undefined4 FUN_8028bbd4(byte *param_1)

{
  undefined4 uVar1;
  bool bVar2;
  
  uVar1 = 0;
  if ((*param_1 < 5) && (2 < *param_1)) {
    if (DAT_8033230c != 0) {
      bVar2 = true;
      DAT_803d8598 = DAT_803d8598 & 0xfffffbff;
      if ((DAT_8033230c != 0) && ((DAT_803d8698 & 0xffff) == 0xd00)) {
        if (DAT_80332310 == '\x01') {
          if ((DAT_80332318 <= DAT_803d8420) && (DAT_803d8420 <= DAT_8033231c)) {
            bVar2 = false;
          }
        }
        else if ((DAT_80332310 == '\0') && (DAT_80332314 != 0)) {
          bVar2 = false;
        }
      }
      if (bVar2) {
        DAT_8033230c = 0;
      }
      else {
        DAT_803d8598 = DAT_803d8598 | 0x400;
        DAT_8033230c = 1;
        if ((DAT_80332310 == '\0') || (DAT_80332310 == '\x10')) {
          DAT_80332314 = DAT_80332314 + -1;
        }
        DAT_803d8394 = 0;
      }
    }
    if (DAT_8033230c == 0) {
      DAT_803d8394 = 1;
      uVar1 = FUN_8028af0c(0x90);
    }
  }
  return uVar1;
}

