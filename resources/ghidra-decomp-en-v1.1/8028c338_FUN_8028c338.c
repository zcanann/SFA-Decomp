// Function: FUN_8028c338
// Entry: 8028c338
// Size: 348 bytes

/* WARNING: Removing unreachable block (ram,0x8028c3b8) */

int FUN_8028c338(byte *param_1)

{
  bool bVar1;
  int iVar2;
  
  iVar2 = 0;
  if ((*param_1 < 5) && (2 < *param_1)) {
    if (DAT_80332f6c != 0) {
      bVar1 = true;
      DAT_803d91f8 = DAT_803d91f8 & 0xfffffbff;
      if ((DAT_80332f6c != 0) && ((DAT_803d92f8 & 0xffff) == 0xd00)) {
        if (DAT_80332f70 == '\x01') {
          if ((DAT_80332f78 <= DAT_803d9080) && (DAT_803d9080 <= DAT_80332f7c)) {
            bVar1 = false;
          }
        }
        else if ((DAT_80332f70 == '\0') && (DAT_80332f74 != 0)) {
          bVar1 = false;
        }
      }
      if (bVar1) {
        DAT_80332f6c = 0;
      }
      else {
        DAT_803d91f8 = DAT_803d91f8 | 0x400;
        DAT_80332f6c = 1;
        if ((DAT_80332f70 == '\0') || (DAT_80332f70 == '\x10')) {
          DAT_80332f74 = DAT_80332f74 + -1;
        }
        DAT_803d8ff4 = 0;
      }
    }
    if (DAT_80332f6c == 0) {
      DAT_803d8ff4 = 1;
      iVar2 = FUN_8028b670(-0x70);
    }
  }
  return iVar2;
}

