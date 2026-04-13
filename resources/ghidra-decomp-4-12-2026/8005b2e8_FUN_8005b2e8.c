// Function: FUN_8005b2e8
// Entry: 8005b2e8
// Size: 400 bytes

/* WARNING: Removing unreachable block (ram,0x8005b45c) */
/* WARNING: Removing unreachable block (ram,0x8005b2f8) */

undefined4 FUN_8005b2e8(void)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  double dVar4;
  
  dVar4 = (double)FUN_802925a0();
  iVar3 = (int)(dVar4 - (double)(float)((double)CONCAT44(0x43300000,DAT_803dda50 ^ 0x80000000) -
                                       DOUBLE_803df840));
  dVar4 = (double)FUN_802925a0();
  iVar1 = (int)(dVar4 - (double)(float)((double)CONCAT44(0x43300000,DAT_803dda54 ^ 0x80000000) -
                                       DOUBLE_803df840));
  if ((iVar3 < 0) || (0xf < iVar3)) {
    uVar2 = 0xffffffff;
  }
  else if ((iVar1 < 0) || (0xf < iVar1)) {
    uVar2 = 0xffffffff;
  }
  else {
    iVar3 = iVar3 + iVar1 * 0x10;
    if (*(char *)(iVar3 + DAT_80382f14) < '\0') {
      if (*(char *)(iVar3 + DAT_80382f18) < '\0') {
        if (*(char *)(iVar3 + DAT_80382f1c) < '\0') {
          if (*(char *)(iVar3 + DAT_80382f20) < '\0') {
            if (*(char *)(iVar3 + DAT_80382f24) < '\0') {
              uVar2 = 0;
            }
            else {
              uVar2 = 1;
            }
          }
          else {
            uVar2 = 1;
          }
        }
        else {
          uVar2 = 1;
        }
      }
      else {
        uVar2 = 1;
      }
    }
    else {
      uVar2 = 1;
    }
  }
  return uVar2;
}

