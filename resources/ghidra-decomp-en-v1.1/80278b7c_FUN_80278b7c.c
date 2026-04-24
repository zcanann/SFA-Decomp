// Function: FUN_80278b7c
// Entry: 80278b7c
// Size: 328 bytes

void FUN_80278b7c(uint param_1)

{
  int *piVar1;
  int *piVar2;
  uint uVar3;
  int iVar4;
  bool bVar5;
  
  piVar2 = DAT_803def58;
  while (piVar1 = DAT_803def54, piVar2 != (int *)0x0) {
    uVar3 = piVar2[0x27];
    iVar4 = piVar2[0x26];
    if (DAT_803def60 < (uint)(DAT_803def64 < uVar3) + iVar4) break;
    piVar1 = (int *)piVar2[0x11];
    FUN_802790f4(piVar2);
    piVar2[0x29] = uVar3;
    piVar2[0x28] = iVar4;
    piVar2 = piVar1;
  }
  for (; piVar1 != (int *)0x0; piVar1 = (int *)piVar1[0xf]) {
    if (*(char *)(piVar1 + 0x1a) == '\0') {
      bVar5 = false;
    }
    else {
      bVar5 = piVar1[0x15] != 0;
    }
    if ((((bVar5) && ((piVar1[0x46] & 0x20U) == 0)) &&
        (bVar5 = FUN_802839b8(piVar1[0x3d] & 0xff), !bVar5)) &&
       ((*(char *)(piVar1 + 0x1a) != '\0' && (piVar1[0x15] != 0)))) {
      piVar1[0xe] = piVar1[0x18];
      piVar1[0xd] = piVar1[0x15];
      piVar1[0x15] = 0;
      FUN_802790f4(piVar1);
    }
    FUN_80277670(piVar1);
  }
  bVar5 = CARRY4(DAT_803def64,param_1);
  DAT_803def64 = DAT_803def64 + param_1;
  DAT_803def60 = DAT_803def60 + bVar5;
  return;
}

