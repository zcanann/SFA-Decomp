// Function: FUN_8000546c
// Entry: 8000546c
// Size: 260 bytes

void FUN_8000546c(void)

{
  uint *puVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  
  if (((DAT_803d94d8 < 0x45) && (0x44 < DAT_803d94d8 + 0x4000)) && ((DAT_803d9238 & 3) != 0)) {
    puVar1 = (uint *)&DAT_00000044;
  }
  else {
    puVar1 = &DAT_80000044;
  }
  uVar5 = *puVar1;
  puVar1 = &DAT_80332f80;
  iVar4 = 0;
  do {
    if ((uVar5 & 1 << iVar4) != 0) {
      uVar2 = *puVar1;
      if (((uVar2 < DAT_803d94d8) || (DAT_803d94d8 + 0x4000 <= uVar2)) ||
         (uVar3 = uVar2, (DAT_803d9238 & 3) == 0)) {
        uVar3 = uVar2 & 0x3fffffff | 0x80000000;
      }
      FUN_80003514(uVar3,uVar2 + 0x80003538,0x100);
      FUN_8028b748(uVar3,0x100);
    }
    iVar4 = iVar4 + 1;
    puVar1 = puVar1 + 1;
  } while (iVar4 < 0xf);
  return;
}

