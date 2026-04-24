// Function: FUN_8001ffb4
// Entry: 8001ffb4
// Size: 308 bytes

/* WARNING: Removing unreachable block (ram,0x80020038) */

uint FUN_8001ffb4(uint param_1)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  int in_r8;
  uint uVar6;
  
  iVar3 = (int)(short)((ushort)param_1 & 0xfff);
  if (iVar3 == 0x95) {
    return 1;
  }
  if (iVar3 == 0x96) {
    return 0;
  }
  if (param_1 == 0xffffffff) {
    return 0;
  }
  if (DAT_803dcad8 <= iVar3) {
    return 0;
  }
  bVar1 = *(byte *)(DAT_803dcadc + iVar3 * 4 + 2);
  uVar2 = (int)(uint)bVar1 >> 6;
  if (uVar2 == 2) {
    in_r8 = DAT_803dcae0 + 0x24;
  }
  else if (uVar2 < 2) {
    if (uVar2 == 0) {
      in_r8 = DAT_803dcae0 + 0xef0;
    }
    else {
      in_r8 = DAT_803dcae0 + 0x564;
    }
  }
  else if (uVar2 < 4) {
    in_r8 = DAT_803dcae0 + 0x5d8;
  }
  uVar5 = (uint)*(ushort *)(DAT_803dcadc + iVar3 * 4);
  uVar6 = 0;
  uVar2 = 1;
  uVar4 = (bVar1 & 0x1f) + uVar5 + 1;
  iVar3 = uVar4 - uVar5;
  if (uVar5 < uVar4) {
    do {
      if ((1 << (uVar5 & 7) & (uint)*(byte *)(in_r8 + ((int)uVar5 >> 3))) != 0) {
        uVar6 = uVar6 | uVar2;
      }
      uVar2 = uVar2 << 1;
      uVar5 = uVar5 + 1;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  if ((param_1 & 0x8000) != 0) {
    uVar6 = uVar6 & 1 ^ 1;
  }
  return uVar6;
}

