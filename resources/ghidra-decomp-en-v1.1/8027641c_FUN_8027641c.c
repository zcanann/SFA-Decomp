// Function: FUN_8027641c
// Entry: 8027641c
// Size: 400 bytes

void FUN_8027641c(int param_1)

{
  byte bVar1;
  ushort *puVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  
  uVar5 = *(uint *)(param_1 + 0x124);
  uVar3 = *(uint *)(param_1 + 0x128) & 0xffffff;
  uVar4 = uVar5 & 0xffffff;
  bVar1 = (byte)(uVar5 >> 0x18);
  if (uVar4 == uVar3) {
    *(ushort *)(param_1 + 300) = (ushort)bVar1;
    *(undefined *)(param_1 + 0x12e) = 0;
    return;
  }
  if (uVar3 <= uVar4) {
    uVar3 = (uVar4 << 0xc) / uVar3;
    iVar7 = 0xb;
    iVar6 = 0;
    do {
      if (uVar3 >> 0xc < (uint)(1 << iVar6 + 1)) break;
      iVar6 = iVar6 + 1;
      iVar7 = iVar7 + -1;
    } while (iVar7 != 0);
    uVar3 = uVar3 / (uint)(1 << iVar6);
    iVar7 = 0xb;
    for (puVar2 = &DAT_8032fa46; uVar3 <= *puVar2; puVar2 = puVar2 + -1) {
      iVar7 = iVar7 + -1;
    }
    iVar6 = iVar7 + iVar6 * 0xc;
    if ((int)(uVar5 >> 0x18) < iVar6) {
      *(undefined *)(param_1 + 0x12e) = 0;
      *(undefined2 *)(param_1 + 300) = 0;
      return;
    }
    *(ushort *)(param_1 + 300) = (ushort)bVar1 - (short)iVar6;
    uVar4 = (uint)*(ushort *)(iVar7 * 2 + -0x7fcd05d0);
    *(char *)(param_1 + 0x12e) =
         (char)(((uVar4 - uVar3) * 100) / (*(ushort *)(iVar7 * 2 + -0x7fcd05ce) - uVar4));
    return;
  }
  uVar4 = (uVar3 << 0xc) / uVar4;
  iVar7 = 0xb;
  iVar6 = 0;
  do {
    if (uVar4 >> 0xc < (uint)(1 << iVar6 + 1)) break;
    iVar6 = iVar6 + 1;
    iVar7 = iVar7 + -1;
  } while (iVar7 != 0);
  uVar4 = uVar4 / (uint)(1 << iVar6);
  iVar7 = 0xb;
  for (puVar2 = &DAT_8032fa46; uVar4 <= *puVar2; puVar2 = puVar2 + -1) {
    iVar7 = iVar7 + -1;
  }
  *(ushort *)(param_1 + 300) = (ushort)bVar1 + (short)iVar6 * 0xc + (short)iVar7;
  uVar3 = (uint)*(ushort *)(iVar7 * 2 + -0x7fcd05d0);
  *(char *)(param_1 + 0x12e) =
       (char)(((uVar4 - uVar3) * 100) / (*(ushort *)(iVar7 * 2 + -0x7fcd05ce) - uVar3));
  return;
}

