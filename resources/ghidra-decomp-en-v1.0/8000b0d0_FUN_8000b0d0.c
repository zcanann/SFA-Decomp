// Function: FUN_8000b0d0
// Entry: 8000b0d0
// Size: 672 bytes

int FUN_8000b0d0(uint param_1)

{
  int iVar1;
  uint uVar2;
  short *psVar3;
  short *psVar4;
  uint *puVar5;
  uint *puVar6;
  int iVar7;
  
  if ((((*(byte *)(param_1 + 0xf) >> 5 & 1) == 0) || (iVar1 = FUN_8000a188(2), iVar1 == 0)) &&
     (((*(byte *)(param_1 + 0xf) >> 5 & 1) != 0 || (iVar1 = FUN_8000a188(1), iVar1 == 0)))) {
    uVar2 = (uint)*(ushort *)(param_1 + 2);
    psVar3 = &DAT_802c5700;
    iVar1 = 99;
    iVar7 = 10;
    do {
      psVar4 = psVar3;
      if (((((((int)*psVar3 == uVar2) || (psVar4 = psVar3 + 8, (int)*psVar4 == uVar2)) ||
            (psVar4 = psVar3 + 0x10, (int)*psVar4 == uVar2)) ||
           ((psVar4 = psVar3 + 0x18, (int)*psVar4 == uVar2 ||
            (psVar4 = psVar3 + 0x20, (int)*psVar4 == uVar2)))) ||
          ((psVar4 = psVar3 + 0x28, (int)*psVar4 == uVar2 ||
           ((psVar4 = psVar3 + 0x30, (int)*psVar4 == uVar2 ||
            (psVar4 = psVar3 + 0x38, (int)*psVar4 == uVar2)))))) ||
         ((psVar4 = psVar3 + 0x40, (int)*psVar4 == uVar2 ||
          (psVar4 = psVar3 + 0x48, (int)psVar3[0x48] == uVar2)))) goto LAB_8000b210;
      psVar3 = psVar3 + 0x50;
      iVar1 = iVar1 + -9;
      iVar7 = iVar7 + -1;
    } while (iVar7 != 0);
    psVar4 = (short *)0x0;
LAB_8000b210:
    if (psVar4 != (short *)0x0) {
      puVar5 = &DAT_80335dc0;
      iVar1 = 0xf;
      iVar7 = 2;
      do {
        puVar6 = puVar5;
        if (((((puVar5[3] == 0) || (puVar6 = puVar5 + 9, puVar5[0xc] == 0)) ||
             (puVar6 = puVar5 + 0x12, puVar5[0x15] == 0)) ||
            ((puVar6 = puVar5 + 0x1b, puVar5[0x1e] == 0 ||
             (puVar6 = puVar5 + 0x24, puVar5[0x27] == 0)))) ||
           ((puVar6 = puVar5 + 0x2d, puVar5[0x30] == 0 ||
            ((puVar6 = puVar5 + 0x36, puVar5[0x39] == 0 ||
             (puVar6 = puVar5 + 0x3f, puVar5[0x42] == 0)))))) goto LAB_8000b2d8;
        puVar5 = puVar5 + 0x48;
        iVar1 = iVar1 + -7;
        iVar7 = iVar7 + -1;
      } while (iVar7 != 0);
      puVar6 = (uint *)0x0;
LAB_8000b2d8:
      if (puVar6 != (uint *)0x0) {
        *puVar6 = uVar2;
        *(ushort *)(puVar6 + 5) = (ushort)*(byte *)(param_1 + 0xc);
        *(byte *)((int)puVar6 + 0x11) = *(byte *)(param_1 + 0xf) >> 5 & 1;
        puVar6[3] = 4;
        *(ushort *)((int)puVar6 + 0x12) = (ushort)*(byte *)(param_1 + 0xd);
        if (*(char *)((int)puVar6 + 0x11) == '\0') {
          uVar2 = DAT_803dc818;
          DAT_803dc818 = DAT_803dc818 + 1;
        }
        else {
          uVar2 = DAT_803dc814;
          DAT_803dc814 = DAT_803dc814 + 1;
        }
        puVar6[6] = uVar2;
        puVar6[7] = param_1;
        puVar6[8] = (uint)FLOAT_803de560;
        iVar1 = FUN_80008df4(*(undefined4 *)(psVar4 + 4),*(undefined4 *)(psVar4 + 6),puVar6 + 2,
                             FUN_8000b370,psVar4,puVar6,param_1);
      }
    }
  }
  return iVar1;
}

