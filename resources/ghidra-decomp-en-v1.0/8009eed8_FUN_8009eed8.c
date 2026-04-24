// Function: FUN_8009eed8
// Entry: 8009eed8
// Size: 260 bytes

void FUN_8009eed8(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined *puVar5;
  undefined2 *puVar6;
  char *pcVar7;
  int *piVar8;
  int *piVar9;
  
  iVar1 = FUN_802860c4();
  if (iVar1 != 0) {
    iVar4 = 0;
    piVar9 = &DAT_8039bd58;
    piVar8 = &DAT_8039ba28;
    pcVar7 = &DAT_8039bbc8;
    puVar6 = &DAT_8030f8c8;
    puVar5 = &DAT_8030f968;
    do {
      iVar3 = *piVar9;
      if (iVar1 == *piVar8) {
        iVar2 = 0;
        do {
          if ((iVar3 != 0) && ((&DAT_8039b4d8)[(uint)(*(byte *)(iVar3 + 0x8a) >> 1) * 4] == iVar1))
          {
            FUN_8009b0e0(*piVar9,iVar4,iVar2,0,1);
          }
          iVar3 = iVar3 + 0xa0;
          if (*pcVar7 == '\0') {
            *puVar6 = 0xffff;
          }
          iVar2 = iVar2 + 1;
        } while (iVar2 < 0x19);
        *piVar8 = 0;
        *puVar5 = 0;
      }
      piVar9 = piVar9 + 1;
      piVar8 = piVar8 + 1;
      pcVar7 = pcVar7 + 1;
      puVar6 = puVar6 + 1;
      puVar5 = puVar5 + 1;
      iVar4 = iVar4 + 1;
    } while (iVar4 < 0x50);
  }
  FUN_80286110();
  return;
}

