// Function: FUN_80056f7c
// Entry: 80056f7c
// Size: 616 bytes

void FUN_80056f7c(void)

{
  char cVar1;
  char *pcVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  char **ppcVar12;
  int iVar13;
  
  FUN_802860c8();
  FUN_80009a94(4);
  FUN_8000d728();
  FUN_8001f678(1,0);
  iVar10 = 0;
  ppcVar12 = (char **)&DAT_803822b4;
  do {
    pcVar2 = *ppcVar12;
    iVar11 = 0;
    do {
      iVar3 = (int)*pcVar2;
      if (-1 < iVar3) {
        *(char *)(DAT_803dce8c + iVar3) = *(char *)(DAT_803dce8c + iVar3) + -1;
        if (*(char *)(DAT_803dce8c + iVar3) == '\0') {
          iVar13 = *(int *)(DAT_803dce9c + iVar3 * 4);
          *(undefined2 *)(DAT_803dce94 + iVar3 * 2) = 0xffff;
          *(undefined4 *)(DAT_803dce9c + iVar3 * 4) = 0;
          iVar3 = 0;
          for (iVar8 = 0; iVar8 < (int)(uint)*(byte *)(iVar13 + 0xa2); iVar8 = iVar8 + 1) {
            iVar7 = *(int *)(iVar13 + 100) + iVar3;
            iVar6 = iVar7;
            for (iVar9 = 0; iVar9 < (int)(uint)*(byte *)(iVar7 + 0x41); iVar9 = iVar9 + 1) {
              if (*(byte *)(iVar6 + 0x2a) != 0xff) {
                iVar4 = (uint)*(byte *)(iVar6 + 0x2a) * 0x10 + 0xc;
                cVar1 = *(char *)(DAT_803dce68 + iVar4);
                if (cVar1 != '\0') {
                  *(char *)(DAT_803dce68 + iVar4) = cVar1 + -1;
                }
              }
              if (*(char *)(iVar6 + 0x29) != '\0') {
                FUN_800566a4(*(undefined4 *)(iVar6 + 0x24));
              }
              iVar6 = iVar6 + 8;
            }
            iVar3 = iVar3 + 0x44;
          }
          iVar3 = 0;
          for (iVar8 = 0; iVar8 < (int)(uint)*(byte *)(iVar13 + 0xa0); iVar8 = iVar8 + 1) {
            FUN_80054308(*(undefined4 *)(*(int *)(iVar13 + 0x54) + iVar3));
            iVar3 = iVar3 + 4;
          }
          if (*(int *)(iVar13 + 0x74) != 0) {
            FUN_80023800();
          }
          if (*(int *)(iVar13 + 0x70) != 0) {
            FUN_80023800();
          }
          FUN_80065678();
          FUN_80023800(iVar13);
        }
      }
      iVar11 = iVar11 + 1;
      pcVar2 = pcVar2 + 1;
    } while (iVar11 < 0x100);
    ppcVar12 = ppcVar12 + 1;
    iVar10 = iVar10 + 1;
  } while (iVar10 < 5);
  DAT_803dce98 = 0;
  FUN_8002e294();
  iVar10 = 0;
  piVar5 = &DAT_80386468;
  do {
    if (*piVar5 != 0) {
      FUN_80023800();
      *piVar5 = 0;
    }
    piVar5 = piVar5 + 1;
    iVar10 = iVar10 + 1;
  } while (iVar10 < 0x78);
  (**(code **)(*DAT_803dca6c + 4))();
  (**(code **)(*DAT_803dca9c + 4))();
  DAT_803dcdec = 0;
  FLOAT_803dcdd8 = FLOAT_803debcc;
  FLOAT_803dcddc = FLOAT_803debcc;
  FUN_800134d4();
  FUN_8012fcec();
  FUN_80133934();
  (**(code **)(*DAT_803dca60 + 0xc))(0xffffffff,0);
  (**(code **)(*DAT_803dca64 + 0x14))();
  FUN_80286114();
  return;
}

