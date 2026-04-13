// Function: FUN_800570f8
// Entry: 800570f8
// Size: 616 bytes

void FUN_800570f8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  char cVar1;
  char *pcVar2;
  int iVar3;
  int iVar4;
  uint *puVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  undefined4 *puVar12;
  uint uVar13;
  undefined8 uVar14;
  
  FUN_8028682c();
  FUN_80009a94(4);
  FUN_8000d748();
  uVar14 = FUN_8001f73c();
  iVar10 = 0;
  puVar12 = &DAT_80382f14;
  do {
    pcVar2 = (char *)*puVar12;
    iVar11 = 0;
    do {
      iVar3 = (int)*pcVar2;
      if ((-1 < iVar3) &&
         (*(char *)(DAT_803ddb0c + iVar3) = *(char *)(DAT_803ddb0c + iVar3) + -1,
         *(char *)(DAT_803ddb0c + iVar3) == '\0')) {
        uVar13 = *(uint *)(DAT_803ddb1c + iVar3 * 4);
        *(undefined2 *)(DAT_803ddb14 + iVar3 * 2) = 0xffff;
        *(undefined4 *)(DAT_803ddb1c + iVar3 * 4) = 0;
        iVar3 = 0;
        for (iVar8 = 0; iVar8 < (int)(uint)*(byte *)(uVar13 + 0xa2); iVar8 = iVar8 + 1) {
          iVar7 = *(int *)(uVar13 + 100) + iVar3;
          iVar6 = iVar7;
          for (iVar9 = 0; iVar9 < (int)(uint)*(byte *)(iVar7 + 0x41); iVar9 = iVar9 + 1) {
            if (*(byte *)(iVar6 + 0x2a) != 0xff) {
              iVar4 = (uint)*(byte *)(iVar6 + 0x2a) * 0x10 + 0xc;
              cVar1 = *(char *)(DAT_803ddae8 + iVar4);
              if (cVar1 != '\0') {
                *(char *)(DAT_803ddae8 + iVar4) = cVar1 + -1;
              }
            }
            if (*(byte *)(iVar6 + 0x29) != 0) {
              FUN_80056820(*(int *)(iVar6 + 0x24),(uint)*(byte *)(iVar6 + 0x29));
            }
            iVar6 = iVar6 + 8;
          }
          iVar3 = iVar3 + 0x44;
        }
        for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(uVar13 + 0xa0); iVar3 = iVar3 + 1) {
          FUN_80054484();
        }
        if (*(uint *)(uVar13 + 0x74) != 0) {
          FUN_800238c4(*(uint *)(uVar13 + 0x74));
        }
        if (*(uint *)(uVar13 + 0x70) != 0) {
          FUN_800238c4(*(uint *)(uVar13 + 0x70));
        }
        FUN_800657f4();
        uVar14 = FUN_800238c4(uVar13);
      }
      iVar11 = iVar11 + 1;
      pcVar2 = pcVar2 + 1;
    } while (iVar11 < 0x100);
    puVar12 = puVar12 + 1;
    iVar10 = iVar10 + 1;
  } while (iVar10 < 5);
  DAT_803ddb18 = 0;
  FUN_8002e38c(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  iVar10 = 0;
  puVar5 = &DAT_803870c8;
  do {
    if (*puVar5 != 0) {
      FUN_800238c4(*puVar5);
      *puVar5 = 0;
    }
    puVar5 = puVar5 + 1;
    iVar10 = iVar10 + 1;
  } while (iVar10 < 0x78);
  (**(code **)(*DAT_803dd6ec + 4))();
  (**(code **)(*DAT_803dd71c + 4))();
  DAT_803dda6c = 0;
  FLOAT_803dda58 = FLOAT_803df84c;
  FLOAT_803dda5c = FLOAT_803df84c;
  uVar14 = FUN_800134f4();
  FUN_80130044(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  FUN_80133cbc();
  (**(code **)(*DAT_803dd6e0 + 0xc))(0xffffffff,0);
  (**(code **)(*DAT_803dd6e4 + 0x14))();
  FUN_80286878();
  return;
}

