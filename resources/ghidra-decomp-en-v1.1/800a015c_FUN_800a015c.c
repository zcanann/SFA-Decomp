// Function: FUN_800a015c
// Entry: 800a015c
// Size: 288 bytes

void FUN_800a015c(void)

{
  undefined2 *puVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined *puVar4;
  int iVar5;
  uint *puVar6;
  int iVar7;
  
  puVar3 = &DAT_8039c878;
  puVar4 = &DAT_8039c828;
  puVar1 = &DAT_80310488;
  iVar7 = 10;
  do {
    iVar5 = 0;
    *puVar3 = 0;
    *puVar4 = 0;
    *puVar1 = 0xffff;
    puVar3[1] = 0;
    puVar4[1] = 0;
    puVar1[1] = 0xffff;
    puVar3[2] = 0;
    puVar4[2] = 0;
    puVar1[2] = 0xffff;
    puVar3[3] = 0;
    puVar4[3] = 0;
    puVar1[3] = 0xffff;
    puVar3[4] = 0;
    puVar4[4] = 0;
    puVar1[4] = 0xffff;
    puVar3[5] = 0;
    puVar4[5] = 0;
    puVar1[5] = 0xffff;
    puVar3[6] = 0;
    puVar4[6] = 0;
    puVar1[6] = 0xffff;
    puVar3[7] = 0;
    puVar4[7] = 0;
    puVar1[7] = 0xffff;
    puVar3 = puVar3 + 8;
    puVar4 = puVar4 + 8;
    puVar1 = puVar1 + 8;
    iVar7 = iVar7 + -1;
  } while (iVar7 != 0);
  puVar6 = &DAT_8039c9b8;
  do {
    uVar2 = FUN_80023d8c(4000,0x14);
    *puVar6 = uVar2;
    FUN_800033a8(*puVar6,0,4000);
    FUN_802420e0(*puVar6,4000);
    puVar6 = puVar6 + 1;
    iVar5 = iVar5 + 1;
  } while (iVar5 < 0x50);
  FUN_800033a8(-0x7fc63ec8,0,0x500);
  return;
}

