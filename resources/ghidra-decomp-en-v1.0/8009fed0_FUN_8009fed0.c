// Function: FUN_8009fed0
// Entry: 8009fed0
// Size: 288 bytes

void FUN_8009fed0(void)

{
  undefined2 *puVar1;
  undefined4 uVar2;
  undefined4 *puVar3;
  undefined *puVar4;
  int iVar5;
  int iVar6;
  
  puVar3 = &DAT_8039bc18;
  puVar4 = &DAT_8039bbc8;
  puVar1 = &DAT_8030f8c8;
  iVar6 = 10;
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
    iVar6 = iVar6 + -1;
  } while (iVar6 != 0);
  puVar3 = &DAT_8039bd58;
  do {
    uVar2 = FUN_80023cc8(4000,0x14,0);
    *puVar3 = uVar2;
    FUN_800033a8(*puVar3,0,4000);
    FUN_802419e8(*puVar3,4000);
    puVar3 = puVar3 + 1;
    iVar5 = iVar5 + 1;
  } while (iVar5 < 0x50);
  FUN_800033a8(&DAT_8039b4d8,0,0x500);
  return;
}

