// Function: FUN_80256e78
// Entry: 80256e78
// Size: 252 bytes

/* WARNING: Removing unreachable block (ram,0x80256ee8) */

void FUN_80256e78(void)

{
  uint uVar1;
  uint *puVar2;
  uint *puVar3;
  uint *puVar4;
  uint *puVar5;
  uint uVar6;
  int iVar7;
  uint auStack_9c [2];
  uint local_94 [5];
  uint local_80;
  uint local_7c;
  undefined4 local_78;
  
  puVar2 = (uint *)FUN_80256f7c();
  puVar3 = (uint *)FUN_80256f74();
  uVar6 = *puVar2;
  iVar7 = 0x10;
  puVar4 = puVar2 + -2;
  puVar5 = auStack_9c;
  do {
    uVar1 = puVar4[3];
    puVar5[2] = puVar4[2];
    puVar5[3] = uVar1;
    iVar7 = iVar7 + -1;
    puVar4 = puVar4 + 2;
    puVar5 = puVar5 + 2;
  } while (iVar7 != 0);
  FUN_80243e74();
  local_78 = 0;
  local_80 = uVar6;
  local_7c = uVar6;
  FUN_80243e9c();
  FUN_80256854(local_94);
  if (puVar3 == puVar2) {
    FUN_80256744(local_94);
  }
  FUN_80243e74();
  puVar2[5] = uVar6;
  puVar2[6] = uVar6;
  puVar2[7] = 0;
  if ((int)puVar2[7] < 0) {
    puVar2[7] = puVar2[7] + puVar2[2];
  }
  FUN_80243e9c();
  FUN_80256854(puVar2);
  if (puVar3 == puVar2) {
    FUN_80256744(puVar3);
  }
  return;
}

