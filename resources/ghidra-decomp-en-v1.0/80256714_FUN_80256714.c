// Function: FUN_80256714
// Entry: 80256714
// Size: 252 bytes

/* WARNING: Removing unreachable block (ram,0x80256784) */

void FUN_80256714(void)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  undefined4 uVar6;
  int iVar7;
  undefined4 auStack156 [2];
  undefined4 local_94 [5];
  undefined4 local_80;
  undefined4 local_7c;
  undefined4 local_78;
  
  puVar2 = (undefined4 *)FUN_80256818();
  puVar3 = (undefined4 *)FUN_80256810();
  uVar6 = *puVar2;
  iVar7 = 0x10;
  puVar4 = puVar2 + -2;
  puVar5 = auStack156;
  do {
    uVar1 = puVar4[3];
    puVar5[2] = puVar4[2];
    puVar5[3] = uVar1;
    iVar7 = iVar7 + -1;
    puVar4 = puVar4 + 2;
    puVar5 = puVar5 + 2;
  } while (iVar7 != 0);
  FUN_8024377c();
  local_78 = 0;
  local_80 = uVar6;
  local_7c = uVar6;
  FUN_802437a4();
  FUN_802560f0(local_94);
  if (puVar3 == puVar2) {
    FUN_80255fe0(local_94);
  }
  FUN_8024377c();
  puVar2[5] = uVar6;
  puVar2[6] = uVar6;
  puVar2[7] = 0;
  if ((int)puVar2[7] < 0) {
    puVar2[7] = puVar2[7] + puVar2[2];
  }
  FUN_802437a4();
  FUN_802560f0(puVar2);
  if (puVar3 == puVar2) {
    FUN_80255fe0(puVar3);
  }
  return;
}

