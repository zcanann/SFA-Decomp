// Function: FUN_801b56b8
// Entry: 801b56b8
// Size: 260 bytes

void FUN_801b56b8(void)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  double dVar5;
  undefined4 local_28 [7];
  
  local_28[0] = DAT_802c2328;
  local_28[1] = DAT_802c232c;
  local_28[2] = DAT_802c2330;
  local_28[3] = DAT_802c2334;
  dVar5 = (double)FUN_80291dd8((double)FLOAT_803e4934);
  FLOAT_803ddb70 = (float)((double)FLOAT_803e492c / dVar5);
  dVar5 = (double)FUN_80291dd8((double)FLOAT_803e493c);
  FLOAT_803ddb6c = (float)((double)FLOAT_803e492c / dVar5);
  dVar5 = (double)FUN_80291dd8((double)FLOAT_803e4958);
  FLOAT_803ddb68 = (float)((double)FLOAT_803e492c / dVar5);
  dVar5 = (double)FUN_80291dd8((double)FLOAT_803e4950);
  FLOAT_803ddb64 = (float)((double)FLOAT_803e492c / dVar5);
  dVar5 = (double)FUN_80291dd8((double)FLOAT_803e4954);
  FLOAT_803ddb60 = (float)((double)FLOAT_803e492c / dVar5);
  dVar5 = (double)FUN_80291dd8((double)FLOAT_803e492c);
  FLOAT_803ddb5c = (float)((double)FLOAT_803e492c / dVar5);
  iVar2 = 0;
  puVar4 = local_28;
  puVar3 = &DAT_803ac960;
  do {
    uVar1 = FUN_80054d54(*puVar4);
    *puVar3 = uVar1;
    puVar4 = puVar4 + 1;
    puVar3 = puVar3 + 1;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 4);
  return;
}

