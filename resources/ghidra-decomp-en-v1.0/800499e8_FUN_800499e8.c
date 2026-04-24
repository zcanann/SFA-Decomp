// Function: FUN_800499e8
// Entry: 800499e8
// Size: 324 bytes

void FUN_800499e8(void)

{
  int iVar1;
  undefined2 *puVar2;
  undefined2 *puVar3;
  undefined4 local_28 [3];
  undefined auStack28 [8];
  int local_14;
  
  if ((DAT_803dd610 == 2) || (DAT_803dd610 == 3)) {
    FUN_8011818c();
  }
  FUN_8001376c(&DAT_8035f730,auStack28);
  puVar3 = &DAT_803966d0;
  puVar2 = &DAT_803965e0;
  for (iVar1 = 0; iVar1 < (int)(uint)DAT_803dd000; iVar1 = iVar1 + 1) {
    *puVar2 = *puVar3;
    puVar2[1] = puVar3[1];
    *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(puVar3 + 4);
    FUN_80258648(*puVar2,puVar2[1],puVar2 + 2);
    puVar3 = puVar3 + 6;
    puVar2 = puVar2 + 6;
  }
  DAT_803dd002 = DAT_803dd000;
  DAT_803dd000 = 0;
  if (local_14 == DAT_803dcccc) {
    DAT_803dcca8 = 1;
    DAT_803dcca9 = 0;
  }
  else {
    FUN_800137a8(&DAT_8035f730,local_28);
    DAT_803dccac = 0;
    FUN_80246b4c(&DAT_803dccc4);
    iVar1 = FUN_8001375c(&DAT_8035f730);
    if (iVar1 == 0) {
      FUN_8001376c(&DAT_8035f730,local_28);
      FUN_802564a4(local_28[0]);
      DAT_803dcca7 = 1;
    }
    else {
      FUN_8025653c();
      DAT_803dcca7 = 0;
    }
  }
  return;
}

