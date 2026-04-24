// Function: FUN_80013e4c
// Entry: 80013e4c
// Size: 156 bytes

undefined4 FUN_80013e4c(undefined *param_1)

{
  undefined4 uVar1;
  undefined *puVar2;
  int iVar3;
  int iVar4;
  
  iVar3 = 0;
  puVar2 = &DAT_80339478;
  iVar4 = 0x2c1;
  do {
    if (puVar2 == param_1) {
      param_1 = (&PTR_DAT_802c6a80)[iVar3];
      break;
    }
    puVar2 = puVar2 + 4;
    iVar3 = iVar3 + 1;
    iVar4 = iVar4 + -1;
  } while (iVar4 != 0);
  (&DAT_80339f7c)[iVar3] = (&DAT_80339f7c)[iVar3] + -1;
  if ((&DAT_80339f7c)[iVar3] == 0) {
    if (*(code **)(param_1 + 0x14) != (code *)0x0) {
      (**(code **)(param_1 + 0x14))();
    }
    uVar1 = 1;
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}

