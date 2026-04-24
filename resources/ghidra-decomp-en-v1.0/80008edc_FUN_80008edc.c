// Function: FUN_80008edc
// Entry: 80008edc
// Size: 92 bytes

void FUN_80008edc(undefined *param_1)

{
  undefined *puVar1;
  int iVar2;
  
  puVar1 = &DAT_80335940;
  iVar2 = 0x10;
  do {
    if (param_1 == puVar1) {
      (**(code **)(puVar1 + 0x20))
                (*(undefined4 *)(puVar1 + 0x24),*(undefined4 *)(puVar1 + 0x28),
                 *(undefined4 *)(puVar1 + 0x2c));
      return;
    }
    puVar1 = puVar1 + 0x30;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  return;
}

