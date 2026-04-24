// Function: FUN_80013ec8
// Entry: 80013ec8
// Size: 160 bytes

void FUN_80013ec8(uint param_1)

{
  undefined *puVar1;
  
  param_1 = param_1 & 0xffff;
  puVar1 = (&PTR_DAT_802c6300)[param_1];
  if (((&DAT_8033931c)[param_1] == 0) && (*(code **)(puVar1 + 0x10) != (code *)0x0)) {
    (**(code **)(puVar1 + 0x10))(puVar1);
  }
  (&DAT_8033931c)[param_1] = (&DAT_8033931c)[param_1] + 1;
  *(undefined **)(&DAT_80338818 + param_1 * 4) = puVar1 + 0x18;
  return;
}

