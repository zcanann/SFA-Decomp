// Function: FUN_80013ee8
// Entry: 80013ee8
// Size: 160 bytes

void FUN_80013ee8(uint param_1)

{
  uint uVar1;
  undefined *puVar2;
  
  uVar1 = param_1 & 0xffff;
  puVar2 = (&PTR_DAT_802c6a80)[uVar1];
  if (((&DAT_80339f7c)[uVar1] == 0) && (*(code **)(puVar2 + 0x10) != (code *)0x0)) {
    (**(code **)(puVar2 + 0x10))(puVar2);
  }
  (&DAT_80339f7c)[uVar1] = (&DAT_80339f7c)[uVar1] + 1;
  *(undefined **)(&DAT_80339478 + uVar1 * 4) = puVar2 + 0x18;
  return;
}

