// Function: FUN_8006ed24
// Entry: 8006ed24
// Size: 168 bytes

undefined2 FUN_8006ed24(uint param_1,undefined param_2)

{
  uint uVar1;
  undefined2 *puVar2;
  
  puVar2 = &DAT_8030e8b0;
  if ((param_1 & 0xff) < 0x23) {
    uVar1 = (uint)(byte)(&DAT_8030e964)[param_1 & 0xff];
  }
  else {
    uVar1 = 0;
  }
  switch(param_2) {
  default:
    puVar2 = &DAT_8030e8d8;
    break;
  case 1:
    break;
  case 3:
    puVar2 = &DAT_8030e8c4;
    break;
  case 4:
    puVar2 = &DAT_8030e8ec;
    break;
  case 5:
    puVar2 = &DAT_8030e914;
    break;
  case 6:
    puVar2 = &DAT_8030e900;
    break;
  case 7:
    puVar2 = &DAT_8030e8d8;
    break;
  case 8:
    puVar2 = &DAT_8030e928;
    break;
  case 9:
    puVar2 = &DAT_8030e950;
    break;
  case 10:
    puVar2 = &DAT_8030e93c;
  }
  return puVar2[uVar1];
}

