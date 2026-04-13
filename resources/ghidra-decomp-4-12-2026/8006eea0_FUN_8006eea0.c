// Function: FUN_8006eea0
// Entry: 8006eea0
// Size: 168 bytes

undefined2 FUN_8006eea0(uint param_1,undefined param_2)

{
  uint uVar1;
  undefined2 *puVar2;
  
  puVar2 = &DAT_8030f470;
  if ((param_1 & 0xff) < 0x23) {
    uVar1 = (uint)(byte)(&DAT_8030f524)[param_1 & 0xff];
  }
  else {
    uVar1 = 0;
  }
  switch(param_2) {
  default:
    puVar2 = &DAT_8030f498;
    break;
  case 1:
    break;
  case 3:
    puVar2 = &DAT_8030f484;
    break;
  case 4:
    puVar2 = &DAT_8030f4ac;
    break;
  case 5:
    puVar2 = &DAT_8030f4d4;
    break;
  case 6:
    puVar2 = &DAT_8030f4c0;
    break;
  case 7:
    puVar2 = &DAT_8030f498;
    break;
  case 8:
    puVar2 = &DAT_8030f4e8;
    break;
  case 9:
    puVar2 = &DAT_8030f510;
    break;
  case 10:
    puVar2 = &DAT_8030f4fc;
  }
  return puVar2[uVar1];
}

