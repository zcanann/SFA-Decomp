// Function: FUN_801dc0bc
// Entry: 801dc0bc
// Size: 372 bytes

void FUN_801dc0bc(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(*(int *)(param_1 + 0x4c) + 0x14);
  if (iVar1 == 0x448c2) {
    iVar1 = FUN_8001ffb4(0xc44);
    if (iVar1 != 0) {
      FUN_800200e8(0xc41,1);
    }
  }
  else if (iVar1 < 0x448c2) {
    if (iVar1 == 0x30d9c) {
      FUN_8000bb18(param_1,299);
      FUN_8000bb18(param_1,0x12a);
      FUN_800200e8(0x7d,1);
    }
    else if (iVar1 < 0x30d9c) {
      if (0x30d9a < iVar1) {
        FUN_8000bb18(param_1,0x12d);
        FUN_8000bb18(param_1,0x12a);
        FUN_800200e8(0x7f,1);
      }
    }
    else if (iVar1 < 0x30d9e) {
      FUN_8000bb18(param_1,300);
      FUN_8000bb18(param_1,0x12a);
      FUN_800200e8(0x7e,1);
    }
  }
  else if (iVar1 == 0x4517c) {
    iVar1 = FUN_8001ffb4(0xc44);
    if (iVar1 != 0) {
      FUN_800200e8(0xc45,1);
    }
  }
  else if (((iVar1 < 0x4517c) && (iVar1 == 0x45178)) && (iVar1 = FUN_8001ffb4(0xc44), iVar1 != 0)) {
    FUN_800200e8(0xc43,1);
  }
  *(float *)(param_2 + 0x34) = FLOAT_803e5588;
  return;
}

