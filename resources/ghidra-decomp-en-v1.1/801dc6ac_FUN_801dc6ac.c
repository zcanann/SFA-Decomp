// Function: FUN_801dc6ac
// Entry: 801dc6ac
// Size: 372 bytes

void FUN_801dc6ac(uint param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(*(int *)(param_1 + 0x4c) + 0x14);
  if (iVar2 == 0x448c2) {
    uVar1 = FUN_80020078(0xc44);
    if (uVar1 != 0) {
      FUN_800201ac(0xc41,1);
    }
  }
  else if (iVar2 < 0x448c2) {
    if (iVar2 == 0x30d9c) {
      FUN_8000bb38(param_1,299);
      FUN_8000bb38(param_1,0x12a);
      FUN_800201ac(0x7d,1);
    }
    else if (iVar2 < 0x30d9c) {
      if (0x30d9a < iVar2) {
        FUN_8000bb38(param_1,0x12d);
        FUN_8000bb38(param_1,0x12a);
        FUN_800201ac(0x7f,1);
      }
    }
    else if (iVar2 < 0x30d9e) {
      FUN_8000bb38(param_1,300);
      FUN_8000bb38(param_1,0x12a);
      FUN_800201ac(0x7e,1);
    }
  }
  else if (iVar2 == 0x4517c) {
    uVar1 = FUN_80020078(0xc44);
    if (uVar1 != 0) {
      FUN_800201ac(0xc45,1);
    }
  }
  else if (((iVar2 < 0x4517c) && (iVar2 == 0x45178)) && (uVar1 = FUN_80020078(0xc44), uVar1 != 0)) {
    FUN_800201ac(0xc43,1);
  }
  *(float *)(param_2 + 0x34) = FLOAT_803e6220;
  return;
}

