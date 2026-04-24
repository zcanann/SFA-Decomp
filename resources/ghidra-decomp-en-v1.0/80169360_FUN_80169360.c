// Function: FUN_80169360
// Entry: 80169360
// Size: 552 bytes

void FUN_80169360(int param_1,byte param_2)

{
  float *pfVar1;
  int iVar2;
  
  if (param_1 == 0) {
    return;
  }
  iVar2 = *(int *)(*(int *)(param_1 + 0x4c) + 0x14);
  if (iVar2 == 0x41ccc) {
    iVar2 = FUN_8002e0b4(0x4b411);
  }
  else if (iVar2 < 0x41ccc) {
    if (iVar2 == 0x41cc6) {
      iVar2 = FUN_8002e0b4(0x4b404);
    }
    else if (iVar2 < 0x41cc6) {
      if (iVar2 == 0x41cc4) {
        iVar2 = FUN_8002e0b4(0x4b402);
      }
      else if (iVar2 < 0x41cc4) {
        if (iVar2 != 0x41be9) {
          return;
        }
        iVar2 = FUN_8002e0b4(0x4b3f9);
      }
      else {
        iVar2 = FUN_8002e0b4(0x4b403);
      }
    }
    else if (iVar2 == 0x41cc9) {
      iVar2 = FUN_8002e0b4(0x4b40f);
    }
    else {
      if (0x41cc8 < iVar2) {
        return;
      }
      if (iVar2 < 0x41cc8) {
        iVar2 = FUN_8002e0b4(0x4b40b);
      }
      else {
        iVar2 = FUN_8002e0b4(0x4b40c);
      }
    }
  }
  else if (iVar2 == 0x41cd6) {
    iVar2 = FUN_8002e0b4(0x4b415);
  }
  else if (iVar2 < 0x41cd6) {
    if (iVar2 == 0x41cd2) {
      iVar2 = FUN_8002e0b4(0x4b410);
    }
    else {
      if (iVar2 < 0x41cd2) {
        return;
      }
      if (iVar2 < 0x41cd5) {
        return;
      }
      iVar2 = FUN_8002e0b4(0x4b414);
    }
  }
  else if (iVar2 == 0x43d14) {
    iVar2 = FUN_8002e0b4(0x4b3b5);
  }
  else {
    if (0x43d13 < iVar2) {
      return;
    }
    if (iVar2 != 0x41cd9) {
      return;
    }
    iVar2 = FUN_8002e0b4(0x4b453);
  }
  pfVar1 = *(float **)(iVar2 + 0xb8);
  if (pfVar1 != (float *)0x0) {
    if (param_2 == 2) {
      pfVar1[2] = FLOAT_803e30d0;
      *pfVar1 = FLOAT_803e30d4;
      pfVar1[1] = FLOAT_803e30d8;
      *(undefined *)(pfVar1 + 3) = 1;
    }
    else if ((param_2 < 2) && (param_2 != 0)) {
      pfVar1[2] = FLOAT_803e30d0;
      *pfVar1 = FLOAT_803e30d4;
      pfVar1[1] = FLOAT_803e30d8;
      *(undefined *)(pfVar1 + 3) = 0;
    }
  }
  return;
}

