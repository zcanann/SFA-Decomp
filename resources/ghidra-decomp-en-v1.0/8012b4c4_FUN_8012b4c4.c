// Function: FUN_8012b4c4
// Entry: 8012b4c4
// Size: 504 bytes

undefined4 FUN_8012b4c4(void)

{
  float fVar1;
  int iVar2;
  char cVar3;
  undefined4 uVar4;
  
  uVar4 = 0;
  cVar3 = FUN_80014c18(0);
  iVar2 = (int)cVar3;
  if (iVar2 < 0) {
    iVar2 = -iVar2;
  }
  if (iVar2 < 0xf) {
    cVar3 = '\0';
  }
  else if (cVar3 < '\0') {
    cVar3 = -1;
  }
  else if (cVar3 < '\x01') {
    cVar3 = '\0';
  }
  else {
    cVar3 = '\x01';
  }
  if (((DAT_803dd75c == 0) && (cVar3 != '\0')) && (FLOAT_803dd7bc == FLOAT_803e1e3c)) {
    iVar2 = DAT_803dd824 + DAT_803dd7d8 * 0x20;
    FUN_8012ddd8(*(undefined4 *)(iVar2 + 0x18),*(undefined *)(iVar2 + 0x1c),2,0);
    FLOAT_803dd7bc = (float)((double)CONCAT44(0x43300000,(int)cVar3 ^ 0x80000000) - DOUBLE_803e1e78)
    ;
    FLOAT_803dd7c0 =
         (float)((double)CONCAT44(0x43300000,cVar3 * 800 ^ 0x80000000) - DOUBLE_803e1e78);
    DAT_803dd7d8 = 0;
    FUN_8000bb18(0,0x100);
  }
  fVar1 = FLOAT_803dd7bc;
  if (FLOAT_803e1e3c < FLOAT_803dd7c0) {
    FLOAT_803dd7bc = FLOAT_803dd7bc + FLOAT_803dd7c0;
    if (FLOAT_803e216c <= FLOAT_803dd7bc) {
      DAT_803dd7c4 = DAT_803dd7c4 ^ 1;
      FLOAT_803dd7bc = FLOAT_803dd7bc - FLOAT_803e1e94;
    }
    if ((FLOAT_803e1e3c < FLOAT_803dd7bc) && (fVar1 < FLOAT_803e1e3c)) {
      FLOAT_803dd7bc = FLOAT_803e1e3c;
      FLOAT_803dd7c0 = FLOAT_803e1e3c;
      uVar4 = 1;
    }
  }
  fVar1 = FLOAT_803dd7bc;
  if (FLOAT_803dd7c0 < FLOAT_803e1e3c) {
    FLOAT_803dd7bc = FLOAT_803dd7bc + FLOAT_803dd7c0;
    if (FLOAT_803dd7bc < FLOAT_803e2170) {
      DAT_803dd7c4 = DAT_803dd7c4 ^ 1;
      FLOAT_803dd7bc = FLOAT_803dd7bc + FLOAT_803e1e94;
    }
    if ((FLOAT_803dd7bc < FLOAT_803e1e3c) && (FLOAT_803e1e3c < fVar1)) {
      FLOAT_803dd7bc = FLOAT_803e1e3c;
      FLOAT_803dd7c0 = FLOAT_803e1e3c;
      uVar4 = 1;
    }
  }
  return uVar4;
}

