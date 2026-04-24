// Function: FUN_8012b800
// Entry: 8012b800
// Size: 504 bytes

undefined4 FUN_8012b800(void)

{
  float fVar1;
  int iVar2;
  char cVar3;
  undefined4 uVar4;
  
  uVar4 = 0;
  cVar3 = FUN_80014c44(0);
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
  if (((DAT_803de3dc == 0) && (cVar3 != '\0')) && (FLOAT_803de43c == FLOAT_803e2abc)) {
    iVar2 = DAT_803de4a4 + DAT_803de458 * 0x20;
    FUN_8012e114(*(undefined4 *)(iVar2 + 0x18),*(byte *)(iVar2 + 0x1c),2,0);
    FLOAT_803de43c = (float)((double)CONCAT44(0x43300000,(int)cVar3 ^ 0x80000000) - DOUBLE_803e2af8)
    ;
    FLOAT_803de440 =
         (float)((double)CONCAT44(0x43300000,cVar3 * 800 ^ 0x80000000) - DOUBLE_803e2af8);
    DAT_803de458 = 0;
    FUN_8000bb38(0,0x100);
  }
  fVar1 = FLOAT_803de43c;
  if (FLOAT_803e2abc < FLOAT_803de440) {
    FLOAT_803de43c = FLOAT_803de43c + FLOAT_803de440;
    if (FLOAT_803e2dfc <= FLOAT_803de43c) {
      DAT_803de444 = DAT_803de444 ^ 1;
      FLOAT_803de43c = FLOAT_803de43c - FLOAT_803e2b14;
    }
    if ((FLOAT_803e2abc < FLOAT_803de43c) && (fVar1 < FLOAT_803e2abc)) {
      FLOAT_803de43c = FLOAT_803e2abc;
      FLOAT_803de440 = FLOAT_803e2abc;
      uVar4 = 1;
    }
  }
  fVar1 = FLOAT_803de43c;
  if (FLOAT_803de440 < FLOAT_803e2abc) {
    FLOAT_803de43c = FLOAT_803de43c + FLOAT_803de440;
    if (FLOAT_803de43c < FLOAT_803e2e00) {
      DAT_803de444 = DAT_803de444 ^ 1;
      FLOAT_803de43c = FLOAT_803de43c + FLOAT_803e2b14;
    }
    if ((FLOAT_803de43c < FLOAT_803e2abc) && (FLOAT_803e2abc < fVar1)) {
      FLOAT_803de43c = FLOAT_803e2abc;
      FLOAT_803de440 = FLOAT_803e2abc;
      uVar4 = 1;
    }
  }
  return uVar4;
}

