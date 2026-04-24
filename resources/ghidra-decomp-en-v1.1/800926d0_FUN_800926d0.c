// Function: FUN_800926d0
// Entry: 800926d0
// Size: 216 bytes

void FUN_800926d0(void)

{
  int iVar1;
  int *piVar2;
  double dVar3;
  undefined8 uVar4;
  double dVar5;
  double dVar6;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  uint3 local_18 [2];
  
  local_18[0]._0_4_ = DAT_803dfe18;
  dVar3 = (double)FLOAT_803dfe20;
  dVar5 = dVar3;
  dVar6 = dVar3;
  uVar4 = FUN_8025ca38(dVar3,dVar3,dVar3,dVar3,0,local_18);
  iVar1 = 0;
  piVar2 = &DAT_8039b488;
  do {
    if ((*piVar2 != 0) && (*(char *)(*piVar2 + 0x144f) == '\0')) {
      uVar4 = FUN_80090500(uVar4,dVar3,dVar5,dVar6,in_f5,in_f6,in_f7,in_f8);
    }
    piVar2 = piVar2 + 1;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 8);
  if (DAT_803dde18 != '\0') {
    FUN_80079fe0((double)FLOAT_803dde10,(double)FLOAT_803dc3c4,(double)FLOAT_803dc3c8,DAT_803dde18,
                 &DAT_8039b550,DAT_803dde19,DAT_803dde1a);
  }
  return;
}

