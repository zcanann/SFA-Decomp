// Function: FUN_800e8abc
// Entry: 800e8abc
// Size: 736 bytes

void FUN_800e8abc(void)

{
  undefined4 uVar1;
  undefined4 uVar2;
  char *pcVar3;
  undefined4 uVar4;
  int iVar5;
  short *psVar6;
  char *pcVar7;
  char cVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_802860dc();
  uVar2 = DAT_802c2178;
  uVar1 = DAT_802c2174;
  uVar4 = DAT_802c2170;
  pcVar7 = (char *)((ulonglong)uVar9 >> 0x20);
  FUN_800033a8(&DAT_803a32a8,0,0xf70);
  if ((*(byte *)(DAT_803dd498 + 0x21) & 0x80) == 0) {
    FUN_800033a8(DAT_803dd498,0,0x6ec);
  }
  DAT_803a32c8 = 0;
  DAT_803a32a8 = 0xc;
  DAT_803a32a9 = 0xc;
  DAT_803a32ae = 0x19;
  DAT_803a32ac = 0;
  DAT_803a32b2 = 1;
  DAT_803a393a = 0xff;
  DAT_803a32b4 = 0xc;
  DAT_803a32b5 = 0xc;
  DAT_803a32ba = 0x19;
  DAT_803a32b8 = 0;
  DAT_803a32be = 1;
  DAT_803a394a = 0xff;
  DAT_803a32c1 = 0x14;
  DAT_803a394c = 0xffff;
  DAT_803a3950 = FLOAT_803e06c8;
  DAT_803a3954 = 0xffff;
  DAT_803a3956 = 0xffff;
  DAT_803a395a = 0xffff;
  DAT_803a395c = 0xffff;
  DAT_803a395e = 0xffff;
  DAT_803a3960 = 0xffff;
  DAT_803a3962 = 0xffff;
  DAT_803a3991 = 0xff;
  DAT_803a3992 = 0xff;
  DAT_803a3993 = 0xff;
  DAT_803a3990 = 9;
  DAT_803a32cb = 0;
  DAT_803a32c9 = 1;
  iVar5 = 0;
  psVar6 = &DAT_80311720;
  do {
    if (*psVar6 != 0) {
      (**(code **)(*DAT_803dcaac + 0x44))(iVar5,1);
    }
    psVar6 = psVar6 + 1;
    iVar5 = iVar5 + 1;
  } while (iVar5 < 0x78);
  FUN_800e8ff8(7,0,1);
  FUN_800e8ff8(7,2,1);
  FUN_800e8ff8(7,3,1);
  FUN_800e8ff8(7,5,1);
  FUN_800e8ff8(7,10,1);
  FUN_800e8ff8(0x1d,0,1);
  FUN_800e8ff8(0x1d,0x1f,1);
  FUN_800e8ff8(0x13,0,1);
  FUN_800e8ff8(0x13,0x16,1);
  FUN_800200e8(0x967,1);
  (&DAT_803a392c)[(uint)DAT_803a32c8 * 4] = uVar4;
  (&DAT_803a3930)[(uint)DAT_803a32c8 * 4] = uVar1;
  (&DAT_803a3934)[(uint)DAT_803a32c8 * 4] = uVar2;
  DAT_803a3805 = 1;
  if (pcVar7 == (char *)0x0) {
    DAT_803a32c4 = 0x46;
    DAT_803a32c5 = 0x4f;
    DAT_803a32c6 = 0x58;
    DAT_803a32c7 = 0;
  }
  else {
    pcVar3 = &DAT_803a32c4;
    do {
      cVar8 = *pcVar7;
      pcVar7 = pcVar7 + 1;
      *pcVar3 = cVar8;
      pcVar3 = pcVar3 + 1;
    } while (cVar8 != '\0');
  }
  FUN_80003494(DAT_803dd498,&DAT_803a32a8,0x6ec);
  cVar8 = (char)uVar9;
  if ((cVar8 == -1) || (DAT_803db890 = cVar8, pcVar7 == (char *)0x0)) {
    uVar4 = 0;
  }
  else {
    uVar4 = FUN_8007db24((uint)uVar9 & 0xff,DAT_803dd498,&DAT_803a31c4);
  }
  FUN_80286128(uVar4);
  return;
}

