// Function: FUN_8012d77c
// Entry: 8012d77c
// Size: 496 bytes

void FUN_8012d77c(void)

{
  ushort uVar2;
  ushort uVar3;
  int iVar1;
  undefined4 uVar4;
  undefined4 uVar5;
  int iVar6;
  int iVar7;
  short sVar8;
  undefined auStack40 [4];
  undefined auStack36 [4];
  undefined local_20 [2];
  short sStack30;
  undefined local_1c [2];
  short sStack26;
  
  FUN_802860dc();
  if ((DAT_803dd774 != 0) && (DAT_803dd776 == 0)) {
    uVar4 = FUN_80019b14();
    FUN_80019b1c(DAT_803dd77b,3);
    uVar5 = FUN_800191c4(DAT_803dba60,DAT_803dba5c);
    iVar6 = FUN_800173c8(0x49);
    DAT_8033be40 = DAT_803a8aec;
    DAT_8033be44 = DAT_803a8af0;
    DAT_8033be48 = DAT_803a8af4;
    DAT_8033be4c = DAT_803a8af8;
    DAT_8033be50 = DAT_803a8afc;
    uVar2 = DAT_803dd774;
    if (0x7f < DAT_803dd774) {
      uVar2 = 0xff - DAT_803dd774;
    }
    uVar2 = uVar2 * 0xf;
    if (0xff < (short)uVar2) {
      uVar2 = 0xff;
    }
    uVar3 = DAT_803dd774;
    if (0x7f < DAT_803dd774) {
      uVar3 = 0xff - DAT_803dd774;
    }
    iVar7 = (short)uVar3 + -0x14;
    if ((short)iVar7 < 0) {
      iVar7 = 0;
    }
    sVar8 = (short)(iVar7 << 4);
    if (0x10e < sVar8) {
      sVar8 = 0x10e;
    }
    FUN_8001984c(*(undefined2 *)(iVar6 + 2),*(undefined2 *)(iVar6 + 10),1);
    FUN_800163c4(uVar5,0x49,0,0,local_1c,local_20,auStack36,auStack40);
    FUN_80019804(1);
    iVar1 = (short)(sStack30 - sStack26) + 0x28;
    iVar7 = (int)sVar8;
    if (iVar1 < iVar7) {
      iVar7 = iVar1;
    }
    uVar3 = (ushort)iVar7;
    if ((short)uVar3 < 0) {
      uVar3 = 0;
    }
    *(ushort *)(iVar6 + 8) = uVar3 & 0xfffe;
    *(short *)(iVar6 + 0x14) = 0x140 - ((short)uVar3 >> 1);
    FUN_8001984c(*(undefined2 *)(iVar6 + 2),*(undefined2 *)(iVar6 + 10),2);
    FUN_80019908(0xff,0xff,0xff,uVar2 & 0xff);
    *(char *)(iVar6 + 0x1e) = (char)uVar2;
    FUN_8001618c(uVar5,0x49);
    FUN_80019804(2);
    FUN_80019b1c(uVar4,3);
  }
  FUN_80286128();
  return;
}

