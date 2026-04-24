// Function: FUN_80059644
// Entry: 80059644
// Size: 232 bytes

void FUN_80059644(void)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  undefined8 uVar7;
  
  uVar7 = FUN_802860dc();
  uVar1 = DAT_803dcec8;
  uVar2 = (undefined4)((ulonglong)uVar7 >> 0x20);
  uVar3 = FUN_80059ee0(uVar2,1);
  iVar5 = 0x50;
  piVar4 = &DAT_803865a8;
  iVar6 = 0x28;
  do {
    if (*piVar4 == 0) {
      (&DAT_80386468)[iVar5] = uVar3;
      break;
    }
    piVar4 = piVar4 + 1;
    iVar5 = iVar5 + 1;
    iVar6 = iVar6 + -1;
  } while (iVar6 != 0);
  *(char *)((int)uVar7 + 0x34) = (char)iVar5;
  (**(code **)(*DAT_803dcaac + 0x48))(uVar2,iVar5);
  FUN_8005972c(uVar3,iVar5 * 0x8c + -0x7fc7dd38,iVar5,0);
  (**(code **)(*DAT_803dcaac + 0x58))(iVar5);
  DAT_803dcec8 = uVar1;
  FUN_80286128();
  return;
}

