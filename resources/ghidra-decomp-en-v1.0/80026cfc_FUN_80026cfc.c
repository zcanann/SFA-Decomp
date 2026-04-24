// Function: FUN_80026cfc
// Entry: 80026cfc
// Size: 260 bytes

void FUN_80026cfc(void)

{
  int *piVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  undefined8 uVar7;
  
  uVar7 = FUN_802860dc();
  piVar6 = (int *)((ulonglong)uVar7 >> 0x20);
  iVar4 = (int)uVar7;
  piVar1 = (int *)FUN_80023cc8(0x1c,0x1a,0);
  piVar1[1] = iVar4;
  *(undefined *)((int)piVar1 + 0x19) = 0;
  *(undefined *)(piVar1 + 6) = 0;
  iVar2 = FUN_80023cc8(iVar4 * 0xc,0x1a,0);
  *piVar1 = iVar2;
  iVar5 = 0;
  for (iVar2 = 0; iVar2 < iVar4; iVar2 = iVar2 + 1) {
    *(int *)(*piVar1 + iVar5 + 4) = *piVar6;
    *(undefined4 *)(*piVar1 + iVar5 + 8) = *(undefined4 *)(*piVar6 + 4);
    uVar3 = FUN_80023cc8((*(int *)(*piVar1 + iVar5 + 8) + 1) * 0x54,0x1a,0);
    *(undefined4 *)(*piVar1 + iVar5) = uVar3;
    piVar6 = piVar6 + 1;
    iVar5 = iVar5 + 0xc;
  }
  piVar1[2] = (int)FLOAT_803de858;
  piVar1[3] = (int)FLOAT_803de85c;
  piVar1[4] = (int)FLOAT_803de860;
  piVar1[5] = (int)FLOAT_803de828;
  *(undefined *)((int)piVar1 + 0x1a) = 1;
  FUN_80286128(piVar1);
  return;
}

