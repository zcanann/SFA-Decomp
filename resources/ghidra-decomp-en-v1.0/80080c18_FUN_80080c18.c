// Function: FUN_80080c18
// Entry: 80080c18
// Size: 464 bytes

void FUN_80080c18(void)

{
  uint uVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined auStack168 [4];
  int local_a4;
  int local_a0 [40];
  
  uVar1 = FUN_802860dc();
  piVar2 = (int *)FUN_8002e0fc(auStack168,&local_a4);
  iVar3 = 0;
  for (iVar7 = 0; iVar7 < local_a4; iVar7 = iVar7 + 1) {
    iVar4 = *piVar2;
    if ((int)*(short *)(iVar4 + 0xb4) == uVar1) {
      *(undefined2 *)(iVar4 + 0xb4) = 0xffff;
    }
    iVar6 = iVar3;
    if ((*(short *)(iVar4 + 0x44) == 0x10) &&
       (iVar5 = *(int *)(iVar4 + 0xb8), (int)*(char *)(iVar5 + 0x57) == uVar1)) {
      if (iVar4 == DAT_803dd0b8) {
        DAT_803dd0b8 = 0;
      }
      iVar6 = iVar3 + 1;
      local_a0[iVar3] = iVar4;
      if (*(code **)(iVar5 + 0xe8) != (code *)0x0) {
        (**(code **)(iVar5 + 0xe8))(*(undefined4 *)(iVar5 + 0x110),iVar4,iVar5);
        *(undefined4 *)(iVar5 + 0xe8) = 0;
      }
      if (iVar6 == 0x10) {
        FUN_801378a8(s_endObjSequence__max_number_of_ob_8030eed4);
      }
    }
    piVar2 = piVar2 + 1;
    iVar3 = iVar6;
  }
  if (DAT_803dd08c == uVar1) {
    DAT_803dd08c = 0;
    FUN_8012fdc0();
  }
  if (uVar1 == DAT_803db720) {
    FUN_8000d0c0();
    DAT_803db720 = 0xffffffff;
  }
  piVar2 = local_a0;
  for (iVar7 = 0; iVar7 < iVar3; iVar7 = iVar7 + 1) {
    FUN_8002cbc4(*piVar2);
    piVar2 = piVar2 + 1;
  }
  if ((uVar1 == DAT_803dd064) && (iVar3 = (**(code **)(*DAT_803dca50 + 0x10))(), iVar3 == 0x4d)) {
    (**(code **)(*DAT_803dca50 + 0x1c))(0x42,0,3,0,0,0,0);
    DAT_803dd064 = 0;
    DAT_803dd08c = 0;
    FUN_8012fdc0();
  }
  DAT_803dd07c = 0;
  (&DAT_8039a3b0)[uVar1] = 0;
  FUN_80286128();
  return;
}

