// Function: FUN_801e9344
// Entry: 801e9344
// Size: 760 bytes

void FUN_801e9344(int param_1)

{
  short sVar1;
  ushort uVar2;
  int iVar3;
  undefined2 uVar4;
  undefined uVar5;
  float *pfVar6;
  double dVar7;
  
  pfVar6 = *(float **)(param_1 + 0xb8);
  iVar3 = FUN_8002b9ec();
  switch(*(undefined2 *)(param_1 + 0xa0)) {
  case 0:
    sVar1 = *(short *)(pfVar6 + 5);
    uVar2 = (ushort)DAT_803db410;
    *(ushort *)(pfVar6 + 5) = sVar1 - uVar2;
    if ((short)(sVar1 - uVar2) < 1) {
      FUN_8000bb18(param_1,0x13f);
      uVar4 = FUN_800221a0(0xb4,300);
      *(undefined2 *)(pfVar6 + 5) = uVar4;
    }
    dVar7 = (double)FUN_8002166c(param_1 + 0x18,iVar3 + 0x18);
    if (dVar7 < (double)FLOAT_803e5aa4) {
      if (iVar3 != 0) {
        if (FLOAT_803e5aa0 <=
            pfVar6[3] + pfVar6[1] * *(float *)(iVar3 + 0xc) + pfVar6[2] * *(float *)(iVar3 + 0x14))
        {
          pfVar6[4] = (float)&DAT_803dc0b4;
        }
        else {
          pfVar6[4] = (float)&DAT_803dc0b0;
        }
      }
      FUN_80030334((double)FLOAT_803e5aa0,param_1,*(undefined *)pfVar6[4],0);
      *pfVar6 = FLOAT_803e5aa8;
      FUN_8000bb18(param_1,0x140);
      FUN_8000faac();
    }
    break;
  case 1:
  case 4:
    if (*(char *)((int)pfVar6 + 0x16) != '\0') {
      dVar7 = (double)FUN_8002166c(param_1 + 0x18,iVar3 + 0x18);
      if (dVar7 <= (double)FLOAT_803e5aac) {
        FUN_80030334((double)FLOAT_803e5aa0,param_1,*(undefined *)((int)pfVar6[4] + 1),0);
        *pfVar6 = FLOAT_803e5ab4;
      }
      else {
        FUN_80030334((double)FLOAT_803e5aa0,param_1,*(undefined *)((int)pfVar6[4] + 2),0);
        FUN_8000bb18(param_1,0x140);
        *pfVar6 = FLOAT_803e5ab0;
      }
    }
    break;
  case 2:
  case 5:
    FUN_8000bb18(param_1,0x141);
    dVar7 = (double)FUN_8002166c(param_1 + 0x18,iVar3 + 0x18);
    if ((double)FLOAT_803e5aac < dVar7) {
      FUN_80030334((double)FLOAT_803e5aa0,param_1,*(undefined *)((int)pfVar6[4] + 2),0);
      FUN_8000b7bc(param_1,0x40);
      FUN_8000bb18(param_1,0x140);
      *pfVar6 = FLOAT_803e5ab0;
    }
    break;
  case 3:
  case 6:
    if ((*(float *)(param_1 + 0x98) <= FLOAT_803e5ab8) ||
       (dVar7 = (double)FUN_8002166c(param_1 + 0x18,iVar3 + 0x18), (double)FLOAT_803e5aa4 <= dVar7))
    {
      if (*(char *)((int)pfVar6 + 0x16) != '\0') {
        FUN_80030334((double)FLOAT_803e5aa0,param_1,0,0);
        *pfVar6 = FLOAT_803e5abc;
        FUN_8000faac();
      }
    }
    else {
      if (iVar3 != 0) {
        if (FLOAT_803e5aa0 <=
            pfVar6[3] + pfVar6[1] * *(float *)(iVar3 + 0xc) + pfVar6[2] * *(float *)(iVar3 + 0x14))
        {
          pfVar6[4] = (float)&DAT_803dc0b4;
        }
        else {
          pfVar6[4] = (float)&DAT_803dc0b0;
        }
      }
      FUN_80030334((double)FLOAT_803e5aa0,param_1,*(undefined *)pfVar6[4],0);
      FUN_8000bb18(param_1,0x140);
      *pfVar6 = FLOAT_803e5aa8;
    }
  }
  uVar5 = FUN_8002fa48((double)*pfVar6,(double)FLOAT_803db414,param_1,0);
  *(undefined *)((int)pfVar6 + 0x16) = uVar5;
  return;
}

