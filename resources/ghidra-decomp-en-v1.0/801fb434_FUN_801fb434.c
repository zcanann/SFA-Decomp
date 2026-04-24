// Function: FUN_801fb434
// Entry: 801fb434
// Size: 756 bytes

void FUN_801fb434(void)

{
  int iVar1;
  int iVar2;
  short sVar3;
  short sVar4;
  short sVar5;
  short sVar6;
  char cVar7;
  int iVar8;
  int iVar9;
  
  iVar1 = FUN_802860d4();
  iVar9 = *(int *)(iVar1 + 0x4c);
  iVar8 = *(int *)(iVar1 + 0xb8);
  iVar2 = FUN_8002b9ec();
  *(byte *)(iVar1 + 0xaf) = *(byte *)(iVar1 + 0xaf) | 8;
  if (iVar2 != 0) {
    sVar3 = FUN_8001ffb4(0x507);
    sVar4 = FUN_8001ffb4(0x508);
    sVar5 = FUN_8001ffb4(0x509);
    sVar6 = FUN_8001ffb4(0x50a);
    cVar7 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(iVar1 + 0xac));
    if (cVar7 == '\x02') {
      sVar3 = 1;
      sVar4 = 1;
      sVar5 = 1;
      sVar6 = 1;
    }
    if ((((sVar3 != 0) && (sVar4 != 0)) && (sVar5 != 0)) &&
       (((sVar6 != 0 && (*(short *)(iVar8 + 10) == 0)) && (iVar2 = FUN_8001ffb4(0x4ee), iVar2 == 0))
       )) {
      (**(code **)(*DAT_803dca54 + 0x48))(4,iVar1,0xffffffff);
      FUN_800200e8(0x4ee,1);
    }
    if (((char)*(byte *)(iVar8 + 0x1c) < '\0') ||
       (((*(byte *)(iVar8 + 0x1c) >> 6 & 1) != 0 && (*(short *)(iVar8 + 10) == 0)))) {
      *(float *)(iVar1 + 0x10) = *(float *)(iVar9 + 0xc) + FLOAT_803e60ec;
      *(byte *)(iVar8 + 0x1c) = *(byte *)(iVar8 + 0x1c) & 0x7f;
      *(byte *)(iVar8 + 0x1c) = *(byte *)(iVar8 + 0x1c) & 0xbf;
      *(undefined2 *)(iVar8 + 10) = 4;
    }
    sVar3 = *(short *)(iVar8 + 10);
    if (sVar3 != 0) {
      if (((sVar3 == 4) || (3 < sVar3)) || (sVar3 < 3)) {
        *(byte *)(iVar1 + 0xaf) = *(byte *)(iVar1 + 0xaf) & 0xf7;
        if ((*(byte *)(iVar1 + 0xaf) & 1) == 0) {
          iVar2 = FUN_8001ffb4((int)*(short *)(iVar8 + 0xe));
          if (iVar2 != 0) {
            *(undefined2 *)(iVar8 + 10) = 3;
            *(undefined4 *)(iVar1 + 0x10) = *(undefined4 *)(iVar9 + 0xc);
          }
        }
        else {
          FUN_80014b3c(0,0x100);
          (**(code **)(*DAT_803dca54 + 0x48))(1,iVar1,0xffffffff);
          *(undefined2 *)(iVar8 + 10) = 3;
          FUN_8000bb18(iVar1,0x113);
          FUN_8000b7bc(iVar1,8);
          FUN_800200e8((int)*(short *)(iVar8 + 0xe),1);
        }
      }
      else {
        *(byte *)(iVar1 + 0xaf) = *(byte *)(iVar1 + 0xaf) & 0xf7;
        if ((*(byte *)(iVar1 + 0xaf) & 1) == 0) {
          iVar2 = FUN_8001ffb4((int)*(short *)(iVar8 + 0xe));
          if (iVar2 == 0) {
            *(undefined2 *)(iVar8 + 10) = 4;
            *(float *)(iVar1 + 0x10) = *(float *)(iVar9 + 0xc) + FLOAT_803e60ec;
          }
        }
        else {
          FUN_80014b3c(0,0x100);
          (**(code **)(*DAT_803dca54 + 0x48))(0,iVar1,0xffffffff);
          *(undefined2 *)(iVar8 + 10) = 4;
          FUN_8000bb18(iVar1,0x113);
          FUN_8000b7bc(iVar1,8);
          FUN_800200e8((int)*(short *)(iVar8 + 0xe),0);
        }
      }
    }
  }
  FUN_80286120();
  return;
}

