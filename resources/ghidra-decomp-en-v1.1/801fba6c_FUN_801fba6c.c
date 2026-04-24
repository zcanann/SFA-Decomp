// Function: FUN_801fba6c
// Entry: 801fba6c
// Size: 756 bytes

void FUN_801fba6c(void)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  short sVar4;
  short sVar5;
  short sVar6;
  short sVar7;
  char cVar8;
  int iVar9;
  int iVar10;
  
  uVar1 = FUN_80286838();
  iVar10 = *(int *)(uVar1 + 0x4c);
  iVar9 = *(int *)(uVar1 + 0xb8);
  iVar2 = FUN_8002bac4();
  *(byte *)(uVar1 + 0xaf) = *(byte *)(uVar1 + 0xaf) | 8;
  if (iVar2 != 0) {
    uVar3 = FUN_80020078(0x507);
    sVar4 = (short)uVar3;
    uVar3 = FUN_80020078(0x508);
    sVar5 = (short)uVar3;
    uVar3 = FUN_80020078(0x509);
    sVar6 = (short)uVar3;
    uVar3 = FUN_80020078(0x50a);
    sVar7 = (short)uVar3;
    cVar8 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(uVar1 + 0xac));
    if (cVar8 == '\x02') {
      sVar4 = 1;
      sVar5 = 1;
      sVar6 = 1;
      sVar7 = 1;
    }
    if ((((sVar4 != 0) && (sVar5 != 0)) && (sVar6 != 0)) &&
       (((sVar7 != 0 && (*(short *)(iVar9 + 10) == 0)) && (uVar3 = FUN_80020078(0x4ee), uVar3 == 0))
       )) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(4,uVar1,0xffffffff);
      FUN_800201ac(0x4ee,1);
    }
    if (((char)*(byte *)(iVar9 + 0x1c) < '\0') ||
       (((*(byte *)(iVar9 + 0x1c) >> 6 & 1) != 0 && (*(short *)(iVar9 + 10) == 0)))) {
      *(float *)(uVar1 + 0x10) = *(float *)(iVar10 + 0xc) + FLOAT_803e6d84;
      *(byte *)(iVar9 + 0x1c) = *(byte *)(iVar9 + 0x1c) & 0x7f;
      *(byte *)(iVar9 + 0x1c) = *(byte *)(iVar9 + 0x1c) & 0xbf;
      *(undefined2 *)(iVar9 + 10) = 4;
    }
    sVar4 = *(short *)(iVar9 + 10);
    if (sVar4 != 0) {
      if (((sVar4 == 4) || (3 < sVar4)) || (sVar4 < 3)) {
        *(byte *)(uVar1 + 0xaf) = *(byte *)(uVar1 + 0xaf) & 0xf7;
        if ((*(byte *)(uVar1 + 0xaf) & 1) == 0) {
          uVar3 = FUN_80020078((int)*(short *)(iVar9 + 0xe));
          if (uVar3 != 0) {
            *(undefined2 *)(iVar9 + 10) = 3;
            *(undefined4 *)(uVar1 + 0x10) = *(undefined4 *)(iVar10 + 0xc);
          }
        }
        else {
          FUN_80014b68(0,0x100);
          (**(code **)(*DAT_803dd6d4 + 0x48))(1,uVar1,0xffffffff);
          *(undefined2 *)(iVar9 + 10) = 3;
          FUN_8000bb38(uVar1,0x113);
          FUN_8000b7dc(uVar1,8);
          FUN_800201ac((int)*(short *)(iVar9 + 0xe),1);
        }
      }
      else {
        *(byte *)(uVar1 + 0xaf) = *(byte *)(uVar1 + 0xaf) & 0xf7;
        if ((*(byte *)(uVar1 + 0xaf) & 1) == 0) {
          uVar3 = FUN_80020078((int)*(short *)(iVar9 + 0xe));
          if (uVar3 == 0) {
            *(undefined2 *)(iVar9 + 10) = 4;
            *(float *)(uVar1 + 0x10) = *(float *)(iVar10 + 0xc) + FLOAT_803e6d84;
          }
        }
        else {
          FUN_80014b68(0,0x100);
          (**(code **)(*DAT_803dd6d4 + 0x48))(0,uVar1,0xffffffff);
          *(undefined2 *)(iVar9 + 10) = 4;
          FUN_8000bb38(uVar1,0x113);
          FUN_8000b7dc(uVar1,8);
          FUN_800201ac((int)*(short *)(iVar9 + 0xe),0);
        }
      }
    }
  }
  FUN_80286884();
  return;
}

