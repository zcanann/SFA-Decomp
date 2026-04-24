// Function: FUN_8023a3e4
// Entry: 8023a3e4
// Size: 676 bytes

void FUN_8023a3e4(void)

{
  byte bVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  byte bVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  undefined8 uVar11;
  int local_28;
  int local_24;
  undefined auStack32 [32];
  
  uVar11 = FUN_802860d8();
  uVar3 = (undefined4)((ulonglong)uVar11 >> 0x20);
  iVar6 = (int)uVar11;
  iVar4 = FUN_8003687c(uVar3,&local_28,&local_24,auStack32);
  for (bVar7 = 0; bVar7 < 4; bVar7 = bVar7 + 1) {
    iVar2 = (uint)*(byte *)(iVar6 + bVar7 + 0xb2) - (uint)DAT_803db410;
    if (iVar2 < 0) {
      iVar2 = 0;
    }
    *(char *)(iVar6 + bVar7 + 0xb2) = (char)iVar2;
  }
  if (iVar4 != 0) {
    if (local_24 == 3) {
      if ((((*(short *)(local_28 + 0x46) == 0x605) && (*(char *)(iVar6 + 0xb5) == '\0')) &&
          (*(char *)(iVar6 + 0xb1) != '\0')) && (*(int *)(iVar6 + 0x88) == 0xc)) {
        FUN_8002ac30(uVar3,0x19,200,0,0,1);
        *(char *)(iVar6 + local_24 + 0xae) = *(char *)(iVar6 + local_24 + 0xae) + -1;
        *(undefined *)(iVar6 + local_24 + 0xb2) = 200;
      }
    }
    else if ((local_24 < 3) && (-1 < local_24)) {
      iVar4 = iVar6 + local_24;
      if ((*(char *)(iVar4 + 0xae) != '\0') && (*(char *)(iVar4 + 0xb2) == '\0')) {
        *(char *)(iVar4 + 0xae) = *(char *)(iVar4 + 0xae) + -1;
        *(undefined *)(iVar6 + local_24 + 0xb2) = 6;
        if (*(char *)(iVar6 + local_24 + 0xae) == '\0') {
          FUN_8000bb18(uVar3,0x485);
        }
        else {
          FUN_8000bb18(uVar3,0x484);
        }
        if (local_24 == 1) {
          *(undefined2 *)(iVar6 + 0xa2) = 0xfa;
        }
        else if (local_24 < 1) {
          if (-1 < local_24) {
            *(undefined2 *)(iVar6 + 0xa2) = 0xff06;
          }
        }
        else if (local_24 < 3) {
          *(undefined2 *)(iVar6 + 0xa4) = 0xff38;
        }
      }
    }
  }
  for (bVar7 = 0; bVar7 < 3; bVar7 = bVar7 + 1) {
    iVar4 = iVar6 + (uint)bVar7;
    if (*(char *)(iVar4 + 0xae) == '\0') {
      *(undefined *)(iVar4 + 0xb9) = 2;
    }
    else if (*(char *)(iVar4 + 0xb2) == '\0') {
      *(undefined *)(iVar4 + 0xb9) = 0;
    }
    else {
      *(undefined *)(iVar4 + 0xb9) = 1;
    }
    bVar1 = *(byte *)(iVar4 + 0xb9);
    uVar8 = (uint)bVar1;
    uVar9 = (uint)(byte)(&DAT_803dc4c8)[bVar7];
    uVar10 = uVar8;
    if ((uVar9 < 2) && (bVar1 == 1)) {
      uVar10 = 0;
    }
    piVar5 = (int *)FUN_800394ac(uVar3,uVar9 << 1,0);
    *piVar5 = uVar10 << 8;
    if ((uVar9 == 2) && (bVar1 == 1)) {
      uVar8 = 0;
    }
    piVar5 = (int *)FUN_800394ac(uVar3,uVar9 * 2 + 1,0);
    *piVar5 = uVar8 << 8;
  }
  FUN_80286124();
  return;
}

