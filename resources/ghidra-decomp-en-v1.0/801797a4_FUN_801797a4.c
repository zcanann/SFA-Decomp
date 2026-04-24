// Function: FUN_801797a4
// Entry: 801797a4
// Size: 648 bytes

/* WARNING: Removing unreachable block (ram,0x801798b0) */

void FUN_801797a4(int param_1)

{
  char cVar1;
  byte bVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  undefined uVar6;
  int iVar7;
  
  iVar7 = *(int *)(param_1 + 0xb8);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  *(undefined *)(iVar7 + 0x275) = 0;
  iVar4 = FUN_8002b9ec();
  iVar5 = FUN_8002b9ac();
  if ((((iVar4 == 0) || ((*(ushort *)(iVar4 + 0xb0) & 0x1000) != 0)) || (iVar5 == 0)) ||
     ((uVar3 = countLeadingZeros((uint)*(ushort *)(iVar5 + 0xb0)), (uVar3 >> 5 & 0x1000) != 0 ||
      (iVar4 = FUN_8001ffb4(0xd00), iVar4 != 0)))) {
    FUN_8002cbc4(param_1);
    return;
  }
  cVar1 = *(char *)(iVar7 + 0x274);
  if ((((cVar1 == '\x03') || (cVar1 == '\x02')) || (cVar1 == '\x01')) &&
     (*(float *)(iVar7 + 0x26c) = *(float *)(iVar7 + 0x26c) + FLOAT_803db414,
     FLOAT_803e36a8 <= *(float *)(iVar7 + 0x26c))) {
    *(float *)(iVar7 + 0x26c) = FLOAT_803e369c;
    *(undefined *)(iVar7 + 0x274) = 5;
  }
  bVar2 = *(byte *)(iVar7 + 0x274);
  if (bVar2 == 3) {
    uVar6 = FUN_80179a2c(param_1);
    *(undefined *)(iVar7 + 0x274) = uVar6;
    return;
  }
  if (bVar2 < 3) {
    if (bVar2 == 1) {
      FUN_80179a2c(param_1);
    }
    else if (bVar2 == 0) {
      FUN_801793b8(param_1,iVar7);
      goto LAB_801799b4;
    }
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    uVar6 = 0;
    uVar3 = FUN_80014b24(0);
    if ((((uVar3 & 0x100) == 0) && (*(int *)(param_1 + 0xf8) == 0)) &&
       (iVar4 = FUN_80038024(param_1), iVar4 != 0)) {
      FUN_80035f00(param_1);
      uVar6 = 1;
    }
    *(undefined *)(iVar7 + 0x2c9) = uVar6;
    if (*(char *)(iVar7 + 0x2c9) != '\0') {
      *(undefined *)(iVar7 + 0x2c8) = 0;
      *(undefined *)(iVar7 + 0x2c9) = 0;
      *(undefined *)(iVar7 + 0x274) = 0;
    }
  }
  else if (bVar2 == 5) {
    *(float *)(iVar7 + 0x26c) = *(float *)(iVar7 + 0x26c) + FLOAT_803db414;
    if (FLOAT_803e36a4 <= *(float *)(iVar7 + 0x26c)) {
      FUN_8002cbc4(param_1);
      return;
    }
    *(char *)(param_1 + 0x36) =
         -1 - (char)(int)((FLOAT_803e36ac * *(float *)(iVar7 + 0x26c)) / FLOAT_803e36a4);
  }
LAB_801799b4:
  (**(code **)(*DAT_803dcaa8 + 0x10))((double)FLOAT_803db414,param_1,iVar7);
  (**(code **)(*DAT_803dcaa8 + 0x14))(param_1,iVar7);
  (**(code **)(*DAT_803dcaa8 + 0x18))((double)FLOAT_803db414,param_1,iVar7);
  return;
}

