// Function: FUN_802b7abc
// Entry: 802b7abc
// Size: 360 bytes

void FUN_802b7abc(void)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined8 uVar7;
  
  uVar7 = FUN_80286840();
  iVar1 = (int)((ulonglong)uVar7 >> 0x20);
  iVar3 = (int)uVar7;
  iVar6 = *(int *)(iVar1 + 0x4c);
  iVar4 = *(int *)(iVar1 + 0xb8);
  iVar5 = *(int *)(iVar4 + 0x40c);
  if ((*(char *)(iVar3 + 0x27b) != '\0') || (*(char *)(iVar3 + 0x346) != '\0')) {
    uVar2 = FUN_80020078((int)*(short *)(iVar6 + 0x1c));
    if (uVar2 != 0) {
      *(byte *)(iVar4 + 0x404) = *(byte *)(iVar4 + 0x404) | 1;
    }
    if ((*(byte *)(iVar4 + 0x404) & 1) == 0) {
      if ((*(short *)(iVar3 + 0x274) != 1) &&
         (uVar2 = FUN_80020078((int)*(short *)(iVar6 + 0x30)), uVar2 != 0)) {
        (**(code **)(*DAT_803dd70c + 0x14))(iVar1,iVar3,1);
      }
    }
    else {
      if (*(short *)(iVar3 + 0x274) != 3) {
        *(undefined *)(iVar5 + 0x2c) = 4;
        (**(code **)(*DAT_803dd70c + 0x14))(iVar1,iVar3,3);
      }
      if ((*(char *)(iVar5 + 0x2c) != '\0') &&
         (*(char *)(iVar5 + 0x2c) = *(char *)(iVar5 + 0x2c) + -1, *(char *)(iVar5 + 0x2c) == '\0'))
      {
        FUN_800201ac((int)*(short *)(iVar6 + 0x1a),1);
        FUN_800201ac((int)*(short *)(iVar6 + 0x30),0);
        *(undefined *)(iVar1 + 0x36) = 0;
        *(ushort *)(iVar1 + 6) = *(ushort *)(iVar1 + 6) | 0x4000;
        *(float *)(iVar5 + 8) = FLOAT_803e8e10;
        *(float *)(iVar5 + 0x10) = FLOAT_803e8e14;
      }
    }
  }
  FUN_8028688c();
  return;
}

