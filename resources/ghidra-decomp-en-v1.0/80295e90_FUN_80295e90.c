// Function: FUN_80295e90
// Entry: 80295e90
// Size: 460 bytes

void FUN_80295e90(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined8 uVar4;
  
  uVar4 = FUN_802860dc();
  iVar2 = (int)((ulonglong)uVar4 >> 0x20);
  iVar3 = *(int *)(iVar2 + 0xb8);
  FUN_800395d8(iVar2,0);
  FUN_800395d8(iVar2,9);
  if ((int)uVar4 == 0) {
    FUN_80295cf4(iVar2,1);
    *(byte *)(iVar3 + 0x3f3) = *(byte *)(iVar3 + 0x3f3) & 0xf7;
    *(byte *)(iVar3 + 0x3f4) = *(byte *)(iVar3 + 0x3f4) & 0x7f;
    (**(code **)(*DAT_803dcab4 + 0xc))(iVar2,0x801,0,0x50,0);
    iVar3 = FUN_8002b588(iVar2);
    FUN_8002b884(iVar2,1);
    iVar1 = FUN_8002b588(iVar2);
    FUN_80003494(*(undefined4 *)(iVar1 + 0x2c),*(undefined4 *)(iVar3 + 0x2c),0x68);
    FUN_80003494(*(undefined4 *)(iVar1 + 0x30),*(undefined4 *)(iVar3 + 0x30),0x68);
    FUN_800200e8(0xc30,0);
    FUN_8000bb18(iVar2,0x69);
  }
  else {
    FUN_80295cf4(iVar2,0);
    *(byte *)(iVar3 + 0x3f3) = *(byte *)(iVar3 + 0x3f3) & 0xf7 | 8;
    iVar1 = FUN_8002b9ac();
    if (iVar1 != 0) {
      FUN_80138ef8();
    }
    FUN_800200e8(0xc30,1);
    FUN_8000bb18(iVar2,0x69);
    (**(code **)(*DAT_803dcab4 + 0xc))(iVar2,0x801,0,0x50,0);
    iVar1 = FUN_8002b588(iVar2);
    FUN_8002b884(iVar2,2);
    iVar2 = FUN_8002b588(iVar2);
    FUN_80003494(*(undefined4 *)(iVar2 + 0x2c),*(undefined4 *)(iVar1 + 0x2c),0x68);
    FUN_80003494(*(undefined4 *)(iVar2 + 0x30),*(undefined4 *)(iVar1 + 0x30),0x68);
    if ((int)uVar4 == 2) {
      *(byte *)(iVar3 + 0x3f4) = *(byte *)(iVar3 + 0x3f4) & 0x7f | 0x80;
    }
  }
  FUN_80286128();
  return;
}

