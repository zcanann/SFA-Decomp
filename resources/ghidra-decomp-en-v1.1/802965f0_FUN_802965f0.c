// Function: FUN_802965f0
// Entry: 802965f0
// Size: 460 bytes

void FUN_802965f0(void)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined8 uVar5;
  
  uVar5 = FUN_80286840();
  uVar1 = (uint)((ulonglong)uVar5 >> 0x20);
  iVar4 = *(int *)(uVar1 + 0xb8);
  FUN_800396d0(uVar1,0);
  FUN_800396d0(uVar1,9);
  if ((int)uVar5 == 0) {
    FUN_80296454(uVar1,1);
    *(byte *)(iVar4 + 0x3f3) = *(byte *)(iVar4 + 0x3f3) & 0xf7;
    *(byte *)(iVar4 + 0x3f4) = *(byte *)(iVar4 + 0x3f4) & 0x7f;
    (**(code **)(*DAT_803dd734 + 0xc))(uVar1,0x801,0,0x50,0);
    iVar4 = FUN_8002b660(uVar1);
    FUN_8002b95c(uVar1,1);
    iVar2 = FUN_8002b660(uVar1);
    FUN_80003494(*(uint *)(iVar2 + 0x2c),*(uint *)(iVar4 + 0x2c),0x68);
    FUN_80003494(*(uint *)(iVar2 + 0x30),*(uint *)(iVar4 + 0x30),0x68);
    FUN_800201ac(0xc30,0);
    FUN_8000bb38(uVar1,0x69);
  }
  else {
    FUN_80296454(uVar1,0);
    *(byte *)(iVar4 + 0x3f3) = *(byte *)(iVar4 + 0x3f3) & 0xf7 | 8;
    iVar2 = FUN_8002ba84();
    if (iVar2 != 0) {
      FUN_80139280(iVar2);
    }
    FUN_800201ac(0xc30,1);
    FUN_8000bb38(uVar1,0x69);
    (**(code **)(*DAT_803dd734 + 0xc))(uVar1,0x801,0,0x50,0);
    iVar2 = FUN_8002b660(uVar1);
    FUN_8002b95c(uVar1,2);
    iVar3 = FUN_8002b660(uVar1);
    FUN_80003494(*(uint *)(iVar3 + 0x2c),*(uint *)(iVar2 + 0x2c),0x68);
    FUN_80003494(*(uint *)(iVar3 + 0x30),*(uint *)(iVar2 + 0x30),0x68);
    if ((int)uVar5 == 2) {
      *(byte *)(iVar4 + 0x3f4) = *(byte *)(iVar4 + 0x3f4) & 0x7f | 0x80;
    }
  }
  FUN_8028688c();
  return;
}

