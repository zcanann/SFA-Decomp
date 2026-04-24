// Function: FUN_802356cc
// Entry: 802356cc
// Size: 284 bytes

void FUN_802356cc(undefined4 param_1,undefined4 param_2,char param_3)

{
  int iVar1;
  char cVar5;
  int iVar2;
  undefined2 uVar4;
  undefined4 uVar3;
  int iVar6;
  undefined8 uVar7;
  
  uVar7 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar7 >> 0x20);
  iVar6 = *(int *)(iVar1 + 0x4c);
  cVar5 = FUN_8002e04c();
  if (cVar5 != '\0') {
    iVar2 = FUN_8002bdf4(0x28,0x210);
    *(undefined *)(iVar2 + 4) = *(undefined *)(iVar6 + 4);
    *(undefined *)(iVar2 + 6) = *(undefined *)(iVar6 + 6);
    *(undefined *)(iVar2 + 5) = *(undefined *)(iVar6 + 5);
    *(char *)(iVar2 + 7) = *(char *)(iVar6 + 7) + -10;
    iVar6 = (int)uVar7 + param_3 * 0xc;
    *(undefined4 *)(iVar2 + 8) = *(undefined4 *)(iVar6 + 0xc);
    *(undefined4 *)(iVar2 + 0xc) = *(undefined4 *)(iVar6 + 0x10);
    *(undefined4 *)(iVar2 + 0x10) = *(undefined4 *)(iVar6 + 0x14);
    uVar4 = FUN_800221a0(0x708,6000);
    *(undefined2 *)(iVar2 + 0x1c) = uVar4;
    *(undefined2 *)(iVar2 + 0x1e) = 0;
    *(undefined *)(iVar2 + 0x20) = 10;
    *(undefined *)(iVar2 + 0x21) = 0x28;
    *(undefined *)(iVar2 + 0x22) = 0x32;
    *(undefined *)(iVar2 + 0x23) = 10;
    *(undefined *)(iVar2 + 0x24) = 0x32;
    *(undefined *)(iVar2 + 0x25) = 0xd8;
    *(undefined2 *)(iVar2 + 0x26) = 0xffff;
    *(undefined4 *)(iVar2 + 0x18) = 0;
    uVar3 = FUN_8002df90(iVar2,5,(int)*(char *)(iVar1 + 0xac),0xffffffff,
                         *(undefined4 *)(iVar1 + 0x30));
    *(undefined4 *)((int)uVar7 + param_3 * 4) = uVar3;
  }
  FUN_80286128();
  return;
}

