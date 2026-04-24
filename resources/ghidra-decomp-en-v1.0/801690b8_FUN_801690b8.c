// Function: FUN_801690b8
// Entry: 801690b8
// Size: 488 bytes

void FUN_801690b8(undefined4 param_1,undefined4 param_2,int param_3)

{
  double dVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  undefined4 *puVar5;
  int iVar6;
  undefined8 uVar7;
  
  uVar7 = FUN_802860dc();
  iVar2 = (int)((ulonglong)uVar7 >> 0x20);
  iVar6 = *(int *)(iVar2 + 0xb8);
  uVar4 = 6;
  if (param_3 != 0) {
    uVar4 = 7;
  }
  (**(code **)(*DAT_803dcab8 + 0x58))((double)FLOAT_803e30c8,iVar2,(int)uVar7,iVar6,8,6,0,uVar4);
  *(undefined4 *)(iVar2 + 0xbc) = 0;
  puVar5 = *(undefined4 **)(iVar6 + 0x40c);
  FUN_80030334((double)FLOAT_803e3060,iVar2,4,0x10);
  *(float *)(iVar2 + 0x98) = FLOAT_803e307c;
  *(byte *)(iVar2 + 0xaf) = *(byte *)(iVar2 + 0xaf) | 8;
  (**(code **)(*DAT_803dca8c + 0x14))(iVar2,iVar6,0);
  *(undefined2 *)(iVar6 + 0x270) = 0;
  *(float *)(iVar6 + 0x2a0) = FLOAT_803e307c;
  *(float *)(iVar6 + 0x280) = FLOAT_803e3060;
  uVar4 = FUN_8002b9ec();
  *(undefined4 *)(iVar6 + 0x2d0) = uVar4;
  *(undefined *)(iVar6 + 0x25f) = 0;
  FUN_80035f00(iVar2);
  uVar3 = FUN_800221a0(300,600);
  puVar5[0xd] = (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e3070);
  uVar3 = FUN_800221a0(0,499);
  dVar1 = DOUBLE_803e3070;
  puVar5[0xe] = (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e3070);
  puVar5[0xf] = FLOAT_803e3060;
  *puVar5 = 0;
  *(ushort *)(iVar2 + 0xb0) = *(ushort *)(iVar2 + 0xb0) | 0x2000;
  *(float *)(iVar2 + 8) =
       FLOAT_803e30a0 +
       (float)((double)CONCAT44(0x43300000,(int)*(char *)((int)uVar7 + 0x28) ^ 0x80000000) - dVar1)
       / FLOAT_803e30a4;
  FUN_80035974(iVar2,(int)(FLOAT_803e30cc * *(float *)(iVar2 + 8)));
  if (param_3 == 0) {
    DAT_803dda90 = FUN_80013ec8(0x5a,1);
  }
  FUN_80286128();
  return;
}

