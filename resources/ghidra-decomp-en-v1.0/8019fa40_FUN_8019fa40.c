// Function: FUN_8019fa40
// Entry: 8019fa40
// Size: 400 bytes

/* WARNING: Removing unreachable block (ram,0x8019fbb0) */

void FUN_8019fa40(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  double dVar7;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar1 = FUN_802860dc();
  iVar5 = *(int *)(iVar1 + 0xb8);
  iVar2 = FUN_8002b9ec();
  iVar4 = *(int *)(iVar1 + 0x4c);
  if ((char)*(byte *)(iVar5 + 0x39) < '\0') {
    *(byte *)(iVar5 + 0x39) = *(byte *)(iVar5 + 0x39) & 0x7f;
  }
  iVar3 = FUN_8001ffb4((int)*(short *)(iVar4 + 0x1e));
  if (iVar3 == 0) {
    iVar3 = FUN_8001ffb4(0x44);
    dVar7 = (double)FUN_80021704(iVar1 + 0x18,iVar2 + 0x18);
    if (*(char *)(iVar5 + 0x38) == '\x01') {
      FUN_800956f4((double)FLOAT_803e4268,iVar1 + 0xc);
      (**(code **)(*DAT_803dca54 + 0x48))(0,iVar1,0xffffffff);
      *(undefined *)(iVar5 + 0x38) = 2;
    }
    if (((iVar3 == 0) &&
        (((*(char *)(iVar5 + 0x37) == '\x04' ||
          (dVar7 < (double)(float)((double)CONCAT44(0x43300000,
                                                    (int)*(short *)(iVar4 + 0x1a) ^ 0x80000000) -
                                  DOUBLE_803e4278))) ||
         (iVar4 = FUN_800956f4((double)FLOAT_803e4268,iVar1 + 0xc), iVar4 != 0)))) &&
       (iVar2 = FUN_80296ba0(iVar2), iVar2 != 0x40)) {
      (**(code **)(*DAT_803dca54 + 0x48))(1,iVar1,0xffffffff);
    }
  }
  else {
    *(byte *)(iVar1 + 0xaf) = *(byte *)(iVar1 + 0xaf) | 8;
    *(ushort *)(iVar1 + 6) = *(ushort *)(iVar1 + 6) | 0x4000;
    FUN_80035f00(iVar1);
    FUN_8002ce88(iVar1);
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  FUN_80286128();
  return;
}

