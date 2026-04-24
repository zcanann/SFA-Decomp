// Function: FUN_8008e858
// Entry: 8008e858
// Size: 296 bytes

/* WARNING: Removing unreachable block (ram,0x8008e958) */
/* WARNING: Removing unreachable block (ram,0x8008e960) */

void FUN_8008e858(void)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  undefined4 uVar4;
  undefined8 in_f30;
  double dVar5;
  undefined8 in_f31;
  double dVar6;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  DAT_803db610 = 0xffffffff;
  uRam803db614 = 0xffffffff;
  iVar2 = 0;
  piVar3 = &DAT_803dd184;
  dVar5 = (double)FLOAT_803df190;
  dVar6 = (double)FLOAT_803df194;
  do {
    if (*piVar3 == 0) {
      iVar1 = FUN_80023cc8(0x318,0x17,0);
      *piVar3 = iVar1;
    }
    FUN_800033a8(*piVar3,0,0x318);
    *(undefined4 *)(*piVar3 + 0x24) = 0xff;
    *(undefined4 *)(*piVar3 + 0x28) = 0xff;
    *(undefined4 *)(*piVar3 + 0x2c) = 0xff;
    *(float *)(*piVar3 + 0x14) = (float)dVar5;
    *(float *)(*piVar3 + 0x18) = (float)dVar6;
    *(undefined4 *)(*piVar3 + 0x30) = 0xff;
    *(undefined4 *)(*piVar3 + 0x34) = 0xff;
    *(undefined4 *)(*piVar3 + 0x38) = 0xff;
    *(float *)(*piVar3 + 0x1c) = (float)dVar5;
    *(float *)(*piVar3 + 0x20) = (float)dVar6;
    if (DAT_803db754 != 0) {
      FUN_80008cbc(0,0,9,0);
      DAT_803db754 = 0;
    }
    piVar3 = piVar3 + 1;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 2);
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  __psq_l0(auStack24,uVar4);
  __psq_l1(auStack24,uVar4);
  return;
}

