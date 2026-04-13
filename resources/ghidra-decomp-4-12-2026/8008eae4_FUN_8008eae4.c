// Function: FUN_8008eae4
// Entry: 8008eae4
// Size: 296 bytes

/* WARNING: Removing unreachable block (ram,0x8008ebec) */
/* WARNING: Removing unreachable block (ram,0x8008ebe4) */
/* WARNING: Removing unreachable block (ram,0x8008eafc) */
/* WARNING: Removing unreachable block (ram,0x8008eaf4) */

void FUN_8008eae4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar2;
  int *piVar3;
  double dVar4;
  double dVar5;
  
  DAT_803dc270 = 0xffffffff;
  uRam803dc274 = 0xffffffff;
  iVar2 = 0;
  piVar3 = &DAT_803dde04;
  dVar4 = (double)FLOAT_803dfe10;
  dVar5 = (double)FLOAT_803dfe14;
  do {
    if (*piVar3 == 0) {
      iVar1 = FUN_80023d8c(0x318,0x17);
      *piVar3 = iVar1;
    }
    FUN_800033a8(*piVar3,0,0x318);
    *(undefined4 *)(*piVar3 + 0x24) = 0xff;
    *(undefined4 *)(*piVar3 + 0x28) = 0xff;
    *(undefined4 *)(*piVar3 + 0x2c) = 0xff;
    *(float *)(*piVar3 + 0x14) = (float)dVar4;
    *(float *)(*piVar3 + 0x18) = (float)dVar5;
    *(undefined4 *)(*piVar3 + 0x30) = 0xff;
    *(undefined4 *)(*piVar3 + 0x34) = 0xff;
    *(undefined4 *)(*piVar3 + 0x38) = 0xff;
    *(float *)(*piVar3 + 0x1c) = (float)dVar4;
    *(float *)(*piVar3 + 0x20) = (float)dVar5;
    if (DAT_803dc3b4 != 0) {
      param_1 = FUN_80008cbc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,9,0
                             ,in_r7,in_r8,in_r9,in_r10);
      DAT_803dc3b4 = 0;
    }
    piVar3 = piVar3 + 1;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 2);
  return;
}

