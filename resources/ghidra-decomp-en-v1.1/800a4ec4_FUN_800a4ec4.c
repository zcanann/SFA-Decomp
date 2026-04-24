// Function: FUN_800a4ec4
// Entry: 800a4ec4
// Size: 444 bytes

void FUN_800a4ec4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  undefined2 *puVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  
  DAT_803ddf24 = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x16b,
                              param_10,param_11,param_12,param_13,param_14,param_15,param_16);
  DAT_803ddf28 = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x201,
                              param_10,param_11,param_12,param_13,param_14,param_15,param_16);
  DAT_8039cf20 = FUN_80023d8c(0x140,0x15);
  DAT_8039cf24 = FUN_80023d8c(0x140,0x15);
  DAT_8039cf28 = FUN_80023d8c(0x140,0x15);
  DAT_8039cf2c = FUN_80023d8c(0x140,0x15);
  DAT_8039cf30 = FUN_80023d8c(0x140,0x15);
  DAT_8039cf34 = FUN_80023d8c(0x140,0x15);
  DAT_8039cf38 = FUN_80023d8c(0x140,0x15);
  piVar3 = &DAT_8039cf20;
  iVar4 = 0;
  do {
    iVar2 = 0;
    iVar5 = 0x14;
    puVar1 = &DAT_80310ba8;
    do {
      *(undefined2 *)(*piVar3 + iVar2) = *puVar1;
      *(undefined2 *)(*piVar3 + iVar2 + 2) = puVar1[1];
      *(undefined2 *)(*piVar3 + iVar2 + 4) = puVar1[2];
      *(undefined2 *)(*piVar3 + iVar2 + 8) = puVar1[4];
      *(undefined2 *)(*piVar3 + iVar2 + 10) = puVar1[5];
      *(undefined *)(*piVar3 + iVar2 + 0xc) = *(undefined *)(puVar1 + 6);
      *(undefined *)(*piVar3 + iVar2 + 0xd) = *(undefined *)((int)puVar1 + 0xd);
      *(undefined *)(*piVar3 + iVar2 + 0xe) = *(undefined *)(puVar1 + 7);
      *(undefined *)(*piVar3 + iVar2 + 0xf) = 0xff;
      puVar1 = puVar1 + 8;
      iVar2 = iVar2 + 0x10;
      iVar5 = iVar5 + -1;
    } while (iVar5 != 0);
    piVar3 = piVar3 + 1;
    iVar4 = iVar4 + 1;
  } while (iVar4 < 7);
  return;
}

