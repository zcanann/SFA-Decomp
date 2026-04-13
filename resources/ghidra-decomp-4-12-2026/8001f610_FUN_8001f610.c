// Function: FUN_8001f610
// Entry: 8001f610
// Size: 300 bytes

void FUN_8001f610(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  undefined4 uVar2;
  char *pcVar3;
  
  switch(*(undefined *)(param_9 + 1)) {
  case 0:
    iVar1 = FUN_800492c0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         *(int *)(param_9 + 4));
    **(int **)(param_9 + 8) = iVar1;
    break;
  case 1:
    FUN_80049208(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 *(int *)(param_9 + 4),*(uint *)(param_9 + 8),param_11,param_12,param_13,param_14,
                 param_15,param_16);
    break;
  case 2:
    FUN_800490c4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 *(undefined4 *)(param_9 + 4),*(undefined4 *)(param_9 + 8),*(uint *)(param_9 + 0x10)
                 ,*(uint *)(param_9 + 0xc),param_13,param_14,param_15,param_16);
    break;
  case 3:
    uVar2 = FUN_80054620(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    **(undefined4 **)(param_9 + 8) = uVar2;
    break;
  case 4:
    uVar2 = FUN_8002d654(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         *(undefined4 *)(param_9 + 0x18),*(undefined4 *)(param_9 + 0x1c),
                         (char)*(undefined4 *)(param_9 + 0x24),*(undefined4 *)(param_9 + 0x20),
                         *(uint **)(param_9 + 0x14),*(int *)(param_9 + 0x28),param_15,param_16);
    **(undefined4 **)(param_9 + 8) = uVar2;
    break;
  case 5:
    uVar2 = FUN_80013ee8(*(uint *)(param_9 + 4) & 0xffff);
    **(undefined4 **)(param_9 + 8) = uVar2;
    break;
  case 6:
    uVar2 = FUN_80029774();
    **(undefined4 **)(param_9 + 8) = uVar2;
    break;
  case 7:
    pcVar3 = FUN_800282c8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                          *(int *)(param_9 + 0x24),(short)*(undefined4 *)(param_9 + 4),
                          (short)*(undefined4 *)(param_9 + 0xc),*(int *)(param_9 + 0x20),param_13,
                          param_14,param_15,param_16);
    **(undefined4 **)(param_9 + 8) = pcVar3;
  }
  return;
}

