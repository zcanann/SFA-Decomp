// Function: FUN_801f4628
// Entry: 801f4628
// Size: 656 bytes

void FUN_801f4628(int param_1)

{
  undefined4 uVar1;
  undefined uVar2;
  float *pfVar3;
  
  FUN_80037200(param_1,9);
  uVar1 = FUN_800481b0(0xb);
  FUN_8004350c(uVar1,0,0);
  pfVar3 = *(float **)(param_1 + 0xb8);
  *(undefined *)((int)pfVar3 + 0xb) = 0;
  *(undefined2 *)((int)pfVar3 + 6) = 0x1e;
  *pfVar3 = FLOAT_803e5e90;
  pfVar3[4] = 0.0;
  FUN_80043560(0xf,0);
  uVar2 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(param_1 + 0xac));
  switch(uVar2) {
  case 1:
    (**(code **)(*DAT_803dcaac + 0x44))(0xe,1);
    (**(code **)(*DAT_803dcaac + 0x50))(0xe,0,1);
    break;
  case 2:
    FUN_800200e8(0xd1b,1);
    FUN_800200e8(0xe6f,1);
    FUN_800200e8(0xf43,1);
    FUN_800200e8(0xf44,0);
    break;
  case 3:
    FUN_800200e8(0xd1b,1);
    FUN_800200e8(0xd1c,1);
    FUN_800200e8(0xa7f,1);
    FUN_800200e8(0xf43,0);
    FUN_800200e8(0xf44,1);
    break;
  case 4:
    FUN_800200e8(0xd1b,1);
    FUN_800200e8(0xd1c,1);
    FUN_800200e8(0xd1d,1);
    FUN_800200e8(0xa7f,1);
    FUN_800200e8(0xf43,0);
    FUN_800200e8(0xf44,1);
    *(undefined2 *)(pfVar3 + 1) = 0xffff;
    break;
  case 5:
    FUN_800200e8(0xd1b,1);
    FUN_800200e8(0xd1c,1);
    FUN_800200e8(0xd1d,1);
    FUN_800200e8(0xd1e,1);
    FUN_800200e8(0xf43,0);
    FUN_800200e8(0xf44,1);
    break;
  case 6:
    FUN_800200e8(0xd1b,1);
    FUN_800200e8(0xd1c,1);
    FUN_800200e8(0xd1d,1);
    FUN_800200e8(0xd1e,1);
    FUN_800200e8(0xd1f,1);
    FUN_800200e8(0x164,1);
    FUN_800200e8(0xf43,0);
    FUN_800200e8(0xf44,0);
    break;
  case 7:
    *(undefined2 *)(pfVar3 + 2) = 700;
    *(undefined *)((int)pfVar3 + 10) = 0x1e;
    *(ushort *)((int)pfVar3 + 6) = (ushort)*(byte *)((int)pfVar3 + 10);
    *(undefined *)(pfVar3 + 5) = 1;
  }
  return;
}

