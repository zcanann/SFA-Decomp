// Function: FUN_801f05d4
// Entry: 801f05d4
// Size: 252 bytes

void FUN_801f05d4(undefined2 *param_1,int param_2)

{
  int iVar1;
  undefined4 *puVar2;
  
  puVar2 = *(undefined4 **)(param_1 + 0x5c);
  iVar1 = FUN_8001ffb4(0x78);
  if ((iVar1 == 0) && (param_1[0x23] != 0x188)) {
    FUN_8002b8c8(param_1,0x5a);
    *(code **)(param_1 + 0x5e) = FUN_801eff7c;
    *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
    *(undefined4 *)(param_1 + 0x7a) = 9;
    *puVar2 = *(undefined4 *)(param_1 + 6);
    puVar2[1] = *(undefined4 *)(param_1 + 8);
    puVar2[2] = *(undefined4 *)(param_1 + 10);
    *(undefined2 *)((int)puVar2 + 0xe) = *param_1;
    FUN_80065574(0,param_1,0);
    iVar1 = 0;
    do {
      (**(code **)(*DAT_803dcaac + 0x50))(*(undefined *)(param_1 + 0x1a),iVar1,0);
      iVar1 = iVar1 + 1;
    } while (iVar1 < 5);
    FUN_800200e8(0xa4,1);
  }
  return;
}

