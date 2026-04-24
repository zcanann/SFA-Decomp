// Function: FUN_801f0c0c
// Entry: 801f0c0c
// Size: 252 bytes

void FUN_801f0c0c(undefined2 *param_1,int param_2)

{
  uint uVar1;
  undefined4 *puVar2;
  int iVar3;
  
  puVar2 = *(undefined4 **)(param_1 + 0x5c);
  uVar1 = FUN_80020078(0x78);
  if ((uVar1 == 0) && (param_1[0x23] != 0x188)) {
    FUN_8002b9a0((int)param_1,'Z');
    *(code **)(param_1 + 0x5e) = FUN_801f05b4;
    *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
    *(undefined4 *)(param_1 + 0x7a) = 9;
    *puVar2 = *(undefined4 *)(param_1 + 6);
    puVar2[1] = *(undefined4 *)(param_1 + 8);
    puVar2[2] = *(undefined4 *)(param_1 + 10);
    *(undefined2 *)((int)puVar2 + 0xe) = *param_1;
    FUN_800656f0(0,(int)param_1,0);
    iVar3 = 0;
    do {
      (**(code **)(*DAT_803dd72c + 0x50))(*(undefined *)(param_1 + 0x1a),iVar3,0);
      iVar3 = iVar3 + 1;
    } while (iVar3 < 5);
    FUN_800201ac(0xa4,1);
  }
  return;
}

