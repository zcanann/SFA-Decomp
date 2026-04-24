// Function: FUN_80223da8
// Entry: 80223da8
// Size: 336 bytes

void FUN_80223da8(undefined2 *param_1)

{
  int iVar1;
  uint *puVar2;
  double dVar3;
  float local_78;
  float local_74;
  float local_70;
  undefined2 local_6c;
  undefined2 local_6a;
  undefined2 local_68;
  float local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined auStack84 [76];
  
  puVar2 = *(uint **)(param_1 + 0x5c);
  iVar1 = FUN_8002b9ec();
  dVar3 = (double)FUN_80021690(param_1 + 0xc,iVar1 + 0x18);
  puVar2[0x2ae] = (uint)(float)dVar3;
  *puVar2 = *puVar2 | 0x2000000;
  (**(code **)(*DAT_803dca8c + 8))
            ((double)FLOAT_803db414,(double)FLOAT_803db414,param_1,puVar2,&DAT_803ad288,
             &DAT_803ad278);
  if ((*(byte *)(puVar2 + 0x2b0) & 1) == 0) {
    *(byte *)((int)puVar2 + 0x96d) = *(byte *)((int)puVar2 + 0x96d) | 1;
  }
  else {
    *(byte *)((int)puVar2 + 0x96d) = *(byte *)((int)puVar2 + 0x96d) & 0xfe;
  }
  FUN_80115094(param_1,puVar2 + 0xd7);
  FUN_8003b310(param_1,puVar2 + 0x260);
  local_60 = *(undefined4 *)(param_1 + 6);
  local_5c = *(undefined4 *)(param_1 + 8);
  local_58 = *(undefined4 *)(param_1 + 10);
  local_6c = *param_1;
  local_6a = param_1[1];
  local_68 = param_1[2];
  local_64 = FLOAT_803e6d18;
  FUN_80021ee8(auStack84,&local_6c);
  dVar3 = (double)FLOAT_803e6cf8;
  FUN_800226cc(dVar3,dVar3,dVar3,auStack84,&local_78,&local_74,&local_70);
  FUN_80062a50((double)local_78,(double)local_74,(double)local_70,param_1);
  return;
}

