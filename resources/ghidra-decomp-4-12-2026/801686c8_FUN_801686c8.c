// Function: FUN_801686c8
// Entry: 801686c8
// Size: 344 bytes

void FUN_801686c8(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int *param_10)

{
  uint uVar1;
  undefined2 *puVar2;
  float *pfVar3;
  int iVar4;
  undefined4 in_r10;
  int iVar5;
  int iVar6;
  double dVar7;
  double dVar8;
  
  iVar6 = *(int *)(param_9 + 0x4c);
  dVar8 = (double)FLOAT_803e3d38;
  FLOAT_803de714 =
       (float)(dVar8 + (double)((float)((double)CONCAT44(0x43300000,
                                                         (int)*(char *)(iVar6 + 0x28) ^ 0x80000000)
                                       - DOUBLE_803e3d08) / FLOAT_803e3d3c));
  param_10[0x10] = (int)FLOAT_803e3d24;
  FUN_8000bb38(param_9,0x276);
  iVar5 = 0x28;
  do {
    pfVar3 = &FLOAT_803de714;
    iVar4 = *DAT_803dd708;
    (**(code **)(iVar4 + 8))(param_9,0x717,0,4,0xffffffff);
    iVar5 = iVar5 + -1;
  } while (iVar5 != 0);
  if ((*param_10 == 0) && (uVar1 = FUN_8002e144(), (uVar1 & 0xff) != 0)) {
    puVar2 = FUN_8002becc(0x24,0x55e);
    *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(param_9 + 0xc);
    dVar7 = (double)FLOAT_803e3d40;
    *(float *)(puVar2 + 6) = (float)(dVar7 + (double)*(float *)(param_9 + 0x10));
    *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(param_9 + 0x14);
    *(undefined *)(puVar2 + 2) = *(undefined *)(iVar6 + 4);
    *(undefined *)((int)puVar2 + 5) = *(undefined *)(iVar6 + 5);
    *(undefined *)(puVar2 + 3) = *(undefined *)(iVar6 + 6);
    *(undefined *)((int)puVar2 + 7) = *(undefined *)(iVar6 + 7);
    iVar5 = FUN_8002e088(dVar7,dVar8,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,5,0xff,
                         0xffffffff,(uint *)0x0,pfVar3,iVar4,in_r10);
    *param_10 = iVar5;
    *(float *)(*param_10 + 8) = FLOAT_803de714;
  }
  return;
}

