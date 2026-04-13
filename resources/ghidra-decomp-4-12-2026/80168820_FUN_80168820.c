// Function: FUN_80168820
// Entry: 80168820
// Size: 488 bytes

/* WARNING: Removing unreachable block (ram,0x801689e0) */
/* WARNING: Removing unreachable block (ram,0x801689d8) */
/* WARNING: Removing unreachable block (ram,0x80168838) */
/* WARNING: Removing unreachable block (ram,0x80168830) */

void FUN_80168820(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10,char param_11,undefined4 param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  undefined2 *puVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  
  iVar4 = *(int *)(param_10 + 0x40c);
  iVar3 = *(int *)(param_9 + 0x4c);
  uVar1 = FUN_8002e144();
  if ((uVar1 & 0xff) != 0) {
    dVar6 = (double)FLOAT_803e3d38;
    dVar5 = (double)(float)((double)CONCAT44(0x43300000,(int)*(char *)(iVar3 + 0x28) ^ 0x80000000) -
                           DOUBLE_803e3d08);
    dVar7 = (double)(float)(dVar6 + (double)(float)(dVar5 / (double)FLOAT_803e3d3c));
    puVar2 = FUN_8002becc(0x24,0x51b);
    if (param_11 == '\0') {
      *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(iVar4 + 0x28);
      *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(iVar4 + 0x2c);
      *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(iVar4 + 0x30);
    }
    else {
      *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(iVar4 + 0x10);
      *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(iVar4 + 0x14);
      *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(iVar4 + 0x18);
    }
    *(undefined *)(puVar2 + 2) = 1;
    *(undefined *)((int)puVar2 + 5) = 4;
    *(undefined *)(puVar2 + 3) = 0xff;
    *(undefined *)((int)puVar2 + 7) = 0xff;
    iVar3 = FUN_8002e088(dVar5,dVar6,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,5,0xff,
                         0xffffffff,(uint *)0x0,param_14,param_15,param_16);
    if (iVar3 != 0) {
      dVar5 = (double)(FLOAT_803e3d44 *
                      (*(float *)(param_10 + 0x2c0) /
                      (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_10 + 0x3fe)) -
                             DOUBLE_803e3d00)));
      *(float *)(iVar3 + 0x24) =
           (float)((double)(*(float *)(*(int *)(param_10 + 0x2d0) + 0xc) - *(float *)(puVar2 + 4)) /
                  dVar5);
      uVar1 = FUN_80022264(0xfffffff6,10);
      *(float *)(iVar3 + 0x28) =
           (float)((double)(((float)((double)FLOAT_803e3d40 * dVar7 +
                                    (double)*(float *)(*(int *)(param_10 + 0x2d0) + 0x10)) +
                            (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) -
                                   DOUBLE_803e3d08)) - *(float *)(puVar2 + 6)) / dVar5);
      *(float *)(iVar3 + 0x2c) =
           (float)((double)(*(float *)(*(int *)(param_10 + 0x2d0) + 0x14) - *(float *)(puVar2 + 8))
                  / dVar5);
    }
  }
  return;
}

