// Function: FUN_8023f754
// Entry: 8023f754
// Size: 416 bytes

/* WARNING: Removing unreachable block (ram,0x8023f8d0) */
/* WARNING: Removing unreachable block (ram,0x8023f8c8) */
/* WARNING: Removing unreachable block (ram,0x8023f8c0) */
/* WARNING: Removing unreachable block (ram,0x8023f774) */
/* WARNING: Removing unreachable block (ram,0x8023f76c) */
/* WARNING: Removing unreachable block (ram,0x8023f764) */

void FUN_8023f754(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  uint uVar4;
  undefined2 *puVar5;
  ushort *puVar6;
  double dVar7;
  double dVar8;
  float local_58;
  float local_54;
  float local_50 [2];
  undefined4 local_48;
  uint uStack_44;
  
  uVar3 = FUN_8002e144();
  if ((uVar3 & 0xff) != 0) {
    FUN_80038524(param_9,0,&local_58,&local_54,local_50,0);
    fVar1 = local_58 - *(float *)(*(int *)(param_10 + 4) + 0xc);
    fVar2 = local_50[0] - *(float *)(*(int *)(param_10 + 4) + 0x14);
    dVar7 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
    uVar3 = FUN_80021884();
    dVar8 = (double)(local_54 - *(float *)(*(int *)(param_10 + 4) + 0x10));
    uVar4 = FUN_80021884();
    DAT_803dea50 = (int)(uVar4 & 0xffff) >> 8;
    puVar5 = FUN_8002becc(0x20,0x7e4);
    *(float *)(puVar5 + 4) = local_58;
    *(float *)(puVar5 + 6) = local_54;
    *(float *)(puVar5 + 8) = local_50[0];
    *(char *)(puVar5 + 0xd) = (char)((int)*param_9 + (uVar3 & 0xffff) + 0x8000 >> 8);
    *(char *)((int)puVar5 + 0x19) = (char)DAT_803dea50;
    *(undefined *)(puVar5 + 0xc) = 0;
    *(undefined *)(puVar5 + 2) = 1;
    *(undefined *)((int)puVar5 + 5) = 1;
    puVar6 = (ushort *)
             FUN_8002b678(dVar8,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9,
                          puVar5);
    if (puVar6 != (ushort *)0x0) {
      FUN_8022ecc4((int)puVar6,DAT_803dd178);
      uStack_44 = DAT_803dd174 ^ 0x80000000;
      local_48 = 0x43300000;
      FUN_8022ec10((double)(float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e8238),puVar6)
      ;
    }
  }
  return;
}

