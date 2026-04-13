// Function: FUN_8023a960
// Entry: 8023a960
// Size: 380 bytes

/* WARNING: Removing unreachable block (ram,0x8023aab8) */
/* WARNING: Removing unreachable block (ram,0x8023aab0) */
/* WARNING: Removing unreachable block (ram,0x8023aaa8) */
/* WARNING: Removing unreachable block (ram,0x8023a980) */
/* WARNING: Removing unreachable block (ram,0x8023a978) */
/* WARNING: Removing unreachable block (ram,0x8023a970) */

void FUN_8023a960(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int *param_10)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  uint uVar4;
  undefined2 *puVar5;
  ushort *puVar6;
  double dVar7;
  double dVar8;
  
  uVar3 = FUN_8002e144();
  if ((uVar3 & 0xff) != 0) {
    fVar1 = (float)param_10[0x30] - *(float *)(*param_10 + 0xc);
    fVar2 = (float)param_10[0x32] - *(float *)(*param_10 + 0x14);
    dVar7 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
    uVar3 = FUN_80021884();
    dVar8 = (double)((float)param_10[0x31] - *(float *)(*param_10 + 0x10));
    uVar4 = FUN_80021884();
    DAT_803dea3c = (int)(uVar4 & 0xffff) >> 8;
    puVar5 = FUN_8002becc(0x20,0x7e4);
    *(int *)(puVar5 + 4) = param_10[0x30];
    *(int *)(puVar5 + 6) = param_10[0x31];
    *(int *)(puVar5 + 8) = param_10[0x32];
    *(char *)(puVar5 + 0xd) = (char)((int)*param_9 + (uVar3 & 0xffff) >> 8);
    *(char *)((int)puVar5 + 0x19) = (char)DAT_803dea3c;
    *(undefined *)(puVar5 + 0xc) = 0;
    *(undefined *)(puVar5 + 2) = 1;
    *(undefined *)((int)puVar5 + 5) = 1;
    puVar6 = (ushort *)
             FUN_8002b678(dVar8,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9,
                          puVar5);
    if (puVar6 != (ushort *)0x0) {
      FUN_8022ecc4((int)puVar6,DAT_803dd144);
      FUN_8022ec10((double)(float)((double)CONCAT44(0x43300000,DAT_803dd140 ^ 0x80000000) -
                                  DOUBLE_803e8130),puVar6);
    }
  }
  return;
}

