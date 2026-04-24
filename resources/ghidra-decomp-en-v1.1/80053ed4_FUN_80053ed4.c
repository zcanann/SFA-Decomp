// Function: FUN_80053ed4
// Entry: 80053ed4
// Size: 356 bytes

void FUN_80053ed4(int param_1)

{
  bool bVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint *puVar5;
  double dVar6;
  
  *(undefined4 *)(param_1 + 0x40) = 0;
  *(undefined *)(param_1 + 0x48) = 0;
  puVar5 = (uint *)(param_1 + 0x20);
  bVar1 = 0 < (int)((uint)*(byte *)(param_1 + 0x1d) - (uint)*(byte *)(param_1 + 0x1c));
  FUN_8025aa74(puVar5,param_1 + 0x60,(uint)*(ushort *)(param_1 + 10),
               (uint)*(ushort *)(param_1 + 0xc),(uint)*(byte *)(param_1 + 0x16),
               (uint)*(byte *)(param_1 + 0x17),(uint)*(byte *)(param_1 + 0x18),bVar1);
  if (bVar1) {
    FUN_8025ace8((double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x1c)) -
                                DOUBLE_803df820),
                 (double)(float)((double)CONCAT44(0x43300000,*(byte *)(param_1 + 0x1d) ^ 0x80000000)
                                - DOUBLE_803df828),(double)FLOAT_803df818,puVar5,
                 (uint)*(byte *)(param_1 + 0x19),(uint)*(byte *)(param_1 + 0x1a),0,'\0',0);
  }
  else {
    dVar6 = (double)FLOAT_803df81c;
    FUN_8025ace8(dVar6,dVar6,dVar6,puVar5,(uint)*(byte *)(param_1 + 0x19),
                 (uint)*(byte *)(param_1 + 0x1a),0,'\0',0);
  }
  FUN_8025ae7c((int)puVar5,param_1);
  iVar2 = FUN_8025aea4((int)puVar5);
  uVar3 = FUN_8025ae84((int)puVar5);
  uVar4 = FUN_8025ae94((int)puVar5);
  iVar2 = FUN_8025a850(uVar3,uVar4,iVar2,'\0',0);
  *(int *)(param_1 + 0x44) = iVar2;
  return;
}

