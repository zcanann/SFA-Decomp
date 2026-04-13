// Function: FUN_80236b44
// Entry: 80236b44
// Size: 492 bytes

void FUN_80236b44(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  byte bVar1;
  int iVar2;
  int *piVar3;
  undefined4 in_r9;
  undefined4 in_r10;
  byte *pbVar4;
  byte *pbVar5;
  int iVar6;
  int iVar7;
  double dVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_80286834();
  iVar2 = (int)((ulonglong)uVar9 >> 0x20);
  piVar3 = (int *)uVar9;
  iVar7 = *(int *)(iVar2 + 0x4c);
  piVar3[4] = (int)((float)piVar3[4] - FLOAT_803dc074);
  if ((float)piVar3[4] <= FLOAT_803e7ff8) {
    piVar3[4] = (int)FLOAT_803e7ffc;
    *(char *)((int)piVar3 + 0x23) = *(char *)((int)piVar3 + 0x23) + '\x01';
    if (2 < *(byte *)((int)piVar3 + 0x23)) {
      *(undefined *)((int)piVar3 + 0x23) = 0;
    }
    if (*piVar3 != 0) {
      iVar6 = (uint)(byte)(&DAT_803dd048)[*(byte *)((int)piVar3 + 0x23)] * 3;
      pbVar4 = &DAT_8032c9a9 + iVar6;
      pbVar5 = &DAT_8032c9aa + iVar6;
      FUN_8001dbb4(*piVar3,(&DAT_8032c9a8)[iVar6],*pbVar4,*pbVar5,0xff);
      FUN_8001dadc(*piVar3,(&DAT_8032c9a8)[iVar6],*pbVar4,*pbVar5,0xff);
      dVar8 = (double)FLOAT_803e8000;
      FUN_8001db7c(*piVar3,(char)(int)(dVar8 * (double)(float)((double)CONCAT44(0x43300000,
                                                                                (uint)(byte)(&
                                                  DAT_8032c9a8)[iVar6]) - DOUBLE_803e7ff0)),
                   (char)(int)(dVar8 * (double)(float)((double)CONCAT44(0x43300000,(uint)*pbVar4) -
                                                      DOUBLE_803e7ff0)),
                   (char)(int)(dVar8 * (double)(float)((double)CONCAT44(0x43300000,(uint)*pbVar5) -
                                                      DOUBLE_803e7ff0)),0xff);
      bVar1 = *(byte *)(iVar7 + 0x29);
      if ((bVar1 & 0x40) != 0) {
        if ((bVar1 & 0x80) == 0) {
          FUN_8001d7f4((double)(FLOAT_803e8008 * *(float *)(iVar2 + 8)),dVar8,param_3,param_4,
                       param_5,param_6,param_7,param_8,*piVar3,0,(uint)(byte)(&DAT_8032c9a8)[iVar6],
                       (uint)*pbVar4,(uint)*pbVar5,0x87,in_r9,in_r10);
        }
        else {
          FUN_8001d7f4((double)(FLOAT_803e8004 * *(float *)(iVar2 + 8)),dVar8,param_3,param_4,
                       param_5,param_6,param_7,param_8,*piVar3,0,(uint)(byte)(&DAT_8032c9a8)[iVar6],
                       (uint)*pbVar4,(uint)*pbVar5,0x87,in_r9,in_r10);
        }
      }
    }
  }
  FUN_80286880();
  return;
}

